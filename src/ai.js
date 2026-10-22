import { contextFor, classifyPath } from './scanner.js';
import { SEVERITY_ORDER } from './rules.js';

// How much source (in characters) Claude may read in full. ~150k chars ≈ 40k tokens.
const SOURCE_BUDGET = Number(process.env.AI_SOURCE_BUDGET_CHARS || 150_000);

const SYSTEM_PROMPT = `You are an expert C++ safety researcher, who is well-versed in common memory vulnerabilities and exploits. We want to use your expertise to scan a given github codebase, and identify all areas in the code that look to be risky (e.g. memory-unsafe code). Then, provide a general summary of the overall risk level of introducing this open source repository into your critical code path. Look only at the source code to determine risk level, ignoring text-based documents.

You will receive:
1. The output of a regex-based pattern scanner (rule hits, counts, hotspot files). These hits are candidates, not confirmed bugs, and the scanner is BLIND to most modern C++ memory-safety bugs.
2. Line-numbered source code. When the repository is small enough you get every non-test source file in full; otherwise you get the highest-risk files in full plus short excerpts around other scanner hits.

Review the source yourself, as a security auditor would. Do not limit yourself to what the scanner flagged — a clean scanner result says little. In particular look for:
- Lifetime bugs: dangling references/pointers/string_views/spans, references to temporaries (including default arguments and members of temporaries in range-for), returning references to locals, lambdas capturing by reference that outlive their scope.
- Invalidation: holding references, pointers or iterators into containers across push_back/insert/erase/rehash.
- Undefined behaviour: signed integer overflow, oversized or negative shifts, misaligned access and strict-aliasing violations via reinterpret_cast/type punning, out-of-bounds indexing, unsigned wraparound in bounds checks (e.g. offset + size overflowing), comparators that are not strict weak orderings, use of moved-from objects, uninitialised reads.
- Concurrency: data races on non-atomic state, unsynchronised containers, captured references shared across threads.
- Classic C issues: unbounded copies, format strings, manual malloc/free, integer overflow in allocation sizes.
Also judge scanner hits in context (e.g. a memcpy whose length is checked against the destination is fine).

Be concrete: cite exact path:line locations from the numbered source and explain the failure mode. Never invent code you were not shown. If you only saw part of the repository, say how that limits your confidence.

Respond with ONLY a JSON object, no prose before or after, matching:
{
  "overall_risk": "Low" | "Moderate" | "High" | "Critical",
  "summary": "2-4 short paragraphs: what the code does at a glance, the dominant risk themes, and whether it is reasonable to put in a critical path",
  "top_concerns": [ { "title": "...", "severity": "critical|high|medium|low", "detail": "why this is dangerous here", "locations": ["path:line", "..."] } ],
  "likely_false_positives": ["short notes on scanner hits that look safe in context"],
  "recommendations": ["concrete steps before adopting: sanitizers (ASan/UBSan/TSan), fuzzing, patches, sandboxing, alternatives"]
}
List at most 12 top_concerns, ordered by severity; group closely related lines into one concern.`;

// Signals that a file is likely to hide lifetime / UB bugs the scanner can't see.
const SUBTLE_RISK_SIGNALS =
  /std::(?:string_view|span)|\[&|\bstd::thread\b|std::async|\.detach\s*\(|reinterpret_cast|\.data\s*\(\)|&\s*\w+\s*=\s*\w+[.\-]|<<\s*[a-z_]|\bstd::sort\b|\bmemcpy\b|\bnew\b|\bdelete\b/g;

function numbered(content) {
  return content
    .split('\n')
    .map((l, i) => `${String(i + 1).padStart(5)} ${l}`)
    .join('\n');
}

/** Chooses which files Claude reads in full, within the character budget. */
export function selectSourceForReview(contentByPath, hotspots, budget = SOURCE_BUDGET) {
  const all = [...contentByPath.entries()];
  const nonTest = all.filter(([p]) => classifyPath(p) !== 'test');
  const pool = nonTest.length ? nonTest : all;
  const total = pool.reduce((s, [, c]) => s + c.length, 0);
  if (total <= budget) {
    return { mode: 'full', files: pool.map(([path]) => path), totalFiles: pool.length };
  }

  const hotRank = new Map(hotspots.map((h, i) => [h.file, hotspots.length - i]));
  const ranked = pool
    .map(([path, content]) => ({
      path,
      size: content.length,
      score: (hotRank.get(path) || 0) * 20 + (content.match(SUBTLE_RISK_SIGNALS) || []).length * 2 - content.length / 4000,
    }))
    .sort((a, b) => b.score - a.score);

  const files = [];
  let used = 0;
  for (const f of ranked) {
    if (f.size > budget / 2) continue; // one giant file shouldn't crowd out everything else
    if (used + f.size > budget) continue;
    files.push(f.path);
    used += f.size;
  }
  // Always give Claude something to read: fall back to the top-ranked file, truncated to fit.
  if (!files.length && ranked.length) files.push(ranked[0].path);
  return { mode: 'partial', files, totalFiles: pool.length };
}

/** Severity-ordered sample of hits in files Claude is NOT reading in full. */
function sampleFindings(findings, skipFiles, max = 40) {
  const pool = findings.filter((f) => f.kind !== 'test' && !skipFiles.has(f.file) && f.severity !== 'low');
  const picked = [];
  const perFile = new Map();
  for (const sev of SEVERITY_ORDER) {
    const byRule = new Map();
    for (const f of pool.filter((x) => x.severity === sev)) {
      if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, []);
      byRule.get(f.ruleId).push(f);
    }
    const queues = [...byRule.values()];
    while (picked.length < max && queues.some((q) => q.length)) {
      for (const q of queues) {
        const f = q.shift();
        if (!f || (perFile.get(f.file) || 0) >= 4) continue;
        perFile.set(f.file, (perFile.get(f.file) || 0) + 1);
        picked.push(f);
        if (picked.length >= max) break;
      }
    }
  }
  return picked;
}

export function aiAvailable() {
  return Boolean(process.env.ANTHROPIC_API_KEY);
}

export function buildReviewRequest({ repo, report, allFindings, contentByPath }) {
  const selection = selectSourceForReview(contentByPath, report.hotspots);
  const fullSet = new Set(selection.files);
  const sample = sampleFindings(allFindings, fullSet);

  const fullSource = selection.files
    .map((p) => {
      let src = numbered(contentByPath.get(p));
      if (src.length > SOURCE_BUDGET) src = src.slice(0, SOURCE_BUDGET) + '\n… [file truncated]';
      return `### FILE ${p}\n\`\`\`cpp\n${src}\n\`\`\``;
    })
    .join('\n\n');

  const excerpts = sample
    .map((f) => {
      const ctx = contextFor(contentByPath.get(f.file), f.line, 4)
        .map((l) => `${String(l.n).padStart(5)}${l.n === f.line ? ' >' : '  '} ${l.text}`)
        .join('\n');
      return `### [${f.severity}] ${f.ruleId} — ${f.file}:${f.line}\n\`\`\`cpp\n${ctx}\n\`\`\``;
    })
    .join('\n\n');

  const input = {
    repository: `${repo.owner}/${repo.repo}${repo.ref ? '@' + repo.ref : ''}`,
    source_coverage:
      selection.mode === 'full'
        ? `All ${selection.totalFiles} non-test source files are included in full below.`
        : `${selection.files.length} of ${selection.totalFiles} non-test source files are included in full (chosen by risk); others appear only as excerpts around scanner hits.`,
    stats: report.stats,
    scanner_risk_estimate: report.risk,
    rule_hits: report.ruleSummary.map(({ ruleId, title, severity, cwe, count, productionCount, files }) => ({ ruleId, title, severity, cwe, count, productionCount, files })),
    hotspot_files: report.hotspots.slice(0, 10),
    modern_cpp_signals: report.mitigations,
  };

  const userContent = [
    `Scanner output (JSON):\n${JSON.stringify(input, null, 1)}`,
    fullSource ? `Full source files (line-numbered):\n\n${fullSource}` : '',
    excerpts ? `Excerpts around scanner hits in other files (">" marks the flagged line):\n\n${excerpts}` : '',
  ]
    .filter(Boolean)
    .join('\n\n');

  return { userContent, selection, excerptCount: sample.length };
}

export async function aiReview(args) {
  const { userContent, selection, excerptCount } = buildReviewRequest(args);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 180_000);
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5',
        max_tokens: 6000,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: userContent }],
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error?.message || `Anthropic API returned ${res.status}`);
    const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start < 0 || end < start) throw new Error('Claude did not return a JSON review.');
    const parsed = JSON.parse(text.slice(start, end + 1));
    return {
      ...parsed,
      model: data.model,
      coverage: {
        mode: selection.mode,
        filesInFull: selection.files.length,
        totalFiles: selection.totalFiles,
        excerpts: excerptCount,
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

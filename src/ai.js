import { contextFor, classifyPath } from './scanner.js';
import { SEVERITY_ORDER } from './rules.js';
import { costUsd } from './budget.js';

// How much source (in characters) Claude may read in full. ~150k chars ≈ 40k tokens.
const SOURCE_BUDGET = Number(process.env.AI_SOURCE_BUDGET_CHARS || 150_000);

const SYSTEM_PROMPT = `You are an expert C++ safety researcher, who is well-versed in common memory vulnerabilities and exploits. We want to use your expertise to scan a given github codebase, and identify all areas in the code that look to be risky (e.g. memory-unsafe code). Then, provide a general summary of the overall risk level of introducing this open source repository into your critical code path. Look only at the source code to determine risk level, ignoring text-based documents.

You will receive:
1. Summary output of a regex-based pattern scanner. Its hits are candidates, not confirmed bugs, and it is BLIND to most modern C++ memory-safety bugs.
2. A list of individual scanner hits, each with an ID like S12.
3. Line-numbered source code: every non-test source file in full when the repository is small enough, otherwise the highest-risk files in full plus short excerpts around other scanner hits.

Review the source yourself, as a security auditor would. Do not limit yourself to what the scanner flagged — a clean scanner result says little. In particular look for:
- Lifetime bugs: dangling references/pointers/string_views/spans (including views into buffers that are later reused or freed), references to temporaries (including default arguments and members of temporaries in range-for), returning references to locals, lambdas capturing by reference that outlive their scope.
- Invalidation: holding references, pointers or iterators into containers across push_back/insert/erase/rehash.
- Undefined behaviour: signed integer overflow, oversized or negative shifts, misaligned access and strict-aliasing violations via reinterpret_cast/type punning, out-of-bounds reads/writes, unsigned wraparound in bounds checks (e.g. offset + size overflowing), lengths never checked against the real buffer, comparators that are not strict weak orderings, use of moved-from objects, uninitialised reads.
- Concurrency: data races on non-atomic state, unsynchronised containers, captured references shared across threads.
- Classic C issues: unbounded copies, format strings, manual malloc/free, integer overflow in allocation sizes.

Report your results by calling the report_review tool exactly once:
- findings: every distinct bug you are confident about, one entry per bug (not per theme), at the line where it occurs, ordered by severity. Cite only path:line locations from the numbered source you were shown — never invent code. When a finding corresponds to scanner hits, list their IDs in scanner_ids (this confirms them). If the scanner flagged the right line but at the wrong severity, give the severity you believe is right.
- dismissed: scanner hits you have checked in context and believe are NOT a problem, with a short reason. Leave a hit out of both lists if you could not judge it.
- Severity: critical = likely exploitable memory corruption; high = memory-unsafe or UB that can corrupt/leak memory or crash; medium = UB or misuse that is dangerous under plausible conditions; low = hardening issue or fragile code.
If you only saw part of the repository, say how that limits your confidence in the summary.`;

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

/** Scanner hits Claude is asked to confirm or dismiss, each with a short ID. */
function reviewableHits(allFindings, fullSet, max = 200) {
  const sevRank = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i]));
  return allFindings
    .filter((f) => f.kind !== 'test' && (f.severity !== 'low' || fullSet.has(f.file)))
    .sort((a, b) => sevRank[a.severity] - sevRank[b.severity] || a.file.localeCompare(b.file) || a.line - b.line)
    .slice(0, max)
    .map((f, i) => ({ id: `S${i + 1}`, finding: f }));
}

const SEVERITY_ENUM = ['critical', 'high', 'medium', 'low'];
const REVIEW_TOOL = {
  name: 'report_review',
  description: 'Report the security review of this repository.',
  input_schema: {
    type: 'object',
    properties: {
      overall_risk: { type: 'string', enum: ['Low', 'Moderate', 'High', 'Critical'] },
      summary: { type: 'string', description: '2-4 short paragraphs: what the code does, dominant risk themes, and whether it is reasonable for a critical path.' },
      findings: {
        type: 'array',
        maxItems: 40,
        items: {
          type: 'object',
          properties: {
            title: { type: 'string', description: 'Short name of the bug, e.g. "Dangling string_view into reused line buffer".' },
            severity: { type: 'string', enum: SEVERITY_ENUM },
            category: { type: 'string', description: 'e.g. Use-after-free, Dangling reference, Out-of-bounds read, Signed integer overflow, Data race, Strict aliasing.' },
            cwe: { type: 'string', description: 'e.g. CWE-416. Optional.' },
            file: { type: 'string', description: 'Path exactly as shown in the source headers.' },
            line: { type: 'integer', minimum: 1 },
            detail: { type: 'string', description: 'Why this is a bug and how it fails, 1-3 sentences.' },
            scanner_ids: { type: 'array', items: { type: 'string' }, description: 'IDs of scanner hits this finding confirms, if any.' },
          },
          required: ['title', 'severity', 'category', 'file', 'line', 'detail'],
        },
      },
      dismissed: {
        type: 'array',
        maxItems: 100,
        items: {
          type: 'object',
          properties: { scanner_id: { type: 'string' }, reason: { type: 'string' } },
          required: ['scanner_id', 'reason'],
        },
      },
      recommendations: { type: 'array', items: { type: 'string' }, maxItems: 8 },
    },
    required: ['overall_risk', 'summary', 'findings', 'dismissed', 'recommendations'],
  },
};

export const DEFAULT_MODEL = 'claude-haiku-5-5';

const REVIEW_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 180_000);
const RETRY_DELAY_MS = Number(process.env.AI_RETRY_DELAY_MS || 3000);
const TRANSIENT = new Set([429, 500, 502, 503, 504, 529]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Claude's review couldn't run; `reason` is a plain-language explanation for the user. */
export class ReviewUnavailableError extends Error {
  constructor(reason, code) {
    super(reason);
    this.code = code;
  }
}

function unavailableFromResponse(status, data) {
  const msg = String(data?.error?.message || '');
  if (/credit balance/i.test(msg)) return new ReviewUnavailableError("The server's Claude API credits have run out", 'credits');
  if (status === 401 || status === 403) return new ReviewUnavailableError("The server's Claude API key was rejected", 'auth');
  if (status === 429) return new ReviewUnavailableError("Claude's API rate limit was reached", 'rate_limit');
  if (status === 529 || status === 503) return new ReviewUnavailableError('Claude is temporarily overloaded', 'overloaded');
  return new ReviewUnavailableError(`Claude's API returned an error (${status}${msg ? `: ${msg.slice(0, 120)}` : ''})`, 'api_error');
}


export function buildReviewRequest({ repo, report, allFindings, contentByPath }) {
  const selection = selectSourceForReview(contentByPath, report.hotspots);
  const fullSet = new Set(selection.files);
  const sample = sampleFindings(allFindings, fullSet);
  const hits = reviewableHits(allFindings, fullSet);

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

  const hitList = hits.map(({ id, finding: f }) => `${id} [${f.severity}] ${f.ruleId} ${f.file}:${f.line} | ${f.code.slice(0, 140)}`).join('\n');

  const input = {
    repository: `${repo.owner}/${repo.repo}${repo.ref ? '@' + repo.ref : ''}`,
    source_coverage:
      selection.mode === 'full'
        ? `All ${selection.totalFiles} non-test source files are included in full below.`
        : `${selection.files.length} of ${selection.totalFiles} non-test source files are included in full (chosen by risk); others appear only as excerpts around scanner hits.`,
    stats: report.stats,
    scanner_risk_estimate: report.risk,
    rule_hits: report.ruleSummary.map(({ ruleId, title, severity, cwe, count, productionCount, files }) => ({ ruleId, title, severity, cwe, count, productionCount, files })),
    modern_cpp_signals: report.mitigations,
  };

  const userContent = [
    `Scanner summary (JSON):\n${JSON.stringify(input, null, 1)}`,
    hitList ? `Individual scanner hits to confirm or dismiss (${hits.length}${hits.length >= 200 ? ', most severe first; others omitted' : ''}):\n${hitList}` : 'The scanner flagged no individual hits for review.',
    fullSource ? `Full source files (line-numbered):\n\n${fullSource}` : '',
    excerpts ? `Excerpts around scanner hits in other files (">" marks the flagged line):\n\n${excerpts}` : '',
  ]
    .filter(Boolean)
    .join('\n\n');

  return { userContent, selection, excerptCount: sample.length, hits };
}

/** Worst-case cost of a review call: conservative input estimate + the full output allowance. */
export function estimateReviewCost(model, userContent, maxTokens) {
  const inputTokens = Math.ceil((SYSTEM_PROMPT.length + JSON.stringify(REVIEW_TOOL).length + userContent.length) / 3);
  return costUsd(model, inputTokens, maxTokens);
}

/**
 * Runs the review. `budget` ({ ledger, clientId }) is optional: when given, the call's
 * worst-case cost is reserved first (throwing BudgetExceededError if over a limit) and then
 * settled with the real cost from the API's reported token usage.
 */
export async function aiReview({ budget, ...args }) {
  const { userContent, selection, excerptCount, hits } = buildReviewRequest(args);
  const model = process.env.ANTHROPIC_MODEL || DEFAULT_MODEL;
  const maxTokens = Number(process.env.AI_MAX_OUTPUT_TOKENS || 8000);

  const reservation = budget ? budget.ledger.reserve(budget.clientId, estimateReviewCost(model, userContent, maxTokens)) : null;
  let actualCost = null; // null = unknown (e.g. timed out after sending): keep the reservation

  const body = JSON.stringify({
    model,
    max_tokens: maxTokens,
    system: SYSTEM_PROMPT,
    tools: [REVIEW_TOOL],
    tool_choice: { type: 'tool', name: REVIEW_TOOL.name },
    messages: [{ role: 'user', content: userContent }],
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REVIEW_TIMEOUT_MS);
  try {
    let res;
    let data;
    // One retry for temporary trouble (rate limit, overload, network blip); rejected calls aren't billed.
    for (let attempt = 1; ; attempt++) {
      try {
        res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          signal: controller.signal,
          headers: { 'content-type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
          body,
        });
      } catch (err) {
        if (err.name === 'AbortError') throw new ReviewUnavailableError("Claude's review took too long", 'timeout');
        if (attempt < 2) {
          await sleep(RETRY_DELAY_MS);
          continue;
        }
        actualCost = 0;
        throw new ReviewUnavailableError("The server couldn't reach Claude's API", 'network');
      }
      data = await res.json().catch(() => ({}));
      if (res.ok || !TRANSIENT.has(res.status) || attempt >= 2) break;
      const wait = Math.min(Number(res.headers.get('retry-after')) * 1000 || RETRY_DELAY_MS, 8000);
      await sleep(wait);
    }
    if (data.usage) actualCost = costUsd(data.model || model, data.usage.input_tokens || 0, data.usage.output_tokens || 0);
    else if (!res.ok) actualCost = 0; // rejected requests aren't billed
    if (!res.ok) throw unavailableFromResponse(res.status, data);
    const call = (data.content || []).find((b) => b.type === 'tool_use' && b.name === REVIEW_TOOL.name);
    if (!call?.input) {
      throw new ReviewUnavailableError("Claude's review came back incomplete", 'incomplete');
    }
    if (data.stop_reason === 'max_tokens') throw new ReviewUnavailableError("Claude's review was cut off before it finished", 'incomplete');
    return {
      review: call.input,
      hits,
      meta: {
        model: data.model,
        usage: data.usage,
        costUsd: actualCost,
        coverage: { mode: selection.mode, filesInFull: selection.files.length, totalFiles: selection.totalFiles, excerpts: excerptCount, scannerHitsReviewed: hits.length },
      },
    };
  } finally {
    clearTimeout(timer);
    if (reservation !== null && actualCost !== null) budget.ledger.settle(reservation, actualCost);
  }
}

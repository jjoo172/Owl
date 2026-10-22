import { contextFor } from './scanner.js';
import { SEVERITY_ORDER } from './rules.js';

const SYSTEM_PROMPT = `You are an expert C++ safety researcher, who is well-versed in common memory vulnerabilities and exploits. We want to use your expertise to scan a given github codebase, and identify all areas in the code that look to be risky (e.g. memory-unsafe code). Then, provide a general summary of the overall risk level of introducing this open source repository into your critical code path. Look only at the source code to determine risk level, ignoring text-based documents.

You are given the output of a static pattern scanner (rule hits, counts, hotspot files) and source excerpts around the most severe hits. Pattern hits are candidates, not confirmed bugs: use the surrounding code to judge whether each is genuinely dangerous (e.g. a memcpy whose length is checked against the destination is fine; a strcpy from a fixed literal into a large buffer is low risk). Be concrete, cite file:line, and do not invent code you were not shown.

Respond with ONLY a JSON object, no prose before or after, matching:
{
  "overall_risk": "Low" | "Moderate" | "High" | "Critical",
  "summary": "2-4 short paragraphs: what the code does at a glance, the dominant risk themes, and whether it is reasonable to put in a critical path",
  "top_concerns": [ { "title": "...", "severity": "critical|high|medium|low", "detail": "why this is dangerous here", "locations": ["path:line", "..."] } ],
  "likely_false_positives": ["short notes on scanner hits that look safe in context"],
  "recommendations": ["concrete steps before adopting: sandboxing, sanitizers, fuzzing, patches, alternatives"]
}
Limit top_concerns to at most 8, ordered by severity.`;

/** Picks a diverse, severity-ordered sample of findings to show the model. */
function sampleFindings(findings, max = 45) {
  const prod = findings.filter((f) => f.kind !== 'test');
  const pool = prod.length ? prod : findings;
  const picked = [];
  const perFile = new Map();
  for (const sev of SEVERITY_ORDER) {
    if (sev === 'low') break; // low-severity hits are summarised by count only
    // round-robin across rules so one noisy rule doesn't crowd out the rest
    const byRule = new Map();
    for (const f of pool.filter((x) => x.severity === sev)) {
      if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, []);
      byRule.get(f.ruleId).push(f);
    }
    const queues = [...byRule.values()];
    while (picked.length < max && queues.some((q) => q.length)) {
      for (const q of queues) {
        const f = q.shift();
        if (!f) continue;
        if ((perFile.get(f.file) || 0) >= 4) continue;
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

export async function aiReview({ repo, report, allFindings, contentByPath }) {
  const sample = sampleFindings(allFindings);
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
    stats: report.stats,
    scanner_risk_estimate: report.risk,
    rule_hits: report.ruleSummary.map(({ ruleId, title, severity, cwe, count, productionCount, files }) => ({ ruleId, title, severity, cwe, count, productionCount, files })),
    hotspot_files: report.hotspots.slice(0, 10),
    modern_cpp_signals: report.mitigations,
  };

  const userContent = `Scanner output (JSON):\n${JSON.stringify(input, null, 1)}\n\nSource excerpts around the most severe hits (">" marks the flagged line):\n\n${excerpts || '(no medium-or-higher findings)'}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
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
        max_tokens: 3000,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: userContent }],
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error?.message || `Anthropic API returned ${res.status}`);
    const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
    const json = text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1);
    const parsed = JSON.parse(json);
    return { ...parsed, model: data.model, reviewedFindings: sample.length };
  } finally {
    clearTimeout(timer);
  }
}

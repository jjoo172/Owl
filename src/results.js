// Builds the full-review results directly from Claude's structured review:
// one findings list, every reported vulnerability visible and counted.

import { SEVERITY_ORDER } from './rules.js';
import { SEVERITY_WEIGHT, classifyPath, contextFor } from './scanner.js';

const SEV_RANK = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i]));
const TEST_FACTOR = 0.2;
const slug = (s) => String(s || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'other';
const normSeverity = (s) => (SEVERITY_ORDER.includes(String(s).toLowerCase()) ? String(s).toLowerCase() : 'medium');
const titleCase = (s) => String(s || 'Other').trim().replace(/^\w/, (c) => c.toUpperCase());

/** Resolves a path Claude cited to a real file (exact, then unique suffix match). */
export function resolvePath(cited, contentByPath) {
  const p = String(cited || '').trim().replace(/^\.?\//, '').replace(/:\d+(-\d+)?$/, '');
  if (contentByPath.has(p)) return p;
  const matches = [...contentByPath.keys()].filter((k) => k.endsWith('/' + p) || p.endsWith('/' + k));
  return matches.length === 1 ? matches[0] : null;
}

export function claudeResults({ review, meta, contentByPath, fileStats }) {
  const seen = new Set();
  const findings = [];
  let unmatched = 0;

  for (const raw of Array.isArray(review.findings) ? review.findings : []) {
    const severity = normSeverity(raw.severity);
    const file = resolvePath(raw.file, contentByPath);
    const content = file ? contentByPath.get(file) : null;
    const lines = content ? content.split('\n') : [];
    const line = Number.isInteger(raw.line) && raw.line >= 1 && raw.line <= lines.length ? raw.line : null;
    const category = titleCase(raw.category || raw.title);
    const key = `${file || raw.file}:${line || raw.line}:${slug(category)}`;
    if (seen.has(key)) continue; // exact duplicate
    seen.add(key);
    if (!file || !line) unmatched++;

    findings.push({
      ruleId: slug(category),
      severity,
      file: file || String(raw.file || 'unknown'),
      line: line || (Number.isInteger(raw.line) ? raw.line : 0),
      code: line ? lines[line - 1].trim().slice(0, 240) : '',
      kind: classifyPath(file || String(raw.file || '')),
      title: String(raw.title || category),
      detail: String(raw.detail || ''),
      category,
      cwe: /^CWE-\d+$/i.test(String(raw.cwe || '').trim()) ? String(raw.cwe).trim().toUpperCase() : '',
      // Shown and counted like any other finding; flagged so readers know to look around it.
      locationVerified: Boolean(file && line),
      context: file && line ? contextFor(content, line, 3) : undefined,
    });
  }

  findings.sort(
    (a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (a.kind === 'test') - (b.kind === 'test') || a.file.localeCompare(b.file) || a.line - b.line,
  );

  // Issue types = Claude's categories.
  const groups = new Map();
  for (const f of findings) {
    if (!groups.has(f.ruleId)) groups.set(f.ruleId, []);
    groups.get(f.ruleId).push(f);
  }
  const ruleSummary = [...groups]
    .map(([ruleId, list]) => ({
      ruleId,
      title: list[0].category,
      severity: list.reduce((s, f) => (SEV_RANK[f.severity] < SEV_RANK[s] ? f.severity : s), 'low'),
      cwe: list.map((f) => f.cwe).find(Boolean) || '',
      description: [...new Set(list.map((f) => f.title))].slice(0, 3).join(' · '),
      count: list.length,
      productionCount: list.filter((f) => f.kind !== 'test').length,
      files: new Set(list.map((f) => f.file)).size,
    }))
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.count - a.count);

  // Files with the most (and most severe) vulnerabilities.
  const perFile = new Map();
  for (const f of findings) {
    if (!perFile.has(f.file)) perFile.set(f.file, []);
    perFile.get(f.file).push(f);
  }
  const hotspots = [...perFile]
    .map(([file, list]) => ({
      file,
      kind: classifyPath(file),
      findings: list.length,
      weighted: Math.round(list.reduce((s, f) => s + SEVERITY_WEIGHT[f.severity] * (f.kind === 'test' ? TEST_FACTOR : 1), 0) * 10) / 10,
      bySeverity: SEVERITY_ORDER.reduce((o, s) => ((o[s] = list.filter((f) => f.severity === s).length), o), {}),
    }))
    .sort((a, b) => b.weighted - a.weighted)
    .slice(0, 15);

  const level = ['Low', 'Moderate', 'High', 'Critical'].includes(review.overall_risk) ? review.overall_risk : 'Moderate';

  return {
    stats: {
      ...fileStats,
      totalFindings: findings.length,
      bySeverity: SEVERITY_ORDER.reduce((o, s) => ((o[s] = findings.filter((f) => f.severity === s).length), o), {}),
      findingsTruncated: false,
    },
    risk: { level },
    ruleSummary,
    hotspots,
    findings,
    ai: {
      overall_risk: level,
      summary: String(review.summary || ''),
      recommendations: Array.isArray(review.recommendations) ? review.recommendations.map(String) : [],
      top_concerns: findings.slice(0, 8).map((f) => ({ title: f.title, severity: f.severity, detail: f.detail, locations: f.line > 0 ? [`${f.file}:${f.line}`] : [] })),
      unmatchedLocations: unmatched,
      model: meta.model,
      usage: meta.usage,
      costUsd: meta.costUsd,
      coverage: meta.coverage,
    },
  };
}

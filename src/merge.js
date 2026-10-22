// Merges Claude's structured review into the scanner's results so the findings
// list, severity counts, rule table and hotspots all reflect both sources.
//
// - Claude findings that match a scanner hit (by ID, or by the same file:line)
//   confirm that hit and set its severity to Claude's judgement.
// - Claude findings with no matching hit become new findings (source "claude").
// - Scanner hits Claude dismissed stay visible but are excluded from counts.

import { RULES, SEVERITY_ORDER } from './rules.js';
import { SEVERITY_WEIGHT, classifyPath, contextFor } from './scanner.js';

const SEV_RANK = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i]));
const TEST_FACTOR = 0.2;

const slug = (s) => String(s || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'other';
const normSeverity = (s) => (SEVERITY_ORDER.includes(String(s).toLowerCase()) ? String(s).toLowerCase() : 'medium');

/** Resolves a path Claude cited to a real file (exact, then unique suffix match). */
function resolvePath(cited, contentByPath) {
  const p = String(cited || '').trim().replace(/^\.?\//, '').replace(/:\d+(-\d+)?$/, '');
  if (contentByPath.has(p)) return p;
  const matches = [...contentByPath.keys()].filter((k) => k.endsWith('/' + p) || p.endsWith('/' + k));
  return matches.length === 1 ? matches[0] : null;
}

export function mergeReview({ report, allFindings, contentByPath, ai, maxFindingsReturned = 3000 }) {
  const { review, hits, meta } = ai;
  // Work on copies so the scanner-only data stays untouched.
  const copies = new Map(allFindings.map((f) => [f, { ...f, source: 'scanner' }]));
  const byId = new Map(hits.map(({ id, finding }) => [id, copies.get(finding)]));
  const byLocation = new Map();
  for (const f of copies.values()) {
    const k = `${f.file}:${f.line}`;
    if (!byLocation.has(k)) byLocation.set(k, []);
    byLocation.get(k).push(f);
  }

  const added = [];
  let confirmed = 0;
  let unverified = 0;

  for (const raw of Array.isArray(review.findings) ? review.findings : []) {
    const severity = normSeverity(raw.severity);
    const file = resolvePath(raw.file, contentByPath);
    const content = file ? contentByPath.get(file) : null;
    const lineCount = content ? content.split('\n').length : 0;
    const line = Number.isInteger(raw.line) && raw.line >= 1 && raw.line <= lineCount ? raw.line : null;
    const note = { title: String(raw.title || raw.category || 'Issue'), detail: String(raw.detail || ''), category: String(raw.category || ''), cwe: raw.cwe ? String(raw.cwe) : '' };

    // Scanner hits this finding confirms: explicit IDs, plus any hit on the exact same line.
    const linked = new Set((Array.isArray(raw.scanner_ids) ? raw.scanner_ids : []).map((id) => byId.get(String(id))).filter(Boolean));
    if (file && line) for (const f of byLocation.get(`${file}:${line}`) || []) linked.add(f);

    for (const f of linked) {
      if (f.verdict !== 'confirmed') confirmed++;
      f.verdict = 'confirmed';
      if (f.scannerSeverity === undefined) f.scannerSeverity = f.severity;
      // Keep the most severe judgement if several Claude findings point at one hit.
      if (f.ai === undefined || SEV_RANK[severity] < SEV_RANK[f.severity]) {
        f.severity = severity;
        f.ai = note;
      }
    }

    // Already represented by a scanner hit on the same line? Then don't add a duplicate row.
    const sameLine = [...linked].some((f) => f.file === file && f.line === line);
    if (sameLine) continue;

    if (!file || !line) unverified++;
    added.push({
      ruleId: `ai:${slug(note.category)}`,
      severity,
      file: file || String(raw.file || 'unknown'),
      line: line || (Number.isInteger(raw.line) ? raw.line : 0),
      code: content && line ? content.split('\n')[line - 1].trim().slice(0, 240) : '',
      kind: classifyPath(file || String(raw.file || '')),
      source: 'claude',
      verdict: 'claude',
      locationVerified: Boolean(file && line),
      confirms: [...linked].map((f) => `${f.file}:${f.line}`),
      ai: note,
    });
  }

  let dismissed = 0;
  for (const d of Array.isArray(review.dismissed) ? review.dismissed : []) {
    const f = byId.get(String(d.scanner_id));
    if (!f || f.verdict === 'confirmed') continue; // a confirmation always wins over a dismissal
    if (f.verdict !== 'dismissed') dismissed++;
    f.verdict = 'dismissed';
    f.ai = { title: 'Dismissed by Claude', detail: String(d.reason || ''), category: '', cwe: '' };
  }

  const merged = [...copies.values(), ...added];
  // Dismissed hits and Claude findings whose location doesn't exist stay visible but aren't counted.
  const isCounted = (f) => f.verdict !== 'dismissed' && f.locationVerified !== false;
  const counted = merged.filter(isCounted);
  const weightOf = (f) => SEVERITY_WEIGHT[f.severity] * (f.kind === 'test' ? TEST_FACTOR : 1);

  // Rule table: scanner rules (with confirmed/dismissed tallies) + one row per Claude category.
  const ruleSummary = [];
  for (const rule of RULES) {
    const all = merged.filter((f) => f.source === 'scanner' && f.ruleId === rule.id);
    if (!all.length) continue;
    const live = all.filter((f) => f.verdict !== 'dismissed');
    ruleSummary.push({
      ruleId: rule.id, title: rule.title, category: rule.category, cwe: rule.cwe, description: rule.description, source: 'scanner',
      severity: live.reduce((s, f) => (SEV_RANK[f.severity] < SEV_RANK[s] ? f.severity : s), live[0]?.severity || rule.severity),
      count: live.length,
      productionCount: live.filter((f) => f.kind !== 'test').length,
      files: new Set(live.map((f) => f.file)).size,
      confirmed: all.filter((f) => f.verdict === 'confirmed').length,
      dismissed: all.filter((f) => f.verdict === 'dismissed').length,
    });
  }
  const groups = new Map();
  for (const f of added.filter(isCounted)) {
    if (!groups.has(f.ruleId)) groups.set(f.ruleId, []);
    groups.get(f.ruleId).push(f);
  }
  for (const [ruleId, list] of groups) {
    const cwes = list.map((f) => f.ai.cwe).filter(Boolean);
    ruleSummary.push({
      ruleId, title: list[0].ai.category || 'Other', category: list[0].ai.category, cwe: cwes[0] || '', source: 'claude',
      description: 'Found by Claude reading the source; not detectable by the pattern scanner.',
      severity: list.reduce((s, f) => (SEV_RANK[f.severity] < SEV_RANK[s] ? f.severity : s), 'low'),
      count: list.length,
      productionCount: list.filter((f) => f.kind !== 'test').length,
      files: new Set(list.map((f) => f.file)).size,
      confirmed: 0,
      dismissed: 0,
    });
  }
  ruleSummary.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.count - a.count);

  // Hotspots from the merged, non-dismissed findings.
  const perFile = new Map();
  for (const f of counted) {
    if (!perFile.has(f.file)) perFile.set(f.file, []);
    perFile.get(f.file).push(f);
  }
  const locOf = (file) => (contentByPath.get(file) || '').split('\n').filter((l) => l.trim()).length;
  const hotspots = [...perFile]
    .map(([file, list]) => ({
      file,
      kind: classifyPath(file),
      loc: locOf(file),
      findings: list.length,
      weighted: Math.round(list.reduce((s, f) => s + weightOf(f), 0) * 10) / 10,
      bySeverity: SEVERITY_ORDER.reduce((o, s) => ((o[s] = list.filter((f) => f.severity === s).length), o), {}),
    }))
    .sort((a, b) => b.weighted - a.weighted)
    .slice(0, 15);

  // Findings list: live findings by severity (Claude-confirmed first within a level), dismissed last.
  const verdictRank = { confirmed: 0, claude: 0, undefined: 1, dismissed: 2 };
  const kindRank = { production: 0, vendored: 1, test: 2 };
  const sorted = merged.sort(
    (a, b) =>
      !isCounted(a) - !isCounted(b) ||
      SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
      verdictRank[a.verdict] - verdictRank[b.verdict] ||
      kindRank[a.kind] - kindRank[b.kind] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
  const findings = sorted.slice(0, maxFindingsReturned).map((f) => ({
    ...f,
    context:
      (SEV_RANK[f.severity] <= 1 || f.source === 'claude' || f.verdict === 'confirmed') && contentByPath.has(f.file) && f.line > 0
        ? contextFor(contentByPath.get(f.file), f.line, 3)
        : undefined,
  }));

  const stats = {
    ...report.stats,
    totalFindings: counted.length,
    bySeverity: SEVERITY_ORDER.reduce((o, s) => ((o[s] = counted.filter((f) => f.severity === s).length), o), {}),
    findingsTruncated: merged.length > maxFindingsReturned,
    scannerBySeverity: report.stats.bySeverity,
    bySource: { scanner: allFindings.length, confirmedByClaude: confirmed, dismissedByClaude: dismissed, addedByClaude: added.length },
  };

  const topConcerns = counted
    .filter((f) => f.ai && (f.source === 'claude' || f.verdict === 'confirmed'))
    .slice()
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])
    .slice(0, 8)
    .map((f) => ({ title: f.ai.title, severity: f.severity, detail: f.ai.detail, locations: f.line > 0 ? [`${f.file}:${f.line}`] : [] }));

  return {
    stats,
    ruleSummary,
    hotspots,
    findings,
    ai: {
      overall_risk: review.overall_risk,
      summary: String(review.summary || ''),
      recommendations: Array.isArray(review.recommendations) ? review.recommendations.map(String) : [],
      top_concerns: topConcerns,
      counts: { findings: (review.findings || []).length, added: added.length, confirmed, dismissed, unverifiedLocations: unverified },
      model: meta.model,
      usage: meta.usage,
      costUsd: meta.costUsd,
      coverage: meta.coverage,
    },
  };
}

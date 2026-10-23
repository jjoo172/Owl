// Compares a scan of the original code with a re-scan of the patched code.
//
// Findings are matched across the two reviews by file, by line (moving the original line
// through the patch's old->new line map, since patching shifts lines) and by kind of bug.
// Unmatched original findings are "fixed", matched ones "still present", and unmatched
// re-scan findings "new". Reviews by a language model vary from run to run, so the page says
// that small differences can be noise.

const LEVELS = ['Low', 'Moderate', 'High', 'Critical'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const NEAR_LINES = 6;

const words = (f) =>
  new Set(
    `${f.category || ''} ${f.title || ''} ${f.ruleId || ''}`
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((w) => w.length > 2 && !['the', 'and', 'for', 'with', 'into', 'from'].includes(w)),
  );
function similarity(a, b) {
  if (a.ruleId && a.ruleId === b.ruleId) return 1;
  const A = words(a);
  const B = words(b);
  if (!A.size || !B.size) return 0;
  let both = 0;
  for (const w of A) if (B.has(w)) both++;
  return both / (A.size + B.size - both);
}

const slim = (f) => ({ file: f.file, line: f.line, severity: f.severity, title: f.title || f.ruleId, category: f.category || '', detail: f.detail || '' });
const counts = (list) => SEVERITIES.reduce((o, s) => ((o[s] = list.filter((f) => f.severity === s).length), o), {});

/**
 * `addedLines`: Map(path -> Set of new-side line numbers the patch wrote).
 * `targeted`: [{ file, line }] of the original vulnerabilities the patches set out to fix.
 */
export function compareScans({ before, after, lineMaps = new Map(), addedLines = new Map(), targeted = [] }) {
  const beforeFindings = (before.findings || []).filter((f) => f.verdict !== 'dismissed');
  const afterFindings = after.findings || [];
  const used = new Set();
  const remaining = [];
  const fixed = [];

  const order = [...beforeFindings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  for (const f of order) {
    const map = lineMaps.get(f.file);
    const expected = map && f.line > 0 ? map(f.line) : f.line;
    let best = null;
    for (const [i, g] of afterFindings.entries()) {
      if (used.has(i) || g.file !== f.file) continue;
      const distance = f.line > 0 && g.line > 0 ? Math.abs(g.line - expected) : NEAR_LINES;
      const sim = similarity(f, g);
      // Same place and a similar kind of bug; a different kind only if it is on the very same line.
      if (distance > NEAR_LINES || (sim < 0.25 && distance > 0)) continue;
      const score = sim * 10 - distance;
      if (!best || score > best.score) best = { i, score };
    }
    if (best) {
      used.add(best.i);
      remaining.push({ before: slim(f), after: slim(afterFindings[best.i]) });
    } else fixed.push(slim(f));
  }
  const introduced = afterFindings.filter((_, i) => !used.has(i)).map(slim);
  // A new finding on (or right next to) a line the patch wrote is likely caused by the patch;
  // anywhere else it is more likely something the first review missed, or run-to-run variation.
  const inPatch = (f) => {
    const set = addedLines.get(f.file);
    return Boolean(set && f.line > 0 && [-2, -1, 0, 1, 2].some((d) => set.has(f.line + d)));
  };
  const introducedInPatchedLines = introduced.filter(inPatch);
  const introducedElsewhere = introduced.filter((f) => !inPatch(f));

  // How well the patches did on the vulnerabilities they set out to fix.
  const isTarget = (f) => targeted.some((t) => t.file === f.file && t.line === f.line);
  const targetedSummary = targeted.length
    ? { total: beforeFindings.filter(isTarget).length, fixed: fixed.filter(isTarget).length, stillPresent: remaining.filter((m) => isTarget(m.before)).length }
    : null;

  const level = (r) => (LEVELS.includes(r?.risk?.level) ? r.risk.level : null);
  const lb = level(before);
  const la = level(after);
  return {
    comparable: before.tier === after.tier && Boolean(before.coverage?.complete) === Boolean(after.coverage?.complete),
    before: { tier: before.tier, level: lb, total: beforeFindings.length, bySeverity: counts(beforeFindings) },
    after: { tier: after.tier, level: la, total: afterFindings.length, bySeverity: counts(afterFindings) },
    levelChange: lb && la ? LEVELS.indexOf(la) - LEVELS.indexOf(lb) : null,
    fixed: fixed.map((f) => ({ ...f, targeted: isTarget(f) })),
    remaining: remaining.map((m) => ({ ...m, targeted: isTarget(m.before) })),
    introduced,
    introducedInPatchedLines,
    introducedElsewhere,
    targeted: targetedSummary,
  };
}

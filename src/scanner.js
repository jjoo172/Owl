import { stripCommentsAndStrings } from './lexer.js';
import { RULES, MITIGATIONS, SEVERITY_ORDER } from './rules.js';

export const SEVERITY_WEIGHT = { critical: 25, high: 6, medium: 1.5, low: 0.25 };
// Test/fuzz/example code is not in a consumer's critical path; count it lightly.
const NON_PRODUCTION_FACTOR = 0.2;

const NON_PRODUCTION_RE =
  /(^|\/)(tests?|testing|unittests?|test_?data|fuzz|fuzzers?|fuzzing|benchmarks?|bench|examples?|samples?|demos?|tools\/test)(\/|$)|(^|\/)(test_[^/]*|[^/]*_(test|tests|unittest|fuzzer|benchmark)\.[^/]+)$/i;
const VENDORED_RE = /(^|\/)(third[_-]?party|3rd[_-]?party|vendor(ed)?|external|extern|deps|contrib)(\/|$)/i;

export function classifyPath(path) {
  if (NON_PRODUCTION_RE.test(path)) return 'test';
  if (VENDORED_RE.test(path)) return 'vendored';
  return 'production';
}

function languageOf(path) {
  const ext = path.slice(path.lastIndexOf('.')).toLowerCase();
  if (ext === '.c') return 'C';
  if (ext === '.h') return 'C/C++ header';
  if (ext === '.mm') return 'Objective-C++';
  if (['.hh', '.hpp', '.hxx', '.h++', '.inl', '.ipp', '.tpp', '.tcc'].includes(ext)) return 'C++ header';
  return 'C++';
}

/** Scans one file. Returns findings plus per-file metrics. */
export function scanFile(path, content) {
  const stripped = stripCommentsAndStrings(content);
  const codeLines = stripped.split('\n');
  const origLines = content.split('\n');
  const kind = classifyPath(path);
  const findings = [];
  let loc = 0;

  for (let i = 0; i < codeLines.length; i++) {
    const code = codeLines[i];
    if (!code.trim()) continue;
    loc++;
    const original = origLines[i] ?? '';
    for (const rule of RULES) {
      const hit = rule.re ? rule.re.test(code) && (!rule.test || rule.test(code, original)) : rule.test(code, original);
      if (hit) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          file: path,
          line: i + 1,
          code: original.trim().slice(0, 240),
          kind,
        });
      }
    }
  }

  const mitigations = {};
  for (const m of MITIGATIONS) {
    const count = (stripped.match(m.re) || []).length;
    if (count) mitigations[m.id] = count;
  }

  return { path, kind, language: languageOf(path), loc, findings, mitigations };
}

export function contextFor(content, line, radius = 3) {
  const lines = content.split('\n');
  const start = Math.max(1, line - radius);
  const end = Math.min(lines.length, line + radius);
  const out = [];
  for (let n = start; n <= end; n++) out.push({ n, text: lines[n - 1].slice(0, 240) });
  return out;
}

/** Scans every file and produces the full report (minus the optional AI review). */
export function scanRepository(files, { maxFindingsReturned = 3000 } = {}) {
  const fileResults = files.map((f) => scanFile(f.path, f.content));
  const contentByPath = new Map(files.map((f) => [f.path, f.content]));

  const allFindings = fileResults.flatMap((r) => r.findings);
  const byLanguage = {};
  const byKind = { production: 0, vendored: 0, test: 0 };
  const locByKind = { production: 0, vendored: 0, test: 0 };
  const mitigationTotals = {};
  let loc = 0;
  for (const r of fileResults) {
    loc += r.loc;
    byLanguage[r.language] = (byLanguage[r.language] || 0) + r.loc;
    byKind[r.kind]++;
    locByKind[r.kind] += r.loc;
    for (const [k, v] of Object.entries(r.mitigations)) mitigationTotals[k] = (mitigationTotals[k] || 0) + v;
  }

  const weightOf = (f) => SEVERITY_WEIGHT[f.severity] * (f.kind === 'test' ? NON_PRODUCTION_FACTOR : 1);

  // Per-rule summary
  const ruleSummary = RULES.map((rule) => {
    const hits = allFindings.filter((f) => f.ruleId === rule.id);
    return {
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      description: rule.description,
      count: hits.length,
      productionCount: hits.filter((f) => f.kind !== 'test').length,
      files: new Set(hits.map((f) => f.file)).size,
    };
  }).filter((r) => r.count > 0);

  // Hotspot files
  const hotspots = fileResults
    .map((r) => ({
      file: r.path,
      kind: r.kind,
      loc: r.loc,
      findings: r.findings.length,
      weighted: Math.round(r.findings.reduce((s, f) => s + weightOf(f), 0) * 10) / 10,
      bySeverity: SEVERITY_ORDER.reduce((o, s) => ((o[s] = r.findings.filter((f) => f.severity === s).length), o), {}),
    }))
    .filter((h) => h.findings > 0)
    .sort((a, b) => b.weighted - a.weighted)
    .slice(0, 15);

  const risk = assessRisk({ allFindings, loc, locByKind, mitigationTotals, byLanguage, weightOf, fileCount: files.length });

  // Order findings by severity then path, attach a little context to the returned set.
  const sevRank = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i]));
  const kindRank = { production: 0, vendored: 1, test: 2 };
  const sorted = [...allFindings].sort(
    (a, b) => sevRank[a.severity] - sevRank[b.severity] || kindRank[a.kind] - kindRank[b.kind] || a.file.localeCompare(b.file) || a.line - b.line,
  );
  const returned = sorted.slice(0, maxFindingsReturned).map((f) => ({
    ...f,
    context: sevRank[f.severity] <= 1 ? contextFor(contentByPath.get(f.file), f.line, 3) : undefined,
  }));

  return {
    stats: {
      sourceFiles: files.length,
      loc,
      byLanguage,
      filesByKind: byKind,
      locByKind,
      totalFindings: allFindings.length,
      bySeverity: SEVERITY_ORDER.reduce((o, s) => ((o[s] = allFindings.filter((f) => f.severity === s).length), o), {}),
      findingsTruncated: allFindings.length > maxFindingsReturned,
    },
    risk,
    ruleSummary,
    hotspots,
    mitigations: mitigationTotals,
    findings: returned,
    // Internal: used for the AI review, stripped before sending to clients.
    _contentByPath: contentByPath,
    _allFindings: allFindings,
  };
}

const LEVELS = ['Low', 'Moderate', 'High', 'Critical'];

export function assessRisk({ allFindings, loc, locByKind, mitigationTotals, byLanguage, weightOf, fileCount }) {
  if (!fileCount) {
    return { level: 'N/A', score: 0, density: 0, rationale: ['No C/C++ source files were found in this repository.'] };
  }
  const weighted = allFindings.reduce((s, f) => s + weightOf(f), 0);
  const productionLoc = locByKind.production + locByKind.vendored;
  const kloc = Math.max((productionLoc || loc) / 1000, 0.5);
  const density = weighted / kloc;
  const score = Math.round(100 * (1 - Math.exp(-density / 10)));

  let idx = density < 2 ? 0 : density < 6 ? 1 : density < 15 ? 2 : 3;
  const rationale = [];
  const prod = allFindings.filter((f) => f.kind !== 'test');
  const count = (sev) => prod.filter((f) => f.severity === sev).length;
  const crit = count('critical');
  const high = count('high');

  rationale.push(`Weighted risk density of ${density.toFixed(1)} per 1,000 lines of non-test code (${Math.round(productionLoc || loc).toLocaleString()} lines scanned).`);

  if (crit > 0) {
    idx = Math.max(idx, 2);
    rationale.push(`${crit} critical finding${crit > 1 ? 's' : ''} (e.g. gets()) in non-test code — these are exploitable as written.`);
  }
  if (high > 0) {
    const highPerKloc = high / kloc;
    if (highPerKloc >= 1) idx = Math.max(idx, 2);
    rationale.push(`${high} high-severity pattern${high > 1 ? 's' : ''} (unbounded copies, non-literal format strings, alloca, shell execution) in non-test code.`);
  } else {
    rationale.push('No high-severity patterns found in non-test code.');
  }

  // Without any high/critical patterns, volume of medium/low hits alone can't make it Critical.
  if (crit === 0 && high === 0) idx = Math.min(idx, 2);
  if (crit === 0 && high / kloc < 0.25) idx = Math.min(idx, 2);

  const cLoc = (byLanguage['C'] || 0) + (byLanguage['C/C++ header'] || 0) * 0.5;
  const cShare = loc ? cLoc / loc : 0;
  if (cShare > 0.6) rationale.push('Predominantly C: no RAII or bounds-checked containers, so every buffer and lifetime is managed by hand.');

  const modern = (mitigationTotals['smart-pointers'] || 0) + (mitigationTotals['safe-views'] || 0) + (mitigationTotals['containers'] || 0);
  if (modern / kloc > 20) rationale.push('Heavy use of modern C++ idioms (smart pointers, containers, spans) offsets some of the risk.');
  if (mitigationTotals['fuzz-harness']) {
    rationale.push(`${mitigationTotals['fuzz-harness']} fuzz harness${mitigationTotals['fuzz-harness'] > 1 ? 'es' : ''} present — evidence the parsing surface is actively fuzzed.`);
  }

  if (idx <= 1) {
    rationale.push(
      "Pattern scanning can't see most lifetime, aliasing or concurrency bugs (dangling references, invalidated iterators, data races), so a low score here is not a clean bill of health — the expert review reads the code for those.",
    );
  }

  // Keep the 0–100 score inside the band of the chosen level (Low 0–24 … Critical 75–100).
  const banded = Math.min(Math.max(score, idx * 25), idx * 25 + (idx === 3 ? 25 : 24));
  return { level: LEVELS[idx], score: banded, density: Math.round(density * 10) / 10, rationale };
}

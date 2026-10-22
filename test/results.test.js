import { test } from 'node:test';
import assert from 'node:assert/strict';
import { claudeResults } from '../src/results.js';
import { summarizeFiles } from '../src/scanner.js';

const files = [
  { path: 'cpp/src/config.cpp', content: ['#include <string>', 'std::string_view f(std::string& line) {', '  std::string_view v(line);', '  return v;', '}'].join('\n') },
  { path: 'cpp/src/wire.cpp', content: ['int g(const unsigned char* b) {', '  return *reinterpret_cast<const int*>(b + 1);', '}'].join('\n') },
];
const contentByPath = new Map(files.map((f) => [f.path, f.content]));
const meta = { model: 'claude-haiku-5-5', coverage: { mode: 'full', filesInFull: 2, totalFiles: 2 }, costUsd: 0.001 };
const build = (findings, extra = {}) =>
  claudeResults({ review: { overall_risk: 'High', summary: 's', recommendations: ['r'], findings, ...extra }, meta, contentByPath, fileStats: summarizeFiles(files) });
const f = (o) => ({ title: 't', severity: 'high', category: 'Use-after-free', detail: 'd', ...o });

test('every reported vulnerability is visible and counted, at every severity', () => {
  const r = build([
    f({ severity: 'critical', file: 'cpp/src/config.cpp', line: 3, title: 'Dangling view' }),
    f({ severity: 'low', category: 'Strict aliasing', cwe: 'cwe-704', file: 'cpp/src/wire.cpp', line: 2 }),
    f({ severity: 'medium', category: 'use-after-free', file: 'config.cpp', line: 4 }), // short path; category case differs
  ]);
  assert.equal(r.findings.length, 3);
  assert.equal(r.stats.totalFindings, 3);
  assert.deepEqual(r.stats.bySeverity, { critical: 1, high: 0, medium: 1, low: 1 });
  assert.deepEqual(r.findings.map((x) => x.severity), ['critical', 'medium', 'low']);
  assert.equal(r.findings[1].file, 'cpp/src/config.cpp', 'short path resolved');
  assert.ok(r.findings.every((x) => x.context && x.code), 'code context for each');
  assert.equal(r.findings[2].cwe, 'CWE-704');
  assert.equal(r.risk.level, 'High');
  // Issue types group Claude's categories regardless of case.
  const uaf = r.ruleSummary.find((t) => t.ruleId === 'use-after-free');
  assert.equal(uaf.count, 2);
  assert.equal(uaf.severity, 'critical');
  assert.equal(r.hotspots[0].file, 'cpp/src/config.cpp');
  assert.equal(r.ai.top_concerns[0].title, 'Dangling view');
});

test('findings whose location does not match are still shown and counted, flagged for the reader', () => {
  const r = build([f({ file: 'cpp/src/nope.cpp', line: 3 }), f({ file: 'cpp/src/wire.cpp', line: 99 })]);
  assert.equal(r.stats.totalFindings, 2);
  assert.ok(r.findings.every((x) => x.locationVerified === false && !x.context));
  assert.equal(r.ai.unmatchedLocations, 2);
});

test('exact duplicates collapse; malformed fields are tolerated', () => {
  const r = build([
    f({ file: 'cpp/src/wire.cpp', line: 2, category: 'Strict aliasing' }),
    f({ file: 'cpp/src/wire.cpp', line: 2, category: 'strict aliasing' }),
    f({ file: 'cpp/src/wire.cpp', line: 2, category: 'Out-of-bounds read' }), // same line, different bug: kept
    f({ severity: 'SEVERE?', file: 'cpp/src/config.cpp', line: 3 }),
  ], { overall_risk: 'Apocalyptic' });
  assert.equal(r.findings.length, 3);
  assert.equal(r.findings.find((x) => x.file.endsWith('config.cpp')).severity, 'medium');
  assert.equal(r.risk.level, 'Moderate', 'unknown overall rating falls back to Moderate');
});

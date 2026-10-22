import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRepository } from '../src/scanner.js';
import { buildReviewRequest, DEFAULT_MODEL } from '../src/ai.js';
import { mergeReview } from '../src/merge.js';

const files = [
  {
    path: 'src/parse.cpp',
    content: [
      '#include <string_view>', //                                   1
      'std::string_view keep(std::string& line) {', //               2
      '  std::string_view v(line);', //                              3  (Claude-only bug)
      '  return v;', //                                              4
      '}', //                                                        5
      'void copy(char* d, const char* s) { strcpy(d, s); }', //      6  (scanner: high)
      'void ok(char* d) { memcpy(d, "abc", 4); }', //                7  (scanner: medium, safe)
      'int bits(unsigned b) { return 1u << b; }', //                 8  (scanner: low)
    ].join('\n'),
  },
];

function setup() {
  const report = scanRepository(files);
  const { _contentByPath, _allFindings, ...pub } = report;
  const req = buildReviewRequest({ repo: { owner: 'o', repo: 'r' }, report: pub, allFindings: _allFindings, contentByPath: _contentByPath });
  const id = (rule) => req.hits.find((h) => h.finding.ruleId === rule).id;
  const run = (review) =>
    mergeReview({ report: pub, allFindings: _allFindings, contentByPath: _contentByPath, ai: { review, hits: req.hits, meta: { model: DEFAULT_MODEL, coverage: {} } } });
  return { pub, req, id, run };
}

const finding = (o) => ({ title: 't', severity: 'high', category: 'Use-after-free', detail: 'd', ...o });

test('defaults to the cheaper model and gives every non-test hit an ID', () => {
  const { req } = setup();
  assert.equal(DEFAULT_MODEL, 'claude-haiku-5-5');
  assert.deepEqual(req.hits.map((h) => h.finding.ruleId).sort(), ['raw-memcpy', 'unbounded-copy', 'variable-shift'].sort());
  assert.match(req.userContent, /S1 \[high\] unbounded-copy src\/parse\.cpp:6/);
});

test('Claude-only findings are added; confirmations change severity; dismissals leave the counts', () => {
  const { pub, id, run } = setup();
  const m = run({
    overall_risk: 'High',
    summary: 's',
    recommendations: [],
    findings: [
      finding({ severity: 'critical', file: 'src/parse.cpp', line: 3, title: 'Dangling view' }),
      finding({ severity: 'medium', category: 'Undefined behaviour', file: 'src/parse.cpp', line: 8, scanner_ids: [id('variable-shift')] }),
      finding({ severity: 'critical', category: 'Buffer overflow', file: 'parse.cpp', line: 6 }), // short path + same line, no ID
    ],
    dismissed: [{ scanner_id: id('raw-memcpy'), reason: 'constant fits' }],
  });

  const at = (line) => m.findings.filter((f) => f.line === line);
  assert.equal(at(3).length, 1);
  assert.equal(at(3)[0].source, 'claude');
  assert.equal(at(3)[0].severity, 'critical');
  assert.ok(at(3)[0].context, 'Claude findings carry code context');

  assert.equal(at(8)[0].verdict, 'confirmed');
  assert.equal(at(8)[0].severity, 'medium');
  assert.equal(at(8)[0].scannerSeverity, 'low');

  assert.equal(at(6).length, 1, 'same-line Claude finding merges into the scanner hit, no duplicate row');
  assert.equal(at(6)[0].verdict, 'confirmed');
  assert.equal(at(6)[0].severity, 'critical');

  assert.equal(at(7)[0].verdict, 'dismissed');
  assert.equal(m.findings.at(-1).line, 7, 'dismissed hits sort last');

  assert.deepEqual(m.stats.bySeverity, { critical: 2, high: 0, medium: 1, low: 0 });
  assert.deepEqual(pub.stats.bySeverity, { critical: 0, high: 1, medium: 1, low: 1 }, 'scanner-only report untouched');
  assert.equal(m.ruleSummary.find((r) => r.ruleId === 'raw-memcpy').count, 0);
  assert.equal(m.ruleSummary.find((r) => r.ruleId === 'raw-memcpy').dismissed, 1);
  assert.ok(m.ruleSummary.some((r) => r.source === 'claude' && r.title === 'Use-after-free'));
  assert.deepEqual(m.ai.counts, { findings: 3, added: 1, confirmed: 2, dismissed: 1, unverifiedLocations: 0 });
});

test('invented locations are shown but never counted', () => {
  const { run } = setup();
  const m = run({
    overall_risk: 'Low', summary: 's', recommendations: [], dismissed: [],
    findings: [finding({ file: 'src/nope.cpp', line: 3 }), finding({ file: 'src/parse.cpp', line: 999 })],
  });
  const bad = m.findings.filter((f) => f.locationVerified === false);
  assert.equal(bad.length, 2);
  assert.equal(m.ai.counts.unverifiedLocations, 2);
  assert.ok(!m.hotspots.some((h) => h.file === 'src/nope.cpp'));
  assert.equal(m.stats.totalFindings, 3, 'only the 3 scanner hits count');
});

test('a confirmation wins over a contradictory dismissal; malformed fields are tolerated', () => {
  const { id, run } = setup();
  const m = run({
    overall_risk: 'High', summary: 's', recommendations: [],
    findings: [finding({ severity: 'SEVERE?', file: 'src/parse.cpp', line: 7, scanner_ids: [id('raw-memcpy'), 'S999'] })],
    dismissed: [{ scanner_id: id('raw-memcpy'), reason: 'contradiction' }, { scanner_id: 'S404', reason: 'unknown id' }],
  });
  const hit = m.findings.find((f) => f.line === 7);
  assert.equal(hit.verdict, 'confirmed');
  assert.equal(hit.severity, 'medium'); // unknown severity falls back to medium
  assert.equal(m.ai.counts.dismissed, 0);
});

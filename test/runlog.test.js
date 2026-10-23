import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startRun, getRun, RUN_ID_RE, clipDeep } from '../src/runlog.js';
import { parseRun, formatRun } from '../src/logview.js';
import { compareScans } from '../src/compare.js';

test('a run log is JSON lines: header, events, end', () => {
  const run = startRun('scan', { owner: 'a', repo: 'b', sha: 'f'.repeat(40) }, { build: 'test' });
  assert.match(run.id, RUN_ID_RE);
  run.trace('downloaded', { sourceFiles: 3 });
  run.trace('progress', { message: 'Claude is reviewing' });
  run.end('ok', { tier: 'full', findings: 0 });
  run.trace('late', {}); // ignored after end

  const lines = run.text().trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((l) => l.type), ['run', 'event', 'event', 'end']);
  assert.equal(lines[0].input.owner, 'a');
  assert.equal(lines[1].event, 'downloaded');
  assert.equal(lines[3].status, 'ok');
  assert.equal(getRun(run.id), run);
  assert.equal(getRun('scan-nope'), null);
  assert.equal(getRun('../../etc/passwd'), null);
});

test('clipDeep bounds long strings at any depth', () => {
  const out = clipDeep({ a: 'x'.repeat(50), b: [{ c: 'y'.repeat(50) }], n: 5 }, 10);
  assert.ok(out.a.startsWith('xxxxxxxxxx…'));
  assert.ok(out.b[0].c.startsWith('yyyyyyyyyy…'));
  assert.equal(out.n, 5);
});

test('compareScans traces why each finding was matched or not', () => {
  const events = [];
  const trace = (event, data) => events.push({ event, ...data });
  const before = {
    tier: 'full',
    risk: { level: 'High' },
    coverage: { complete: true },
    findings: [
      { file: 'a.c', line: 10, severity: 'high', title: 'Buffer overflow in copy', category: 'buffer overflow' },
      { file: 'a.c', line: 40, severity: 'medium', title: 'Integer overflow in size', category: 'integer overflow' },
    ],
  };
  const after = {
    tier: 'full',
    risk: { level: 'Moderate' },
    coverage: { complete: true },
    findings: [
      { file: 'a.c', line: 42, severity: 'medium', title: 'Integer overflow in size computation', category: 'integer overflow' },
      { file: 'a.c', line: 11, severity: 'low', title: 'Unchecked return value', category: 'error handling' },
    ],
  };
  const c = compareScans({ before, after, targeted: [{ file: 'a.c', line: 10 }], addedLines: new Map([['a.c', new Set([11])]]), trace });
  assert.equal(c.fixed.length, 1);
  assert.equal(c.remaining.length, 1);

  const matches = events.filter((e) => e.event === 'match');
  const overflow = matches.find((m) => m.before.line === 10);
  assert.equal(overflow.outcome, 'fixed');
  assert.equal(overflow.targeted, true);
  assert.match(overflow.candidates.find((x) => x.line === 11).rejected, /different kind/);
  const intOverflow = matches.find((m) => m.before.line === 40);
  assert.equal(intOverflow.outcome, 'still_present');
  assert.equal(intOverflow.targeted, false);
  assert.equal(intOverflow.matchedTo, 0);

  const fresh = events.filter((e) => e.event === 'new_finding');
  assert.equal(fresh.length, 1);
  assert.equal(fresh[0].where, 'in_patched_lines');
});

test('formatRun turns a re-scan log into a readable report', () => {
  const run = startRun('rescan', { owner: 'o', repo: 'r', sha: 'a'.repeat(40) });
  run.trace('match', {
    outcome: 'still_present', targeted: false, expectedLine: 40, lineMoved: false, matchedTo: 0,
    before: { severity: 'medium', file: 'a.c', line: 40, title: 'Integer overflow' },
    candidates: [{ index: 0, severity: 'medium', file: 'a.c', line: 42, title: 'Integer overflow again', distance: 2, similarity: 0.6, score: 4, rejected: null }],
  });
  run.trace('new_finding', { where: 'elsewhere', after: { severity: 'low', file: 'b.c', line: 3, title: 'Leak' } });
  run.end('ok', { before: { level: 'High', total: 2 }, after: { level: 'Moderate', total: 2 }, comparable: true, fixed: 1, stillPresent: 1, stillPresentTargeted: 0, stillPresentNotTargeted: 1, newInPatchedLines: 0, newElsewhere: 1 });

  const { header, events, end } = parseRun(run.text() + 'not json\n');
  assert.equal(header.kind, 'rescan');
  assert.equal(events.length, 2);
  assert.equal(end.status, 'ok');

  const report = formatRun(run.text());
  assert.match(report, /STILL PRESENT, never targeted by a patch \(1\)/);
  assert.match(report, /matched → MEDIUM\s+a\.c:42/);
  assert.match(report, /NEW in the re-scan \(1\)/);
  assert.match(report, /1 never targeted/);
});

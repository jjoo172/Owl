import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { unifiedDiff } from '../src/diff.js';
import { applyPatch, PatchError } from '../src/applypatch.js';
import { compareScans } from '../src/compare.js';
import { buildReviewRequest, selectSourceForReview } from '../src/ai.js';
import { analyze } from '../src/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const stats = readFileSync(join(here, 'fixtures', 'stats.cpp'), 'utf8');
const fixedStats = stats.replace('return a <= b;', 'return a < b;').replace('    int sum = 0;', '    // widened to avoid overflow\n    long long sum = 0;');
const patchText = '# Owl security patches\n#\n\n' + unifiedDiff('cpp/src/stats.cpp', stats, fixedStats);

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.ANTHROPIC_API_KEY;
});

test('patches apply exactly; mismatched or unsafe patches are refused', () => {
  const src = new Map([['cpp/src/stats.cpp', stats]]);
  const r = applyPatch(src, patchText);
  assert.equal(r.files.get('cpp/src/stats.cpp'), fixedStats);
  assert.equal(src.get('cpp/src/stats.cpp'), stats, 'original untouched');
  const map = r.lineMaps.get('cpp/src/stats.cpp');
  assert.equal(map(7), 7, 'lines above the change keep their number');
  assert.equal(map(23), 24, 'lines below the inserted comment move down one');

  assert.throws(() => applyPatch(new Map([['cpp/src/stats.cpp', stats.replace('    int sum = 0;', '    int sum = 1;')]]), patchText), PatchError);
  assert.throws(() => applyPatch(new Map(), patchText), /not in this repository/);
  assert.throws(() => applyPatch(src, '--- /dev/null\n+++ b/new.c\n@@ -0,0 +1 @@\n+x\n'), /adds, deletes or renames/);
  assert.throws(() => applyPatch(src, '# nothing here\n'), /no changes/);
});

test('a re-scan reads the same files as the original scan, even if patching changes their ranking', () => {
  const big = (risky, n) => risky + 'y'.repeat(n);
  const orig = new Map([
    ['src/risky.c', big('strcpy(a,b); sprintf(c,d); memcpy(e,f,g);\n'.repeat(40), 70_000)],
    ['src/plain.c', big('', 72_000)],
    ['src/other.c', big('', 72_000)],
  ]);
  const before = selectSourceForReview(orig);
  assert.equal(before.mode, 'partial');
  // "Patch" the risky file so it would no longer rank first on its own.
  const patched = new Map(orig);
  patched.set('src/risky.c', big('snprintf(c,n,d);\n'.repeat(40), 70_000));
  patched.set('src/plain.c', big('memcpy(a,b,c); strcpy(x,y);\n'.repeat(40), 72_000));
  assert.notDeepEqual(selectSourceForReview(patched).files, before.files, 'ranking alone would change');
  const req = buildReviewRequest({ repo: { owner: 'o', repo: 'r' }, contentByPath: patched, selectionFrom: orig });
  assert.deepEqual(req.selection.files, before.files);
  assert.match(req.userContent, /snprintf/, 'but it reads the patched code');
});

test('re-scan end to end: the review sees patched code, and findings are matched through line shifts', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const dir = mkdtempSync(join(tmpdir(), 'owl-rescan-'));
  mkdirSync(join(dir, 'cpp/src'), { recursive: true });
  writeFileSync(join(dir, 'cpp/src/stats.cpp'), stats);
  let sent;
  globalThis.fetch = async (_u, opts) => {
    sent = JSON.parse(opts.body).messages[0].content;
    // After patching: the median overflow (line 29 -> 30) is still there; one new low issue appears.
    const findings = [
      { title: 'Signed overflow in median sum', severity: 'medium', category: 'Signed integer overflow', cwe: 'CWE-190', file: 'cpp/src/stats.cpp', line: 30, detail: 'd' },
      { title: 'Unchecked empty input', severity: 'low', category: 'Robustness', cwe: '', file: 'cpp/src/stats.cpp', line: 9, detail: 'd' },
    ];
    return new Response(JSON.stringify({ model: 'claude-haiku-5-5', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 10 },
      content: [{ type: 'text', text: JSON.stringify({ findings, overall_risk: 'Moderate', summary: 'Better.', recommendations: [] }) }] }));
  };
  const after = await analyze(null, { dir, patchText });
  assert.equal(after.tier, 'full');
  assert.match(sent, /return a < b;/, 'Claude reviewed the patched code');
  assert.deepEqual(after.patchedFiles, ['cpp/src/stats.cpp']);
  assert.ok(!('lineMaps' in JSON.parse(JSON.stringify(after))), 'line maps never serialized');

  const before = {
    tier: 'full', risk: { level: 'High' }, coverage: { complete: true },
    findings: [
      { file: 'cpp/src/stats.cpp', line: 23, severity: 'high', title: 'Non-strict comparator in std::sort', category: 'Undefined behaviour' },
      { file: 'cpp/src/stats.cpp', line: 13, severity: 'medium', title: 'Signed overflow summing int', category: 'Signed integer overflow' },
      { file: 'cpp/src/stats.cpp', line: 29, severity: 'medium', title: 'Signed overflow in median sum', category: 'Signed integer overflow' },
    ],
  };
  const c = compareScans({ before, after, lineMaps: after.lineMaps });
  assert.equal(c.comparable, true);
  assert.equal(c.before.level, 'High');
  assert.equal(c.after.level, 'Moderate');
  assert.equal(c.levelChange, -1);
  assert.deepEqual(c.fixed.map((f) => f.line).sort((a, b) => a - b), [13, 23]);
  assert.equal(c.remaining.length, 1);
  assert.deepEqual([c.remaining[0].before.line, c.remaining[0].after.line], [29, 30], 'matched across the shifted line');
  assert.deepEqual(c.introduced.map((f) => f.title), ['Unchecked empty input']);
  assert.deepEqual(c.after.bySeverity, { critical: 0, high: 0, medium: 1, low: 1 });
});

test('a different kind of bug nearby is not mistaken for the same one; tiers that differ are flagged', () => {
  const before = { tier: 'full', risk: { level: 'High' }, coverage: { complete: true }, findings: [{ file: 'a.c', line: 10, severity: 'high', title: 'Buffer overflow in copy', category: 'Buffer overflow' }] };
  const after = { tier: 'basic', risk: { level: 'Moderate' }, coverage: { complete: true }, findings: [{ file: 'a.c', line: 12, severity: 'medium', title: 'Data race on counter', category: 'Data race' }] };
  const c = compareScans({ before, after });
  assert.equal(c.fixed.length, 1);
  assert.equal(c.introduced.length, 1);
  assert.equal(c.comparable, false);
});

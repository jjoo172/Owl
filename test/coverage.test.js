import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCoverage } from '../src/analyze.js';

const files = [{ path: 'a.c', content: 'x'.repeat(900) }, { path: 'b.c', content: 'y'.repeat(100) }];
const noSkips = { skippedLarge: [], truncated: false };

test('a full review of everything is complete', () => {
  const c = buildCoverage({ tier: 'full', aiCoverage: { filesInFull: 2, totalFiles: 2, reviewedChars: 1000, totalChars: 1000, skipped: [] }, files, fetchStats: noSkips });
  assert.equal(c.complete, true);
  assert.equal(c.percent, 100);
  assert.deepEqual(c.notReviewed, []);
});

test('Claude reading only part of the repo is a partial scan, with the files it skipped', () => {
  const c = buildCoverage({ tier: 'full', aiCoverage: { filesInFull: 1, totalFiles: 2, reviewedChars: 100, totalChars: 1000, skipped: ['a.c'] }, files, fetchStats: noSkips });
  assert.equal(c.complete, false);
  assert.equal(c.percent, 10);
  assert.equal(c.reviewedFiles, 1);
  assert.deepEqual(c.notReviewed, [{ path: 'a.c', why: 'did not fit in the review' }]);
  assert.match(c.reasons[0], /1 riskiest of 2 source files/);
});

test('tiny coverage never rounds down to 0%, and never claims 100% when partial', () => {
  const tiny = buildCoverage({ tier: 'full', aiCoverage: { filesInFull: 1, totalFiles: 5000, reviewedChars: 1, totalChars: 1e8, skipped: ['x'] }, files, fetchStats: noSkips });
  assert.equal(tiny.percent, 0.1);
  const most = buildCoverage({ tier: 'basic', files, fetchStats: { skippedLarge: ['huge.c'], truncated: false } });
  assert.equal(most.complete, false);
  assert.ok(most.percent < 100);
});

test('basic scans are partial only when files were skipped or the file cap was hit', () => {
  assert.equal(buildCoverage({ tier: 'basic', files, fetchStats: noSkips }).complete, true);
  const big = buildCoverage({ tier: 'basic', files, fetchStats: { skippedLarge: ['gen/tables.c'], truncated: true } });
  assert.equal(big.complete, false);
  assert.equal(big.totalFiles, 3);
  assert.equal(big.reasons.length, 2);
  assert.deepEqual(big.notReviewed, [{ path: 'gen/tables.c', why: 'over 1 MB (usually generated code)' }]);
});

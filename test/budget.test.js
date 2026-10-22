import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { DailyBudget, BudgetExceededError, costUsd, clientIdOf } from '../src/budget.js';
import { aiReview } from '../src/ai.js';
import { analyze } from '../src/analyze.js';
import { scanRepository } from '../src/scanner.js';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.ANTHROPIC_API_KEY;
});

test('prices tokens at current rates, including Haiku 5.5 long-prompt tier', () => {
  assert.equal(costUsd('claude-haiku-5-5', 100_000, 0), 0.01); // at the 100k threshold: short-prompt rate
  assert.equal(costUsd('claude-haiku-5-5', 50_000, 10_000), (50_000 * 0.1 + 10_000 * 0.5) / 1e6);
  assert.equal(costUsd('claude-haiku-5-5', 200_000, 0), (200_000 * 0.5) / 1e6);
  assert.equal(costUsd('claude-sonnet-5-5', 1_000_000, 1_000_000), 12);
  assert.equal(costUsd('claude-sonnet-5-5-20260601', 1_000_000, 0), 2, 'dated model ids match by prefix');
  assert.equal(costUsd('some-future-model', 1_000_000, 0), 4, 'unknown models priced conservatively');
});

test('per-visitor limit: reserve, settle, isolation', () => {
  const b = new DailyBudget({ perUserUsd: 10, globalUsd: null });
  const id = b.reserve('1.1.1.1', 6);
  assert.equal(b.remaining('1.1.1.1'), 4);
  assert.throws(() => b.reserve('1.1.1.1', 5), BudgetExceededError, 'reservations count immediately (no concurrent overshoot)');
  b.settle(id, 0.5); // real cost far below the worst case
  assert.equal(b.remaining('1.1.1.1'), 9.5);
  assert.equal(b.remaining('2.2.2.2'), 10, 'other visitors unaffected');
  b.reserve('1.1.1.1', 9.5);
  assert.throws(() => b.reserve('1.1.1.1', 0.01), /used today's \$10\.00 budget/);
  assert.throws(() => new DailyBudget({ perUserUsd: 1, globalUsd: null }).reserve('z', 2), /could cost up to \$2\.00, but only \$1\.00/);
});

test('site-wide limit applies across visitors', () => {
  const b = new DailyBudget({ perUserUsd: 10, globalUsd: 3 });
  b.reserve('a', 2);
  assert.equal(b.remaining('b'), 1);
  assert.throws(() => b.reserve('b', 1.5), /site has reached its daily budget/);
});

test('counters reset at midnight UTC', () => {
  let now = Date.UTC(2026, 9, 22, 23, 59);
  const b = new DailyBudget({ perUserUsd: 10, globalUsd: null, now: () => now });
  const id = b.reserve('a', 9);
  now = Date.UTC(2026, 9, 23, 0, 1);
  assert.equal(b.remaining('a'), 10);
  b.settle(id, 9); // settling yesterday's reservation doesn't touch today
  assert.equal(b.remaining('a'), 10);
});

test('visitor identity prefers edge-set headers over X-Forwarded-For', () => {
  const req = (headers) => ({ headers, socket: { remoteAddress: '10.0.0.1' } });
  assert.equal(clientIdOf(req({ 'cf-connecting-ip': '1.2.3.4', 'x-forwarded-for': '6.6.6.6' })), '1.2.3.4');
  assert.equal(clientIdOf(req({ 'true-client-ip': '5.5.5.5' })), '5.5.5.5');
  assert.equal(clientIdOf(req({ 'x-forwarded-for': '7.7.7.7, 10.1.1.1' })), '7.7.7.7');
  assert.equal(clientIdOf(req({})), '10.0.0.1');
});

// --- integration with the Claude call ---
const files = [{ path: 'src/a.c', content: 'void f(char*d,const char*s){ strcpy(d,s); }\n' }];
function reviewArgs() {
  const report = scanRepository(files);
  const { _contentByPath, _allFindings, ...pub } = report;
  return { repo: { owner: 'o', repo: 'r' }, report: pub, allFindings: _allFindings, contentByPath: _contentByPath };
}
function fakeClaude({ status = 200, usage = { input_tokens: 2000, output_tokens: 500 } } = {}) {
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    if (status !== 200) return new Response(JSON.stringify({ error: { message: 'overloaded' } }), { status });
    return new Response(JSON.stringify({
      model: 'claude-haiku-5-5', stop_reason: 'tool_use', usage,
      content: [{ type: 'tool_use', name: 'report_review', input: { overall_risk: 'High', summary: 's', findings: [], dismissed: [], recommendations: [] } }],
    }));
  };
  return () => calls;
}

test('a review is charged its real cost, not the reserved worst case', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  fakeClaude();
  const ledger = new DailyBudget({ perUserUsd: 10, globalUsd: null });
  const r = await aiReview({ budget: { ledger, clientId: 'a' }, ...reviewArgs() });
  const expected = costUsd('claude-haiku-5-5', 2000, 500);
  assert.equal(r.meta.costUsd, expected);
  assert.ok(Math.abs(ledger.spent('a') - expected) < 1e-12);
});

test('rejected API calls cost nothing; over-budget visitors never reach the API', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  fakeClaude({ status: 529 });
  const ledger = new DailyBudget({ perUserUsd: 10, globalUsd: null });
  await assert.rejects(aiReview({ budget: { ledger, clientId: 'a' }, ...reviewArgs() }), /overloaded/);
  assert.equal(ledger.spent('a'), 0);

  const calls = fakeClaude();
  const broke = new DailyBudget({ perUserUsd: 0.000001, globalUsd: null });
  await assert.rejects(aiReview({ budget: { ledger: broke, clientId: 'a' }, ...reviewArgs() }), BudgetExceededError);
  assert.equal(calls(), 0);
});

test('when over budget the scan still completes, with a clear note instead of a failure', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  fakeClaude();
  const dir = mkdtempSync(join(tmpdir(), 'owl-'));
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src/a.c'), files[0].content);
  const ledger = new DailyBudget({ perUserUsd: 0.000001, globalUsd: null });
  const r = await analyze(null, { dir, budget: { ledger, clientId: 'a' } });
  assert.equal(r.ai, null);
  assert.equal(r.tier, 'basic');
  assert.match(r.tierReason, /could cost up to/);
  assert.doesNotMatch(r.tierReason, /failed|\.$/);
  assert.ok(r.stats.totalFindings > 0, 'scanner results still returned');
});

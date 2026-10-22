import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.AI_RETRY_DELAY_MS = '10'; // set before the modules read it
const { analyze } = await import('../src/analyze.js');

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.ANTHROPIC_API_KEY;
});

const dir = mkdtempSync(join(tmpdir(), 'owl-tier-'));
mkdirSync(join(dir, 'src'));
writeFileSync(join(dir, 'src/a.c'), 'void f(char*d,const char*s){ strcpy(d,s); }\n');

const ok = () =>
  new Response(JSON.stringify({
    model: 'claude-haiku-5-5', stop_reason: 'tool_use', usage: { input_tokens: 100, output_tokens: 50 },
    content: [{ type: 'tool_use', name: 'report_review', input: { overall_risk: 'High', summary: 's', findings: [], dismissed: [], recommendations: [] } }],
  }));
const err = (status, message = 'x') => new Response(JSON.stringify({ error: { message } }), { status });

function claude(...responses) {
  let i = 0;
  globalThis.fetch = async () => responses[Math.min(i++, responses.length - 1)]();
  return () => i;
}

test('full review is the default', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  claude(ok);
  const r = await analyze(null, { dir });
  assert.equal(r.tier, 'full');
  assert.equal(r.tierReason, null);
  assert.ok(r.ai);
});

test('one temporary failure is retried transparently', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const calls = claude(() => err(529, 'Overloaded'), ok);
  const r = await analyze(null, { dir });
  assert.equal(r.tier, 'full');
  assert.equal(calls(), 2);
});

test('falls back to a basic scan with a plain-language reason', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const cases = [
    [[() => err(529, 'Overloaded')], /temporarily overloaded/, 2],
    [[() => err(429, 'rate')], /rate limit/, 2],
    [[() => err(400, 'Your credit balance is too low to access the Anthropic API.')], /credits have run out/, 1],
    [[() => err(401, 'invalid x-api-key')], /key was rejected/, 1],
    [[() => new Response(JSON.stringify({ stop_reason: 'end_turn', content: [] }))], /came back incomplete/, 1],
  ];
  for (const [responses, reason, expectedCalls] of cases) {
    const calls = claude(...responses);
    const r = await analyze(null, { dir });
    assert.equal(r.tier, 'basic');
    assert.match(r.tierReason, reason);
    assert.equal(calls(), expectedCalls, `${reason}: retries only temporary errors`);
    assert.ok(r.stats.totalFindings > 0, 'scanner results still returned');
  }
});

test('no key configured is a basic scan, not an error', async () => {
  const r = await analyze(null, { dir });
  assert.equal(r.tier, 'basic');
  assert.match(r.tierReason, /isn't configured/);
});

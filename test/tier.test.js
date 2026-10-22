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
    content: [{ type: 'tool_use', name: 'report_review', input: { overall_risk: 'High', summary: 's', findings: [{ title: 'Unbounded copy', severity: 'high', category: 'Buffer overflow', file: 'src/a.c', line: 1, detail: 'd' }], recommendations: [] } }],
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
    [[() => new Response(JSON.stringify({ stop_reason: 'end_turn', content: [] }))], /form Owl couldn't use/, 2],
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

test('malformed but recoverable reviews are accepted; unusable ones are retried, then fall back', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const reply = (input) => () =>
    new Response(JSON.stringify({ model: 'claude-haiku-5-5', stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 10 }, content: [{ type: 'tool_use', name: 'report_review', input }] }));
  const one = { title: 'Unbounded copy', severity: 'high', category: 'Buffer overflow', detail: 'd' };

  // findings sent as a JSON string, with path/line_number field names
  let calls = claude(reply({ overall_risk: 'High', summary: 's', findings: JSON.stringify([{ ...one, path: 'src/a.c', line_number: '1' }]), recommendations: '["Fix it"]' }));
  let r = await analyze(null, { dir });
  assert.equal(r.tier, 'full');
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].file, 'src/a.c');
  assert.equal(r.findings[0].line, 1);
  assert.deepEqual(r.ai.recommendations, ['Fix it']);
  assert.equal(calls(), 1);

  // review nested one level down, location written as "file:line"
  calls = claude(reply({ review: { overall_risk: 'High', summary: 's', findings: [{ ...one, file: 'src/a.c:1' }], recommendations: [] } }));
  r = await analyze(null, { dir });
  assert.equal(r.tier, 'full');
  assert.equal(r.findings[0].locationVerified, true);

  // High rating with nothing listed: retried once, then a recovered second answer is used
  calls = claude(reply({ overall_risk: 'High', summary: 's', findings: [], recommendations: [] }), reply({ overall_risk: 'High', summary: 's', findings: [{ ...one, file: 'src/a.c', line: 1 }], recommendations: [] }));
  r = await analyze(null, { dir });
  assert.equal(r.tier, 'full');
  assert.equal(calls(), 2);

  // still unusable after the retry: basic scan, with the reason
  calls = claude(reply({ overall_risk: 'Critical', summary: 's', findings: 'see above', recommendations: [] }));
  r = await analyze(null, { dir });
  assert.equal(r.tier, 'basic');
  assert.match(r.tierReason, /form Owl couldn't use/);
  assert.equal(calls(), 2);

  // a genuinely clean result (Low, nothing listed) is accepted as-is
  calls = claude(reply({ overall_risk: 'Low', summary: 'Looks fine', findings: [], recommendations: [] }));
  r = await analyze(null, { dir });
  assert.equal(r.tier, 'full');
  assert.equal(r.findings.length, 0);
  assert.equal(calls(), 1);
});

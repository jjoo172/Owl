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
    model: 'claude-haiku-5-5', stop_reason: 'end_turn', usage: { input_tokens: 100, output_tokens: 50 },
    content: [{ type: 'text', text: JSON.stringify({ overall_risk: 'High', summary: 's', findings: [{ title: 'Unbounded copy', severity: 'high', category: 'Buffer overflow', cwe: '', file: 'src/a.c', line: 1, detail: 'd' }], recommendations: [] }) }],
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
    new Response(JSON.stringify({ model: 'claude-haiku-5-5', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 10 }, content: [{ type: 'text', text: JSON.stringify(input) }] }));
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

test('the request uses API-enforced structured output with a schema the API accepts', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  let sent;
  globalThis.fetch = async (_url, opts) => {
    sent = JSON.parse(opts.body);
    return ok();
  };
  await analyze(null, { dir });
  assert.equal(sent.tools, undefined);
  assert.equal(sent.output_config.format.type, 'json_schema');
  const schema = sent.output_config.format.schema;
  assert.deepEqual(Object.keys(schema.properties).slice(0, 1), ['findings'], 'vulnerabilities come first');
  // Structured outputs: every object closed, no unsupported constraints.
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'object') {
      assert.equal(node.additionalProperties, false);
      assert.deepEqual([...node.required].sort(), Object.keys(node.properties).sort(), 'all fields required');
    }
    for (const bad of ['maxItems', 'minimum', 'maximum', 'minLength', 'maxLength']) assert.equal(node[bad], undefined, bad);
    Object.values(node).forEach(walk);
  };
  walk(schema);
});

test('each unusable outcome gets its own plain-language reason', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const reply = (extra) => () => new Response(JSON.stringify({ model: 'claude-haiku-5-5', usage: { input_tokens: 1, output_tokens: 1 }, ...extra }));
  const cases = [
    [{ stop_reason: 'refusal', content: [{ type: 'text', text: '' }] }, /declined to review/],
    [{ stop_reason: 'max_tokens', content: [{ type: 'text', text: '{"findings":[' }] }, /cut off/],
    [{ stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify({ findings: [], overall_risk: 'high', summary: 's', recommendations: [] }) }] }, /rated the code High but listed no specific vulnerabilities/],
    [{ stop_reason: 'end_turn', content: [{ type: 'text', text: 'not json' }] }, /form Owl couldn't use/],
  ];
  for (const [extra, reason] of cases) {
    claude(reply(extra));
    const r = await analyze(null, { dir });
    assert.equal(r.tier, 'basic');
    assert.match(r.tierReason, reason);
  }
});

test('an empty findings field does not hide vulnerabilities listed under another name', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const { normalizeReview } = await import('../src/ai.js');
  const { review } = normalizeReview({ findings: [], vulnerabilities: [{ title: 't', severity: 'high', category: 'c', file: 'src/a.c', line: 1, detail: 'd' }], overall_risk: 'HIGH', summary: 's', recommendations: [] });
  assert.equal(review.findings.length, 1);
  assert.equal(review.overall_risk, 'High', 'rating casing normalized');
});

test('a review cut off at the output limit is retried at low effort, with room for thinking', async () => {
  process.env.ANTHROPIC_API_KEY = 'test';
  const bodies = [];
  const cut = () => new Response(JSON.stringify({ model: 'claude-haiku-5-5', stop_reason: 'max_tokens', usage: { input_tokens: 100, output_tokens: 40000 }, content: [] }));
  const responses = [cut, ok];
  globalThis.fetch = async (_url, opts) => {
    bodies.push(JSON.parse(opts.body));
    return responses[bodies.length - 1]();
  };
  const r = await analyze(null, { dir });
  assert.equal(r.tier, 'full');
  assert.equal(bodies.length, 2);
  assert.ok(bodies[0].max_tokens >= 32000, 'leaves room for adaptive thinking');
  assert.equal(bodies[0].output_config.effort, undefined, 'first try uses the default effort');
  assert.equal(bodies[1].output_config.effort, 'low');
  assert.ok(bodies[1].output_config.format, 'still uses structured output');
});

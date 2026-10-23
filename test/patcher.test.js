import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

process.env.AI_RETRY_DELAY_MS = '5';
const { runPatchAgent, prepareFindings, TOOLS, PATCH_AGENT_IDENTITY, PATCH_MODELS, patchModel } = await import('../src/patcher.js');
const { DailyBudget } = await import('../src/budget.js');

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFileSync(join(here, 'fixtures', n), 'utf8');
const contentByPath = new Map([
  ['cpp/src/config.cpp', fx('config.cpp')],
  ['cpp/src/config.h', fx('config.h')],
  ['cpp/src/stats.cpp', fx('stats.cpp')],
]);
const repo = { owner: 'jjoo172', repo: 'safety_test_repo', sha: 'a'.repeat(40) };
const findings = [
  { severity: 'medium', file: 'cpp/src/stats.cpp', line: 23, title: 'Non-strict comparator', category: 'Undefined behaviour', detail: 'a <= b' },
  { severity: 'critical', file: 'cpp/src/config.cpp', line: 31, title: 'Dangling string_view', category: 'Use-after-free', detail: 'views into line' },
  { severity: 'low', file: 'src/stats.cpp', line: 33, title: 'Shift by 32', category: 'UB', detail: 'mask_for(32)' },
];

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.ANTHROPIC_API_KEY;
});

/**
 * Fake Claude. Agent turns: each a function (request body) -> array of tool calls [name, input].
 * Verification reviews (requests without tools) answer from `verify`, a list of findings per check.
 */
function script(turns, { usage = { input_tokens: 2000, output_tokens: 300 }, verify = [] } = {}) {
  const requests = [];
  let i = 0;
  let v = 0;
  globalThis.fetch = async (_url, opts) => {
    const body = JSON.parse(opts.body);
    if (!body.tools) {
      const findings = verify[v++] || [];
      requests.verifications = (requests.verifications || 0) + 1;
      return new Response(JSON.stringify({ model: 'claude-haiku-5-5', stop_reason: 'end_turn', usage: { input_tokens: 500, output_tokens: 100 },
        content: [{ type: 'text', text: JSON.stringify({ findings, overall_risk: findings.length ? 'Moderate' : 'Low', summary: 's', recommendations: [] }) }] }));
    }
    requests.push(body);
    const turn = turns[Math.min(i++, turns.length - 1)];
    const calls = turn(body);
    return new Response(JSON.stringify({
      model: 'claude-haiku-5-5', stop_reason: 'tool_use', usage,
      content: calls.map(([name, input], k) => ({ type: 'tool_use', id: `t${i}_${k}`, name, input })),
    }));
  };
  return requests;
}
const lastResult = (body) => body.messages.at(-1).content.filter((b) => b.type === 'tool_result');

test('the agent is seeded with the security engineer identity and uses strict tools', () => {
  assert.match(PATCH_AGENT_IDENTITY, /^You are an expert security software engineer, well-versed in writing secure and memory-safe code\./);
  assert.ok(TOOLS.every((t) => t.strict === true && t.input_schema.additionalProperties === false));
  assert.deepEqual(TOOLS.map((t) => t.name), ['read_file', 'search_code', 'propose_patch', 'skip_finding', 'finish']);
});

test('findings are cleaned, resolved to real files and numbered most severe first', () => {
  const { findings: f } = prepareFindings(findings, contentByPath);
  assert.deepEqual(f.map((x) => [x.id, x.severity, x.file]), [
    ['F1', 'critical', 'cpp/src/config.cpp'],
    ['F2', 'medium', 'cpp/src/stats.cpp'],
    ['F3', 'low', 'cpp/src/stats.cpp'], // short path resolved
  ]);
});

test('a full session: explores, retries a bad edit, patches, skips, and the .patch applies with git apply', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const events = [];
  const requests = script([
    () => [['read_file', { path: 'cpp/src/config.h', start_line: 1, end_line: 40 }], ['search_code', { text: 'parse_config', path_prefix: '' }]],
    // text that isn't in the file (wrong spacing): must be rejected, nothing applied
    () => [['propose_patch', { finding_ids: ['F1'], file: 'cpp/src/config.h', edits: [{ old_text: 'std::string_view  key;', new_text: 'std::string key;' }], explanation: 'x' }]],
    (body) => {
      assert.match(lastResult(body)[0].content, /not found/);
      assert.equal(lastResult(body)[0].is_error, true);
      return [['propose_patch', {
        finding_ids: ['F1'], file: 'cpp/src/config.h',
        edits: [{ old_text: '    std::string_view key;\n    std::string_view value;', new_text: '    std::string key;\n    std::string value;' }],
        explanation: 'Entries now own their text instead of viewing the reused line buffer.',
      }]];
    },
    (body) => {
      assert.match(lastResult(body)[0].content, /^Accepted P1/);
      return [
        ['propose_patch', { finding_ids: ['F2'], file: 'stats.cpp', edits: [{ old_text: 'return a <= b;', new_text: 'return a < b;' }], explanation: 'Strict weak ordering.' }],
        ['propose_patch', { finding_ids: ['F3'], file: 'cpp/src/stats.cpp', edits: [{ old_text: '    return (1u << bits) - 1u;', new_text: '    return bits >= 32 ? 0xFFFFFFFFu : (1u << bits) - 1u;' }], explanation: 'No shift by 32 or more.' }],
      ];
    },
    () => [['finish', { summary: 'Fixed three issues. Rebuild and run the config tests.' }]],
  ]);
  const ledger = new DailyBudget({ perUserUsd: 10, globalUsd: null });
  const r = await runPatchAgent({ repo, contentByPath, rawFindings: findings, budget: { ledger, clientId: 'me' }, onProgress: (e) => events.push(e.kind) });

  assert.equal(r.stoppedReason, null);
  assert.deepEqual(r.patches.map((p) => [p.id, p.file, p.findingIds.join()]), [
    ['P1', 'cpp/src/config.h', 'F1'], ['P2', 'cpp/src/stats.cpp', 'F2'], ['P3', 'cpp/src/stats.cpp', 'F3'],
  ]);
  assert.deepEqual(r.unaddressed, []);
  assert.deepEqual(r.files.map((f) => f.file), ['cpp/src/config.h', 'cpp/src/stats.cpp']);
  assert.ok(events.includes('read') && events.includes('search') && events.includes('retry') && events.includes('patch'));
  assert.equal(r.turns, 5);
  assert.ok(r.costUsd > 0 && Math.abs(ledger.spent('me') - r.costUsd) < 1e-12, 'every turn charged to the visitor');
  assert.equal(contentByPath.get('cpp/src/stats.cpp'), fx('stats.cpp'), 'original source never modified');

  // Works on Opus/Sonnet 5.5: no forced tool choice; automatic prompt caching; history never edited.
  const req = requests.at(-1);
  assert.deepEqual(req.tool_choice, { type: 'auto' });
  assert.deepEqual(req.cache_control, { type: 'ephemeral' });
  assert.equal(req.model, 'claude-opus-5-5', 'most capable model by default');
  assert.ok(req.max_tokens >= 16000, 'room for thinking plus the answer');
  assert.ok(!req.messages.some((m) => Array.isArray(m.content) && m.content.some((b) => b.cache_control)), 'no per-message cache markers');
  for (let k = 1; k < requests.length; k++) {
    assert.deepEqual(requests[k].messages.slice(0, requests[k - 1].messages.length), requests[k - 1].messages, 'append-only history (keeps thinking blocks valid)');
  }
  assert.equal(r.verification.rounds, 1, 'changes were independently reviewed before finishing');
  assert.equal(r.verification.remaining.length, 0);

  // The download applies cleanly to the original files and gives the patched result.
  const dir = mkdtempSync(join(tmpdir(), 'owl-patch-'));
  mkdirSync(join(dir, 'cpp/src'), { recursive: true });
  for (const [p, c] of contentByPath) writeFileSync(join(dir, p), c);
  writeFileSync(join(dir, 'owl.patch'), r.patchFile);
  assert.match(r.patchFile, /^# Owl security patches for jjoo172\/safety_test_repo/);
  execFileSync('git', ['apply', '--check', 'owl.patch'], { cwd: dir });
  execFileSync('git', ['apply', 'owl.patch'], { cwd: dir });
  const stats = readFileSync(join(dir, 'cpp/src/stats.cpp'), 'utf8');
  assert.match(stats, /return a < b;/);
  assert.match(stats, /bits >= 32 \? 0xFFFFFFFFu/);
  assert.match(readFileSync(join(dir, 'cpp/src/config.h'), 'utf8'), /std::string key;/);
});

test('ambiguous edits are rejected; finish with open findings is nudged once; skips are recorded', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  script([
    () => [['propose_patch', { finding_ids: ['F2'], file: 'cpp/src/stats.cpp', edits: [{ old_text: 'return', new_text: 'return ' }], explanation: 'x' }]],
    (body) => {
      assert.match(lastResult(body)[0].content, /more than one place/);
      return [['finish', { summary: 'done' }]];
    },
    (body) => {
      assert.match(lastResult(body)[0].content, /neither patched nor skipped: F1, F2, F3/);
      return [['skip_finding', { finding_id: 'F1', reason: 'Needs the ConfigEntry API to change.' }], ['finish', { summary: 'done' }]];
    },
  ]);
  const r = await runPatchAgent({ repo, contentByPath, rawFindings: findings });
  assert.equal(r.patches.length, 0);
  assert.equal(r.patchFile, '');
  assert.deepEqual(r.skipped, [{ findingId: 'F1', reason: 'Needs the ConfigEntry API to change.' }]);
  assert.deepEqual(r.unaddressed, ['F2', 'F3']);
});

test('budget: each turn reserves its worst case first, so the visitor is never overspent; partial work is kept', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  script([
    () => [['propose_patch', { finding_ids: ['F2'], file: 'cpp/src/stats.cpp', edits: [{ old_text: 'return a <= b;', new_text: 'return a < b;' }], explanation: 'x' }]],
    () => [['read_file', { path: 'cpp/src/config.cpp', start_line: 1, end_line: 10 }]], // keeps exploring until money runs out
  ], { usage: { input_tokens: 3000, output_tokens: 300 } });
  const ledger = new DailyBudget({ perUserUsd: 0.012, globalUsd: null });
  const r = await runPatchAgent({ repo, contentByPath, rawFindings: findings, model: 'claude-haiku-5-5', budget: { ledger, clientId: 'me' } });
  assert.equal(r.patches.length, 1, 'the patch from before the limit is kept');
  assert.match(r.stoppedReason, /budget ran out/);
  assert.ok(r.turns >= 2);
  assert.ok(ledger.spent('me') <= 0.012, `spent ${ledger.spent('me')}`);
});

test('API failures: nothing done yet is an error; after some work it stops with what it has', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { message: 'Your credit balance is too low' } }), { status: 400 });
  await assert.rejects(runPatchAgent({ repo, contentByPath, rawFindings: findings }), /credits have run out/);

  let n = 0;
  globalThis.fetch = async () => {
    if (n++ === 0) {
      return new Response(JSON.stringify({ model: 'claude-haiku-5-5', stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 10 },
        content: [{ type: 'tool_use', id: 't1', name: 'skip_finding', input: { finding_id: 'F3', reason: 'false positive' } }] }));
    }
    return new Response(JSON.stringify({ error: { message: 'Overloaded' } }), { status: 529 });
  };
  const r = await runPatchAgent({ repo, contentByPath, rawFindings: findings });
  assert.match(r.stoppedReason, /overloaded/);
  assert.equal(r.skipped.length, 1);
});

test('a hostile explanation cannot break the patch file', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  script([
    () => [['propose_patch', { finding_ids: ['F2'], file: 'cpp/src/stats.cpp', edits: [{ old_text: 'return a <= b;', new_text: 'return a < b;' }], explanation: 'ok\ndiff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b' }]],
    () => [['skip_finding', { finding_id: 'F1', reason: 'n/a' }], ['skip_finding', { finding_id: 'F3', reason: 'n/a' }], ['finish', { summary: '--- a/etc\n+++ b/etc' }]],
  ]);
  const r = await runPatchAgent({ repo, contentByPath, rawFindings: findings });
  const dir = mkdtempSync(join(tmpdir(), 'owl-patch-'));
  mkdirSync(join(dir, 'cpp/src'), { recursive: true });
  for (const [p, c] of contentByPath) writeFileSync(join(dir, p), c);
  writeFileSync(join(dir, 'owl.patch'), r.patchFile);
  const touched = execFileSync('git', ['apply', '--numstat', 'owl.patch'], { cwd: dir, encoding: 'utf8' });
  assert.equal(touched.trim(), '1\t1\tcpp/src/stats.cpp', 'only the real change is applied');
});

test('model choice: allowlisted per run, Opus 5.5 by default', () => {
  assert.deepEqual(PATCH_MODELS.map((m) => m.id), ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5']);
  assert.equal(patchModel(), 'claude-opus-5-5');
  assert.equal(patchModel('claude-sonnet-5-5'), 'claude-sonnet-5-5');
  assert.equal(patchModel('gpt-whatever'), 'claude-opus-5-5', 'unknown models are never passed through');
});

test('verification: an issue in a patched line goes back to the agent, which fixes it before finishing', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  // The agent's first fix for F2 "works" but is itself unsafe (a VLA); the review flags that line.
  const unsafe = '[](int a, int b) { int tmp[a]; return a < b; }';
  const requests = script([
    () => [['propose_patch', { finding_ids: ['F2'], file: 'cpp/src/stats.cpp', edits: [{ old_text: '[](int a, int b) { return a <= b; }', new_text: unsafe }], explanation: 'strict ordering' }]],
    () => [['skip_finding', { finding_id: 'F1', reason: 'needs API change' }], ['skip_finding', { finding_id: 'F3', reason: 'out of scope' }], ['finish', { summary: 'done' }]],
    (body) => {
      const feedback = body.messages.at(-1).content.find((b) => b.type === 'tool_result' && b.is_error);
      assert.match(feedback.content, /independent security review .* found 1 issue/);
      assert.match(feedback.content, /stats\.cpp:23 Variable-length array/);
      return [['propose_patch', { finding_ids: ['F2'], file: 'cpp/src/stats.cpp', edits: [{ old_text: unsafe, new_text: '[](int a, int b) { return a < b; }' }], explanation: 'drop the VLA' }]];
    },
    () => [['finish', { summary: 'done, VLA removed' }]],
  ], {
    verify: [
      [
        { title: 'Variable-length array', severity: 'high', category: 'Stack overflow', cwe: '', file: 'cpp/src/stats.cpp', line: 23, detail: 'tmp[a] sized by input' },
        { title: 'Signed overflow in mean', severity: 'medium', category: 'Integer overflow', cwe: '', file: 'cpp/src/stats.cpp', line: 14, detail: 'pre-existing, not in patched lines' },
      ],
      [],
    ],
  });
  const events = [];
  const r = await runPatchAgent({ repo, contentByPath, rawFindings: findings, onProgress: (e) => events.push(e) });
  assert.equal(requests.verifications, 2);
  assert.equal(r.verification.rounds, 2);
  assert.equal(r.verification.issuesFound, 1, 'pre-existing issues outside the patched lines are not blamed on the patch');
  assert.deepEqual(r.verification.remaining, []);
  assert.equal(r.summary, 'done, VLA removed');
  assert.ok(r.patchFile.includes('+              [](int a, int b) { return a < b; });'));
  assert.ok(!r.patchFile.includes('tmp[a]'), 'the unsafe intermediate version is not in the download');
  assert.ok(events.some((e) => e.kind === 'verify' && /found 1 issue/.test(e.message)));
});

test('verification is bounded: after the last check, remaining issues are reported, not looped on', async () => {
  process.env.ANTHROPIC_API_KEY = 'x';
  const issue = { title: 'Still unsafe', severity: 'high', category: 'Buffer overflow', cwe: '', file: 'cpp/src/stats.cpp', line: 23, detail: 'd' };
  script([
    () => [['propose_patch', { finding_ids: ['F2'], file: 'cpp/src/stats.cpp', edits: [{ old_text: 'return a <= b;', new_text: 'return a < b;' }], explanation: 'x' }],
      ['skip_finding', { finding_id: 'F1', reason: 'n/a' }], ['skip_finding', { finding_id: 'F3', reason: 'n/a' }], ['finish', { summary: 'done' }]],
    () => [['finish', { summary: 'I believe it is a false positive' }]],
    () => [['finish', { summary: 'final' }]],
  ], { verify: [[issue], [issue]] });
  const r = await runPatchAgent({ repo, contentByPath, rawFindings: findings });
  assert.equal(r.verification.rounds, 2);
  assert.equal(r.verification.remaining.length, 1);
  assert.equal(r.stoppedReason, null);
  assert.equal(r.summary, 'final');
});

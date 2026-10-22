import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { checkRepository } from '../src/access.js';

const SHA = 'a'.repeat(40);
const realFetch = globalThis.fetch;
const json = (o, status = 200, headers = {}) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', ...headers } });

// A fake GitHub: one public C++ repo "acme/widget" on branch "main".
function fakeGitHub({ archiveStatus = 200, rateLimited = false, langs = { 'C++': 900, CMake: 100 }, priv = false } = {}) {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    if (u.hostname === 'api.github.com') {
      if (rateLimited) return json({ message: 'rate limit' }, 403, { 'x-ratelimit-remaining': '0' });
      if (!u.pathname.startsWith('/repos/acme/widget')) return json({ message: 'Not Found' }, 404);
      const rest = u.pathname.slice('/repos/acme/widget'.length);
      if (!rest) return json({ full_name: 'acme/widget', name: 'widget', owner: { login: 'acme' }, private: priv, default_branch: 'main', size: 1024 });
      if (rest === '/languages') return json(langs);
      if (rest === '/commits/main') return new Response(SHA);
      return json({ message: 'No commit found' }, 422);
    }
    if (u.hostname === 'codeload.github.com') {
      return archiveStatus === 200 ? new Response(gzipSync(Buffer.from('tar'))) : new Response('nope', { status: archiveStatus });
    }
    throw new Error('unexpected fetch ' + url);
  };
}

beforeEach(() => { delete process.env.ANTHROPIC_API_KEY; });
afterEach(() => { globalThis.fetch = realFetch; });

const statusOf = (r, id) => r.checks.find((c) => c.id === id)?.status;

test('a readable repository passes and pins the commit', async () => {
  fakeGitHub();
  const r = await checkRepository('https://github.com/acme/widget');
  assert.equal(r.canScan, true);
  assert.deepEqual(r.target, { owner: 'acme', repo: 'widget', ref: 'main', sha: SHA });
  for (const id of ['input', 'exists', 'ref', 'language', 'size', 'archive']) assert.equal(statusOf(r, id), 'pass', id);
  assert.equal(statusOf(r, 'ai'), 'warn'); // no API key: informational only, never blocks
});

test('stops at the first blocking problem with a reason', async () => {
  fakeGitHub();
  let r = await checkRepository('acme/missing');
  assert.equal(r.canScan, false);
  assert.equal(statusOf(r, 'exists'), 'fail');
  assert.equal(statusOf(r, 'ref'), undefined); // later checks don't run

  r = await checkRepository('acme/widget', 'no-such-branch');
  assert.equal(statusOf(r, 'ref'), 'fail');
  assert.match(r.checks.find((c) => c.id === 'ref').detail, /no-such-branch/);

  r = await checkRepository('not a repo');
  assert.equal(statusOf(r, 'input'), 'fail');
});

test('private repos, rate limits and broken archives are reported clearly', async () => {
  fakeGitHub({ priv: true });
  assert.match((await checkRepository('acme/widget')).checks.find((c) => c.id === 'exists').detail, /private/);

  fakeGitHub({ rateLimited: true });
  assert.match((await checkRepository('acme/widget')).checks.find((c) => c.id === 'exists').detail, /rate limit/i);

  fakeGitHub({ archiveStatus: 500 });
  const r = await checkRepository('acme/widget');
  assert.equal(r.canScan, false);
  assert.equal(statusOf(r, 'archive'), 'fail');
});

test('no C/C++ is a warning, not a failure', async () => {
  fakeGitHub({ langs: { Python: 100 } });
  const r = await checkRepository('acme/widget');
  assert.equal(statusOf(r, 'language'), 'warn');
  assert.equal(r.canScan, true);
});

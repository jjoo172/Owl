import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { analyze } from './analyze.js';
import { aiAvailable, ReviewUnavailableError } from './ai.js';
import { createHash } from 'node:crypto';
import { fetchSourceFiles } from './github.js';
import { runPatchAgent, patchModel } from './patcher.js';
import { compareScans } from './compare.js';
import { PatchError } from './applypatch.js';
import { checkRepository, modelLabel } from './access.js';
import { DailyBudget, clientIdOf, fmtUsd } from './budget.js';

const PUBLIC = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
const PORT = process.env.PORT || 3000;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_SCANS || 2);
const CACHE_TTL_MS = 30 * 60 * 1000;
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
};

// Which build is live: Render sets RENDER_GIT_COMMIT; elsewhere fall back to the start time.
const BUILD = (process.env.RENDER_GIT_COMMIT || '').slice(0, 7) || `dev-${Date.now().toString(36)}`;

let active = 0;
const ledger = new DailyBudget();
const cache = new Map(); // key -> { at, data }

async function readJson(req, limit = 10_000) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > limit) throw new Error('Request too large');
  }
  return body ? JSON.parse(body) : {};
}

async function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const rel = normalize(urlPath === '/' ? '/index.html' : urlPath).replace(/^(\.\.[/\\])+/, '');
  const file = join(PUBLIC, rel);
  if (!file.startsWith(PUBLIC)) return send404(res);
  try {
    let data = await readFile(file);
    const isPage = extname(file) === '.html';
    if (isPage) {
      // Point the page at this build's assets, so a deploy is never mixed with a cached old script.
      data = Buffer.from(data.toString('utf8').replace(/(href|src)="(styles\.css|app\.js)"/g, `$1="$2?v=${BUILD}"`).replace('{{BUILD}}', BUILD));
    }
    const versioned = new URL(req.url, 'http://x').searchParams.get('v') === BUILD;
    res.writeHead(200, {
      'Content-Type': TYPES[extname(file)] || 'application/octet-stream',
      'Cache-Control': isPage ? 'no-cache' : versioned ? 'public, max-age=31536000, immutable' : 'no-cache',
    });
    res.end(data);
  } catch {
    send404(res);
  }
}

function send404(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
}

// Streams newline-delimited JSON: progress events, then one result or error.
async function handleScan(req, res) {
  let input;
  try {
    input = await readJson(req);
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ type: 'error', message: 'Bad request' }));
  }
  // Step 2 scans exactly the commit that step 1 (/api/check) confirmed.
  const { owner, repo, ref, sha, ai = true } = input;
  const send = (obj) => res.write(JSON.stringify(obj) + '\n');
  if (!/^[\w.-]+$/.test(owner || '') || !/^[\w.-]+$/.test(repo || '') || !/^[0-9a-f]{40}$/.test(sha || '')) {
    res.writeHead(400, { 'Content-Type': 'application/x-ndjson' });
    send({ type: 'error', message: 'Scan requests need the owner, repo and commit from the access check. Run the check first.' });
    return res.end();
  }
  const target = { owner, repo, ref: typeof ref === 'string' ? ref : undefined, sha };
  const useAi = ai !== false;
  const key = `${owner}/${repo}@${sha}@${useAi}`.toLowerCase();

  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store' });
    send({ type: 'result', data: { ...hit.data, cached: true } });
    return res.end();
  }
  if (active >= MAX_CONCURRENT) {
    res.writeHead(429, { 'Content-Type': 'application/x-ndjson' });
    send({ type: 'error', message: 'The scanner is busy with other repositories. Try again in a minute.' });
    return res.end();
  }

  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
  active++;
  const heartbeat = setInterval(() => send({ type: 'ping' }), 15_000);
  try {
    const budget = { ledger, clientId: clientIdOf(req) };
    const data = await analyze(target, { ai: useAi, budget, onProgress: (message) => send({ type: 'progress', message }) });
    // Only cache complete results: a review skipped for one visitor's budget mustn't be served to others.
    // Only cache complete, non-empty full reviews; anything else should be re-run fresh next time.
    if (data.tier === 'full' && data.findings.length > 0) cache.set(key, { at: Date.now(), data });
    if (cache.size > 50) cache.delete(cache.keys().next().value);
    send({ type: 'result', data });
  } catch (err) {
    console.error('scan failed', `${owner}/${repo}@${sha}`, err);
    send({ type: 'error', message: err.status ? err.message : 'Something went wrong while scanning that repository.' });
  } finally {
    clearInterval(heartbeat);
    active--;
    res.end();
  }
}

// Opt-in patch workflow: a separate security-engineer agent proposes patches for the
// vulnerabilities from a scan. Streams progress like /api/scan, then one result.
const MAX_CONCURRENT_PATCHES = Number(process.env.MAX_CONCURRENT_PATCHES || 1);
let activePatches = 0;
const patchCache = new Map(); // key -> { at, data }

async function handlePatch(req, res) {
  const send = (obj) => res.write(JSON.stringify(obj) + '\n');
  const fail = (status, message) => {
    res.writeHead(status, { 'Content-Type': 'application/x-ndjson' });
    send({ type: 'error', message });
    res.end();
  };
  let input;
  try {
    input = await readJson(req, 300_000);
  } catch {
    return fail(400, 'Bad request');
  }
  const { owner, repo, sha, ref, findings } = input;
  if (!/^[\w.-]+$/.test(owner || '') || !/^[\w.-]+$/.test(repo || '') || !/^[0-9a-f]{40}$/.test(sha || '')) {
    return fail(400, 'Patch requests need the owner, repo and commit of a scan.');
  }
  if (!Array.isArray(findings) || !findings.length) return fail(400, 'There are no vulnerabilities to patch.');
  if (!aiAvailable()) return fail(503, "Proposing patches needs Claude, which isn't configured on this server.");

  const key = `${owner}/${repo}@${sha}#${createHash('sha256').update(JSON.stringify(findings)).digest('hex').slice(0, 16)}`.toLowerCase();
  const hit = patchCache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store' });
    send({ type: 'result', data: { ...hit.data, cached: true } });
    return res.end();
  }
  if (activePatches >= MAX_CONCURRENT_PATCHES) return fail(429, 'The patch agent is busy with another repository. Try again in a few minutes.');

  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
  activePatches++;
  const heartbeat = setInterval(() => send({ type: 'ping' }), 15_000);
  try {
    send({ type: 'progress', message: `Downloading ${owner}/${repo} @ ${sha.slice(0, 10)}` });
    const { files } = await fetchSourceFiles({ owner, repo, sha });
    const contentByPath = new Map(files.map((f) => [f.path, f.content]));
    const data = await runPatchAgent({
      repo: { owner, repo, sha, ref },
      contentByPath,
      rawFindings: findings,
      budget: { ledger, clientId: clientIdOf(req) },
      onProgress: (ev) => send({ type: 'progress', ...ev }),
    });
    if (data.patches.length && !data.stoppedReason) {
      patchCache.set(key, { at: Date.now(), data });
      if (patchCache.size > 20) patchCache.delete(patchCache.keys().next().value);
    }
    send({ type: 'result', data });
  } catch (err) {
    if (!(err instanceof ReviewUnavailableError) && !err.status) console.error('patch failed', `${owner}/${repo}@${sha}`, err);
    send({ type: 'error', message: err instanceof ReviewUnavailableError || err.status ? err.message : 'Something went wrong while proposing patches.' });
  } finally {
    clearInterval(heartbeat);
    activePatches--;
    res.end();
  }
}

// Opt-in re-scan: runs the original vulnerability review on the patched code (same prompt, same
// files) and compares it with the original scan. Streams progress like /api/scan.
const rescanCache = new Map(); // key -> { at, data }

async function handleRescan(req, res) {
  const send = (obj) => res.write(JSON.stringify(obj) + '\n');
  const fail = (status, message) => {
    res.writeHead(status, { 'Content-Type': 'application/x-ndjson' });
    send({ type: 'error', message });
    res.end();
  };
  let input;
  try {
    input = await readJson(req, 4_000_000);
  } catch {
    return fail(400, 'Bad request (the patch may be too large to re-scan).');
  }
  const { owner, repo, sha, ref, patchFile, before } = input;
  if (!/^[\w.-]+$/.test(owner || '') || !/^[\w.-]+$/.test(repo || '') || !/^[0-9a-f]{40}$/.test(sha || '')) {
    return fail(400, 'Re-scan requests need the owner, repo and commit of a scan.');
  }
  if (typeof patchFile !== 'string' || !patchFile.includes('@@')) return fail(400, 'There is no patch to re-scan.');
  if (!before || !Array.isArray(before.findings)) return fail(400, 'Re-scan requests need the original scan to compare with.');

  const key = `${owner}/${repo}@${sha}#${createHash('sha256').update(patchFile).update(JSON.stringify(before.findings)).digest('hex').slice(0, 16)}`.toLowerCase();
  const hit = rescanCache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store' });
    send({ type: 'result', data: { ...hit.data, cached: true } });
    return res.end();
  }
  if (active >= MAX_CONCURRENT) return fail(429, 'The scanner is busy with other repositories. Try again in a minute.');

  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
  active++;
  const heartbeat = setInterval(() => send({ type: 'ping' }), 15_000);
  try {
    const after = await analyze(
      { owner, repo, ref: typeof ref === 'string' ? ref : undefined, sha },
      { patchText: patchFile, budget: { ledger, clientId: clientIdOf(req) }, onProgress: (message) => send({ type: 'progress', message }) },
    );
    const comparison = compareScans({
      before: { tier: before.tier, risk: before.risk, coverage: before.coverage, findings: before.findings.slice(0, 3000) },
      after,
      lineMaps: after.lineMaps,
    });
    const data = { after, comparison };
    if (after.tier === 'full') {
      rescanCache.set(key, { at: Date.now(), data });
      if (rescanCache.size > 20) rescanCache.delete(rescanCache.keys().next().value);
    }
    send({ type: 'result', data });
  } catch (err) {
    if (!(err instanceof PatchError) && !err.status) console.error('rescan failed', `${owner}/${repo}@${sha}`, err);
    send({ type: 'error', message: err instanceof PatchError || err.status ? err.message : 'Something went wrong while re-scanning the patched code.' });
  } finally {
    clearInterval(heartbeat);
    active--;
    res.end();
  }
}

// Step 1: is the repository readable? Plain JSON, no scanning.
const checkCache = new Map(); // short-lived, saves GitHub API quota on repeat checks
async function handleCheck(req, res) {
  const url = new URL(req.url, 'http://x');
  const repo = url.searchParams.get('repo') || '';
  const ref = url.searchParams.get('ref') || '';
  const key = `${repo.toLowerCase().trim()}@${ref.trim()}`;
  let result;
  const hit = checkCache.get(key);
  if (hit && Date.now() - hit.at < 2 * 60 * 1000) result = hit.result;
  else {
    try {
      result = await checkRepository(repo, ref || undefined);
    } catch (err) {
      console.error('check failed', repo, err);
      result = { canScan: false, checks: [{ id: 'server', label: 'Access check', status: 'fail', detail: 'The server hit an unexpected error while checking this repository.' }] };
    }
    if (result.canScan) {
      checkCache.set(key, { at: Date.now(), result });
      if (checkCache.size > 200) checkCache.delete(checkCache.keys().next().value);
    }
  }
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(withBudget(result, clientIdOf(req))));
}

/** Adds this visitor's remaining Claude budget to the expert-review check (per request, not cached). */
function withBudget(result, clientId) {
  if (!aiAvailable() || !result.checks) return result;
  const left = ledger.remaining(clientId);
  const limit = ledger.perUserUsd;
  const checks = result.checks.map((c) => {
    if (c.id !== 'ai') return c;
    if (left <= 0) {
      return { ...c, status: 'warn', detail: "Basic scan only — you've used today's Claude review budget (resets at midnight UTC)" };
    }
    return { ...c, detail: limit === null ? c.detail : `${c.detail} — $${fmtUsd(left)} of your $${fmtUsd(limit)} daily budget left` };
  });
  return { ...result, checks };
}

const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  if (path === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify({ ok: true, version: BUILD, ai: aiAvailable(), model: aiAvailable() ? modelLabel() : null, patchModel: aiAvailable() ? modelLabel(patchModel()) : null, githubToken: Boolean(process.env.GITHUB_TOKEN) }));
  }
  if (path === '/api/check' && req.method === 'GET') return handleCheck(req, res);
  if (path === '/api/scan' && req.method === 'POST') return handleScan(req, res);
  if (path === '/api/patch' && req.method === 'POST') return handlePatch(req, res);
  if (path === '/api/rescan' && req.method === 'POST') return handleRescan(req, res);
  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res);
  res.writeHead(405).end();
});

server.requestTimeout = 0; // scans of large repos can take a few minutes
server.listen(PORT, () => console.log(`Owl ${BUILD} listening on :${PORT} (AI review ${aiAvailable() ? 'enabled' : 'disabled'}, patch agent ${aiAvailable() ? patchModel() : 'disabled'})`));

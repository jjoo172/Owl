import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { analyze } from './analyze.js';
import { aiAvailable } from './ai.js';

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

let active = 0;
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
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream', 'Cache-Control': 'public, max-age=300' });
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
  const { repo, ref, ai = true } = input;
  const useAi = Boolean(ai) && aiAvailable();
  const send = (obj) => res.write(JSON.stringify(obj) + '\n');
  const key = `${String(repo).toLowerCase().trim()}@${ref || ''}@${useAi}`;

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
    const data = await analyze(repo, { ref, ai: useAi, onProgress: (message) => send({ type: 'progress', message }) });
    cache.set(key, { at: Date.now(), data });
    if (cache.size > 50) cache.delete(cache.keys().next().value);
    send({ type: 'result', data });
  } catch (err) {
    console.error('scan failed', repo, err);
    send({ type: 'error', message: err.status ? err.message : 'Something went wrong while scanning that repository.' });
  } finally {
    clearInterval(heartbeat);
    active--;
    res.end();
  }
}

const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  if (path === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, ai: aiAvailable() }));
  }
  if (path === '/api/scan' && req.method === 'POST') return handleScan(req, res);
  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res);
  res.writeHead(405).end();
});

server.requestTimeout = 0; // scans of large repos can take a few minutes
server.listen(PORT, () => console.log(`Owl listening on :${PORT} (AI review ${aiAvailable() ? 'enabled' : 'disabled'})`));

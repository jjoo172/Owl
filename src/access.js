// Step 1: confirm a repository is readable before any scanning starts.
// Every check reports pass / warn / fail with a human-readable reason, and the
// result pins the exact commit that step 2 will scan.

import { parseRepoInput, codeloadUrl } from './github.js';
import { aiAvailable, DEFAULT_MODEL, SOURCE_BUDGET } from './ai.js';

export const modelLabel = (id = process.env.ANTHROPIC_MODEL || DEFAULT_MODEL) =>
  id.replace(/^claude-/, '').replace(/-(\d+)-(\d+)(?:-\d{8})?$/, ' $1.$2').replace(/^\w/, (c) => 'Claude ' + c.toUpperCase());

const MAX_TARBALL_MB = Number(process.env.MAX_TARBALL_MB || 300);
const C_FAMILY = ['C', 'C++', 'Objective-C++', 'Cuda'];

function ghHeaders(extra = {}) {
  const h = { 'User-Agent': 'owl-scanner', Accept: 'application/vnd.github+json', ...extra };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

/** GitHub API GET that turns transport and HTTP failures into readable messages. */
async function gh(path, accept) {
  let res;
  try {
    res = await fetch(`https://api.github.com${path}`, {
      headers: ghHeaders(accept ? { Accept: accept } : {}),
      signal: AbortSignal.timeout(15_000),
    });
  } catch (err) {
    return { ok: false, status: 0, problem: `The server could not reach GitHub (${err.name === 'TimeoutError' ? 'timed out' : err.message}).` };
  }
  if (res.ok) return { ok: true, status: res.status, res };
  const remaining = res.headers.get('x-ratelimit-remaining');
  if (res.status === 429 || (res.status === 403 && remaining === '0')) {
    const reset = Number(res.headers.get('x-ratelimit-reset')) * 1000;
    const mins = reset ? Math.max(1, Math.ceil((reset - Date.now()) / 60000)) : null;
    return {
      ok: false,
      status: res.status,
      problem: `GitHub's API rate limit for this server is used up${mins ? `; it resets in about ${mins} min` : ''}. Setting GITHUB_TOKEN on the server raises the limit from 60 to 5,000 requests per hour.`,
    };
  }
  return { ok: false, status: res.status, problem: null };
}

/**
 * Runs the access checks. Returns { canScan, checks, target, info }.
 * `target` ({ owner, repo, ref, sha }) is what step 2 should scan.
 */
export async function checkRepository(input, refOverride) {
  const checks = [];
  const add = (id, label, status, detail) => checks.push({ id, label, status, detail });
  const done = (extra = {}) => ({ canScan: !checks.some((c) => c.status === 'fail'), checks, ...extra });

  // 1. Input is a GitHub repository reference
  let parsed;
  try {
    parsed = parseRepoInput(input, refOverride);
    add('input', 'Repository address', 'pass', `${parsed.owner}/${parsed.repo}${parsed.ref ? ` @ ${parsed.ref}` : ''}`);
  } catch (err) {
    add('input', 'Repository address', 'fail', err.message);
    return done();
  }
  const { owner, repo } = parsed;

  // 2. Repository exists and is publicly readable
  const meta = await gh(`/repos/${owner}/${repo}`);
  if (!meta.ok) {
    add(
      'exists',
      'Repository is public and reachable',
      'fail',
      meta.problem || (meta.status === 404 ? `GitHub has no public repository called ${owner}/${repo}. Check the spelling, or it may be private.` : `GitHub answered HTTP ${meta.status}.`),
    );
    return done();
  }
  const info = await meta.res.json();
  const canonical = { owner: info.owner?.login || owner, repo: info.name || repo };
  if (info.private) {
    add('exists', 'Repository is public and reachable', 'fail', 'This repository is private; Owl can only scan public repositories.');
    return done();
  }
  add('exists', 'Repository is public and reachable', 'pass', `${info.full_name}${info.archived ? ' (archived)' : ''}`);

  // 3. Branch / tag / commit resolves to a commit
  const ref = parsed.ref || info.default_branch;
  const commit = await gh(`/repos/${canonical.owner}/${canonical.repo}/commits/${encodeURIComponent(ref)}`, 'application/vnd.github.sha');
  let sha = null;
  if (commit.ok) sha = (await commit.res.text()).trim();
  if (!sha || !/^[0-9a-f]{40}$/.test(sha)) {
    add(
      'ref',
      'Branch / tag / commit exists',
      'fail',
      commit.problem || (commit.status === 404 || commit.status === 422 ? `“${ref}” is not a branch, tag or commit in ${info.full_name}.` : `Could not resolve “${ref}” (HTTP ${commit.status}).`),
    );
    return done({ info: summarize(info) });
  }
  add('ref', 'Branch / tag / commit exists', 'pass', `${ref}${parsed.ref ? '' : ' (default branch)'} → ${sha.slice(0, 10)}`);

  // 4. Contains C/C++ source (GitHub's language breakdown; informational)
  const langs = await gh(`/repos/${canonical.owner}/${canonical.repo}/languages`);
  let languages = null;
  if (langs.ok) {
    languages = await langs.res.json();
    const total = Object.values(languages).reduce((a, b) => a + b, 0) || 1;
    const cBytes = C_FAMILY.reduce((s, l) => s + (languages[l] || 0), 0);
    const share = Math.round((100 * cBytes) / total);
    if (cBytes === 0) add('language', 'Contains C/C++ source', 'warn', 'GitHub detects no C or C++ in this repository, so the scan will likely find nothing to analyse.');
    else add('language', 'Contains C/C++ source', 'pass', `${share}% C/C++ by size (${C_FAMILY.filter((l) => languages[l]).join(', ')})`);
    // Forecast whether Claude can read it all (GitHub's byte count includes tests, so this is approximate).
    if (cBytes > 0 && aiAvailable()) {
      if (cBytes <= SOURCE_BUDGET) add('coverage', 'Review coverage', 'pass', 'Small enough for Claude to review the whole codebase');
      else {
        const pct = Math.max(0.1, Math.round((1000 * SOURCE_BUDGET) / cBytes) / 10);
        add('coverage', 'Review coverage', 'warn',
          `Expect a partial scan: about ${pct}% of this repository's ${cBytes >= 1e6 ? `${(cBytes / 1e6).toFixed(cBytes >= 1e7 ? 0 : 1)} MB` : `${Math.round(cBytes / 1e3)} KB`} of C/C++ fits in one review, so Claude will read the riskiest files first`);
      }
    }
  } else {
    add('language', 'Contains C/C++ source', 'warn', langs.problem || 'Could not read the language breakdown; continuing anyway.');
  }

  // 5. Size is within what the server will download
  const sizeMb = Math.round((info.size || 0) / 1024);
  if (sizeMb > MAX_TARBALL_MB * 3) {
    add('size', 'Size within limits', 'fail', `About ${sizeMb.toLocaleString()} MB on GitHub — far over this server's ${MAX_TARBALL_MB} MB download limit.`);
    return done({ info: summarize(info, languages) });
  }
  add('size', 'Size within limits', sizeMb > MAX_TARBALL_MB ? 'warn' : 'pass',
    sizeMb > MAX_TARBALL_MB
      ? `About ${sizeMb.toLocaleString()} MB on GitHub (including history); the source archive may still exceed the ${MAX_TARBALL_MB} MB limit.`
      : `About ${Math.max(1, sizeMb).toLocaleString()} MB on GitHub`);

  // 6. The source archive for that commit actually downloads
  const archive = await probeArchive(canonical.owner, canonical.repo, sha);
  add('archive', 'Source archive downloads', archive.ok ? 'pass' : 'fail', archive.detail);

  // 7. Which scan tier this server can provide (never blocks scanning)
  add('ai', 'Scan tier', aiAvailable() ? 'pass' : 'warn',
    aiAvailable() ? `Full review by ${modelLabel()}` : "Basic scan only — Claude review isn't configured on this server (ANTHROPIC_API_KEY not set)");

  return done({ target: { ...canonical, ref, sha }, info: summarize(info, languages) });
}

function summarize(info, languages = null) {
  return {
    fullName: info.full_name,
    description: info.description,
    htmlUrl: info.html_url,
    defaultBranch: info.default_branch,
    stars: info.stargazers_count,
    pushedAt: info.pushed_at,
    archived: info.archived,
    languages,
  };
}

/** Fetches just the first bytes of the archive to prove it is downloadable gzip. */
async function probeArchive(owner, repo, sha) {
  const started = Date.now();
  let res;
  try {
    res = await fetch(codeloadUrl(owner, repo, sha), { headers: { 'User-Agent': 'owl-scanner' }, signal: AbortSignal.timeout(30_000) });
  } catch (err) {
    return { ok: false, detail: `Could not download the archive (${err.name === 'TimeoutError' ? 'timed out' : err.message}).` };
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    return { ok: false, detail: `GitHub answered HTTP ${res.status} for the source archive.` };
  }
  try {
    const reader = res.body.getReader();
    const { value } = await reader.read();
    await reader.cancel().catch(() => {});
    if (!value || value[0] !== 0x1f || value[1] !== 0x8b) return { ok: false, detail: 'The archive GitHub returned is not a gzip file.' };
  } catch (err) {
    return { ok: false, detail: `The archive download broke off (${err.message}).` };
  }
  return { ok: true, detail: `Readable (${Date.now() - started} ms to first byte)` };
}

import { Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';
import { readTar } from './tar.js';

export const SOURCE_EXTENSIONS = new Set([
  '.c', '.cc', '.cpp', '.cxx', '.c++', '.cp',
  '.h', '.hh', '.hpp', '.hxx', '.h++', '.inl', '.ipp', '.tpp', '.tcc',
  '.ixx', '.cppm', '.mm',
]);

const MAX_FILE_BYTES = 1024 * 1024; // skip generated/amalgamated files over 1 MB
const MAX_TARBALL_BYTES = Number(process.env.MAX_TARBALL_MB || 300) * 1024 * 1024;
const MAX_SOURCE_FILES = Number(process.env.MAX_SOURCE_FILES || 25000);

export class UserError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

/** Accepts owner/repo, a github.com URL (optionally /tree/<ref>), or a .git URL. */
export function parseRepoInput(input, refOverride) {
  const raw = String(input || '').trim();
  let owner, repo, ref;
  const url = raw.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+)\/([^/\s#?]+)(?:\/(?:tree|blob|commit)\/([^\s#?]+))?/i);
  const short = raw.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (url) [, owner, repo, ref] = url;
  else if (short) [, owner, repo] = short;
  else throw new UserError('Enter a GitHub repository as owner/repo or a github.com URL.');
  repo = repo.replace(/\.git$/i, '');
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) throw new UserError('That does not look like a valid GitHub repository.');
  ref = (refOverride || ref || '').trim() || undefined;
  if (ref && !/^[\w./-]+$/.test(ref)) throw new UserError('Invalid branch, tag or commit.');
  return { owner, repo, ref };
}

/** Direct archive URL for a commit (not counted against GitHub's API rate limit). */
export function codeloadUrl(owner, repo, sha) {
  return `https://codeload.github.com/${owner}/${repo}/tar.gz/${sha}`;
}

/** Reads C/C++ source files from a local checkout (used by the CLI's --dir mode). */
export async function readLocalSourceFiles(dir) {
  const { readdir, readFile, stat } = await import('node:fs/promises');
  const { join, relative } = await import('node:path');
  const files = [];
  const stats = { totalFiles: 0, skippedLarge: [], truncated: false };
  const walk = async (d) => {
    for (const ent of await readdir(d, { withFileTypes: true })) {
      if (ent.name === '.git' || ent.name === 'node_modules') continue;
      const full = join(d, ent.name);
      if (ent.isDirectory()) await walk(full);
      else if (ent.isFile()) {
        stats.totalFiles++;
        const path = relative(dir, full).split('\\').join('/');
        if (!SOURCE_EXTENSIONS.has(extOf(path))) continue;
        if ((await stat(full)).size > MAX_FILE_BYTES) {
          stats.skippedLarge.push(path);
          continue;
        }
        const buf = await readFile(full);
        if (!buf.subarray(0, 8000).includes(0)) files.push({ path, content: buf.toString('utf8') });
      }
    }
  };
  await walk(dir);
  return { files, stats, sha: null, downloadedBytes: 0 };
}

function extOf(path) {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  return dot < 0 ? '' : base.slice(dot).toLowerCase();
}

/**
 * Streams the source archive for one commit (as confirmed by the access check)
 * and returns only C/C++ source files. Docs, build scripts and other text files
 * are ignored by design.
 */
export async function fetchSourceFiles({ owner, repo, sha }) {
  if (!/^[0-9a-f]{40}$/.test(sha || '')) throw new UserError('Missing or invalid commit — run the access check first.', 400);
  let res;
  try {
    res = await fetch(codeloadUrl(owner, repo, sha), { headers: { 'User-Agent': 'owl-scanner' } });
  } catch (err) {
    throw new UserError(`Could not download the repository from GitHub (${err.message}).`, 502);
  }
  if (res.status === 404) throw new UserError(`Commit ${sha.slice(0, 10)} of ${owner}/${repo} is no longer available.`, 404);
  if (res.status === 429 || (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0')) {
    throw new UserError('GitHub rate limit reached. Try again later, or set GITHUB_TOKEN on the server.', 429);
  }
  if (res.status === 403) throw new UserError(`GitHub refused access to ${owner}/${repo} (403).`, 403);
  if (!res.ok) throw new UserError(`GitHub returned ${res.status} while downloading the repository.`, 502);

  const files = [];
  const stats = { totalFiles: 0, skippedLarge: [], truncated: false };
  let downloaded = 0;

  const body = Readable.fromWeb(res.body);
  const gunzip = createGunzip();
  body.on('data', (chunk) => {
    downloaded += chunk.length;
    if (downloaded > MAX_TARBALL_BYTES) {
      const err = new UserError(`Repository archive is larger than ${MAX_TARBALL_BYTES / 1024 / 1024} MB; too big to scan here.`, 413);
      body.destroy();
      gunzip.destroy(err);
    }
  });
  body.on('error', (err) => gunzip.destroy(err));
  body.pipe(gunzip);

  // Archive entries are "<owner>-<repo>-<shortsha>/path/to/file".
  const rel = (name) => {
    const slash = name.indexOf('/');
    return slash < 0 ? '' : name.slice(slash + 1);
  };

  const globalPax = await readTar(gunzip, {
    want: (h) => {
      const path = rel(h.name);
      if (!path) return false;
      stats.totalFiles++;
      if (!SOURCE_EXTENSIONS.has(extOf(path))) return false;
      if (h.size > MAX_FILE_BYTES) {
        stats.skippedLarge.push(path);
        return false;
      }
      if (files.length >= MAX_SOURCE_FILES) {
        stats.truncated = true;
        return false;
      }
      return true;
    },
    onFile: (h, buf) => {
      // Skip binary blobs that happen to use a source extension.
      if (!buf.subarray(0, 8000).includes(0)) files.push({ path: rel(h.name), content: buf.toString('utf8') });
    },
  });

  return { files, stats, sha: /^[0-9a-f]{40}$/.test(globalPax.comment || '') ? globalPax.comment : sha, downloadedBytes: downloaded };
}

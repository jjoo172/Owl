import { basename, resolve } from 'node:path';
import { fetchSourceFiles, readLocalSourceFiles, UserError } from './github.js';
import { scanRepository } from './scanner.js';
import { aiAvailable, aiReview } from './ai.js';

/**
 * Step 2: download the confirmed commit → scan source → (optional) expert review.
 * `target` is { owner, repo, ref, sha } from the access check (step 1).
 * Pass `dir` instead to scan a local checkout.
 */
export async function analyze(target, { dir, ai = true, onProgress = () => {} } = {}) {
  const repo = dir ? { owner: 'local', repo: basename(resolve(dir)), ref: undefined, sha: null } : target;
  if (!dir && !repo?.sha) throw new UserError('Run the access check before scanning.', 400);
  const started = Date.now();

  onProgress(dir ? 'Reading local files' : `Downloading ${repo.owner}/${repo.repo} @ ${repo.sha.slice(0, 10)}`);
  const { files, stats: fetchStats, sha, downloadedBytes } = dir ? await readLocalSourceFiles(dir) : await fetchSourceFiles(repo);

  onProgress(`Scanning ${files.length.toLocaleString()} source files`);
  const report = scanRepository(files);
  const { _contentByPath, _allFindings, ...publicReport } = report;

  let aiResult = null;
  let aiError = null;
  if (ai && aiAvailable() && files.length) {
    onProgress('Expert review with Claude');
    try {
      aiResult = await aiReview({ repo, report: publicReport, allFindings: _allFindings, contentByPath: _contentByPath });
    } catch (err) {
      aiError = err.name === 'AbortError' ? 'AI review timed out.' : `AI review failed: ${err.message}`;
    }
  }

  return {
    repo: {
      owner: repo.owner,
      name: repo.repo,
      ref: repo.ref || null,
      sha,
      url: dir ? null : `https://github.com/${repo.owner}/${repo.repo}`,
      blobBase: dir ? null : `https://github.com/${repo.owner}/${repo.repo}/blob/${sha}/`,
    },
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    archive: {
      totalFiles: fetchStats.totalFiles,
      ignoredNonSourceFiles: fetchStats.totalFiles - files.length - fetchStats.skippedLarge.length,
      skippedLargeFiles: fetchStats.skippedLarge,
      truncated: fetchStats.truncated,
      downloadedBytes,
    },
    ...publicReport,
    ai: aiResult,
    aiError,
    aiEnabled: aiAvailable(),
  };
}

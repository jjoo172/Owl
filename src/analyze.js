import { basename, resolve } from 'node:path';
import { fetchSourceFiles, parseRepoInput, readLocalSourceFiles } from './github.js';
import { scanRepository } from './scanner.js';
import { aiAvailable, aiReview } from './ai.js';

/**
 * Full pipeline: download → scan source → (optional) expert AI review.
 * Pass `dir` to scan a local checkout instead of downloading from GitHub.
 */
export async function analyze(repoInput, { ref, dir, ai = true, onProgress = () => {} } = {}) {
  const repo = dir
    ? { owner: 'local', repo: basename(resolve(dir)), ref: undefined }
    : parseRepoInput(repoInput, ref);
  const started = Date.now();

  onProgress(dir ? 'Reading local files' : 'Downloading repository');
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
      blobBase: dir ? null : `https://github.com/${repo.owner}/${repo.repo}/blob/${sha || repo.ref || 'HEAD'}/`,
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

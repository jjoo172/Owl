import { basename, resolve } from 'node:path';
import { fetchSourceFiles, readLocalSourceFiles, UserError } from './github.js';
import { scanRepository } from './scanner.js';
import { aiAvailable, aiReview } from './ai.js';
import { mergeReview } from './merge.js';
import { BudgetExceededError } from './budget.js';

/**
 * Step 2: download the confirmed commit → scan source → (optional) expert review.
 * `target` is { owner, repo, ref, sha } from the access check (step 1).
 * Pass `dir` instead to scan a local checkout.
 */
export async function analyze(target, { dir, ai = true, budget, onProgress = () => {} } = {}) {
  const repo = dir ? { owner: 'local', repo: basename(resolve(dir)), ref: undefined, sha: null } : target;
  if (!dir && !repo?.sha) throw new UserError('Run the access check before scanning.', 400);
  const started = Date.now();

  onProgress(dir ? 'Reading local files' : `Downloading ${repo.owner}/${repo.repo} @ ${repo.sha.slice(0, 10)}`);
  const { files, stats: fetchStats, sha, downloadedBytes } = dir ? await readLocalSourceFiles(dir) : await fetchSourceFiles(repo);

  onProgress(`Scanning ${files.length.toLocaleString()} source files`);
  const report = scanRepository(files);
  const { _contentByPath, _allFindings, ...publicReport } = report;

  let results = publicReport;
  let aiResult = null;
  let aiError = null;
  if (ai && aiAvailable() && files.length) {
    onProgress('Expert review with Claude');
    try {
      const review = await aiReview({ budget, repo, report: publicReport, allFindings: _allFindings, contentByPath: _contentByPath });
      const merged = mergeReview({ report: publicReport, allFindings: _allFindings, contentByPath: _contentByPath, ai: review });
      aiResult = merged.ai;
      results = { ...publicReport, stats: merged.stats, ruleSummary: merged.ruleSummary, hotspots: merged.hotspots, findings: merged.findings };
    } catch (err) {
      aiError =
        err instanceof BudgetExceededError ? err.message : err.name === 'AbortError' ? 'AI review timed out.' : `AI review failed: ${err.message}`;
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
    ...results,
    ai: aiResult,
    aiError,
    aiEnabled: aiAvailable(),
  };
}

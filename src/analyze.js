import { basename, resolve } from 'node:path';
import { fetchSourceFiles, readLocalSourceFiles, UserError } from './github.js';
import { scanRepository, summarizeFiles } from './scanner.js';
import { aiAvailable, aiReview, ReviewUnavailableError } from './ai.js';
import { claudeResults } from './results.js';
import { BudgetExceededError } from './budget.js';

/**
 * Step 2: download the confirmed commit → Claude reviews the source (full review),
 * or, if Claude can't run, a pattern scan (basic scan).
 * `target` is { owner, repo, ref, sha } from the access check (step 1).
 * Pass `dir` instead to scan a local checkout.
 */
export async function analyze(target, { dir, ai = true, budget, onProgress = () => {} } = {}) {
  const repo = dir ? { owner: 'local', repo: basename(resolve(dir)), ref: undefined, sha: null } : target;
  if (!dir && !repo?.sha) throw new UserError('Run the access check before scanning.', 400);
  const started = Date.now();

  onProgress(dir ? 'Reading local files' : `Downloading ${repo.owner}/${repo.repo} @ ${repo.sha.slice(0, 10)}`);
  const { files, stats: fetchStats, sha, downloadedBytes } = dir ? await readLocalSourceFiles(dir) : await fetchSourceFiles(repo);

  const contentByPath = new Map(files.map((f) => [f.path, f.content]));
  const fileStats = summarizeFiles(files);

  // Full review: Claude reads the source. The pattern scanner runs only if Claude can't.
  let results = null;
  let aiResult = null;
  let tier = 'basic';
  let tierReason = null;
  if (!ai) tierReason = 'Claude review was turned off for this scan';
  else if (!aiAvailable()) tierReason = "Claude review isn't configured on this server";
  else if (!files.length) tierReason = 'There is no C/C++ source for Claude to review';
  else {
    onProgress(`Claude is reviewing ${files.length.toLocaleString()} source file${files.length === 1 ? '' : 's'}`);
    try {
      const { review, meta } = await aiReview({ budget, repo, contentByPath });
      const built = claudeResults({ review, meta, contentByPath, fileStats });
      aiResult = built.ai;
      results = { stats: built.stats, risk: built.risk, ruleSummary: built.ruleSummary, hotspots: built.hotspots, findings: built.findings };
      tier = 'full';
    } catch (err) {
      if (err instanceof BudgetExceededError || err instanceof ReviewUnavailableError) tierReason = err.message.replace(/ Showing scanner results only\.$/, '').replace(/\.$/, '');
      else {
        console.error('Claude review failed', err);
        tierReason = "Claude's review failed unexpectedly";
      }
    }
  }

  if (!results) {
    onProgress(`Running a basic pattern scan of ${files.length.toLocaleString()} source files`);
    const { _contentByPath, _allFindings, ...report } = scanRepository(files);
    results = report;
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
    tier,
    tierReason,
    ai: aiResult,
    aiEnabled: aiAvailable(),
  };
}

import { basename, resolve } from 'node:path';
import { fetchSourceFiles, readLocalSourceFiles, UserError } from './github.js';
import { scanRepository, summarizeFiles } from './scanner.js';
import { aiAvailable, aiReview, ReviewUnavailableError } from './ai.js';
import { claudeResults } from './results.js';
import { applyPatch } from './applypatch.js';
import { BudgetExceededError } from './budget.js';

/**
 * Step 2: download the confirmed commit → Claude reviews the source (full review),
 * or, if Claude can't run, a pattern scan (basic scan).
 * `target` is { owner, repo, ref, sha } from the access check (step 1).
 * Pass `dir` instead to scan a local checkout.
 */
export async function analyze(target, { dir, ai = true, budget, patchText, onProgress = () => {} } = {}) {
  const repo = dir ? { owner: 'local', repo: basename(resolve(dir)), ref: undefined, sha: null } : target;
  if (!dir && !repo?.sha) throw new UserError('Run the access check before scanning.', 400);
  const started = Date.now();

  onProgress(dir ? 'Reading local files' : `Downloading ${repo.owner}/${repo.repo} @ ${repo.sha.slice(0, 10)}`);
  const { files, stats: fetchStats, sha, downloadedBytes } = dir ? await readLocalSourceFiles(dir) : await fetchSourceFiles(repo);

  let contentByPath = new Map(files.map((f) => [f.path, f.content]));
  let selectionFrom;
  let patched = null;
  if (patchText) {
    // Re-scan: apply the patches, then review the patched code exactly as the original was reviewed.
    onProgress('Applying the patches');
    const applied = applyPatch(contentByPath, patchText);
    selectionFrom = contentByPath; // same files as the original scan
    contentByPath = applied.files;
    for (const f of files) f.content = contentByPath.get(f.path);
    patched = { changedFiles: applied.changed, lineMaps: applied.lineMaps, addedLines: applied.addedLines };
  }
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
      const { review, meta } = await aiReview({ budget, repo, contentByPath, selectionFrom });
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

  const coverage = buildCoverage({ tier, aiCoverage: aiResult?.coverage, files, fetchStats });
  if (aiResult?.coverage) delete aiResult.coverage.skipped; // listed once, in coverage.notReviewed

  const result = {
    coverage,
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
    patchedFiles: patched ? patched.changedFiles : undefined,
    ai: aiResult,
    aiEnabled: aiAvailable(),
  };
  // Old->new line maps for a re-scan; not enumerable, so they never go into the JSON response.
  if (patched) {
    Object.defineProperty(result, 'lineMaps', { value: patched.lineMaps, enumerable: false });
    Object.defineProperty(result, 'addedLines', { value: patched.addedLines, enumerable: false });
  }
  return result;
}

/**
 * What share of the repository's C/C++ the results actually cover, and why anything was left out.
 * `complete: false` = a partial scan; the UI says so prominently.
 */
export function buildCoverage({ tier, aiCoverage, files, fetchStats }) {
  const reasons = [];
  const notReviewed = [];
  let reviewedFiles;
  let totalFiles;
  let reviewedChars;
  let totalChars;

  if (tier === 'full' && aiCoverage) {
    reviewedFiles = aiCoverage.filesInFull;
    totalFiles = aiCoverage.totalFiles;
    reviewedChars = aiCoverage.reviewedChars ?? 0;
    totalChars = aiCoverage.totalChars ?? 0;
    for (const path of aiCoverage.skipped || []) notReviewed.push({ path, why: 'did not fit in the review' });
    if ((aiCoverage.skipped || []).length) {
      reasons.push(`The repository is too large for one review, so Claude read the ${reviewedFiles.toLocaleString()} riskiest of ${totalFiles.toLocaleString()} source files`);
    }
  } else {
    reviewedFiles = totalFiles = files.length;
    reviewedChars = totalChars = files.reduce((n, f) => n + f.content.length, 0);
  }

  const large = fetchStats.skippedLarge || [];
  if (large.length) {
    totalFiles += large.length;
    for (const path of large) notReviewed.push({ path, why: 'over 1 MB (usually generated code)' });
    reasons.push(`${large.length.toLocaleString()} file${large.length === 1 ? ' was' : 's were'} skipped for being over 1 MB`);
  }
  if (fetchStats.truncated) reasons.push("The repository has more source files than this server reads, so the rest weren't read at all");

  const percent = totalChars ? Math.max(0.1, Math.round((1000 * reviewedChars) / totalChars) / 10) : 100;
  return {
    complete: reasons.length === 0,
    reviewedFiles,
    totalFiles,
    percent: reasons.length === 0 ? 100 : Math.min(percent, 99.9),
    reasons,
    notReviewed,
  };
}

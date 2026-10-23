#!/usr/bin/env node
// Usage: node src/cli.js <owner/repo | github url> [--ref <branch|tag|sha>] [--no-ai] [--json] [--check-only] [--patch [--out <file>]]
//        node src/cli.js --dir <path to local checkout> [--no-ai] [--json]
import { analyze } from './analyze.js';
import { checkRepository } from './access.js';
import { writeFileSync } from 'node:fs';
import { fetchSourceFiles, readLocalSourceFiles } from './github.js';
import { runPatchAgent } from './patcher.js';

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const repo = args.find((a, i) => !a.startsWith('--') && !['--ref', '--dir'].includes(args[i - 1]));
const dir = opt('--dir');
const json = flag('--json');
const log = (m) => !json && console.error(m);

if (!repo && !dir) {
  console.error('Usage: node src/cli.js <owner/repo> [--ref <ref>] [--no-ai] [--json] [--check-only]\n       node src/cli.js --dir <path> [--no-ai] [--json]');
  process.exit(1);
}

let target;
if (!dir) {
  // Step 1: access check
  log('Step 1 — access check');
  const check = await checkRepository(repo, opt('--ref'));
  const icon = { pass: '✓', warn: '!', fail: '✗' };
  for (const c of check.checks) log(`  ${icon[c.status]} ${c.label}: ${c.detail}`);
  if (flag('--check-only') || !check.canScan) {
    if (json) console.log(JSON.stringify(check, null, 2));
    process.exit(check.canScan ? 0 : 2);
  }
  target = check.target;
  log('Step 2 — scan');
}

const result = await analyze(target, { dir, ai: !flag('--no-ai'), onProgress: (m) => log(`  … ${m}`) });

if (json) {
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}

const { stats, risk, findings, ai } = result;
console.log(`\n${result.repo.owner}/${result.repo.name} @ ${result.repo.sha || 'local'}`);
console.log(`Source files: ${stats.sourceFiles}  Lines: ${stats.loc}  Findings: ${stats.totalFindings}`);
if (result.tier === 'full') {
  console.log(`Full review (${ai.model}${typeof ai.costUsd === 'number' ? `, $${ai.costUsd.toFixed(4)}` : ''}): ${ai.overall_risk} risk\n\n${ai.summary}\n`);
} else {
  console.log(`BASIC SCAN (pattern matching only) — ${result.tierReason}.`);
  console.log(`Rating: ${risk.level} (score ${risk.score}/100) — a lower bound`);
  risk.rationale.forEach((r) => console.log(`  - ${r}`));
  console.log('');
}
for (const f of findings.filter((x) => result.tier === 'full' || x.severity !== 'low').slice(0, 60)) {
  const what = f.title || f.ruleId;
  console.log(`  [${f.severity.padEnd(8)}] ${`${f.file}:${f.line}`.padEnd(32)} ${what}`);
}

// Opt-in: the security engineer agent proposes patches for the vulnerabilities found.
if (flag('--patch')) {
  const sevs = ['critical', 'high', 'medium', 'low'];
  const wanted = findings.filter((f) => f.kind !== 'test' && f.line > 0);
  if (!wanted.length) {
    console.log('\nNothing to patch.');
  } else {
    console.log(`\nProposing patches for ${wanted.length} vulnerabilit${wanted.length === 1 ? 'y' : 'ies'}…`);
    const { files } = dir ? await readLocalSourceFiles(dir) : await fetchSourceFiles(target);
    const rules = Object.fromEntries(result.ruleSummary.map((r) => [r.ruleId, r]));
    const r = await runPatchAgent({
      repo: { owner: result.repo.owner, repo: result.repo.name, sha: result.repo.sha || 'local' },
      contentByPath: new Map(files.map((f) => [f.path, f.content])),
      rawFindings: wanted
        .sort((a, b) => sevs.indexOf(a.severity) - sevs.indexOf(b.severity))
        .map((f) => ({ ...f, title: f.title || rules[f.ruleId]?.title, detail: f.detail || rules[f.ruleId]?.description })),
      onProgress: (ev) => ['patch', 'skip', 'retry'].includes(ev.kind) && console.error(`  … ${ev.message}`),
    });
    for (const p of r.patches) console.log(`  ${p.id} ${p.file} (+${p.added} −${p.removed}): ${p.explanation}`);
    for (const sk of r.skipped) console.log(`  not patched ${sk.findingId}: ${sk.reason}`);
    if (r.stoppedReason) console.log(`  stopped early: ${r.stoppedReason}`);
    if (r.patchFile) {
      const out = opt('--out') || 'owl-patches.patch';
      writeFileSync(out, r.patchFile);
      console.log(`\nWrote ${out} — review it, then: git apply --check ${out} && git apply ${out}`);
    }
  }
}

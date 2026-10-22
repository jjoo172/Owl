#!/usr/bin/env node
// Usage: node src/cli.js <owner/repo | github url> [--ref <branch|tag|sha>] [--no-ai] [--json] [--check-only]
//        node src/cli.js --dir <path to local checkout> [--no-ai] [--json]
import { analyze } from './analyze.js';
import { checkRepository } from './access.js';

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

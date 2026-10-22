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

const { stats, risk, ruleSummary, hotspots, ai } = result;
console.log(`\n${result.repo.owner}/${result.repo.name} @ ${result.repo.sha}`);
console.log(`Source files: ${stats.sourceFiles}  Lines: ${stats.loc}  Findings: ${stats.totalFindings}`);
console.log(`Scanner risk: ${risk.level} (score ${risk.score}/100, density ${risk.density}/KLOC)`);
risk.rationale.forEach((r) => console.log(`  - ${r}`));
console.log('\nRule hits:');
for (const r of ruleSummary) console.log(`  [${r.severity.padEnd(8)}] ${String(r.count).padStart(5)}  ${r.title}`);
console.log('\nHotspots:');
for (const h of hotspots.slice(0, 8)) console.log(`  ${String(h.weighted).padStart(7)}  ${h.file}${h.kind !== 'production' ? ` (${h.kind})` : ''}`);
if (ai) {
  console.log(`\nAI review (${ai.model}): ${ai.overall_risk}\n${ai.summary}`);
} else {
  console.log(`\nBasic scan (pattern matching only): ${result.tierReason}.`);
}

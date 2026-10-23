#!/usr/bin/env node
// Parses an Owl run log (JSON lines, from /api/runs/<id>) into a readable report.
//
//   node src/logview.js owl-rescan-….jsonl              readable report
//   node src/logview.js https://…/api/runs/<id>          fetch and report
//   node src/logview.js run.jsonl --event match          only those events, one JSON object per line
//   node src/logview.js run.jsonl --events               list event names with counts
//   cat run.jsonl | node src/logview.js -                read stdin

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

/** Splits a run log into { header, events, end }. Tolerates blank or broken lines. */
export function parseRun(text) {
  let header = null;
  let end = null;
  const events = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }
    if (obj.type === 'run') header = obj;
    else if (obj.type === 'end') end = obj;
    else if (obj.type === 'event') events.push(obj);
  }
  return { header, events, end };
}

const secs = (ms) => `${(ms / 1000).toFixed(1)}s`;
const usd = (n) => (typeof n === 'number' ? `$${n < 0.01 ? n.toFixed(4) : n.toFixed(2)}` : '—');
const loc = (f) => `${f.file}${f.line ? ':' + f.line : ''}`;
const sev = (s) => (s || '?').toUpperCase().padEnd(8);
const one = (s, n = 140) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
};
const tokens = (u = {}) =>
  `in ${u.input_tokens ?? 0}${u.cache_read_input_tokens ? ` (+${u.cache_read_input_tokens} cached)` : ''}${u.cache_creation_input_tokens ? ` (+${u.cache_creation_input_tokens} cache write)` : ''} · out ${u.output_tokens ?? 0}`;

/** A readable, plain-text report of one run. */
export function formatRun(text) {
  const { header, events, end } = parseRun(text);
  const out = [];
  const h = (title) => out.push('', `== ${title} ${'='.repeat(Math.max(0, 70 - title.length))}`);
  const of = (name) => events.filter((e) => e.event === name);

  if (!header) return 'Not an Owl run log (no header line).\n';
  out.push(`Owl ${header.kind} run ${header.id}`);
  out.push(`started ${header.startedAt}${header.build ? ` · build ${header.build}` : ''}`);
  const inp = header.input || {};
  if (inp.owner) out.push(`repo ${inp.owner}/${inp.repo} @ ${String(inp.sha || '').slice(0, 12)}${inp.ref ? ` (${inp.ref})` : ''}`);
  if (end) {
    out.push(`status ${end.status} after ${secs(end.durationMs)}${end.costUsd !== undefined ? ` · Claude cost ${usd(end.costUsd)}` : ''}${end.droppedEvents ? ` · ${end.droppedEvents} events not kept (log size limit)` : ''}`);
    if (end.message) out.push(`error: ${end.message}`);
  } else out.push('status: still running (no end line yet)');

  // ---- summary ----
  if (end && end.status !== 'error') {
    h('Summary');
    if (header.kind === 'scan') {
      out.push(`${end.tier === 'full' ? 'Full review' : 'Basic scan'}${end.tierReason ? ` (${end.tierReason})` : ''} · risk ${end.level} · ${end.findings} findings ${JSON.stringify(end.bySeverity)} · coverage ${end.coveragePercent}%`);
      if (end.criticalPath) out.push(`critical path: ${end.criticalPath}`);
    } else if (header.kind === 'patch') {
      out.push(`${end.patches} patches · ${end.skipped} skipped · ${end.unaddressed} not reached · ${end.turns} turns · ${end.model}${end.stoppedReason ? ` · stopped: ${end.stoppedReason}` : ''}`);
      if (end.verificationRemaining) out.push(`independent review still flags ${end.verificationRemaining} issue(s) in patched lines`);
    } else if (header.kind === 'rescan') {
      out.push(`risk ${end.before?.level} → ${end.after?.level} · findings ${end.before?.total} → ${end.after?.total}${end.comparable ? '' : ' · NOT like for like'}`);
      if (end.criticalPath) out.push(`critical path: ${end.criticalPath.before ?? '?'} → ${end.criticalPath.after ?? '?'}`);
      out.push(`fixed ${end.fixed} · still present ${end.stillPresent} (${end.stillPresentTargeted} targeted by a patch, ${end.stillPresentNotTargeted} never targeted) · new in patched lines ${end.newInPatchedLines} · new elsewhere ${end.newElsewhere}`);
      if (end.targeted) out.push(`targeted by patches: ${end.targeted.total} · fixed ${end.targeted.fixed} · still present ${end.targeted.stillPresent}`);
    }
  }

  // ---- input files / selection ----
  const dl = of('downloaded')[0];
  if (dl) {
    h('Source');
    out.push(`${dl.sourceFiles} C/C++ files (${dl.sourceChars} chars) of ${dl.archiveFiles} in the archive · ${dl.downloadedBytes} bytes · ${secs(dl.ms)}`);
    if (dl.skippedLarge?.length) out.push(`skipped (over 1 MB): ${dl.skippedLarge.join(', ')}`);
    if (dl.truncated) out.push('file cap reached: some files were not read');
  }
  const applied = of('patch_applied')[0];
  if (applied) {
    out.push(`patch applied to ${applied.changedFiles.length} file(s):`);
    for (const [file, lines] of Object.entries(applied.addedLines || {})) out.push(`  ${file}: wrote lines ${lines.join(', ')}`);
  }

  // ---- Claude calls ----
  const calls = events.filter((e) => /_api_call$/.test(e.event) || e.event === 'agent_turn');
  if (calls.length) {
    h('Claude calls');
    for (const e of calls) {
      const label = e.event === 'agent_turn' ? `agent turn ${e.turn}` : `${e.event.replace(/_api_call$/, '')} (attempt ${e.attempt})`;
      out.push(`+${secs(e.t).padStart(7)}  ${label.padEnd(22)} ${e.error ? `ERROR ${e.error}` : `${e.status ? `HTTP ${e.status} · ` : ''}${secs(e.ms)} · ${e.stopReason} · ${tokens(e.usage)} · ${usd(e.costUsd)}`}`);
    }
  }
  for (const e of events.filter((x) => /_request$/.test(x.event))) {
    out.push(`${e.event.replace(/_request$/, '')}: ${e.model} reviewed ${e.filesInFull}/${e.totalFiles} files (${e.mode}), ${e.promptChars} prompt chars, reserved ${usd(e.reservedUsd)}`);
    if (e.skipped?.length) out.push(`  not in the review: ${e.skipped.slice(0, 40).join(', ')}${e.skipped.length > 40 ? `, … (${e.skipped.length})` : ''}`);
  }
  for (const e of events.filter((x) => /_ok$/.test(x.event) && x.criticalPath)) {
    out.push(`${e.event.replace(/_ok$/, '')} critical-path verdict: ${e.criticalPath.verdict}`);
    if (e.criticalPath.analysis) out.push(`  ${one(e.criticalPath.analysis, 400)}`);
  }
  for (const e of events.filter((x) => /_unusable$/.test(x.event))) out.push(`${e.event.replace(/_unusable$/, '')} attempt ${e.attempt} unusable: ${e.problem}`);
  const tier = of('tier')[0];
  if (tier && tier.tier !== 'full') out.push(`fell back to a basic scan: ${tier.reason}`);

  // ---- findings ----
  for (const e of of('findings')) {
    h(`Findings (${e.count})`);
    for (const f of e.findings) out.push(`${sev(f.severity)} ${loc(f).padEnd(34)} ${one(f.title, 80)}${f.locationVerified === false ? '  [line not found in source]' : ''}`);
  }

  // ---- patch agent ----
  const start = of('patch_start')[0];
  if (start) {
    h(`Patch agent (${start.model})`);
    out.push(`asked to fix ${start.findings.length}:`);
    for (const f of start.findings) out.push(`  ${f.id.padEnd(4)} ${sev(f.severity)} ${loc(f)}  ${one(f.title, 70)}`);
    if (start.dropped?.length) out.push(`  dropped before the session: ${JSON.stringify(start.dropped)}`);
    out.push('');
    let turn = null;
    for (const e of events) {
      if (e.event === 'agent_turn' && !e.error) {
        turn = e.turn;
        out.push(`turn ${turn}: ${e.toolCalls.length ? e.toolCalls.join(', ') : '(no tool call)'}${e.stopReason === 'max_tokens' ? '  [CUT OFF at max_tokens]' : ''}`);
        if (e.text) out.push(`  says: ${one(e.text, 200)}`);
      } else if (e.event === 'tool_call') {
        const i = e.input || {};
        const what =
          e.name === 'propose_patch' ? `${i.file} for ${(i.finding_ids || []).join(',')} (${(i.edits || []).length} edit(s))`
          : e.name === 'skip_finding' ? `${i.finding_id}: ${one(i.reason, 120)}`
          : e.name === 'read_file' ? `${i.path} ${i.start_line || 1}-${i.end_line || ''}`
          : e.name === 'search_code' ? `"${one(i.text, 60)}"`
          : e.name === 'finish' ? one(i.summary, 120)
          : one(JSON.stringify(i), 120);
        out.push(`  ${e.ok ? 'ok ' : 'ERR'} ${e.name} ${what}${e.ok ? '' : `\n      → ${one(e.result, 220)}`}`);
      } else if (e.event === 'verify_result') {
        out.push(`  verification check ${e.round}: ${e.reviewFindings} finding(s) in ${e.changedFiles.length} changed file(s); ${e.inPatchedLines.length} in lines the agent wrote${e.ignoredElsewhere ? `, ${e.ignoredElsewhere} elsewhere (ignored)` : ''}`);
        for (const f of e.inPatchedLines) out.push(`      ${sev(f.severity)} ${loc(f)}  ${one(f.title, 80)}`);
      }
    }
  }
  const pr = of('patch_result')[0];
  if (pr) {
    out.push('', 'result:');
    for (const p of pr.patches) out.push(`  ${p.id.padEnd(4)} ${p.file} fixes ${p.findingIds.join(',')} (+${p.added} −${p.removed})`);
    for (const s of pr.skipped) out.push(`  skipped ${s.findingId}: ${one(s.reason, 150)}`);
    if (pr.unaddressed.length) out.push(`  never addressed: ${pr.unaddressed.join(', ')}`);
    if (pr.stoppedReason) out.push(`  stopped early: ${pr.stoppedReason}`);
  }

  // ---- comparison ----
  const matches = of('match');
  if (matches.length) {
    h('Matching: original finding → re-scan');
    out.push('Each original finding is matched to a re-scan finding in the same file, within 6 lines of where it');
    out.push('should be after patching and of a similar kind (or on the very same line). Unmatched = fixed.');
    const groups = [
      ['STILL PRESENT, patch targeted it', (m) => m.outcome === 'still_present' && m.targeted],
      ['STILL PRESENT, never targeted by a patch', (m) => m.outcome === 'still_present' && !m.targeted],
      ['FIXED, patch targeted it', (m) => m.outcome === 'fixed' && m.targeted],
      ['FIXED without a patch (not flagged again)', (m) => m.outcome === 'fixed' && !m.targeted],
    ];
    for (const [title, test] of groups) {
      const list = matches.filter(test);
      if (!list.length) continue;
      out.push('', `-- ${title} (${list.length})`);
      for (const m of list) {
        out.push(`${sev(m.before.severity)} ${loc(m.before)}${m.lineMoved ? ` (now ~${m.expectedLine})` : ''}  ${one(m.before.title, 70)}`);
        const chosen = m.candidates.find((c) => c.index === m.matchedTo);
        if (chosen) out.push(`    matched → ${sev(chosen.severity)}${loc(chosen)}  ${one(chosen.title, 60)}  [${chosen.distance} lines away, similarity ${chosen.similarity}]`);
        for (const c of m.candidates.filter((c) => c.index !== m.matchedTo).slice(0, 3)) {
          out.push(`    ${c.rejected ? 'rejected' : 'lower   '} ${loc(c)}  ${one(c.title, 50)}  [${c.rejected || `score ${c.score}`}]`);
        }
      }
    }
    const fresh = of('new_finding');
    if (fresh.length) {
      out.push('', `-- NEW in the re-scan (${fresh.length})`);
      for (const e of fresh) out.push(`${sev(e.after.severity)} ${loc(e.after).padEnd(34)} ${one(e.after.title, 60)}  [${e.where === 'in_patched_lines' ? 'in lines a patch wrote' : 'elsewhere'}]`);
    }
  }

  // ---- timeline ----
  const steps = of('progress');
  if (steps.length) {
    h('Timeline');
    for (const e of steps) out.push(`+${secs(e.t).padStart(7)}  ${e.message}`);
  }
  return out.join('\n') + '\n';
}

// ---- command line ----
async function main(argv) {
  const args = argv.filter((a) => !a.startsWith('--'));
  const flag = (name) => argv.includes(`--${name}`);
  const eventIdx = argv.indexOf('--event');
  const eventName = eventIdx >= 0 ? argv[eventIdx + 1] : null;
  const src = args.find((a) => a !== eventName);
  if (!src) {
    console.error('usage: node src/logview.js <run.jsonl | URL | -> [--event name] [--events]');
    process.exit(2);
  }
  let text;
  if (src === '-') {
    text = '';
    for await (const chunk of process.stdin) text += chunk;
  } else if (/^https?:\/\//.test(src)) {
    const res = await fetch(src.replace(/\?format=text$/, ''));
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    text = await res.text();
  } else text = await readFile(src, 'utf8');

  const run = parseRun(text);
  if (eventName) {
    for (const e of run.events) if (e.event === eventName) console.log(JSON.stringify(e));
  } else if (flag('events')) {
    const counts = {};
    for (const e of run.events) counts[e.event] = (counts[e.event] || 0) + 1;
    for (const [name, n] of Object.entries(counts)) console.log(`${String(n).padStart(5)}  ${name}`);
  } else process.stdout.write(formatRun(text));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}

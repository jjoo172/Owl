// Structured run logs: one per scan, patch session and re-scan.
//
// A run log is newline-delimited JSON:
//   {"type":"run", id, kind, startedAt, build, input}        first line
//   {"type":"event", t, event, ...data}                       one per step (t = ms since start)
//   {"type":"end", status, durationMs, ...summary}            last line, once the run finishes
//
// Logs are kept in memory (newest RUN_LOG_MAX_RUNS runs, for RUN_LOG_TTL_HOURS) and served at
// /api/runs/<id>. Set RUN_LOG_DIR to also write each finished run to <dir>/<id>.jsonl.
// Every run also prints one summary line ("owl-run {...}") to stdout, so the host's log viewer
// (e.g. Render's) can be searched by run id. Logs never contain the visitor's IP address.

import { randomBytes } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

const MAX_RUNS = Number(process.env.RUN_LOG_MAX_RUNS || 100);
const TTL_MS = Number(process.env.RUN_LOG_TTL_HOURS || 24) * 3600_000;
const MAX_EVENTS = 5000;
const MAX_CHARS = 8_000_000; // per run; later events are counted but not kept
const DIR = process.env.RUN_LOG_DIR || '';

export const RUN_ID_RE = /^(scan|patch|rescan)-\d{8}-\d{6}-[0-9a-f]{12}$/;

const runs = new Map(); // id -> RunLog

/** Clips long strings (and strings inside objects/arrays) so a log stays readable and bounded. */
export function clipDeep(value, max = 4000) {
  if (typeof value === 'string') return value.length > max ? `${value.slice(0, max)}… [${value.length - max} more chars]` : value;
  if (Array.isArray(value)) return value.map((v) => clipDeep(v, max));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, clipDeep(v, max)]));
  return value;
}

export class RunLog {
  constructor(kind, input = {}, { build = '' } = {}) {
    const now = new Date();
    const stamp = now.toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
    this.id = `${kind}-${stamp}-${randomBytes(6).toString('hex')}`;
    this.kind = kind;
    this.started = Date.now();
    this.lines = [JSON.stringify({ type: 'run', id: this.id, kind, startedAt: now.toISOString(), build, input })];
    this.chars = this.lines[0].length;
    this.dropped = 0;
    this.ended = false;
    this.trace = this.trace.bind(this);
  }

  /** Records one step. Safe to call with anything JSON-serializable; never throws. */
  trace(event, data = {}) {
    if (this.ended) return;
    let line;
    try {
      line = JSON.stringify({ type: 'event', t: Date.now() - this.started, event, ...data });
    } catch {
      line = JSON.stringify({ type: 'event', t: Date.now() - this.started, event, note: 'data was not serializable' });
    }
    if (this.lines.length >= MAX_EVENTS || this.chars + line.length > MAX_CHARS) {
      this.dropped++;
      return;
    }
    this.lines.push(line);
    this.chars += line.length;
  }

  /** Closes the log with a status ('ok' | 'error' | …) and a short summary. */
  end(status, summary = {}) {
    if (this.ended) return;
    const end = { type: 'end', status, durationMs: Date.now() - this.started, ...(this.dropped ? { droppedEvents: this.dropped } : {}), ...summary };
    this.lines.push(JSON.stringify(end));
    this.ended = true;
    console.log(`owl-run ${JSON.stringify({ id: this.id, kind: this.kind, ...clipDeep(end, 300) })}`);
    if (DIR) {
      mkdir(DIR, { recursive: true })
        .then(() => appendFile(join(DIR, `${this.id}.jsonl`), this.text()))
        .catch((err) => console.error('could not write run log', this.id, err.message));
    }
  }

  text() {
    return this.lines.join('\n') + '\n';
  }
}

/** Starts and stores a new run log. */
export function startRun(kind, input, opts) {
  const run = new RunLog(kind, input, opts);
  runs.set(run.id, run);
  prune();
  return run;
}

export function getRun(id) {
  if (!RUN_ID_RE.test(id || '')) return null;
  const run = runs.get(id);
  if (!run) return null;
  if (Date.now() - run.started > TTL_MS) {
    runs.delete(id);
    return null;
  }
  return run;
}

function prune() {
  const now = Date.now();
  for (const [id, run] of runs) if (now - run.started > TTL_MS) runs.delete(id);
  while (runs.size > MAX_RUNS) runs.delete(runs.keys().next().value);
}

/** A trace function that does nothing (the default everywhere a trace is optional). */
export const noTrace = () => {};

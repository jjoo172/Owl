// Unified diffs in the format `git apply` and `patch -p1` accept. No dependencies.
//
// Lines are compared with Myers' O(ND) algorithm, which stays fast on large files when the
// change is small (the usual case for a security patch), after trimming common lines from
// both ends.

/** Splits text into lines, remembering whether the last line ended with a newline. */
function toLines(text) {
  if (text === '') return { lines: [], eofNewline: true };
  const eofNewline = text.endsWith('\n');
  const lines = (eofNewline ? text.slice(0, -1) : text).split('\n');
  return { lines, eofNewline };
}

/** Myers shortest edit script between line arrays; returns [['=', line] | ['-', line] | ['+', line]]. */
function myers(a, b) {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  const v = new Map([[1, 0]]);
  const trace = [];
  outer: for (let d = 0; d <= max; d++) {
    trace.push(new Map(v));
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && (v.get(k - 1) ?? -1) < (v.get(k + 1) ?? -1))) x = v.get(k + 1) ?? 0;
      else x = (v.get(k - 1) ?? 0) + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v.set(k, x);
      if (x >= n && y >= m) break outer;
    }
  }
  // Walk back through the trace to recover the edit script.
  const ops = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0; d--) {
    const vd = trace.at(d);
    const k = x - y;
    let prevK;
    if (k === -d || (k !== d && (vd.get(k - 1) ?? -1) < (vd.get(k + 1) ?? -1))) prevK = k + 1;
    else prevK = k - 1;
    const prevX = vd.get(prevK) ?? 0;
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      ops.push(['=', a[x - 1]]);
      x--;
      y--;
    }
    if (d > 0) {
      if (x === prevX) ops.push(['+', b[y - 1]]);
      else ops.push(['-', a[x - 1]]);
    }
    x = prevX;
    y = prevY;
  }
  return ops.reverse();
}

/** Line-level edit script for two texts, trimming common lines at both ends first. */
function lineOps(a, b) {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  return [
    ...a.slice(0, start).map((l) => ['=', l]),
    ...myers(a.slice(start, endA), b.slice(start, endB)),
    ...a.slice(endA).map((l) => ['=', l]),
  ];
}

/**
 * Unified diff of one file (`path` relative to the repo root), with `context` lines around
 * each change. Returns '' when the texts are identical.
 */
export function unifiedDiff(path, before, after, context = 3) {
  if (before === after) return '';
  const A = toLines(before);
  const B = toLines(after);
  // Compare the final line together with its newline status, so a change to only the
  // trailing newline is still a change.
  const a = A.lines.map((l, i) => (i === A.lines.length - 1 && !A.eofNewline ? l + '\u0000' : l));
  const b = B.lines.map((l, i) => (i === B.lines.length - 1 && !B.eofNewline ? l + '\u0000' : l));
  const ops = lineOps(a, b);

  // Number every op with its position in each file.
  let ia = 0;
  let ib = 0;
  const rows = ops.map(([op, text]) => {
    const row = { op, text, a: ia, b: ib };
    if (op !== '+') ia++;
    if (op !== '-') ib++;
    return row;
  });

  // Group changes into hunks with surrounding context, merging hunks that touch.
  const changed = rows.map((r, i) => (r.op === '=' ? -1 : i)).filter((i) => i >= 0);
  const hunks = [];
  for (const i of changed) {
    const lo = Math.max(0, i - context);
    const hi = Math.min(rows.length - 1, i + context);
    const last = hunks.at(-1);
    if (last && lo <= last.hi + 1) last.hi = Math.max(last.hi, hi);
    else hunks.push({ lo, hi });
  }

  const out = [`diff --git a/${path} b/${path}`, `--- a/${path}`, `+++ b/${path}`];
  for (const { lo, hi } of hunks) {
    const slice = rows.slice(lo, hi + 1);
    const aCount = slice.filter((r) => r.op !== '+').length;
    const bCount = slice.filter((r) => r.op !== '-').length;
    const aStart = aCount ? slice.find((r) => r.op !== '+').a + 1 : slice[0].a;
    const bStart = bCount ? slice.find((r) => r.op !== '-').b + 1 : slice[0].b;
    out.push(`@@ -${aStart},${aCount} +${bStart},${bCount} @@`);
    for (const r of slice) {
      const noEol = r.text.endsWith('\u0000');
      out.push((r.op === '=' ? ' ' : r.op) + (noEol ? r.text.slice(0, -1) : r.text));
      if (noEol) out.push('\\ No newline at end of file');
    }
  }
  return out.join('\n') + '\n';
}

/** Summary counts for a diff, for display. */
export function diffStats(diff) {
  let added = 0;
  let removed = 0;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) added++;
    else if (line.startsWith('-') && !line.startsWith('---')) removed++;
  }
  return { added, removed };
}

/** New-side line numbers of the lines a diff adds or changes, for each hunk. */
export function addedLines(diff) {
  const out = [];
  let n = 0;
  for (const line of diff.split('\n')) {
    const m = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (m) {
      n = Number(m[1]);
      continue;
    }
    if (!n || line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+')) out.push(n++);
    else if (line.startsWith(' ')) n++;
  }
  return out;
}

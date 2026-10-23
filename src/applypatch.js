// Applies a unified diff (as produced by diff.js) to in-memory source, exactly: every context
// and removed line must match. Used to re-scan the patched code. Also maps each file's old line
// numbers to new ones, so findings from before and after the patch can be compared.

import { unifiedDiff, addedLines as addedLinesOf } from './diff.js';

export class PatchError extends Error {}

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/** Parses a unified diff into [{ path, hunks: [{ oldStart, oldCount, newStart, newCount, lines }] }]. */
export function parsePatch(text) {
  const files = [];
  let file = null;
  let hunk = null;
  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('diff --git ')) {
      file = null;
      hunk = null;
      continue;
    }
    const m = line.match(HUNK);
    if (m && file && !hunk?.remaining) {
      hunk = { oldStart: +m[1], oldCount: m[2] === undefined ? 1 : +m[2], newStart: +m[3], newCount: m[4] === undefined ? 1 : +m[4], lines: [] };
      hunk.remaining = hunk.oldCount + hunk.newCount;
      file.hunks.push(hunk);
      continue;
    }
    if (line.startsWith('\\') && hunk?.lines.length) {
      hunk.lines.at(-1).noEol = true; // "\ No newline at end of file"
      continue;
    }
    if (hunk && hunk.remaining > 0) {
      const op = line[0];
      if (op === ' ') hunk.remaining -= 2;
      else if (op === '-' || op === '+') hunk.remaining -= 1;
      else throw new PatchError(`Malformed hunk in ${file.path}.`);
      hunk.lines.push({ op, text: line.slice(1), noEol: false });
      continue;
    }
    if (line.startsWith('--- ') && !hunk?.remaining) {
      const next = lines[i + 1] || '';
      if (!next.startsWith('+++ ')) throw new PatchError(`Malformed patch near line ${i + 1}.`);
      const oldPath = line.slice(4).replace(/^a\//, '');
      const newPath = next.slice(4).replace(/^b\//, '');
      if (oldPath === '/dev/null' || newPath === '/dev/null' || oldPath !== newPath) {
        throw new PatchError(`The patch adds, deletes or renames a file (${newPath}); only edits to existing files can be re-scanned.`);
      }
      file = { path: newPath, hunks: [] };
      files.push(file);
      hunk = null;
      i++;
      continue;
    }
    // Anything else (comments, blank lines) between files is ignored, as git apply does.
  }
  for (const f of files) for (const h of f.hunks) if (h.remaining > 0) throw new PatchError(`The patch for ${f.path} is truncated.`);
  return files;
}

/**
 * Applies the patch to `contentByPath` (left unchanged). Returns { files: Map (patched copy),
 * changed: [paths], lineMaps: Map(path -> (oldLine) => newLine) }.
 */
export function applyPatch(contentByPath, text) {
  const parsed = parsePatch(text);
  if (!parsed.length) throw new PatchError('The patch contains no changes.');
  const files = new Map(contentByPath);
  const lineMaps = new Map();
  for (const { path, hunks } of parsed) {
    if (!files.has(path)) throw new PatchError(`The patch changes ${path}, which is not in this repository's source.`);
    const original = files.get(path);
    const eofNewline = original.endsWith('\n') || original === '';
    const src = (eofNewline ? original.slice(0, -1) : original).split('\n');
    if (original === '') src.length = 0;
    const out = [];
    const anchors = []; // [oldLine (1-based), newLine (1-based)] for unchanged lines
    let pos = 0; // index into src
    let outEofNewline = eofNewline;
    for (const h of hunks) {
      const start = h.oldCount === 0 ? h.oldStart : h.oldStart - 1;
      if (start < pos || start > src.length) throw new PatchError(`The patch for ${path} doesn't match this version of the file.`);
      while (pos < start) {
        anchors.push([pos + 1, out.length + 1]);
        out.push(src[pos++]);
      }
      for (const l of h.lines) {
        if (l.op === ' ' || l.op === '-') {
          if (src[pos] !== l.text) throw new PatchError(`The patch for ${path} doesn't match this version of the file (line ${pos + 1}).`);
          if (l.op === ' ') {
            anchors.push([pos + 1, out.length + 1]);
            out.push(l.text);
          }
          if (l.noEol && pos === src.length - 1 && l.op === ' ') outEofNewline = false;
          pos++;
        } else {
          out.push(l.text);
          if (l.noEol) outEofNewline = false;
          else if (pos >= src.length) outEofNewline = true;
        }
      }
    }
    while (pos < src.length) {
      anchors.push([pos + 1, out.length + 1]);
      out.push(src[pos++]);
    }
    files.set(path, out.join('\n') + (out.length && outEofNewline ? '\n' : ''));
    lineMaps.set(path, lineMapper(anchors));
  }
  // New-side line numbers each file's patch added or changed (to tell patch-introduced findings apart).
  const addedLines = new Map(parsed.map(({ path }) => [path, new Set(addedLinesOf(unifiedDiff(path, contentByPath.get(path), files.get(path))))]));
  return { files, changed: parsed.map((f) => f.path), lineMaps, addedLines };
}

/** Old line -> new line: exact for unchanged lines, nearest unchanged neighbour for edited ones. */
function lineMapper(anchors) {
  return (oldLine) => {
    let best = null;
    for (const [o, n] of anchors) {
      if (o === oldLine) return n;
      if (o < oldLine) best = n + (oldLine - o);
      else return best ?? n;
    }
    return best ?? oldLine;
  };
}

// Minimal streaming tar reader (ustar + pax + GNU long names), enough for
// GitHub's repository archives. No dependencies.

function str(buf, start, len) {
  const s = buf.subarray(start, start + len);
  const z = s.indexOf(0);
  return s.subarray(0, z < 0 ? s.length : z).toString('utf8');
}

function num(buf, start, len) {
  if (buf[start] & 0x80) {
    // base-256 encoding for large sizes
    let v = 0;
    for (let i = start + 1; i < start + len; i++) v = v * 256 + buf[i];
    return v;
  }
  return parseInt(str(buf, start, len).trim() || '0', 8) || 0;
}

function parsePax(data) {
  const out = {};
  let i = 0;
  const s = data.toString('utf8');
  while (i < s.length) {
    const sp = s.indexOf(' ', i);
    if (sp < 0) break;
    const len = parseInt(s.slice(i, sp), 10);
    if (!len) break;
    const rec = s.slice(sp + 1, i + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/**
 * Reads a tar stream. For each entry, `want(header)` decides whether the
 * content is needed; if so `onFile(header, buffer)` receives it.
 * Returns the pax global header (GitHub puts the commit SHA in `comment`).
 */
export async function readTar(readable, { want, onFile }) {
  const it = readable[Symbol.asyncIterator]();
  let buf = Buffer.alloc(0);
  let ended = false;
  let globalPax = {};

  const fill = async (n) => {
    while (buf.length < n && !ended) {
      const r = await it.next();
      if (r.done) ended = true;
      else buf = buf.length ? Buffer.concat([buf, r.value]) : r.value;
    }
    return buf.length >= n;
  };
  const take = async (n) => {
    await fill(n);
    const out = Buffer.from(buf.subarray(0, n));
    buf = buf.subarray(n);
    return out;
  };
  const skip = async (n) => {
    while (n > 0) {
      if (!buf.length && !(await fill(1))) return;
      const k = Math.min(n, buf.length);
      buf = buf.subarray(k);
      n -= k;
    }
  };

  let paxPath = null;
  let longName = null;
  while (await fill(512)) {
    const h = Buffer.from(buf.subarray(0, 512));
    buf = buf.subarray(512);
    if (h.every((b) => b === 0)) break; // end-of-archive marker

    const size = num(h, 124, 12);
    const padded = Math.ceil(size / 512) * 512;
    const flag = String.fromCharCode(h[156] || 48);

    if (flag === 'x' || flag === 'g') {
      const pax = parsePax(await take(size));
      await skip(padded - size);
      if (flag === 'g') globalPax = { ...globalPax, ...pax };
      else if (pax.path) paxPath = pax.path;
      continue;
    }
    if (flag === 'L') {
      longName = str(await take(size), 0, size);
      await skip(padded - size);
      continue;
    }

    const magic = str(h, 257, 6);
    const prefix = magic.startsWith('ustar') ? str(h, 345, 155) : '';
    const baseName = str(h, 0, 100);
    const name = longName || paxPath || (prefix ? `${prefix}/${baseName}` : baseName);
    longName = paxPath = null;

    const type = flag === '0' || flag === '7' || h[156] === 0 ? 'file' : flag === '5' ? 'directory' : 'other';
    const header = { name, size, type };
    if (type === 'file' && want(header)) {
      const data = await take(size);
      await skip(padded - size);
      onFile(header, data);
    } else {
      await skip(padded);
    }
  }
  // Drain anything left so the underlying stream closes cleanly.
  while (!ended) {
    const r = await it.next();
    if (r.done) ended = true;
  }
  return globalPax;
}

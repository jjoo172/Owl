// Blanks out comments and the contents of string/char literals in C/C++ source,
// preserving length and newlines so line numbers stay aligned. Quote characters
// are kept so rules can still tell `printf("...")` apart from `printf(buf)`.

const RAW_PREFIXES = new Set(['', 'u8', 'L', 'u', 'U']);

export function stripCommentsAndStrings(src) {
  const out = src.split('');
  const n = src.length;
  const blank = (a, b) => {
    for (let k = a; k < b && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
  };

  let i = 0;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];

    // // line comment (honours backslash line continuation)
    if (c === '/' && d === '/') {
      let j = i;
      while (j < n && src[j] !== '\n') {
        if (src[j] === '\\' && src[j + 1] === '\n') j++;
        j++;
      }
      blank(i, j);
      i = j;
      continue;
    }

    // /* block comment */
    if (c === '/' && d === '*') {
      let j = src.indexOf('*/', i + 2);
      j = j < 0 ? n : j + 2;
      blank(i, j);
      i = j;
      continue;
    }

    // Raw string literal: [u8|L|u|U]R"delim( ... )delim"
    if (c === 'R' && d === '"') {
      let k = i;
      while (k > 0 && /\w/.test(src[k - 1])) k--;
      if (RAW_PREFIXES.has(src.slice(k, i))) {
        const open = src.indexOf('(', i + 2);
        if (open > 0 && open - (i + 2) <= 16) {
          const delim = src.slice(i + 2, open);
          const close = src.indexOf(')' + delim + '"', open + 1);
          const endQuote = close < 0 ? n : close + delim.length + 1;
          blank(i + 2, endQuote);
          i = endQuote + 1;
          continue;
        }
      }
    }

    // "string literal"
    if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"' && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      blank(i + 1, j);
      i = j + 1;
      continue;
    }

    // 'c' char literal (but not a C++14 digit separator like 1'000'000)
    if (c === "'") {
      let k = i;
      while (k > 0 && /[\w']/.test(src[k - 1])) k--;
      const isDigitSeparator = k < i && /[0-9]/.test(src[k]);
      if (!isDigitSeparator) {
        let j = i + 1;
        while (j < n && src[j] !== "'" && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
        blank(i + 1, j);
        i = j + 1;
        continue;
      }
    }

    i++;
  }
  return out.join('');
}

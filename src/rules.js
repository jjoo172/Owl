// Memory-safety and related risk patterns for C/C++ source.
// Each rule is matched per line against code with comments and string contents
// blanked out (see lexer.js). `test` may also inspect the original line.

// A free-function call: not a member access (foo.bar / foo->bar), not part of a
// longer identifier. `std::name(` and `::name(` still match.
const call = (names) => new RegExp(`(?<![\\w.]|->)(?:std::|::)?(?:${names})\\s*\\(`);

const TYPES =
  '(?:char|wchar_t|int|short|long|unsigned|signed|float|double|u?int(?:8|16|32|64)_t|size_t|uint8_t|BYTE|byte)';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

export const RULES = [
  {
    id: 'gets',
    title: 'gets() — unbounded input read',
    severity: 'critical',
    category: 'Buffer overflow',
    cwe: 'CWE-242',
    description:
      'gets() cannot limit how much it writes and was removed from C11. Any use is an exploitable stack/heap overflow.',
    re: call('gets|_getws'),
  },
  {
    id: 'unbounded-copy',
    title: 'Unbounded string copy/concat',
    severity: 'high',
    category: 'Buffer overflow',
    cwe: 'CWE-120',
    description:
      'strcpy/strcat-style functions write until the source NUL with no destination bound — the classic overflow primitive.',
    re: call('strcpy|strcat|wcscpy|wcscat|stpcpy|_mbscpy|_mbscat|lstrcpy[AW]?|lstrcat[AW]?|StrCpy[AW]?|StrCat[AW]?|_tcscpy|_tcscat'),
  },
  {
    id: 'unbounded-sprintf',
    title: 'Unbounded formatted write (sprintf)',
    severity: 'high',
    category: 'Buffer overflow',
    cwe: 'CWE-120',
    description:
      'sprintf/vsprintf have no output size limit; long or attacker-influenced arguments overflow the destination.',
    re: call('sprintf|vsprintf|wsprintf[AW]?|_stprintf'),
  },
  {
    id: 'unbounded-scanf',
    title: 'scanf %s / %[ without width',
    severity: 'high',
    category: 'Buffer overflow',
    cwe: 'CWE-120',
    description: 'A %s or %[ conversion with no field width writes an unbounded amount of input into the buffer.',
    re: call('scanf|fscanf|sscanf|vscanf|vfscanf|vsscanf|wscanf|swscanf|fwscanf'),
    test: (_code, original) => /%(?:l|h)?(?:s|\[)/.test(original),
  },
  {
    id: 'format-string',
    title: 'Non-literal format string',
    severity: 'high',
    category: 'Format string',
    cwe: 'CWE-134',
    description:
      'The format argument is a variable, not a string literal. If it can carry attacker data, %n/%s give memory read/write.',
    test: (code) => {
      const m =
        code.match(/(?<![\w.]|->)(?:std::)?(?:printf|vprintf|wprintf)\s*\(\s*([A-Za-z_][\w.\->]*)\s*[,)]/) ||
        code.match(/(?<![\w.]|->)(?:std::)?(?:fprintf|vfprintf|dprintf|syslog|fwprintf)\s*\(\s*[^,()]+,\s*([A-Za-z_][\w.\->]*)\s*[,)]/) ||
        code.match(/(?<![\w.]|->)(?:std::)?(?:snprintf|vsnprintf|swprintf)\s*\(\s*[^,()]+,\s*[^,()]+,\s*([A-Za-z_][\w.\->]*)\s*[,)]/);
      // ALL_CAPS arguments are almost always format macros that expand to literals.
      return !!m && !/^[A-Z][A-Z0-9_]+$/.test(m[1]);
    },
  },
  {
    id: 'alloca',
    title: 'alloca() / dynamic stack allocation',
    severity: 'high',
    category: 'Stack exhaustion',
    cwe: 'CWE-770',
    description: 'alloca has no failure path; a large or attacker-controlled size silently smashes the stack.',
    re: call('_?alloca|__builtin_alloca|_malloca'),
  },
  {
    id: 'command-exec',
    title: 'Shell / process execution',
    severity: 'high',
    category: 'Command injection',
    cwe: 'CWE-78',
    description: 'Spawns a shell or process. Dangerous in a critical path if any part of the command is externally influenced.',
    re: call('system|popen|_popen|_wpopen|execl|execlp|execle|execv|execvp|execvpe|ShellExecute[AW]?|ShellExecuteEx[AW]?|WinExec|CreateProcess[AW]?'),
  },
  {
    id: 'raw-memcpy',
    title: 'Raw memory copy',
    severity: 'medium',
    category: 'Buffer overflow',
    cwe: 'CWE-787',
    description:
      'memcpy/memmove trust the caller-supplied length. Correctness depends entirely on manual bounds checks nearby.',
    re: call('memcpy|memmove|wmemcpy|wmemmove|bcopy|CopyMemory|RtlCopyMemory|MoveMemory|RtlMoveMemory|__builtin_memcpy'),
  },
  {
    id: 'bounded-but-fragile',
    title: 'strncpy/strncat — truncation & termination pitfalls',
    severity: 'medium',
    category: 'Buffer overflow',
    cwe: 'CWE-170',
    description:
      'strncpy may leave the buffer unterminated; strncat\'s length is the remaining space, a frequent off-by-one source.',
    re: call('strncpy|strncat|wcsncpy|wcsncat|_tcsncpy|_tcsncat'),
  },
  {
    id: 'alloc-size-arith',
    title: 'Allocation size computed with multiplication',
    severity: 'medium',
    category: 'Integer overflow',
    cwe: 'CWE-190',
    description:
      'n * size inside malloc/realloc can wrap around, producing a too-small buffer that later writes overflow.',
    test: (code) => {
      const m = code.match(/(?<![\w.]|->)(?:std::)?(?:malloc|realloc|_?alloca|operator\s+new)\s*\((.*)/);
      if (!m) return false;
      // Treat sizeof(...) and ALL_CAPS macros as constants; flag only when a
      // runtime variable takes part in a multiplication.
      const args = m[1]
        .replace(/sizeof\s*\([^()]*\)|sizeof\s+\w+/g, '1')
        .replace(/\b0x[0-9a-fA-F]+[uUlL]*\b|\b\d+[uUlL]*\b/g, '1');
      const isVariable = (t) => /^[A-Za-z_]/.test(t) && /[a-z]/.test(t);
      for (const [, left, right] of args.matchAll(/([\w.\->]+)\s*\*\s*\(?\s*([\w.\->]+)/g)) {
        if (isVariable(left) || isVariable(right)) return true;
      }
      return false;
    },
  },
  {
    id: 'realloc-self',
    title: 'p = realloc(p, …)',
    severity: 'medium',
    category: 'Memory leak / null deref',
    cwe: 'CWE-401',
    description: 'If realloc fails the original pointer is overwritten with NULL — the block leaks and later use derefs NULL.',
    re: /(\b[\w.]+(?:->\w+)*)\s*=\s*(?:\([^()]*\)\s*)?realloc\s*\(\s*\1\s*,/,
  },
  {
    id: 'vla',
    title: 'Variable-length array on the stack',
    severity: 'medium',
    category: 'Stack exhaustion',
    cwe: 'CWE-121',
    description: 'Stack array sized by a runtime value; an unchecked size overflows or exhausts the stack.',
    re: new RegExp(`^\\s*(?:const\\s+)?${TYPES}(?:\\s+${TYPES})*\\s+\\w+\\s*\\[\\s*[a-z_][a-z0-9_]*(?:\\s*[-+*]\\s*[\\w]+)?\\s*\\]\\s*;`),
  },
  {
    id: 'setjmp',
    title: 'setjmp/longjmp',
    severity: 'medium',
    category: 'Control-flow integrity',
    cwe: 'CWE-1325',
    description: 'longjmp skips destructors and cleanup, easily leaking or corrupting state; jmp_buf is a classic overwrite target.',
    re: call('setjmp|longjmp|_setjmp|_longjmp|sigsetjmp|siglongjmp'),
  },
  {
    id: 'inline-asm',
    title: 'Inline assembly',
    severity: 'medium',
    category: 'Unchecked low-level code',
    cwe: 'CWE-1104',
    description: 'Inline assembly bypasses every compiler safety check and sanitizer.',
    re: /(?<!\w)(?:__asm__|__asm|asm)\s*(?:volatile|__volatile__|goto)?\s*[({]/,
  },
  {
    id: 'exec-memory',
    title: 'Executable / protection-changing memory',
    severity: 'medium',
    category: 'Memory protection',
    cwe: 'CWE-749',
    description: 'Changing page protections or mapping executable memory weakens W^X and is a common exploitation primitive.',
    test: (code, original) =>
      /(?<![\w.]|->)(?:mprotect|VirtualProtect(?:Ex)?|VirtualAlloc(?:Ex)?)\s*\(/.test(code) ||
      (/(?<![\w.]|->)mmap\s*\(/.test(code) && /PROT_EXEC/.test(original)),
  },
  {
    id: 'sanitizer-off',
    title: 'Sanitizer / warning suppression',
    severity: 'medium',
    category: 'Suppressed checks',
    cwe: 'CWE-1164',
    description: 'Code explicitly opts out of sanitizers or silences compiler warnings — often a marker of known-sketchy code.',
    re: /no_sanitize|__no_sanitize|NO_SANITIZE|#\s*pragma\s+(?:GCC|clang)\s+diagnostic\s+ignored|#\s*pragma\s+warning\s*\(\s*disable/,
  },
  {
    id: 'deferred-ref-lambda',
    title: 'Reference-capturing lambda stored or deferred',
    severity: 'medium',
    category: 'Lifetime (dangling reference)',
    cwe: 'CWE-416',
    description:
      'A [&] lambda is handed to something that may run it later (queue, callback, thread). If it outlives the captured locals it reads freed stack memory.',
    re: /(?:\b(?:add|push_back|emplace_back|push|push_front|emplace|post|submit|enqueue|schedule|defer|then|async|connect|subscribe|set_callback|on_\w+)\s*\(|std::thread\s*[({]|std::jthread\s*[({])[^;]*?\[\s*&/,
  },
  {
    id: 'temporary-range-for',
    title: 'Range-for over a member of a temporary',
    severity: 'medium',
    category: 'Lifetime (dangling reference)',
    cwe: 'CWE-416',
    description:
      'for (x : f().items()) — before C++23 only the outermost temporary is kept alive, so the loop iterates storage that has already been destroyed.',
    test: (code) => {
      const m = code.match(/\bfor\s*\((.*)\)/);
      if (!m) return false;
      const parts = m[1].split(/(?<!:):(?!:)/);
      if (parts.length < 2) return false;
      const range = parts.slice(1).join(':').trim();
      return /\)\s*\.\s*\w+\s*(?:\(\s*\))?$/.test(range);
    },
  },
  {
    id: 'non-strict-comparator',
    title: 'Comparator using <= or >=',
    severity: 'medium',
    category: 'Undefined behaviour',
    cwe: 'CWE-758',
    description:
      'Sorting/ordered containers require a strict weak ordering. A <= / >= comparator is undefined behaviour; std::sort can read out of bounds.',
    re: /\[[^\]]*\]\s*\(\s*[^,()]+,\s*[^,()]+\)\s*(?:->\s*bool\s*)?\{\s*return\s+[\w.\->()[\]]+\s*(?:<=|>=)\s*[\w.\->()[\]]+\s*;\s*\}/,
  },
  {
    id: 'manual-alloc',
    title: 'Manual heap management (malloc/free)',
    severity: 'low',
    category: 'Lifetime management',
    cwe: 'CWE-416',
    description: 'Manual malloc/free is where use-after-free, double-free and leaks come from. Volume indicates attack surface.',
    re: call('malloc|calloc|realloc|free|strdup|strndup|_strdup|wcsdup'),
  },
  {
    id: 'raw-new-delete',
    title: 'Raw new/delete',
    severity: 'low',
    category: 'Lifetime management',
    cwe: 'CWE-416',
    description: 'Owning raw pointers instead of RAII (unique_ptr/containers) — use-after-free and leak risk.',
    re: /(?<![\w.]|->)(?:new\s+(?!\()[A-Za-z_][\w:<>]*(?:\s*[[(;{]|\s*$)|delete\b\s*(?:\[\s*\])?\s*[A-Za-z_(*])/,
  },
  {
    id: 'unsafe-cast',
    title: 'reinterpret_cast / const_cast',
    severity: 'low',
    category: 'Type confusion',
    cwe: 'CWE-704',
    description: 'Reinterpreting memory or casting away const defeats the type system and can cause type confusion.',
    re: /\b(?:reinterpret_cast|const_cast)\s*</,
  },
  {
    id: 'fixed-stack-buffer',
    title: 'Fixed-size stack char buffer',
    severity: 'low',
    category: 'Buffer overflow',
    cwe: 'CWE-121',
    description: 'Fixed char arrays are the usual destination of overflows; risky when paired with the copy functions above.',
    re: /^\s*(?:unsigned\s+|signed\s+)?(?:char|wchar_t|TCHAR|WCHAR)\s+\w+\s*\[\s*(?:\d+|[A-Z_][A-Z0-9_]*)\s*\]\s*[;=]/,
  },
  {
    id: 'unchecked-conversion',
    title: 'atoi-family numeric parsing',
    severity: 'low',
    category: 'Integer handling',
    cwe: 'CWE-190',
    description: 'atoi/atol report no errors and overflow silently; parsed values used as sizes/indices become dangerous.',
    re: call('atoi|atol|atoll|_wtoi|_ttoi'),
  },
  {
    id: 'ref-param-temp-default',
    title: 'Reference parameter defaulted to a temporary',
    severity: 'low',
    category: 'Lifetime (dangling reference)',
    cwe: 'CWE-562',
    description:
      'const T& x = "" binds to a temporary that dies at the end of the call. Harmless unless the reference is returned or stored — then it dangles.',
    re: /\bconst\s+[\w:<>]+\s*&\s*\w+\s*=\s*(?:"|\{|[\w:<>]+\s*[({]|-?\d)/,
  },
  {
    id: 'variable-shift',
    title: 'Shift by a variable amount',
    severity: 'low',
    category: 'Undefined behaviour',
    cwe: 'CWE-1335',
    description: 'Shifting by ≥ the type width (e.g. 1u << 32) or a negative amount is undefined behaviour.',
    re: /\b1[uUlL]*\s*<<\s*\(?\s*[a-z_][\w.\->]*/,
  },
  {
    id: 'strtok',
    title: 'strtok — non-reentrant, mutates input',
    severity: 'low',
    category: 'Concurrency / state',
    cwe: 'CWE-676',
    description: 'strtok keeps hidden global state and writes into its input; unsafe across threads and with const data.',
    re: call('strtok|wcstok'),
  },
];

// Positive signals: modern, bounds-aware idioms that reduce memory risk.
export const MITIGATIONS = [
  { id: 'smart-pointers', title: 'Smart pointers (unique_ptr / shared_ptr)', re: /\bstd::(?:unique_ptr|shared_ptr|make_unique|make_shared)\b/g },
  { id: 'safe-views', title: 'Bounds-carrying views (span / string_view)', re: /\bstd::(?:span|string_view)\b|\bgsl::span\b/g },
  { id: 'containers', title: 'Standard containers (vector / array / string)', re: /\bstd::(?:vector|array|string)\b/g },
  { id: 'checked-access', title: 'Checked element access (.at())', re: /\.at\s*\(/g },
  { id: 'fuzz-harness', title: 'Fuzz harnesses (LLVMFuzzerTestOneInput)', re: /\bLLVMFuzzerTestOneInput\b/g },
];

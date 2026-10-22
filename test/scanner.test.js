import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stripCommentsAndStrings } from '../src/lexer.js';
import { scanFile, classifyPath, scanRepository } from '../src/scanner.js';
import { parseRepoInput } from '../src/github.js';

const ids = (src, path = 'src/a.c') => scanFile(path, src).findings.map((f) => f.ruleId);

test('lexer blanks comments and string contents but keeps lines', () => {
  const src = 'a(); // strcpy(x,y)\n/* gets(b) */ b("strcpy(");\nchar c = \'"\';\nint n = 1\'000;';
  const out = stripCommentsAndStrings(src);
  assert.equal(out.length, src.length);
  assert.equal(out.split('\n').length, 4);
  assert.ok(!out.includes('strcpy'));
  assert.ok(!out.includes('gets'));
  assert.ok(out.includes('b("'));
  assert.ok(out.includes("1'000"));
});

test('lexer handles raw strings', () => {
  const out = stripCommentsAndStrings('auto s = R"x(strcpy(a,b); ")x"; strcat(a,b);');
  assert.ok(!out.includes('strcpy'));
  assert.ok(out.includes('strcat'));
});

test('flags classic unsafe calls, ignores comments and member calls', () => {
  assert.deepEqual(ids('gets(buf);'), ['gets']);
  assert.ok(ids('strcpy(dst, src);').includes('unbounded-copy'));
  assert.ok(ids('std::strcat(dst, src);').includes('unbounded-copy'));
  assert.deepEqual(ids('// strcpy(dst, src);'), []);
  assert.deepEqual(ids('obj.strcpy(dst, src);'), []);
  assert.deepEqual(ids('my_strcpy(dst, src);'), []);
  assert.ok(ids('sprintf(buf, "%d", x);').includes('unbounded-sprintf'));
  assert.deepEqual(ids('snprintf(buf, sizeof buf, "%d", x);'), []);
});

test('scanf only flagged without field width', () => {
  assert.ok(ids('scanf("%s", buf);').includes('unbounded-scanf'));
  assert.ok(!ids('scanf("%63s", buf);').includes('unbounded-scanf'));
  assert.ok(!ids('scanf("%d", &n);').includes('unbounded-scanf'));
});

test('format string detection', () => {
  assert.ok(ids('printf(msg);').includes('format-string'));
  assert.ok(ids('fprintf(stderr, user_input);').includes('format-string'));
  assert.ok(ids('snprintf(b, n, fmt, a);').includes('format-string'));
  assert.ok(!ids('printf("%s", msg);').includes('format-string'));
  assert.ok(!ids('printf(FMT_HEADER, a);').includes('format-string'));
});

test('memory management patterns', () => {
  assert.ok(ids('p = realloc(p, n);').includes('realloc-self'));
  assert.ok(!ids('q = realloc(p, n);').includes('realloc-self'));
  assert.ok(ids('char *b = malloc(n * sizeof(int));').includes('alloc-size-arith'));
  assert.ok(ids('p = realloc(q, sizeof(point_t) * idx->mode);').includes('alloc-size-arith'));
  assert.ok(!ids('p = (char *)malloc(7 + 3 * sizeof(int));').includes('alloc-size-arith'));
  assert.ok(!ids('p = malloc(MAX_LEN * 2);').includes('alloc-size-arith'));
  assert.ok(!ids('struct deleter {', 'a.cpp').includes('raw-new-delete'));
  assert.ok(ids('memcpy(dst, src, len);').includes('raw-memcpy'));
  assert.ok(ids('Foo *f = new Foo(1);', 'a.cpp').includes('raw-new-delete'));
  assert.ok(ids('delete[] arr;', 'a.cpp').includes('raw-new-delete'));
  assert.ok(!ids('Foo(const Foo&) = delete;', 'a.cpp').includes('raw-new-delete'));
  assert.ok(ids('  char buf[256];').includes('fixed-stack-buffer'));
  assert.ok(ids('  int arr[n];').includes('vla'));
  assert.ok(!ids('  int arr[MAX];').includes('vla'));
});

test('path classification', () => {
  assert.equal(classifyPath('src/parser.c'), 'production');
  assert.equal(classifyPath('tests/parser_test.c'), 'test');
  assert.equal(classifyPath('src/parser_unittest.cc'), 'test');
  assert.equal(classifyPath('fuzz/x.cc'), 'test');
  assert.equal(classifyPath('third_party/zlib/inflate.c'), 'vendored');
});

test('risk levels move in the right direction', () => {
  const safe = scanRepository([{ path: 'a.cpp', content: 'std::vector<int> v;\nint f(){ return v.at(0); }\n'.repeat(200) }]);
  const bad = scanRepository([{ path: 'a.c', content: 'void f(char*s){ char b[16]; strcpy(b,s); sprintf(b,s); gets(b); }\n'.repeat(50) }]);
  assert.equal(safe.risk.level, 'Low');
  assert.equal(bad.risk.level, 'Critical');
  assert.equal(scanRepository([]).risk.level, 'N/A');
});

test('repo input parsing', () => {
  assert.deepEqual(parseRepoInput('jjoo172/Owl'), { owner: 'jjoo172', repo: 'Owl', ref: undefined });
  assert.deepEqual(parseRepoInput('https://github.com/madler/zlib.git'), { owner: 'madler', repo: 'zlib', ref: undefined });
  assert.deepEqual(parseRepoInput('github.com/a/b/tree/dev'), { owner: 'a', repo: 'b', ref: 'dev' });
  assert.throws(() => parseRepoInput('not a repo'));
});

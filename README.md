# Owl

Provides insights into open-source directories.

Owl scans a GitHub C/C++ repository for memory-unsafe code and rates the risk of
putting it in your critical code path. It looks **only at source code**
(`.c`, `.cc`, `.cpp`, `.h`, `.hpp`, …) — READMEs, docs, build scripts and other
text files are ignored.

## How it works

1. **Download** — streams the repository tarball from GitHub and keeps only C/C++ source files.
2. **Pattern scan** — strips comments and string literals, then checks every line against
   ~20 rules mapped to CWEs:

   | Severity | Examples |
   | --- | --- |
   | Critical | `gets()` |
   | High | `strcpy`/`strcat`, `sprintf`, `scanf("%s")`, non-literal format strings, `alloca`, `system`/`popen`/`exec*` |
   | Medium | `memcpy`/`memmove`, `strncpy`, `n * size` in allocations, `p = realloc(p, …)`, VLAs, `setjmp`/`longjmp`, inline asm, `mprotect`, sanitizer opt-outs |
   | Low | raw `malloc`/`free`, raw `new`/`delete`, `reinterpret_cast`/`const_cast`, fixed stack buffers, `atoi`, `strtok` |

   Test, fuzz, example and benchmark code is labelled and counted at 20% weight; vendored
   (`third_party/`, `contrib/`, …) code is labelled but counted in full.
3. **Risk rating** — severity-weighted hits per 1,000 lines of non-test code give a
   Low / Moderate / High / Critical rating, adjusted for critical/high hits and offset
   notes for modern C++ idioms (smart pointers, spans, containers) and fuzz harnesses.
4. **Expert review (optional)** — if `ANTHROPIC_API_KEY` is set, the most severe hits are
   sent with surrounding code to Claude, prompted as an expert C++ safety researcher, which
   confirms or dismisses them in context and writes the overall risk summary,
   top concerns and recommendations.

Pattern matching finds *candidates*, not confirmed bugs — treat findings as a review checklist.

## Run locally

Requires Node 20+. No dependencies.

```bash
npm start                      # web UI on http://localhost:3000
npm test                       # unit tests

node src/cli.js madler/zlib    # scan from the command line
node src/cli.js --dir ../some-checkout --no-ai
node src/cli.js owner/repo --ref v1.2.3 --json > report.json
```

## Deploying to Render

`render.yaml` defines a free Node web service called `owl-scanner`.

1. In the Render dashboard, choose **New → Blueprint** and select this repository.
2. When prompted, fill in the environment variables:
   - `ANTHROPIC_API_KEY` — enables the expert review step (optional).
   - `GITHUB_TOKEN` — any GitHub token; raises the download limit from 60 to 5,000 per hour (optional).
3. Apply. The app is served at `https://owl-scanner-*.onrender.com`; pushes to `main` redeploy it.

Other optional settings: `ANTHROPIC_MODEL` (default `claude-sonnet-5-5`), `MAX_TARBALL_MB`
(default 300), `MAX_SOURCE_FILES` (default 25000), `MAX_CONCURRENT_SCANS` (default 2).

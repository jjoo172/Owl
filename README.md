# Owl

Provides insights into open-source directories.

Owl scans a GitHub C/C++ repository for memory-unsafe code and rates the risk of
putting it in your critical code path. It looks **only at source code**
(`.c`, `.cc`, `.cpp`, `.h`, `.hpp`, …) — READMEs, docs, build scripts and other
text files are ignored.

## How it works

Every scan runs in two steps.

**Step 1 — access check** (`GET /api/check?repo=…&ref=…`, plain JSON, no scanning). Confirms, one
check at a time and with a reason for each: the address is a GitHub repo, it exists and is public,
the branch/tag/commit resolves to a commit, it contains C/C++, it's within size limits, and the
source archive for that commit actually downloads. It also reports whether the Claude review is
enabled. Step 2 only starts if nothing failed.

**Step 2 — scan** (`POST /api/scan`, streamed progress) of exactly the commit step 1 confirmed:

1. **Download** — streams the source archive for that commit and keeps only C/C++ source files.
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
4. **Expert review (optional)** — if `ANTHROPIC_API_KEY` is set, Claude (prompted as an expert
   C++ safety researcher) reads the source itself: every non-test file when the repo fits in
   ~150k characters, otherwise the highest-risk files in full plus excerpts around other hits.
   It returns a structured review (via a forced tool call) that Owl merges into the results:
   - **new findings** for bugs the patterns can't see (dangling references, invalidated
     iterators, undefined behaviour, data races…), each with file, line, severity and reason;
   - **confirmations** of scanner hits, with the severity Claude judges correct;
   - **dismissals** of scanner hits that are safe in context (kept visible, not counted).

   Severity counts, the issue table, hotspots and the findings list all reflect the merged
   result; every finding is labelled as scanner-only, found by Claude, confirmed or dismissed.
   Findings citing a file or line that doesn't exist are shown with a warning and never counted.

Pattern matching finds *candidates*, not confirmed bugs — treat findings as a review checklist.

## Run locally

Requires Node 20+. No dependencies.

```bash
npm start                      # web UI on http://localhost:3000
npm test                       # unit tests

node src/cli.js madler/zlib    # access check, then scan
node src/cli.js madler/zlib --check-only
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

Make sure you open the **web service** URL. If the page is served by a static site instead,
step 1 reports "scan server isn't answering" because there is no backend to run scans.

Each scan makes three GitHub API calls (repo, commit, languages); without `GITHUB_TOKEN`
GitHub allows 60 per hour, so about 20 scans an hour. The archive download itself is not
rate-limited.

### Cost

The expert review defaults to **Claude Haiku 5.5** — under a cent per scan at Owl's prompt sizes
(well below the 100k-token threshold where Haiku pricing rises). For deeper reviews of subtle
lifetime/UB bugs, set `ANTHROPIC_MODEL=claude-sonnet-5-5` (roughly $0.04–0.15 per scan).
A Claude Max plan includes monthly API credits that can fund this; link them to the Console
organization that owns the key. Results are cached per commit for 30 minutes.

Other optional settings: `ANTHROPIC_MODEL` (default `claude-haiku-5-5`), `AI_SOURCE_BUDGET_CHARS`
(default 150000), `AI_MAX_OUTPUT_TOKENS` (default 8000), `MAX_TARBALL_MB`
(default 300), `MAX_SOURCE_FILES` (default 25000), `MAX_CONCURRENT_SCANS` (default 2).

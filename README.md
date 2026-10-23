# Owl

Provides insights into open-source directories.

Owl scans a GitHub C/C++ repository for memory-unsafe code and rates the risk of
putting it in your critical code path. It looks **only at source code**
(`.c`, `.cc`, `.cpp`, `.h`, `.hpp`, …) — READMEs, docs, build scripts and other
text files are ignored.

## How it works

Every scan runs in two steps.

**Step 1 — access check** (`GET /api/check?repo=…&ref=…`, plain JSON). Confirms, with a reason for
each check, that the address is a GitHub repo, it exists and is public, the branch/tag/commit
resolves to a commit, it contains C/C++, it's within size limits and its source archive downloads.
It also shows which scan tier to expect. Step 2 only starts if nothing failed.

**Step 2 — scan** (`POST /api/scan`, streamed progress) of exactly that commit. Only C/C++ source
files are read (`.c`, `.cc`, `.cpp`, `.h`, `.hpp`, …); docs and other text files are ignored.

- **Full review (default).** Claude, prompted as an expert C++ safety researcher, reads the source
  — every non-test file when the repo fits in ~150k characters, otherwise the riskiest files first —
  and reports every vulnerability it finds: file, line, severity, category, CWE and explanation,
  plus an overall risk rating, a summary and recommendations. That list *is* the result: every
  reported vulnerability is shown and counted, at every severity. A finding whose cited line doesn't
  match the source is still shown, flagged "exact line not found — check nearby".
- **Partial scans are labelled as such.** When a repository is too big for one review (or files are
  skipped for being over 1 MB, or the server's file cap is hit), the result is a *partial scan*: step 1
  forecasts it, the results open with a banner giving the share of code reviewed and why, the rating
  is marked "(partial scan)", and a "Not reviewed" section lists every file that wasn't read.
- **Basic scan (fallback only).** If Claude can't run — no `ANTHROPIC_API_KEY`, the visitor's
  daily budget is used up, API credits have run out, the API is rate-limited or overloaded (after
  one automatic retry), or the review times out — Owl runs a regex pattern scanner instead (~25
  CWE-mapped rules for unbounded copies, format strings, manual memory management, a few lifetime
  patterns, …). The fallback is never silent: basic results open with a banner giving the reason
  and what pattern matching misses, and are never cached so a re-run can get the full review.

Findings come from an automated review (Claude, or pattern matching on a basic scan) — verify each one before acting on it.

## Proposing patches (opt-in)

After a scan, **Propose patches** starts a separate agentic workflow. It never runs unless the user
clicks it. A new Claude agent, seeded with the identity of an expert security software engineer
well-versed in writing secure and memory-safe code, works through the selected vulnerabilities
(critical and high by default; or add medium, or all):

1. It explores the code with read-only tools (`read_file`, `search_code`) to understand each bug:
   callers, buffer sizes, ownership and lifetimes.
2. It fixes each one with `propose_patch`: exact text edits that Owl validates (the old text must
   match exactly one place) and applies to an in-memory copy of the source. A rejected edit is
   returned to the agent to correct. It marks false positives and redesign-sized problems with
   `skip_finding`, then calls `finish` with notes for maintainers.
   Before the session may end, Owl runs an **independent security review of the changed files** and
   sends anything it finds in lines the agent wrote back to the agent to fix (up to two checks). The
   page shows what that check found and anything it still flags.
3. Owl assembles a unified diff of every accepted change. The page shows each patch, the
   vulnerabilities it fixes and why, with its diff, and offers a `.patch` download that applies with
   `git apply` from the repository root.

The page lets the person pick the patch model per run: **Claude Opus 5.5** (default, most capable),
Sonnet 5.5, or Haiku 5.5. Writing correct fixes is harder than spotting bugs, so the default favours
capability; a session on a small repo costs well under a dollar with Opus. The agent uses
`tool_choice: auto` (Opus and Sonnet 5.5 reject forced tool use), a 16k-token allowance per turn
(adaptive thinking counts toward it), automatic prompt caching and append-only history, so thinking
blocks stay valid across turns.

Owl never pushes or opens pull requests: the person reviews, builds and tests the patch themselves.
Tools are strict (schema-validated by the API), turns use prompt caching, and every turn's cost
is reserved against the visitor's daily Claude budget first. A session stops early, keeping its
completed patches, at 40 steps, a $5 session cap, 10 minutes, or when the daily budget runs out.

CLI: `node src/cli.js owner/repo --patch [--out file.patch]`.

### Re-scanning the patched code

After patches are proposed, **Re-scan patched code** runs the original vulnerability review again
on the code with the patches applied, using the same model, the same instructions and the same
files as the first scan (so large repositories are compared like for like). Owl applies the patch
exactly (refusing it if it doesn't match the commit), then shows **before and after** side by side:
the overall risk level, vulnerability counts by severity, and which vulnerabilities were **fixed**,
are **still present** (including ones whose severity changed, and ones a patch targeted but didn't
fix), or are **new**, plus Claude's summary of the patched code. It also reports how many of the
vulnerabilities the patches *targeted* are gone, and splits new findings into those **in lines the
patches changed** (most likely introduced by a patch) and those **elsewhere** (most likely missed by
the first review, or run-to-run variation). Findings are matched across the two reviews by file, by line (moved through the
patch, since patching shifts lines) and by kind of bug. AI reviews vary slightly between runs, so the
page notes that a small difference can be noise. The re-scan costs one more review and counts toward
the daily budget; if it falls back to a basic scan, the comparison is flagged as not like for like.

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

**Spending limits.** Each visitor (identified by IP) can spend at most **$10/day** of Claude
review (`AI_USER_DAILY_BUDGET_USD`); set `AI_DAILY_BUDGET_USD` for an optional site-wide cap.
Before each review Owl reserves its worst-case cost, then settles it with the real cost from the
API's token counts, so simultaneous scans can't overshoot. Over the limit, scans still run without
the review, and step 1 shows each visitor's remaining budget. Limits reset at midnight UTC. They
are kept in memory, so they also reset when the service restarts or sleeps, and IP identity is
best-effort (edge headers first; override with `CLIENT_IP_HEADER`). Keep a spend limit on the API
key's Console workspace as the hard backstop.

Other optional settings: `ANTHROPIC_MODEL` (default `claude-haiku-5-5`), `PATCH_MODEL` (default model for the patch agent; `claude-opus-5-5` unless set), `PATCH_JOB_BUDGET_USD` (default 5), `PATCH_VERIFY_ROUNDS` (default 2), `PATCH_MAX_TURNS` (default 40), `PATCH_MAX_FINDINGS` (default 40), `MAX_CONCURRENT_PATCHES` (default 1), `AI_SOURCE_BUDGET_CHARS`
(default 150000), `AI_MAX_OUTPUT_TOKENS` (default 8000), `MAX_TARBALL_MB`
(default 300), `MAX_SOURCE_FILES` (default 25000), `MAX_CONCURRENT_SCANS` (default 2).

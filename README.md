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
- **Basic scan (fallback only).** If Claude can't run — no `ANTHROPIC_API_KEY`, the visitor's
  daily budget is used up, API credits have run out, the API is rate-limited or overloaded (after
  one automatic retry), or the review times out — Owl runs a regex pattern scanner instead (~25
  CWE-mapped rules for unbounded copies, format strings, manual memory management, a few lifetime
  patterns, …). The fallback is never silent: basic results open with a banner giving the reason
  and what pattern matching misses, and are never cached so a re-run can get the full review.

Findings come from an automated review (Claude, or pattern matching on a basic scan) — verify each one before acting on it.

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

Other optional settings: `ANTHROPIC_MODEL` (default `claude-haiku-5-5`), `AI_SOURCE_BUDGET_CHARS`
(default 150000), `AI_MAX_OUTPUT_TOKENS` (default 8000), `MAX_TARBALL_MB`
(default 300), `MAX_SOURCE_FILES` (default 25000), `MAX_CONCURRENT_SCANS` (default 2).

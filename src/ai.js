import { classifyPath } from './scanner.js';
import { costUsd } from './budget.js';

// How much source (in characters) Claude may read in full. ~150k chars ≈ 40k tokens,
// comfortably under Haiku 5.5's 100k-token pricing threshold.
export const SOURCE_BUDGET = Number(process.env.AI_SOURCE_BUDGET_CHARS || 150_000);

const SYSTEM_PROMPT = `You are an expert C++ safety researcher, who is well-versed in common memory vulnerabilities and exploits. We want to use your expertise to scan a given github codebase, and identify all areas in the code that look to be risky (e.g. memory-unsafe code). Then, provide a general summary of the overall risk level of introducing this open source repository into your critical code path. Look only at the source code to determine risk level, ignoring text-based documents.

You will receive the repository's C/C++ source, line-numbered: every non-test source file when the repository is small enough, otherwise the highest-risk files (with a list of the files you were not shown).

Review it as a security auditor would, file by file. Look for every vulnerability, including:
- Lifetime bugs: dangling references/pointers/string_views/spans (including views into buffers that are later reused or freed), references to temporaries (including default arguments and members of temporaries in range-for), returning references to locals, lambdas capturing by reference that outlive their scope.
- Invalidation: holding references, pointers or iterators into containers across push_back/insert/erase/rehash.
- Undefined behaviour: signed integer overflow, oversized or negative shifts, misaligned access and strict-aliasing violations via reinterpret_cast/type punning, out-of-bounds reads/writes, unsigned wraparound in bounds checks (e.g. offset + size overflowing), lengths never checked against the real buffer, comparators that are not strict weak orderings, use of moved-from objects, uninitialised reads.
- Concurrency: data races on non-atomic state, unsynchronised containers, captured references shared across threads.
- Classic C issues: unbounded copies (strcpy, sprintf, gets), format strings, manual malloc/free mistakes, integer overflow in allocation sizes, command injection.

Report your results as a single JSON object in the required format, listing the findings first:
- findings: every distinct vulnerability you are confident about, one entry per bug (not per theme), at the line where it occurs, ordered by severity. Cite only path:line locations from the numbered source you were shown — never invent code. Include low-severity issues too.
- Severity: critical = likely exploitable memory corruption; high = memory-unsafe or UB that can corrupt/leak memory or crash; medium = UB or misuse that is dangerous under plausible conditions; low = hardening issue or fragile code.
- overall_risk reflects the risk of putting this code in a critical path. If you only saw part of the repository, say how that limits your confidence in the summary.
- critical_path: your direct answer to whether it is reasonable to rely on this library, as the code stands now, in a critical code path. verdict is "yes" (reasonable as is), "conditional" (reasonable only after specific steps or with specific limits on how it is used) or "no" (not reasonable until the problems are fixed). analysis is 1-2 short paragraphs justifying it: which remaining issues decide it, how likely they are to be hit by realistic inputs, what the conditions are for a "conditional" verdict, and how much a partial view limits your confidence.`;

// Signals that a file is worth reading first when the whole repo doesn't fit.
const RISK_SIGNALS =
  /std::(?:string_view|span)|\[&|\bstd::thread\b|std::async|\.detach\s*\(|reinterpret_cast|\.data\s*\(\)|<<\s*[a-z_]|\bstd::sort\b|\b(?:memcpy|memmove|strcpy|strcat|sprintf|gets|alloca|malloc|realloc|free|system|popen)\s*\(|\bnew\b|\bdelete\b/g;

function numbered(content) {
  return content
    .split('\n')
    .map((l, i) => `${String(i + 1).padStart(5)} ${l}`)
    .join('\n');
}

/** Re-measures a selection's sizes against `contentByPath` (e.g. after patching). */
function sameSelection(selection, contentByPath) {
  const size = (p) => (contentByPath.get(p) || '').length;
  const pool = [...selection.files, ...selection.skipped];
  const reviewedChars = Math.min(selection.mode === 'full' ? Infinity : SOURCE_BUDGET, selection.files.reduce((n, p) => n + size(p), 0));
  return { ...selection, reviewedChars, totalChars: pool.reduce((n, p) => n + size(p), 0) };
}

/** Chooses which files Claude reads, within the character budget (riskiest first). */
export function selectSourceForReview(contentByPath, budget = SOURCE_BUDGET) {
  const all = [...contentByPath.entries()];
  const nonTest = all.filter(([p]) => classifyPath(p) !== 'test');
  const pool = nonTest.length ? nonTest : all;
  const total = pool.reduce((s, [, c]) => s + c.length, 0);
  if (total <= budget) {
    return { mode: 'full', files: pool.map(([path]) => path), skipped: [], totalFiles: pool.length, reviewedChars: total, totalChars: total };
  }

  const ranked = pool
    .map(([path, content]) => ({
      path,
      size: content.length,
      // Density of risky constructs, with a nudge towards production (non-vendored) code.
      score: ((content.match(RISK_SIGNALS) || []).length / Math.max(1, content.length / 1000)) * (classifyPath(path) === 'vendored' ? 0.5 : 1),
    }))
    .sort((a, b) => b.score - a.score);

  const files = [];
  let used = 0;
  for (const f of ranked) {
    if (f.size > budget / 2) continue; // one giant file shouldn't crowd out everything else
    if (used + f.size > budget) continue;
    files.push(f.path);
    used += f.size;
  }
  // Always give Claude something to read: fall back to the top-ranked file, truncated to fit.
  if (!files.length && ranked.length) files.push(ranked[0].path);
  const chosen = new Set(files);
  // A lone oversized file is sent truncated to the budget, so count at most that much of it.
  const reviewedChars = Math.min(budget, ranked.filter((f) => chosen.has(f.path)).reduce((n, f) => n + f.size, 0));
  return { mode: 'partial', files, skipped: pool.map(([p]) => p).filter((p) => !chosen.has(p)), totalFiles: pool.length, reviewedChars, totalChars: total };
}

export function aiAvailable() {
  return Boolean(process.env.ANTHROPIC_API_KEY);
}

const SEVERITY_ENUM = ['critical', 'high', 'medium', 'low'];

// The review's shape, enforced by the API's structured outputs (output_config.format), so the
// response is always valid JSON in this shape. Structured outputs require additionalProperties:
// false and don't support maxItems/minimum. Fields come out in this order, so the vulnerabilities
// are listed before the rating and summary that are drawn from them.
export const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      description: 'Every distinct vulnerability, one entry per bug, most severe first.',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'Short name of the bug, e.g. "Dangling string_view into reused line buffer".' },
          severity: { type: 'string', enum: SEVERITY_ENUM },
          category: { type: 'string', description: 'e.g. Use-after-free, Dangling reference, Out-of-bounds read, Signed integer overflow, Data race, Strict aliasing, Buffer overflow.' },
          cwe: { type: 'string', description: 'e.g. CWE-416, or an empty string if none fits.' },
          file: { type: 'string', description: 'Path exactly as shown in the source headers.' },
          line: { type: 'integer', description: 'Line number from the numbered source (1 or more).' },
          detail: { type: 'string', description: 'Why this is a bug and how it fails, 1-3 sentences.' },
        },
        required: ['title', 'severity', 'category', 'cwe', 'file', 'line', 'detail'],
        additionalProperties: false,
      },
    },
    overall_risk: { type: 'string', enum: ['Low', 'Moderate', 'High', 'Critical'] },
    summary: { type: 'string', description: '2-4 short paragraphs: what the code does, dominant risk themes, and whether it is reasonable for a critical path.' },
    critical_path: {
      type: 'object',
      description: 'Whether it is reasonable to rely on this library, as the code stands now, in a critical code path.',
      properties: {
        verdict: { type: 'string', enum: ['yes', 'conditional', 'no'] },
        analysis: { type: 'string', description: '1-2 short paragraphs: the deciding issues, how likely they are to be hit, any conditions, and confidence.' },
      },
      required: ['verdict', 'analysis'],
      additionalProperties: false,
    },
    recommendations: { type: 'array', description: 'Up to 8 concrete steps before adopting this code.', items: { type: 'string' } },
  },
  required: ['findings', 'overall_risk', 'summary', 'critical_path', 'recommendations'],
  additionalProperties: false,
};

export const DEFAULT_MODEL = 'claude-haiku-5-5';

const REVIEW_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 600_000); // whole review, both attempts
// One call. Responses aren't streamed, so the call must finish before Node's fetch gives up waiting
// for response headers (300 s); max_tokens is sized to fit inside that.
const CALL_TIMEOUT_MS = Number(process.env.AI_CALL_TIMEOUT_MS || 285_000);
const RETRY_DELAY_MS = Number(process.env.AI_RETRY_DELAY_MS || 3000);
const TRANSIENT = new Set([429, 500, 502, 503, 504, 529]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Claude's review couldn't run; `reason` is a plain-language explanation for the user. */
export class ReviewUnavailableError extends Error {
  constructor(reason, code) {
    super(reason);
    this.code = code;
  }
}

export function unavailableFromResponse(status, data) {
  const msg = String(data?.error?.message || '');
  if (/credit balance/i.test(msg)) return new ReviewUnavailableError("The server's Claude API credits have run out", 'credits');
  if (status === 401 || status === 403) return new ReviewUnavailableError("The server's Claude API key was rejected", 'auth');
  if (status === 429) return new ReviewUnavailableError("Claude's API rate limit was reached", 'rate_limit');
  if (status === 529 || status === 503) return new ReviewUnavailableError('Claude is temporarily overloaded', 'overloaded');
  return new ReviewUnavailableError(`Claude's API returned an error (${status}${msg ? `: ${msg.slice(0, 120)}` : ''})`, 'api_error');
}


/**
 * `selectionFrom` (optional) = the source whose file selection to reuse. A re-scan of patched code
 * passes the original source, so Claude reads exactly the same files as the scan it is compared with.
 */
export function buildReviewRequest({ repo, contentByPath, selectionFrom }) {
  const selection = sameSelection(selectSourceForReview(selectionFrom || contentByPath), contentByPath);
  const fullSource = selection.files
    .map((p) => {
      let src = numbered(contentByPath.get(p));
      if (src.length > SOURCE_BUDGET) src = src.slice(0, SOURCE_BUDGET) + '\n… [file truncated]';
      return `### FILE ${p}\n\`\`\`cpp\n${src}\n\`\`\``;
    })
    .join('\n\n');

  const coverage =
    selection.mode === 'full'
      ? `All ${selection.totalFiles} non-test C/C++ source files are included below.`
      : `${selection.files.length} of ${selection.totalFiles} non-test C/C++ source files are included below (riskiest first). Not shown: ${selection.skipped.slice(0, 300).join(', ')}${selection.skipped.length > 300 ? ', …' : ''}.`;

  const userContent = `Repository: ${repo.owner}/${repo.repo}${repo.ref ? '@' + repo.ref : ''}\n${coverage}\n\n${fullSource}`;
  return { userContent, selection };
}

export function estimateReviewCost(model, userContent, maxTokens) {
  const inputTokens = Math.ceil((SYSTEM_PROMPT.length + JSON.stringify(REVIEW_SCHEMA).length + userContent.length) / 3);
  return costUsd(model, inputTokens, maxTokens);
}

/**
 * Runs the review. `budget` ({ ledger, clientId }) is optional: when given, the call's
 * worst-case cost is reserved first (throwing BudgetExceededError if over a limit) and then
 * settled with the real cost from the API's reported token usage.
 */
const tryJson = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};
const toLine = (v) => {
  const n = parseInt(String(v ?? '').match(/\d+/)?.[0] ?? '', 10);
  return Number.isInteger(n) && n > 0 ? n : undefined;
};

/**
 * Accepts the shapes models actually produce for the review tool, not just the ideal one:
 * lists sent as JSON text, the review nested one level down, and common field-name variants.
 * Returns { review } or { problem } (a short description for the logs; never the content).
 */
export function normalizeReview(input) {
  let r = typeof input === 'string' ? tryJson(input) : input;
  if (r && typeof r === 'object' && !Array.isArray(r) && !('findings' in r)) {
    const nested = r.review ?? r.result ?? r.report;
    if (nested && typeof nested === 'object') r = nested;
  }
  if (!r || typeof r !== 'object' || Array.isArray(r)) return { problem: `review was ${Array.isArray(r) ? 'an array' : typeof r}` };

  const asList = (v) => {
    if (Array.isArray(v)) return v;
    if (typeof v === 'string') {
      const parsed = tryJson(v);
      if (Array.isArray(parsed)) return parsed;
      if (parsed && Array.isArray(parsed.findings)) return parsed.findings;
    }
    if (v && typeof v === 'object' && Array.isArray(v.items)) return v.items;
    return undefined;
  };
  // Prefer whichever field actually holds vulnerabilities; an empty `findings` mustn't hide a full alias.
  const lists = [r.findings, r.vulnerabilities, r.issues].map(asList).filter(Boolean);
  const list = lists.find((l) => l.length) ?? lists[0];
  if (!list) return { problem: `findings was ${r.findings === undefined ? 'missing' : typeof r.findings} (keys: ${Object.keys(r).join(', ')})` };

  const findings = list
    .map((f) => (typeof f === 'string' ? tryJson(f) : f))
    .filter((f) => f && typeof f === 'object')
    .map((f) => {
      const file = f.file ?? f.path ?? f.file_path ?? f.filename ?? f.location;
      const line = toLine(f.line ?? f.line_number ?? f.lineNumber ?? f.start_line) ?? toLine(String(file ?? '').match(/:(\d+)/)?.[1]);
      return { ...f, file, line, title: f.title ?? f.name ?? f.summary, detail: f.detail ?? f.description ?? f.explanation };
    });
  const recommendations = (asList(r.recommendations) ?? []).map(String);
  const risk = String(r.overall_risk ?? '').trim().toLowerCase();
  const overall_risk = ['low', 'moderate', 'high', 'critical'].includes(risk) ? risk[0].toUpperCase() + risk.slice(1) : r.overall_risk;
  return { review: { ...r, overall_risk, findings, recommendations: recommendations.slice(0, 8), summary: String(r.summary ?? ''), critical_path: normalizeCriticalPath(r.critical_path) } };
}

/** { verdict: 'yes' | 'conditional' | 'no', analysis } or null if the review didn't give one. */
export function normalizeCriticalPath(v) {
  if (typeof v === 'string') v = tryJson(v) ?? { analysis: v };
  if (!v || typeof v !== 'object') return null;
  const raw = String(v.verdict ?? v.answer ?? '').trim().toLowerCase().replace(/[\s_-]+/g, ' ');
  const verdict = /condition|only if|caveat|with /.test(raw) ? 'conditional' : /^(no|not)\b/.test(raw) ? 'no' : /^(yes|reasonable|ok|safe)\b/.test(raw) ? 'yes' : null;
  const analysis = String(v.analysis ?? v.reasoning ?? v.explanation ?? '').trim();
  return verdict || analysis ? { verdict, analysis } : null;
}

const HIGH_RATINGS = new Set(['High', 'Critical']);

/** Plain-language reason for the page when both attempts were unusable. */
function reasonFor(problem = '') {
  if (/cut off/.test(problem)) return "Claude's review was cut off before it finished, twice";
  if (problem === 'refusal') return 'Claude declined to review this code';
  const rated = problem.match(/^rated (\w+) but listed no findings/);
  if (rated) return `Claude rated the code ${rated[1]} but listed no specific vulnerabilities, twice`;
  return "Claude's review came back in a form Owl couldn't use, twice";
}

/**
 * Runs the review. `budget` ({ ledger, clientId }) is optional: when given, the call's
 * worst-case cost is reserved first (throwing BudgetExceededError if over a limit) and then
 * settled with the real cost from the API's reported token usage.
 */
export async function aiReview({ budget, trace = () => {}, traceLabel = 'review', ...args }) {
  const { userContent, selection } = buildReviewRequest(args);
  const model = process.env.ANTHROPIC_MODEL || DEFAULT_MODEL;
  // Adaptive thinking counts toward max_tokens, so leave room for it plus a long findings list:
  // at 16k, Haiku 5.5 regularly spent the whole allowance thinking and was cut off before answering.
  const maxTokens = Number(process.env.AI_MAX_OUTPUT_TOKENS || 40000);

  const reservedUsd = estimateReviewCost(model, userContent, maxTokens);
  trace(`${traceLabel}_request`, {
    model,
    maxTokens,
    mode: selection.mode,
    filesInFull: selection.files.length,
    totalFiles: selection.totalFiles,
    reviewedChars: selection.reviewedChars,
    totalChars: selection.totalChars,
    promptChars: userContent.length,
    reservedUsd,
    files: selection.files.map((f) => f.path ?? f),
    skipped: selection.skipped,
  });
  const reservation = budget ? budget.ledger.reserve(budget.clientId, reservedUsd) : null;
  let spent = 0;
  let costKnown = true; // false once a call may have been billed without us seeing its usage

  // effort: undefined = the model's default; 'low' for a retry after the first answer was cut off,
  // so the model thinks less and leaves room for the findings (the API docs' remedy for max_tokens stops).
  const bodyFor = (effort) =>
    JSON.stringify({
      model,
      max_tokens: maxTokens,
      system: SYSTEM_PROMPT,
      output_config: { format: { type: 'json_schema', schema: REVIEW_SCHEMA }, ...(effort ? { effort } : {}) },
      messages: [{ role: 'user', content: userContent }],
    });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REVIEW_TIMEOUT_MS);

  /** One API request, with one retry for temporary trouble (rejected calls aren't billed). */
  const send = async (effort) => {
    let res;
    let data;
    const body = bodyFor(effort);
    for (let attempt = 1; ; attempt++) {
      const t0 = Date.now();
      try {
        res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(CALL_TIMEOUT_MS)]),
          headers: { 'content-type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
          body,
        });
        data = await res.json().catch(() => ({}));
      } catch (err) {
        const timedOut = err.name === 'AbortError' || err.name === 'TimeoutError';
        trace(`${traceLabel}_api_call`, { attempt, effort: effort || 'default', ms: Date.now() - t0, error: timedOut ? 'timeout' : `network: ${err.message}` });
        if (timedOut) {
          costKnown = false;
          throw new ReviewUnavailableError("Claude's review took too long", 'timeout');
        }
        if (attempt < 2) {
          await sleep(RETRY_DELAY_MS);
          continue;
        }
        throw new ReviewUnavailableError("The server couldn't reach Claude's API", 'network');
      }
      trace(`${traceLabel}_api_call`, {
        attempt,
        effort: effort || 'default',
        status: res.status,
        ms: Date.now() - t0,
        model: data.model,
        stopReason: data.stop_reason,
        usage: data.usage,
        costUsd: data.usage ? costUsd(data.model || model, data.usage.input_tokens || 0, data.usage.output_tokens || 0) : 0,
        ...(res.ok ? {} : { error: data.error?.message || data.error?.type || `HTTP ${res.status}` }),
      });
      if (res.ok || !TRANSIENT.has(res.status) || attempt >= 2) break;
      await sleep(Math.min(Number(res.headers.get('retry-after')) * 1000 || RETRY_DELAY_MS, 8000));
    }
    if (data.usage) spent += costUsd(data.model || model, data.usage.input_tokens || 0, data.usage.output_tokens || 0);
    if (!res.ok) throw unavailableFromResponse(res.status, data);
    return data;
  };

  try {
    // A response we can't use (malformed, cut off, or a High rating with no findings listed) gets one more try.
    let lastProblem = null;
    for (let attempt = 1; attempt <= 2; attempt++) {
      const data = await send(attempt > 1 && /cut off/.test(lastProblem || '') ? 'low' : undefined);
      const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
      trace(`${traceLabel}_output`, { attempt, stopReason: data.stop_reason, chars: text.length, text: text.length > 300_000 ? text.slice(0, 300_000) + '… [cut]' : text });
      let problem = null;
      let review = null;
      if (data.stop_reason === 'max_tokens') problem = 'cut off at the output limit';
      else if (data.stop_reason === 'refusal') problem = 'refusal';
      else if (!text.trim()) problem = 'no review in the response';
      else {
        const parsed = tryJson(text);
        if (parsed === undefined) problem = 'response was not valid JSON';
        else {
          ({ review, problem } = normalizeReview(parsed));
          if (review && review.findings.length === 0 && HIGH_RATINGS.has(review.overall_risk)) {
            problem = `rated ${review.overall_risk} but listed no findings`;
            review = null;
          }
        }
      }
      if (review) {
        trace(`${traceLabel}_ok`, { attempt, overallRisk: review.overall_risk, criticalPath: review.critical_path, findings: review.findings.length, costUsd: spent });
        return {
          review,
          meta: {
            model: data.model,
            usage: data.usage,
            costUsd: spent,
            attempts: attempt,
            coverage: {
              mode: selection.mode,
              filesInFull: selection.files.length,
              totalFiles: selection.totalFiles,
              reviewedChars: selection.reviewedChars,
              totalChars: selection.totalChars,
              skipped: selection.skipped,
            },
          },
        };
      }
      lastProblem = problem;
      trace(`${traceLabel}_unusable`, { attempt, problem });
      console.warn(`Claude review unusable (attempt ${attempt}): ${problem}`);
    }
    throw new ReviewUnavailableError(reasonFor(lastProblem), 'format');
  } finally {
    clearTimeout(timer);
    if (reservation !== null) budget.ledger.settle(reservation, costKnown ? spent : Math.max(spent, budget.ledger.reservations.get(reservation)?.usd ?? spent));
  }
}

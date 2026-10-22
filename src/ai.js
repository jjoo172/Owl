import { classifyPath } from './scanner.js';
import { costUsd } from './budget.js';

// How much source (in characters) Claude may read in full. ~150k chars ≈ 40k tokens,
// comfortably under Haiku 5.5's 100k-token pricing threshold.
const SOURCE_BUDGET = Number(process.env.AI_SOURCE_BUDGET_CHARS || 150_000);

const SYSTEM_PROMPT = `You are an expert C++ safety researcher, who is well-versed in common memory vulnerabilities and exploits. We want to use your expertise to scan a given github codebase, and identify all areas in the code that look to be risky (e.g. memory-unsafe code). Then, provide a general summary of the overall risk level of introducing this open source repository into your critical code path. Look only at the source code to determine risk level, ignoring text-based documents.

You will receive the repository's C/C++ source, line-numbered: every non-test source file when the repository is small enough, otherwise the highest-risk files (with a list of the files you were not shown).

Review it as a security auditor would, file by file. Look for every vulnerability, including:
- Lifetime bugs: dangling references/pointers/string_views/spans (including views into buffers that are later reused or freed), references to temporaries (including default arguments and members of temporaries in range-for), returning references to locals, lambdas capturing by reference that outlive their scope.
- Invalidation: holding references, pointers or iterators into containers across push_back/insert/erase/rehash.
- Undefined behaviour: signed integer overflow, oversized or negative shifts, misaligned access and strict-aliasing violations via reinterpret_cast/type punning, out-of-bounds reads/writes, unsigned wraparound in bounds checks (e.g. offset + size overflowing), lengths never checked against the real buffer, comparators that are not strict weak orderings, use of moved-from objects, uninitialised reads.
- Concurrency: data races on non-atomic state, unsynchronised containers, captured references shared across threads.
- Classic C issues: unbounded copies (strcpy, sprintf, gets), format strings, manual malloc/free mistakes, integer overflow in allocation sizes, command injection.

Report your results by calling the report_review tool exactly once:
- findings: every distinct vulnerability you are confident about, one entry per bug (not per theme), at the line where it occurs, ordered by severity. Cite only path:line locations from the numbered source you were shown — never invent code. Include low-severity issues too.
- Severity: critical = likely exploitable memory corruption; high = memory-unsafe or UB that can corrupt/leak memory or crash; medium = UB or misuse that is dangerous under plausible conditions; low = hardening issue or fragile code.
- overall_risk reflects the risk of putting this code in a critical path. If you only saw part of the repository, say how that limits your confidence in the summary.`;

// Signals that a file is worth reading first when the whole repo doesn't fit.
const RISK_SIGNALS =
  /std::(?:string_view|span)|\[&|\bstd::thread\b|std::async|\.detach\s*\(|reinterpret_cast|\.data\s*\(\)|<<\s*[a-z_]|\bstd::sort\b|\b(?:memcpy|memmove|strcpy|strcat|sprintf|gets|alloca|malloc|realloc|free|system|popen)\s*\(|\bnew\b|\bdelete\b/g;

function numbered(content) {
  return content
    .split('\n')
    .map((l, i) => `${String(i + 1).padStart(5)} ${l}`)
    .join('\n');
}

/** Chooses which files Claude reads, within the character budget (riskiest first). */
export function selectSourceForReview(contentByPath, budget = SOURCE_BUDGET) {
  const all = [...contentByPath.entries()];
  const nonTest = all.filter(([p]) => classifyPath(p) !== 'test');
  const pool = nonTest.length ? nonTest : all;
  const total = pool.reduce((s, [, c]) => s + c.length, 0);
  if (total <= budget) {
    return { mode: 'full', files: pool.map(([path]) => path), skipped: [], totalFiles: pool.length };
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
  return { mode: 'partial', files, skipped: pool.map(([p]) => p).filter((p) => !chosen.has(p)), totalFiles: pool.length };
}

export function aiAvailable() {
  return Boolean(process.env.ANTHROPIC_API_KEY);
}

const SEVERITY_ENUM = ['critical', 'high', 'medium', 'low'];
const REVIEW_TOOL = {
  name: 'report_review',
  description: 'Report the security review of this repository.',
  input_schema: {
    type: 'object',
    properties: {
      overall_risk: { type: 'string', enum: ['Low', 'Moderate', 'High', 'Critical'] },
      summary: { type: 'string', description: '2-4 short paragraphs: what the code does, dominant risk themes, and whether it is reasonable for a critical path.' },
      findings: {
        type: 'array',
        maxItems: 60,
        items: {
          type: 'object',
          properties: {
            title: { type: 'string', description: 'Short name of the bug, e.g. "Dangling string_view into reused line buffer".' },
            severity: { type: 'string', enum: SEVERITY_ENUM },
            category: { type: 'string', description: 'e.g. Use-after-free, Dangling reference, Out-of-bounds read, Signed integer overflow, Data race, Strict aliasing, Buffer overflow.' },
            cwe: { type: 'string', description: 'e.g. CWE-416. Optional.' },
            file: { type: 'string', description: 'Path exactly as shown in the source headers.' },
            line: { type: 'integer', minimum: 1 },
            detail: { type: 'string', description: 'Why this is a bug and how it fails, 1-3 sentences.' },
          },
          required: ['title', 'severity', 'category', 'file', 'line', 'detail'],
        },
      },
      recommendations: { type: 'array', items: { type: 'string' }, maxItems: 8 },
    },
    required: ['overall_risk', 'summary', 'findings', 'recommendations'],
  },
};

export const DEFAULT_MODEL = 'claude-haiku-5-5';

const REVIEW_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 180_000);
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

function unavailableFromResponse(status, data) {
  const msg = String(data?.error?.message || '');
  if (/credit balance/i.test(msg)) return new ReviewUnavailableError("The server's Claude API credits have run out", 'credits');
  if (status === 401 || status === 403) return new ReviewUnavailableError("The server's Claude API key was rejected", 'auth');
  if (status === 429) return new ReviewUnavailableError("Claude's API rate limit was reached", 'rate_limit');
  if (status === 529 || status === 503) return new ReviewUnavailableError('Claude is temporarily overloaded', 'overloaded');
  return new ReviewUnavailableError(`Claude's API returned an error (${status}${msg ? `: ${msg.slice(0, 120)}` : ''})`, 'api_error');
}


export function buildReviewRequest({ repo, contentByPath }) {
  const selection = selectSourceForReview(contentByPath);
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
  const inputTokens = Math.ceil((SYSTEM_PROMPT.length + JSON.stringify(REVIEW_TOOL).length + userContent.length) / 3);
  return costUsd(model, inputTokens, maxTokens);
}

/**
 * Runs the review. `budget` ({ ledger, clientId }) is optional: when given, the call's
 * worst-case cost is reserved first (throwing BudgetExceededError if over a limit) and then
 * settled with the real cost from the API's reported token usage.
 */
export async function aiReview({ budget, ...args }) {
  const { userContent, selection } = buildReviewRequest(args);
  const model = process.env.ANTHROPIC_MODEL || DEFAULT_MODEL;
  const maxTokens = Number(process.env.AI_MAX_OUTPUT_TOKENS || 8000);

  const reservation = budget ? budget.ledger.reserve(budget.clientId, estimateReviewCost(model, userContent, maxTokens)) : null;
  let actualCost = null; // null = unknown (e.g. timed out after sending): keep the reservation

  const body = JSON.stringify({
    model,
    max_tokens: maxTokens,
    system: SYSTEM_PROMPT,
    tools: [REVIEW_TOOL],
    tool_choice: { type: 'tool', name: REVIEW_TOOL.name },
    messages: [{ role: 'user', content: userContent }],
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REVIEW_TIMEOUT_MS);
  try {
    let res;
    let data;
    // One retry for temporary trouble (rate limit, overload, network blip); rejected calls aren't billed.
    for (let attempt = 1; ; attempt++) {
      try {
        res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          signal: controller.signal,
          headers: { 'content-type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
          body,
        });
      } catch (err) {
        if (err.name === 'AbortError') throw new ReviewUnavailableError("Claude's review took too long", 'timeout');
        if (attempt < 2) {
          await sleep(RETRY_DELAY_MS);
          continue;
        }
        actualCost = 0;
        throw new ReviewUnavailableError("The server couldn't reach Claude's API", 'network');
      }
      data = await res.json().catch(() => ({}));
      if (res.ok || !TRANSIENT.has(res.status) || attempt >= 2) break;
      const wait = Math.min(Number(res.headers.get('retry-after')) * 1000 || RETRY_DELAY_MS, 8000);
      await sleep(wait);
    }
    if (data.usage) actualCost = costUsd(data.model || model, data.usage.input_tokens || 0, data.usage.output_tokens || 0);
    else if (!res.ok) actualCost = 0; // rejected requests aren't billed
    if (!res.ok) throw unavailableFromResponse(res.status, data);
    const call = (data.content || []).find((b) => b.type === 'tool_use' && b.name === REVIEW_TOOL.name);
    if (!call?.input) {
      throw new ReviewUnavailableError("Claude's review came back incomplete", 'incomplete');
    }
    if (data.stop_reason === 'max_tokens') throw new ReviewUnavailableError("Claude's review was cut off before it finished", 'incomplete');
    return {
      review: call.input,
      meta: {
        model: data.model,
        usage: data.usage,
        costUsd: actualCost,
        coverage: { mode: selection.mode, filesInFull: selection.files.length, totalFiles: selection.totalFiles },
      },
    };
  } finally {
    clearTimeout(timer);
    if (reservation !== null && actualCost !== null) budget.ledger.settle(reservation, actualCost);
  }
}

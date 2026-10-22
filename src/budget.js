// Daily spend limits for the Claude review, per visitor (by IP) and optionally site-wide.
//
// Before each Claude call we reserve its worst-case cost; afterwards we settle it with the
// real cost from the API's token usage. Reserving first means concurrent scans can't jointly
// overshoot a limit. Counters live in memory and reset at midnight UTC — and also whenever the
// server restarts (Render's free plan sleeps when idle), so pair this with a spend limit on the
// API key in the Claude Console as the hard backstop.

// USD per million tokens (https://platform.claude.com/docs/en/about-claude/pricing).
// Haiku 5.5 is priced by prompt length: prompts over 100k input tokens cost more.
const RATES = [
  { prefix: 'claude-haiku-5-5', tiers: [{ upTo: 100_000, input: 0.1, output: 0.5 }, { input: 0.5, output: 2.5 }] },
  { prefix: 'claude-sonnet-5-5', tiers: [{ input: 2, output: 10 }] },
  { prefix: 'claude-sonnet-5', tiers: [{ input: 2, output: 10 }] },
  { prefix: 'claude-opus-5-5', tiers: [{ input: 4, output: 20 }] },
  { prefix: 'claude-haiku-4-5', tiers: [{ input: 1, output: 5 }] },
];
// Unknown models are priced conservatively (most expensive known rate).
const FALLBACK = { input: 4, output: 20 };

export function costUsd(model, inputTokens, outputTokens) {
  const entry = RATES.find((r) => String(model || '').startsWith(r.prefix));
  const tier = entry ? entry.tiers.find((t) => t.upTo === undefined || inputTokens <= t.upTo) : FALLBACK;
  return (inputTokens * tier.input + outputTokens * tier.output) / 1_000_000;
}

const envUsd = (name, fallback) => {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
};

export class BudgetExceededError extends Error {}

export class DailyBudget {
  constructor({ perUserUsd = envUsd('AI_USER_DAILY_BUDGET_USD', 10), globalUsd = envUsd('AI_DAILY_BUDGET_USD', null), now = () => Date.now() } = {}) {
    this.perUserUsd = perUserUsd;
    this.globalUsd = globalUsd;
    this.now = now;
    this.day = null;
    this.reset();
  }

  reset() {
    this.day = this.dayKey();
    this.users = new Map(); // clientId -> USD committed today (reserved + settled)
    this.global = 0;
    this.reservations = new Map();
    this.nextId = 1;
  }

  dayKey() {
    return new Date(this.now()).toISOString().slice(0, 10); // UTC date
  }

  rollover() {
    if (this.dayKey() !== this.day) this.reset();
  }

  /** Seconds until counters reset (next midnight UTC). */
  resetsInSeconds() {
    const d = new Date(this.now());
    const next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
    return Math.ceil((next - d.getTime()) / 1000);
  }

  spent(clientId) {
    this.rollover();
    return this.users.get(clientId) || 0;
  }

  /** What this visitor can still spend today, accounting for the site-wide cap too. */
  remaining(clientId) {
    this.rollover();
    let left = this.perUserUsd === null ? Infinity : this.perUserUsd - this.spent(clientId);
    if (this.globalUsd !== null) left = Math.min(left, this.globalUsd - this.global);
    return Math.max(0, left);
  }

  /** Reserves `usd` for a call. Throws BudgetExceededError if it would break a limit. */
  reserve(clientId, usd) {
    this.rollover();
    const hours = Math.max(1, Math.round(this.resetsInSeconds() / 3600));
    const when = `resets at midnight UTC, in about ${hours} h`;
    if (this.perUserUsd !== null && this.spent(clientId) + usd > this.perUserUsd) {
      const left = Math.max(0, this.perUserUsd - this.spent(clientId));
      throw new BudgetExceededError(
        left <= 0
          ? `You've used today's $${fmtUsd(this.perUserUsd)} budget for Claude reviews (${when}). Showing scanner results only.`
          : `This review could cost up to $${fmtUsd(usd)}, but only $${fmtUsd(left)} of your $${fmtUsd(this.perUserUsd)} daily Claude budget is left (${when}). Showing scanner results only.`,
      );
    }
    if (this.globalUsd !== null && this.global + usd > this.globalUsd) {
      throw new BudgetExceededError(`This site has reached its daily budget for Claude reviews (${when}). Showing scanner results only.`);
    }
    const id = this.nextId++;
    this.users.set(clientId, this.spent(clientId) + usd);
    this.global += usd;
    this.reservations.set(id, { clientId, usd, day: this.day });
    return id;
  }

  /** Replaces a reservation with the actual cost (0 if the call failed before billing). */
  settle(id, actualUsd) {
    const r = this.reservations.get(id);
    if (!r) return;
    this.reservations.delete(id);
    if (r.day !== this.day) return; // reserved before a rollover; nothing to adjust
    const delta = actualUsd - r.usd;
    this.users.set(r.clientId, Math.max(0, (this.users.get(r.clientId) || 0) + delta));
    this.global = Math.max(0, this.global + delta);
  }
}

export function fmtUsd(n) {
  return n >= 1 ? n.toFixed(2) : n.toFixed(n >= 0.1 ? 2 : 3);
}

/**
 * Best-effort visitor identity. Render sits behind Cloudflare, whose CF-Connecting-IP /
 * True-Client-IP headers are set at the edge; X-Forwarded-For may contain client-supplied
 * values, so it is only a fallback. Override with CLIENT_IP_HEADER if your setup differs.
 */
export function clientIdOf(req) {
  const h = req.headers;
  const custom = process.env.CLIENT_IP_HEADER?.toLowerCase();
  const pick = (v) => (Array.isArray(v) ? v[0] : v)?.split(',')[0]?.trim();
  return (
    (custom && pick(h[custom])) ||
    pick(h['cf-connecting-ip']) ||
    pick(h['true-client-ip']) ||
    pick(h['x-forwarded-for']) ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

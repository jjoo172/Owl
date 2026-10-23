const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmt = (n) => Number(n || 0).toLocaleString();
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEV_COLOR = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };

const form = $('#scan-form');
const stepsEl = $('#steps');
const errorEl = $('#error');
const resultsEl = $('#results');
const btn = $('#scan-btn');

const NO_SERVER_MESSAGE =
  "Owl's scan server isn't answering on this site, so scans can't run. This usually means the page is being " +
  'served by a static site; open the "owl-scanner" web service deployed from render.yaml instead.';

let current = null;
let server = { ai: false, patchModel: null, patchModels: [] };
let patchRun = 0; // bumps on every new scan or patch request, so stale streams are ignored

// ---------- setup ----------
// Results wait for this, so features that depend on the server (the patch agent) never miss it.
const serverReady = fetch('/api/health', { cache: 'no-store' })
  .then((r) => r.json())
  .then(({ ai, model, patchModel, patchModels }) => {
    server = { ai, patchModel, patchModels: patchModels || [] };
    $('#ai-hint').textContent = ai
      ? `Every scan is a full review by ${model || 'Claude'}, which reads the source like a security auditor. If Claude is unavailable, Owl falls back to a basic pattern scan and tells you.`
      : "This server has no Claude API key, so scans run as a basic pattern scan only (set ANTHROPIC_API_KEY to enable full reviews).";
  })
  .catch(() => showError(NO_SERVER_MESSAGE));
const whenServerReady = () => serverReady.catch(() => {});

document.querySelectorAll('[data-repo]').forEach((b) =>
  b.addEventListener('click', () => {
    $('#repo').value = b.dataset.repo;
    $('#ref').value = '';
    form.requestSubmit();
  }),
);

const params = new URLSearchParams(location.search);
if (params.get('repo')) {
  $('#repo').value = params.get('repo');
  $('#ref').value = params.get('ref') || '';
  queueMicrotask(() => form.requestSubmit());
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  run($('#repo').value.trim(), $('#ref').value.trim());
});

function showError(message) {
  errorEl.textContent = message;
  errorEl.hidden = false;
}

function setStep(n, state, text) {
  const el = $(`#step${n}-state`);
  el.className = `step-state ${state}`;
  el.innerHTML =
    state === 'running' ? `<span class="spinner sm" aria-hidden="true"></span>${esc(text)}` :
    state === 'pass' ? `✓ ${esc(text)}` :
    state === 'fail' ? `✗ ${esc(text)}` :
    state === 'warn' ? `! ${esc(text)}` : esc(text || '');
}

/** Collapses or expands the access-check details (the header row stays visible). */
function setStep1Open(open) {
  $('#step1-toggle').setAttribute('aria-expanded', String(open));
  $('#step1-body').hidden = !open;
}
$('#step1-toggle').addEventListener('click', () => setStep1Open($('#step1-toggle').getAttribute('aria-expanded') !== 'true'));

function renderChecks(checks) {
  const icon = { pass: '✓', warn: '!', fail: '✗' };
  $('#checks').innerHTML = checks
    .map((c) => `<li class="${esc(c.status)}"><span class="ic" aria-label="${esc(c.status)}">${icon[c.status] || '·'}</span>
      <div><b>${esc(c.label)}</b><div class="d">${esc(c.detail)}</div></div></li>`)
    .join('');
}

// ---------- the two steps ----------
async function run(repo, ref) {
  if (!repo) return;
  const url = new URL(location.href);
  url.searchParams.set('repo', repo);
  ref ? url.searchParams.set('ref', ref) : url.searchParams.delete('ref');
  history.replaceState(null, '', url);

  btn.disabled = true;
  errorEl.hidden = true;
  resultsEl.hidden = true;
  stepsEl.hidden = false;
  current = null;
  patchRun++;
  $('#checks').innerHTML = '';
  setStep1Open(true);
  $('#step2-text').textContent = 'Starts once the access check passes.';
  setStep(1, 'running', 'Checking…');
  setStep(2, 'idle', 'Waiting');

  try {
    const check = await accessCheck(repo, ref);
    if (!check) return;
    await scan(check.target);
  } finally {
    btn.disabled = false;
  }
}

/** Step 1: is the repository readable? Returns the check result, or null if it failed. */
async function accessCheck(repo, ref) {
  let res;
  try {
    res = await fetch(`/api/check?${new URLSearchParams({ repo, ...(ref ? { ref } : {}) })}`);
  } catch {
    setStep(1, 'fail', 'Server unreachable');
    showError('Could not reach the Owl server. Check your connection and that the service is running.');
    return null;
  }
  let check;
  try {
    if (!(res.headers.get('content-type') || '').includes('application/json')) throw new Error();
    check = await res.json();
  } catch {
    setStep(1, 'fail', `No scan server (HTTP ${res.status})`);
    showError(NO_SERVER_MESSAGE);
    return null;
  }
  renderChecks(check.checks || []);
  if (!check.canScan) {
    const failed = (check.checks || []).find((c) => c.status === 'fail');
    setStep(1, 'fail', 'Failed');
    $('#step2-text').textContent = 'Not started — fix the failed check above and try again.';
    setStep(2, 'idle', 'Not started');
    if (failed) showError(`${failed.label}: ${failed.detail}`);
    return null;
  }
  const warns = check.checks.filter((c) => c.status === 'warn').length;
  setStep(1, 'pass', `${warns ? `Passed with ${warns} warning${warns > 1 ? 's' : ''}` : 'Passed'} · ${check.checks.length} checks`);
  return check;
}

/** Step 2: scan the exact commit the access check confirmed. */
async function scan(target) {
  setStep(2, 'running', 'Starting…');
  $('#step2-text').textContent = `Scanning ${target.owner}/${target.repo} at commit ${target.sha.slice(0, 10)}.`;
  let gotResult = false;
  let lastStage = 'starting';
  try {
    let res;
    try {
      res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(target),
      });
    } catch {
      throw new Error('Lost contact with the Owl server when starting the scan. Try again.');
    }
    if (!(res.headers.get('content-type') || '').includes('application/x-ndjson') || !res.body) {
      throw new Error(`The scan endpoint answered HTTP ${res.status} without scan data. ${NO_SERVER_MESSAGE}`);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let done = false;
    while (!done) {
      const chunk = await reader.read();
      done = chunk.done;
      buf += decoder.decode(chunk.value || new Uint8Array(), { stream: !done });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          throw new Error('The server sent a response Owl could not read. Try again in a moment.');
        }
        if (msg.type === 'progress') {
          lastStage = msg.message;
          setStep(2, 'running', msg.message + '…');
        } else if (msg.type === 'error') throw new Error(msg.message);
        else if (msg.type === 'result') {
          gotResult = true;
          current = msg.data;
          await whenServerReady();
          render(msg.data);
        }
      }
    }
    if (!gotResult) {
      throw new Error(
        `The connection closed during "${lastStage}" before a result arrived. This usually means the server ` +
          'restarted mid-scan (for example, it ran out of memory on a large repository). Try again, or try a smaller repository.',
      );
    }
    const part = current.coverage && !current.coverage.complete;
    setStep(2, current.tier === 'full' && !part ? 'pass' : 'warn',
      `${current.tier === 'full' ? (part ? 'Partial review' : 'Full review') : part ? 'Basic, partial scan' : 'Basic scan'} · ${(current.durationMs / 1000).toFixed(1)}s${current.cached ? ' (cached)' : ''}`);
    setStep1Open(false); // the checks passed; keep them one click away
    $('#step2-text').textContent = current.tier === 'full'
      ? part
        ? `Claude reviewed ${fmt(current.coverage.reviewedFiles)} of ${fmt(current.coverage.totalFiles)} source files (about ${current.coverage.percent}% of the code) at commit ${target.sha.slice(0, 10)} — a partial scan.`
        : `Claude reviewed all of ${target.owner}/${target.repo} at commit ${target.sha.slice(0, 10)}.`
      : `Claude was unavailable (${current.tierReason}), so this is a basic pattern scan.`;
  } catch (err) {
    setStep(2, 'fail', 'Failed');
    showError(err.message || String(err));
  }
}

// ---------- rendering ----------
function fileLink(data, file) {
  if (!data.repo.blobBase) return `<code>${esc(file)}</code>`;
  return `<a class="mono" href="${esc(data.repo.blobBase + file.split('/').map(encodeURIComponent).join('/'))}" target="_blank" rel="noopener">${esc(file)}</a>`;
}

function locLink(data, file, line) {
  const label = `${file}:${line}`;
  if (!data.repo.blobBase) return `<code>${esc(label)}</code>`;
  return `<a href="${esc(data.repo.blobBase + file.split('/').map(encodeURIComponent).join('/'))}#L${line}" target="_blank" rel="noopener">${esc(label)}</a>`;
}

function locFromString(data, s) {
  const m = String(s).match(/^(.*?):(\d+)(?:-\d+)?$/);
  return m ? locLink(data, m[1], Number(m[2])) : `<code>${esc(s)}</code>`;
}

function render(data) {
  const { repo, stats, risk, ai } = data;
  const full = data.tier === 'full';
  const cov = data.coverage || { complete: true, notReviewed: [], reasons: [] };
  const partial = !cov.complete;
  const headline = ['Low', 'Moderate', 'High', 'Critical'].includes(risk.level) ? risk.level : 'Moderate';
  const meterPct = full ? { Low: 20, Moderate: 45, High: 70, Critical: 95 }[headline] : Math.max(4, risk.score);
  const sevTotal = SEVERITIES.reduce((s, k) => s + (stats.bySeverity[k] || 0), 0) || 1;

  resultsEl.innerHTML = `
    ${full ? '' : `<section class="tier-banner" role="status">
      <b>Basic scan — lower tier.</b> ${esc(data.tierReason || 'Claude was unavailable')}, so these results come from pattern matching alone.
      It misses most lifetime, aliasing and concurrency bugs (dangling references, use-after-free, data races), so treat the rating as a lower bound and re-run later for a full review.
    </section>`}
    ${partial ? `<section class="tier-banner partial-banner" role="status">
      <b>Partial scan — about ${cov.percent}% of the code was reviewed.</b> ${cov.reasons.map((r) => esc(r)).join('. ')}.
      The rating and findings below cover only the reviewed files, so problems elsewhere would not show up here.
      ${cov.notReviewed.length ? `<button type="button" class="link" id="show-not-reviewed">See the ${fmt(cov.notReviewed.length)} file${cov.notReviewed.length === 1 ? '' : 's'} not reviewed</button>` : ''}
    </section>` : ''}
    <section class="card hero">
      <div class="verdict">
        <div class="label">Overall risk${[!full && 'basic', partial && 'partial'].filter(Boolean).length ? ` (${[!full && 'basic', partial && 'partial'].filter(Boolean).join(', ')} scan)` : ''}</div>
        <div class="level lvl-${esc(headline)}">${esc(headline)}</div>
        <div class="meter"><div class="bg-${esc(headline)}" style="width:${meterPct}%"></div></div>
        <div class="sub" style="margin-top:6px">${full ? `Assessed by ${esc(modelName(ai.model))}` : `Pattern score ${risk.score}/100 — a lower bound`}</div>
      </div>
      <div>
        <div class="repo-line">${repo.url ? `<a href="${esc(repo.url)}" target="_blank" rel="noopener">${esc(repo.owner)}/${esc(repo.name)}</a>` : esc(repo.name)}
          ${repo.ref ? `<span class="pill">${esc(repo.ref)}</span>` : ''}
          ${repo.sha ? `<span class="pill mono">${esc(repo.sha.slice(0, 10))}</span>` : ''}
          ${full ? `<span class="pill claude">${partial ? 'Claude review' : 'Full review'}</span>` : '<span class="pill warn">Basic scan</span>'}
          ${partial ? `<span class="pill warn">Partial scan · ${cov.percent}% reviewed</span>` : ''}
          ${data.cached ? '<span class="pill">cached</span>' : ''}
        </div>
        <div class="stats">
          <div class="stat"><b>${fmt(stats.totalFindings)}</b><span>${full ? 'vulnerabilities found' : 'pattern hits'}</span></div>
          ${partial
            ? `<div class="stat stat-warn"><b>${fmt(cov.reviewedFiles)} of ${fmt(cov.totalFiles)}</b><span>source files reviewed (${cov.percent}% of the code)</span></div>`
            : `<div class="stat"><b>${fmt(stats.sourceFiles)}</b><span>C/C++ source files${full ? ', all reviewed' : ''}</span></div>`}
          <div class="stat"><b>${fmt(stats.loc)}</b><span>lines of code</span></div>
          <div class="stat"><b>${fmt(data.archive.ignoredNonSourceFiles)}</b><span>non-source files ignored</span></div>
        </div>
        <div class="bars" aria-label="Findings by severity">
          ${SEVERITIES.map((s) => `<div style="width:${(100 * (stats.bySeverity[s] || 0)) / sevTotal}%;background:${SEV_COLOR[s]}" title="${s}: ${stats.bySeverity[s] || 0}"></div>`).join('')}
        </div>
        <div class="sub">${SEVERITIES.map((s) => `<span style="white-space:nowrap"><span class="sev sev-${s}">${s}</span> ${fmt(stats.bySeverity[s] || 0)}</span>`).join(' &nbsp; ')}</div>
      </div>
    </section>

    ${renderSummary(data)}

    ${full && (ai.top_concerns || []).length ? fold('concerns-card', 'Top concerns', `${fmt(ai.top_concerns.length)} · most severe: ${sevPill(ai.top_concerns[0].severity)}`, renderConcerns(data)) : ''}

    ${fold('findings-card', full ? 'All vulnerabilities' : 'Pattern hits', '<span id="findings-count"></span>', `
      <div class="filters">
        ${SEVERITIES.map((s) => `<label><input type="checkbox" data-sev="${s}" checked> <span class="sev sev-${s}">${s}</span></label>`).join('')}
        <label><input type="checkbox" id="f-tests" ${data.findings.every((f) => f.kind === 'test') ? 'checked' : ''}> include test / example code</label>
        <select id="f-rule"><option value="">All issue types</option>${data.ruleSummary.map((r) => `<option value="${esc(r.ruleId)}">${esc(r.title)}</option>`).join('')}</select>
        <input type="search" id="f-text" placeholder="Filter by file, code or description…">
      </div>
      <div id="findings-list"></div>
      ${stats.findingsTruncated ? `<p class="sub">Showing the first ${fmt(data.findings.length)} (most severe first).</p>` : ''}`)}

    ${fold('types-card', 'Issue types', `${fmt(data.ruleSummary.length)} type${data.ruleSummary.length === 1 ? '' : 's'}`, `
      <p class="sub" style="margin-top:0">Click a row to see its ${full ? 'vulnerabilities' : 'pattern hits'}.</p>
      <div class="table-scroll"><table>
        <thead><tr><th>Severity</th><th>Issue</th><th class="hide-sm">CWE</th><th class="num">Count</th><th class="num hide-sm">Files</th></tr></thead>
        <tbody>${data.ruleSummary.map((r) => `<tr class="rule" data-rule="${esc(r.ruleId)}">
          <td><span class="sev sev-${r.severity}">${r.severity}</span></td>
          <td><b>${esc(r.title)}</b><div class="sub">${esc(r.description)}</div></td>
          <td class="hide-sm mono">${/^CWE-\d+$/.test(r.cwe || '') ? `<a href="https://cwe.mitre.org/data/definitions/${esc(r.cwe.replace('CWE-', ''))}.html" target="_blank" rel="noopener">${esc(r.cwe)}</a>` : esc(r.cwe || '')}</td>
          <td class="num">${fmt(r.count)}</td><td class="num hide-sm">${fmt(r.files)}</td>
        </tr>`).join('') || `<tr><td colspan="5" class="sub">${full ? 'Claude reported no vulnerabilities in the code it reviewed.' : 'No risky patterns found.'}</td></tr>`}</tbody>
      </table></div>`)}


    ${cov.notReviewed.length ? fold('notreviewed-card', 'Not reviewed', `${fmt(cov.notReviewed.length)} file${cov.notReviewed.length === 1 ? '' : 's'}`, renderNotReviewed(data, cov)) : ''}


    <section class="actions">
      <button id="dl-json" type="button">Download full report (JSON)</button>
      <button id="copy-link" type="button">Copy link to this scan</button>
    </section>

    ${renderPatchCard(data)}
  `;

  resultsEl.hidden = false;
  wireFindings(data);
  wirePatch(data);
  $('#show-not-reviewed')?.addEventListener('click', () => {
    $('#notreviewed-card').open = true;
    $('#notreviewed-card').scrollIntoView({ behavior: 'smooth' });
  });
  $('#dl-json').onclick = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `owl-${repo.owner}-${repo.name}.json` });
    a.click();
    URL.revokeObjectURL(a.href);
  };
  $('#copy-link').onclick = async (e) => {
    try {
      await navigator.clipboard.writeText(location.href);
      e.target.textContent = 'Link copied';
    } catch {
      e.target.textContent = location.href;
    }
  };
  resultsEl.querySelectorAll('tr.rule').forEach((tr) =>
    tr.addEventListener('click', () => {
      const rule = tr.dataset.rule;
      $('#f-rule').value = rule;
      const sev = data.ruleSummary.find((r) => r.ruleId === rule)?.severity;
      if (sev) $(`[data-sev="${sev}"]`).checked = true;
      $('#f-rule').dispatchEvent(new Event('change'));
      $('#findings-card').open = true;
      $('#findings-card').scrollIntoView({ behavior: 'smooth' });
    }),
  );
}

/** A collapsible results section: a clear one-line header with a count, details on click. */
function fold(id, title, meta, body, open = false) {
  return `<details class="card fold" id="${id}"${open ? ' open' : ''}>
    <summary><span class="fold-title">${esc(title)}</span><span class="fold-meta">${meta}</span><span class="chev" aria-hidden="true"></span></summary>
    <div class="fold-body">${body}</div>
  </details>`;
}

/** "claude-haiku-5-5-20260601" -> "Claude Haiku 5.5" */
const modelName = (id) =>
  String(id || 'Claude').replace(/^claude-/, '').replace(/-(\d+)-(\d+)(?:-\d{8})?$/, ' $1.$2').replace(/^\w/, (c) => 'Claude ' + c.toUpperCase());

const sevPill = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;

/** Always-visible summary: Claude's assessment on full reviews, the rating rationale on basic scans. */
function renderSummary(data) {
  const ai = data.ai;
  if (!ai) {
    return `<section class="card summary">
      <h2>Summary</h2>
      <ul class="plain">${data.risk.rationale.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
    </section>`;
  }
  const paras = String(ai.summary || '').split(/\n{2,}/).map((p) => `<p>${esc(p)}</p>`).join('');
  const cov = ai.coverage
    ? ai.coverage.mode === 'full'
      ? `Claude read all ${fmt(ai.coverage.totalFiles)} non-test source files in full`
      : `Claude read the ${fmt(ai.coverage.filesInFull)} riskiest of ${fmt(ai.coverage.totalFiles)} non-test source files (the repository is too large to read whole)`
    : '';
  const cost = typeof ai.costUsd === 'number' ? ` · cost $${ai.costUsd < 0.01 ? ai.costUsd.toFixed(4) : ai.costUsd.toFixed(2)}` : '';
  return `<section class="card summary">
    <h2>Summary</h2>
    <div class="ai-summary">${paras}</div>
    <p class="sub">${cov} · ${esc(modelName(ai.model))}${cost}. Open the sections below for details.</p>
  </section>`;
}

function renderNotReviewed(data, cov) {
  const LIMIT = 500;
  const byWhy = new Map();
  for (const f of cov.notReviewed) {
    if (!byWhy.has(f.why)) byWhy.set(f.why, []);
    byWhy.get(f.why).push(f.path);
  }
  const link = (p) => (data.repo.blobBase ? `<a href="${esc(data.repo.blobBase + p.split('/').map(encodeURIComponent).join('/'))}" target="_blank" rel="noopener">${esc(p)}</a>` : esc(p));
  return `<p class="sub" style="margin-top:0">These files were not read, so any vulnerabilities in them are not reflected in the rating or findings.</p>` +
    [...byWhy].map(([why, paths]) => `<h3>${esc(why[0].toUpperCase() + why.slice(1))} · ${fmt(paths.length)}</h3>
      <ul class="plain mono not-reviewed">${paths.slice(0, LIMIT).map((p) => `<li>${link(p)}</li>`).join('')}</ul>
      ${paths.length > LIMIT ? `<p class="sub">…and ${fmt(paths.length - LIMIT)} more (all are listed in the downloadable JSON report).</p>` : ''}`).join('');
}

function renderConcerns(data) {
  return (data.ai.top_concerns || []).map((c) => `
    <div class="concern ${esc(c.severity)}">
      <div class="t">${sevPill(c.severity)} ${esc(c.title)}</div>
      <div>${esc(c.detail)}</div>
      ${(c.locations || []).length ? `<div class="locs">${c.locations.map((l) => locFromString(data, l)).join('')}</div>` : ''}
    </div>`).join('');
}

function wireFindings(data) {
  const list = $('#findings-list');
  const PAGE = 150;
  let shown = PAGE;
  const titles = Object.fromEntries(data.ruleSummary.map((r) => [r.ruleId, r.title]));

  const apply = () => {
    const sevs = new Set([...document.querySelectorAll('[data-sev]')].filter((c) => c.checked).map((c) => c.dataset.sev));
    const tests = $('#f-tests').checked;
    const rule = $('#f-rule').value;
    const text = $('#f-text').value.trim().toLowerCase();
    const items = data.findings.filter(
      (f) =>
        sevs.has(f.severity) &&
        (tests || f.kind !== 'test') &&
        (!rule || f.ruleId === rule) &&
        (!text || `${f.file} ${f.code} ${f.title || ''} ${f.detail || ''} ${f.category || ''}`.toLowerCase().includes(text)),
    );
    const bySev = SEVERITIES.map((s) => [s, items.filter((f) => f.severity === s).length]).filter(([, n]) => n);
    const total = data.findings.length;
    $('#findings-count').innerHTML = `${items.length === total ? fmt(total) : `${fmt(items.length)} of ${fmt(total)}`}${bySev.length ? ' · ' + bySev.map(([s, n]) => `${sevPill(s)} ${fmt(n)}`).join(' ') : ''}`;
    list.innerHTML =
      (items.length
        ? ''
        : `<p class="sub">${
            data.findings.length
              ? 'Nothing matches these filters.'
              : data.tier === 'full'
                ? 'Claude reported no vulnerabilities in the code it reviewed.'
                : 'The basic pattern scan found no risky patterns.'
          }</p>`) +
      items
        .slice(0, shown)
        .map(
          (f) => `<div class="finding">
          <div class="head"><span class="sev sev-${f.severity}">${f.severity}</span>
            <span class="loc">${f.locationVerified === false ? `<code>${esc(f.file)}${f.line ? ':' + f.line : ''}</code>` : locLink(data, f.file, f.line)}</span>
            <span class="pill">${esc(f.category || titles[f.ruleId] || f.ruleId)}</span>
            ${f.cwe ? `<span class="pill mono">${esc(f.cwe)}</span>` : ''}
            ${f.locationVerified === false ? '<span class="pill warn">exact line not found — check nearby</span>' : ''}
            ${f.kind !== 'production' ? `<span class="pill">${esc(f.kind)}</span>` : ''}</div>
          ${f.title || f.detail ? `<div class="ai-note">${f.title ? `<b>${esc(f.title)}.</b> ` : ''}${esc(f.detail || '')}</div>` : ''}
          ${!f.context && !f.code ? '' : `<pre>${
            f.context
              ? f.context.map((l) => `<span class="${l.n === f.line ? 'hl' : ''}"><span class="ln">${l.n}</span>${esc(l.text)}</span>`).join('')
              : `<span class="hl"><span class="ln">${f.line}</span>${esc(f.code)}</span>`
          }</pre>`}
        </div>`,
        )
        .join('') +
      (items.length > shown ? `<button class="more" type="button" id="more">Show more (${fmt(items.length - shown)} remaining)</button>` : '');
    const more = $('#more');
    if (more) more.onclick = () => ((shown += PAGE), apply());
  };

  document.querySelectorAll('#findings-card [data-sev], #f-tests, #f-rule').forEach((el) => el.addEventListener('change', () => ((shown = PAGE), apply())));
  $('#f-text').addEventListener('input', () => ((shown = PAGE), apply()));
  apply();
}

// ---------- patch agent (opt-in) ----------
const SCOPES = [
  { id: 'high', label: 'Critical and high', sevs: ['critical', 'high'] },
  { id: 'medium', label: 'Critical, high and medium', sevs: ['critical', 'high', 'medium'] },
  { id: 'all', label: 'All', sevs: ['critical', 'high', 'medium', 'low'] },
];

/** Findings as the patch agent needs them; basic-scan hits get their rule's name and description. */
function patchableFindings(data, sevs) {
  const rules = Object.fromEntries(data.ruleSummary.map((r) => [r.ruleId, r]));
  return data.findings
    .filter((f) => sevs.includes(f.severity) && f.kind !== 'test' && f.line > 0)
    .map((f) => {
      const rule = rules[f.ruleId] || {};
      return {
        file: f.file,
        line: f.line,
        severity: f.severity,
        title: f.title || rule.title || f.ruleId,
        category: f.category || rule.title || '',
        cwe: f.cwe || rule.cwe || '',
        detail: f.detail || [rule.description, f.code ? `Flagged code: ${f.code}` : ''].filter(Boolean).join(' '),
      };
    });
}

function renderPatchCard(data) {
  if (!server.ai || !data.repo.sha || !data.findings.length) return '';
  const options = SCOPES.map((sc) => ({ ...sc, n: patchableFindings(data, sc.sevs).length })).filter((sc, i, all) => sc.n && (i === 0 || sc.n !== all[i - 1].n));
  if (!options.length) return '';
  return `<section class="card patch-card" id="patch-card">
    <div class="patch-head">
      <div>
        <h2>Propose patches</h2>
        <p class="sub" style="margin:0">A separate agent, acting as a security engineer, reads the code around each vulnerability and writes fixes you can download as a <code>.patch</code> file. It only runs if you start it.</p>
      </div>
    </div>
    <div class="patch-controls" id="patch-controls">
      <label class="patch-scope"><span>Patch</span>
        <select id="patch-scope">${options.map((o) => `<option value="${o.id}">${esc(o.label)} (${fmt(o.n)})</option>`).join('')}</select>
      </label>
      ${server.patchModels.length ? `<label class="patch-scope"><span>Model</span>
        <select id="patch-model">${server.patchModels.map((m) => `<option value="${esc(m.id)}"${m.default ? ' selected' : ''}>${esc(m.label)} (${esc(m.note)})</option>`).join('')}</select>
      </label>` : ''}
      <button type="button" id="patch-btn" class="primary">Propose patches</button>
      <span class="sub">Every patch is checked by an independent review before the agent finishes · counts toward your daily Claude budget · a few minutes</span>
    </div>
    <div id="patch-progress" hidden></div>
    <div id="patch-results" hidden></div>
  </section>
  <section class="card compare-card" id="compare-card" hidden></section>`;
}

function wirePatch(data) {
  const btn = $('#patch-btn');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const scope = SCOPES.find((sc) => sc.id === $('#patch-scope').value) || SCOPES[0];
    runPatch(data, patchableFindings(data, scope.sevs), $('#patch-model')?.value);
  });
}

async function runPatch(data, findings, model) {
  const run = ++patchRun;
  const live = () => run === patchRun && current === data;
  const btn = $('#patch-btn');
  const progress = $('#patch-progress');
  const out = $('#patch-results');
  btn.disabled = true;
  $('#patch-scope').disabled = true;
  if ($('#patch-model')) $('#patch-model').disabled = true;
  out.hidden = true;
  progress.hidden = false;
  progress.innerHTML = `<div class="patch-status"><span class="spinner sm" aria-hidden="true"></span><span id="patch-status-text">Starting the security engineer agent…</span></div><ol class="patch-log" id="patch-log"></ol>`;
  const log = (ev) => {
    if (!live()) return;
    $('#patch-status-text').textContent = ev.message + '…';
    if (['patch', 'skip', 'retry', 'verify'].includes(ev.kind)) {
      const li = document.createElement('li');
      li.className = `log-${ev.kind}`;
      li.textContent = ev.message;
      $('#patch-log').append(li);
    }
  };
  try {
    const res = await fetch('/api/patch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner: data.repo.owner, repo: data.repo.name, sha: data.repo.sha, ref: data.repo.ref, findings, ...(model ? { model } : {}) }),
    });
    if (!(res.headers.get('content-type') || '').includes('application/x-ndjson') || !res.body) throw new Error(`The patch service answered HTTP ${res.status}.`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let result = null;
    for (;;) {
      const { done, value } = await reader.read();
      buf += decoder.decode(value || new Uint8Array(), { stream: !done });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.type === 'progress') log(msg);
        else if (msg.type === 'error') throw new Error(msg.message);
        else if (msg.type === 'result') result = msg.data;
      }
      if (done) break;
    }
    if (!live()) return;
    if (!result) throw new Error('The connection closed before the patches were ready. Try again.');
    progress.hidden = true;
    renderPatchResults(data, result);
  } catch (err) {
    if (!live()) return;
    progress.innerHTML = `<div class="error" role="alert" style="margin:12px 0 0">${esc(err.message || String(err))}</div>`;
  } finally {
    if (live()) {
      btn.disabled = false;
      $('#patch-scope').disabled = false;
      if ($('#patch-model')) $('#patch-model').disabled = false;
      btn.textContent = 'Propose again';
    }
  }
}

function renderVerification(r) {
  const v = r.verification;
  if (!v || !r.patches.length) return '';
  const issues = (list) => `<ul class="plain cmp-list">${list.map((f) => `<li>${sevPill(f.severity)} <b>${esc(f.title)}</b> <span class="mono sub">${esc(f.file)}:${f.line}</span><div class="sub">${esc(f.detail)}</div></li>`).join('')}</ul>`;
  if (v.unavailable && !v.rounds) return `<div class="verify-box warn"><b>Not independently checked.</b> ${esc(v.unavailable)}.</div>`;
  if (v.remaining.length) {
    return `<div class="verify-box warn"><b>Independent review still flags ${fmt(v.remaining.length)} issue${v.remaining.length === 1 ? '' : 's'} in the patched lines</b> after ${fmt(v.rounds)} check${v.rounds === 1 ? '' : 's'}. Review ${v.remaining.length === 1 ? 'it' : 'them'} before applying:${issues(v.remaining)}</div>`;
  }
  if (v.unavailable) return `<div class="verify-box warn"><b>Partly checked.</b> ${esc(v.unavailable)}.</div>`;
  return `<div class="verify-box ok"><b>✓ Independently reviewed:</b> ${
    v.issuesFound
      ? `the review found ${fmt(v.issuesFound)} issue${v.issuesFound === 1 ? '' : 's'} in the agent's first draft, and ${v.issuesFound === 1 ? 'it was' : 'all were'} fixed before it finished.`
      : 'no new issues in the patched lines.'
  }</div>`;
}

function renderDiff(diff) {
  return diff
    .split('\n')
    .filter((l) => l && !l.startsWith('diff --git') && !l.startsWith('--- ') && !l.startsWith('+++ '))
    .map((l) => {
      const cls = l.startsWith('@@') ? 'd-hunk' : l.startsWith('+') ? 'd-add' : l.startsWith('-') ? 'd-del' : l.startsWith('\\') ? 'd-note' : 'd-ctx';
      return `<span class="${cls}">${esc(l)}</span>`;
    })
    .join('');
}

function renderPatchResults(data, r) {
  const out = $('#patch-results');
  const byId = Object.fromEntries(r.findings.map((f) => [f.id, f]));
  const fname = `owl-patches-${data.repo.owner}-${data.repo.name}-${data.repo.sha.slice(0, 7)}.patch`;
  const cost = typeof r.costUsd === 'number' ? ` · cost $${r.costUsd < 0.01 ? r.costUsd.toFixed(4) : r.costUsd.toFixed(2)}` : '';
  const findingLabel = (id) => {
    const f = byId[id];
    return f ? `${sevPill(f.severity)} ${esc(f.title)} <span class="sub mono">${esc(f.file.split('/').pop())}${f.line ? ':' + f.line : ''}</span>` : esc(id);
  };
  out.innerHTML = `
    ${r.stoppedReason ? `<div class="tier-banner partial-banner" role="status"><b>Stopped early:</b> ${esc(r.stoppedReason)}. The patches below are complete and usable; the rest weren't reached.</div>` : ''}
    <div class="patch-summary">
      <div><b>${fmt(r.patches.length)} patch${r.patches.length === 1 ? '' : 'es'}</b> to ${fmt(r.files.length)} file${r.files.length === 1 ? '' : 's'}
        ${r.files.length ? `<span class="sub">(+${fmt(r.files.reduce((n, f) => n + f.added, 0))} −${fmt(r.files.reduce((n, f) => n + f.removed, 0))} lines)</span>` : ''}
        · ${fmt(r.skipped.length)} not patched${r.unaddressed.length ? ` · ${fmt(r.unaddressed.length)} not reached` : ''}
        <span class="sub">· ${esc(modelName(r.model))}${cost}${r.cached ? ' · cached' : ''}</span></div>
      ${r.patchFile ? `<div class="actions"><button type="button" id="dl-patch" class="primary">Download ${esc(fname)}</button><button type="button" id="copy-patch">Copy patch</button><button type="button" id="rescan-btn">Re-scan patched code</button></div>` : ''}
    </div>
    ${r.patchFile ? `<p class="sub">Apply from the repository root with <code>git apply --check ${esc(fname)} &amp;&amp; git apply ${esc(fname)}</code>. These fixes were written by an AI agent, checked to apply cleanly and reviewed by a second AI pass — still review, build and test them before relying on them.</p>` : ''}
    ${renderVerification(r)}
    ${r.patches.map((p) => `
      <div class="patch-item">
        <div class="head"><b class="mono">${esc(p.id)}</b> ${fileLink(data, p.file)} <span class="sub">+${p.added} −${p.removed}</span></div>
        <ul class="plain patch-fixes">${p.findingIds.map((id) => `<li>${findingLabel(id)}</li>`).join('')}</ul>
        <div class="ai-note">${esc(p.explanation)}</div>
        <details class="diff-toggle"><summary>Show diff <span class="sub">(+${p.added} −${p.removed})</span></summary><pre class="diff">${renderDiff(p.diff)}</pre></details>
      </div>`).join('')}
    ${r.skipped.length || r.unaddressed.length ? `<h3>Not patched</h3><ul class="plain patch-skips">
      ${r.skipped.map((sk) => `<li>${findingLabel(sk.findingId)}<div class="sub">${esc(sk.reason)}</div></li>`).join('')}
      ${r.unaddressed.map((id) => `<li>${findingLabel(id)}<div class="sub">Not reached in this session.</div></li>`).join('')}
    </ul>` : ''}
    ${r.droppedFindings ? `<p class="sub">Only the ${fmt(r.findings.length)} most severe vulnerabilities were sent to the agent; ${fmt(r.droppedFindings)} more were left out.</p>` : ''}`;
  out.hidden = false;
  $('#dl-patch')?.addEventListener('click', () => {
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([r.patchFile], { type: 'text/x-patch' })), download: fname });
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $('#rescan-btn')?.addEventListener('click', () => runRescan(data, r));
  $('#copy-patch')?.addEventListener('click', async (e) => {
    try {
      await navigator.clipboard.writeText(r.patchFile);
      e.target.textContent = 'Copied';
    } catch {
      e.target.textContent = 'Copy failed — use Download';
    }
  });
}

// ---------- re-scan the patched code and compare ----------
async function runRescan(data, patch) {
  const run = ++patchRun;
  const live = () => run === patchRun && current === data;
  const card = $('#compare-card');
  const btn = $('#rescan-btn');
  btn.disabled = true;
  card.hidden = false;
  card.innerHTML = `<h2>Before and after patching</h2>
    <p class="sub" style="margin-top:0">Running the original vulnerability review on the patched code, with the same model, instructions and files.</p>
    <div class="patch-status"><span class="spinner sm" aria-hidden="true"></span><span id="rescan-status">Starting…</span></div>`;
  card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const res = await fetch('/api/rescan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        owner: data.repo.owner, repo: data.repo.name, sha: data.repo.sha, ref: data.repo.ref, patchFile: patch.patchFile,
        targeted: patch.findings.filter((f) => patch.patches.some((p) => p.findingIds.includes(f.id))).map((f) => ({ file: f.file, line: f.line })),
        before: {
          tier: data.tier, risk: { level: data.risk.level }, coverage: { complete: data.coverage?.complete !== false },
          findings: data.findings.map((f) => ({ file: f.file, line: f.line, severity: f.severity, title: f.title || '', category: f.category || '', ruleId: f.ruleId || '', detail: f.detail || '', verdict: f.verdict })),
        },
      }),
    });
    if (!(res.headers.get('content-type') || '').includes('application/x-ndjson') || !res.body) throw new Error(`The re-scan service answered HTTP ${res.status}.`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let result = null;
    for (;;) {
      const { done, value } = await reader.read();
      buf += decoder.decode(value || new Uint8Array(), { stream: !done });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.type === 'progress' && live()) $('#rescan-status').textContent = msg.message + '…';
        else if (msg.type === 'error') throw new Error(msg.message);
        else if (msg.type === 'result') result = msg.data;
      }
      if (done) break;
    }
    if (!live()) return;
    if (!result) throw new Error('The connection closed before the re-scan finished. Try again.');
    renderComparison(data, result);
  } catch (err) {
    if (!live()) return;
    card.innerHTML = `<h2>Before and after patching</h2><div class="error" role="alert" style="margin:0">${esc(err.message || String(err))}</div>`;
  } finally {
    if (live()) {
      btn.disabled = false;
      btn.textContent = 'Re-scan again';
    }
  }
}

function renderComparison(data, { after, comparison: c }) {
  const card = $('#compare-card');
  const max = Math.max(1, ...SEVERITIES.map((s) => Math.max(c.before.bySeverity[s], c.after.bySeverity[s])));
  const delta = (n) => (n < 0 ? `<span class="down">−${fmt(-n)}</span>` : n > 0 ? `<span class="up">+${fmt(n)}</span>` : '<span class="sub">no change</span>');
  const levelWord = c.levelChange === null ? '' : c.levelChange < 0 ? `${-c.levelChange} level${c.levelChange === -1 ? '' : 's'} lower` : c.levelChange > 0 ? `${c.levelChange} level${c.levelChange === 1 ? '' : 's'} higher` : 'unchanged';
  const side = (label, s, tier) => `<div class="cmp-side">
      <div class="label">${esc(label)}</div>
      <div class="level lvl-${esc(s.level || 'Moderate')}">${esc(s.level || '—')}</div>
      <div class="sub">${fmt(s.total)} vulnerabilit${s.total === 1 ? 'y' : 'ies'}${tier === 'full' ? '' : ' · basic scan'}</div>
    </div>`;
  const row = (f, extra = '') => `<li><div>${sevPill(f.severity)} <b>${esc(f.title)}</b> <span class="mono sub">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>${extra}</div>${f.detail ? `<div class="sub">${esc(f.detail)}</div>` : ''}</li>`;
  const list = (items, render) => (items.length ? `<ul class="plain cmp-list">${items.map(render).join('')}</ul>` : '<p class="sub">None.</p>');

  card.innerHTML = `
    <h2>Before and after patching</h2>
    ${c.comparable ? '' : `<div class="tier-banner partial-banner" role="status"><b>Not a like-for-like comparison.</b> ${
      after.tier !== 'full' ? `The re-scan fell back to a basic scan (${esc(after.tierReason || 'Claude was unavailable')}), so it can't be compared fairly with the full review.` : 'The two scans covered different amounts of the code.'
    } Re-run the re-scan when Claude is available.</div>`}
    <div class="cmp-hero">
      ${side('Original code', c.before, c.before.tier)}
      <div class="cmp-arrow" aria-hidden="true">→</div>
      ${side('With the patches', c.after, c.after.tier)}
      <div class="cmp-verdict"><b>${c.levelChange === null ? '' : c.levelChange < 0 ? 'Risk reduced' : c.levelChange > 0 ? 'Risk increased' : 'Risk level unchanged'}</b>
        <div class="sub">${esc(levelWord)} · ${fmt(c.fixed.length)} fixed · ${fmt(c.remaining.length)} still present · ${fmt(c.introduced.length)} new</div>
        ${c.targeted ? `<div class="cmp-targeted"><b>${fmt(c.targeted.fixed)} of ${fmt(c.targeted.total)}</b> vulnerabilities the patches targeted are gone${c.targeted.stillPresent ? ` · <span class="up">${fmt(c.targeted.stillPresent)} still flagged</span>` : ''}</div>` : ''}
        ${c.introducedInPatchedLines?.length ? `<div class="cmp-targeted"><span class="up"><b>${fmt(c.introducedInPatchedLines.length)}</b> new issue${c.introducedInPatchedLines.length === 1 ? '' : 's'} in lines the patches changed</span></div>` : ''}</div>
    </div>
    <table class="cmp-table">
      <thead><tr><th>Severity</th><th class="num">Before</th><th class="num">After</th><th class="hide-sm"></th><th class="num">Change</th></tr></thead>
      <tbody>${SEVERITIES.map((s) => `<tr>
        <td>${sevPill(s)}</td><td class="num">${fmt(c.before.bySeverity[s])}</td><td class="num">${fmt(c.after.bySeverity[s])}</td>
        <td class="hide-sm cmp-bars"><span class="bar before" style="width:${(100 * c.before.bySeverity[s]) / max}%"></span><span class="bar after" style="width:${(100 * c.after.bySeverity[s]) / max}%;background:${SEV_COLOR[s]}"></span></td>
        <td class="num">${delta(c.after.bySeverity[s] - c.before.bySeverity[s])}</td></tr>`).join('')}
      <tr class="total"><td><b>Total</b></td><td class="num"><b>${fmt(c.before.total)}</b></td><td class="num"><b>${fmt(c.after.total)}</b></td><td class="hide-sm"></td><td class="num">${delta(c.after.total - c.before.total)}</td></tr></tbody>
    </table>
    <p class="sub">Both reviews used the same model, instructions and ${after.coverage?.complete === false ? 'subset of files' : 'files'}${after.patchedFiles ? `; ${fmt(after.patchedFiles.length)} file${after.patchedFiles.length === 1 ? ' was' : 's were'} patched` : ''}. AI reviews vary a little from run to run, so a small difference can be noise.</p>
    ${fold('cmp-fixed', 'Fixed', `${fmt(c.fixed.length)}`, list(c.fixed, (f) => row(f, f.targeted ? ' <span class="pill claude">patched</span>' : ' <span class="pill">not targeted</span>')))}
    ${fold('cmp-remaining', 'Still present', `${fmt(c.remaining.length)}`, `${c.remaining.some((m) => m.targeted) ? '<p class="sub" style="margin-top:0">Items marked <span class="pill warn">patch didn\'t fix it</span> were targeted by a patch but the re-scan still flags them.</p>' : ''}${list(c.remaining, (m) => row(m.after, `${m.targeted ? ' <span class="pill warn">patch didn\'t fix it</span>' : ''}${m.after.severity !== m.before.severity ? ` <span class="pill">was ${esc(m.before.severity)}</span>` : ''}`))}`)}
    ${fold('cmp-new-patched', 'New in lines the patches changed', `${fmt((c.introducedInPatchedLines || []).length)}`, `${(c.introducedInPatchedLines || []).length ? '<p class="sub" style="margin-top:0">These are on or next to lines a patch wrote, so the patch most likely introduced them. Review these first.</p>' : ''}${list(c.introducedInPatchedLines || [], (f) => row(f))}`)}
    ${fold('cmp-new', 'New elsewhere', `${fmt((c.introducedElsewhere || c.introduced).length)}`, `${(c.introducedElsewhere || c.introduced).length ? '<p class="sub" style="margin-top:0">In code the patches didn\'t touch, so most likely issues the first review missed, or run-to-run variation between reviews.</p>' : ''}${list(c.introducedElsewhere || c.introduced, (f) => row(f))}`)}
    ${after.ai?.recommendations?.length ? fold('cmp-recs', 'Remaining recommendations', `${fmt(after.ai.recommendations.length)}`, `<ul class="plain">${after.ai.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>`) : ''}
    <p class="sub">${esc(after.ai ? modelName(after.ai.model) : 'Basic scan')}${typeof after.ai?.costUsd === 'number' ? ` · re-scan cost $${after.ai.costUsd < 0.01 ? after.ai.costUsd.toFixed(4) : after.ai.costUsd.toFixed(2)}` : ''}${after.cached ? ' · cached' : ''}</p>`;
}

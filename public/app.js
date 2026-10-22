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

// ---------- setup ----------
fetch('/api/health')
  .then((r) => r.json())
  .then(({ ai, model }) => {
    $('#ai-hint').textContent = ai
      ? `Every scan is a full review by ${model || 'Claude'}, which reads the source like a security auditor. If Claude is unavailable, Owl falls back to a basic pattern scan and tells you.`
      : "This server has no Claude API key, so scans run as a basic pattern scan only (set ANTHROPIC_API_KEY to enable full reviews).";
  })
  .catch(() => showError(NO_SERVER_MESSAGE));

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
  const noun = full ? 'vulnerabilit' : 'pattern hit';
  const plural = (n) => (full ? (n === 1 ? 'y' : 'ies') : n === 1 ? '' : 's');

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

    ${full && (ai.recommendations || []).length ? fold('recs-card', 'Before adopting', `${fmt(ai.recommendations.length)} recommendation${ai.recommendations.length === 1 ? '' : 's'}`,
      `<ul class="plain">${ai.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>`) : ''}

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

    ${fold('hotspots-card', 'Riskiest files', data.hotspots.length ? `${fmt(Math.min(10, data.hotspots.length))} file${data.hotspots.length === 1 ? '' : 's'} · top: <code>${esc(data.hotspots[0].file.split('/').pop())}</code>` : 'none',
      data.hotspots.length ? `<div class="table-scroll"><table>
          <thead><tr><th>File</th><th>By severity</th><th class="num">Count</th></tr></thead>
          <tbody>${data.hotspots.slice(0, 10).map((h) => `<tr>
            <td class="mono" style="word-break:break-all">${repo.blobBase ? `<a href="${esc(repo.blobBase + h.file)}" target="_blank" rel="noopener">${esc(h.file)}</a>` : esc(h.file)}
              ${h.kind !== 'production' ? `<span class="pill">${esc(h.kind)}</span>` : ''}</td>
            <td>${SEVERITIES.filter((s) => h.bySeverity?.[s]).map((s) => `${sevPill(s)} ${h.bySeverity[s]}`).join(' ')}</td>
            <td class="num">${fmt(h.findings)}</td></tr>`).join('')}</tbody>
        </table></div>` : `<p class="sub">No ${noun}${plural(0)} found.</p>`)}

    ${cov.notReviewed.length ? fold('notreviewed-card', 'Not reviewed', `${fmt(cov.notReviewed.length)} file${cov.notReviewed.length === 1 ? '' : 's'}`, renderNotReviewed(data, cov)) : ''}


    <section class="actions">
      <button id="dl-json" type="button">Download full report (JSON)</button>
      <button id="copy-link" type="button">Copy link to this scan</button>
    </section>
  `;

  resultsEl.hidden = false;
  wireFindings(data);
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

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
    setStep(2, current.tier === 'full' ? 'pass' : 'warn',
      `${current.tier === 'full' ? 'Full review' : 'Basic scan'} · ${(current.durationMs / 1000).toFixed(1)}s${current.cached ? ' (cached)' : ''}`);
    setStep1Open(false); // the checks passed; keep them one click away
    $('#step2-text').textContent = current.tier === 'full'
      ? `Claude reviewed ${target.owner}/${target.repo} at commit ${target.sha.slice(0, 10)}.`
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
  const unreviewed = ai ? data.findings.filter((f) => f.source === 'scanner' && !f.verdict).length : 0;
  const level = ai?.overall_risk || risk.level;
  const headline = ['Low', 'Moderate', 'High', 'Critical'].includes(level) ? level : risk.level;
  const sevTotal = SEVERITIES.reduce((s, k) => s + (stats.bySeverity[k] || 0), 0) || 1;

  resultsEl.innerHTML = `
    ${data.tier === 'full' ? '' : `<section class="tier-banner" role="status">
      <b>Basic scan — lower tier.</b> ${esc(data.tierReason || 'Claude was unavailable')}, so these results come from pattern matching alone.
      It misses most lifetime, aliasing and concurrency bugs (dangling references, use-after-free, data races), so treat the rating as a lower bound and re-run later for a full review.
    </section>`}
    <section class="card hero">
      <div class="verdict">
        <div class="label">Overall risk${data.tier === 'full' ? '' : ' (basic scan)'}</div>
        <div class="level lvl-${esc(headline)}">${esc(headline)}</div>
        <div class="meter" title="Scanner score ${risk.score}/100"><div class="bg-${esc(risk.level)}" style="width:${Math.max(4, risk.score)}%"></div></div>
        <div class="sub" style="margin-top:6px">${ai ? `Claude's assessment · patterns alone: ${esc(risk.level)}` : `Pattern score ${risk.score}/100 — a lower bound`}</div>
      </div>
      <div>
        <div class="repo-line">${repo.url ? `<a href="${esc(repo.url)}" target="_blank" rel="noopener">${esc(repo.owner)}/${esc(repo.name)}</a>` : esc(repo.name)}
          ${repo.ref ? `<span class="pill">${esc(repo.ref)}</span>` : ''}
          ${repo.sha ? `<span class="pill mono">${esc(repo.sha.slice(0, 10))}</span>` : ''}
          ${data.tier === 'full' ? '<span class="pill claude">Full review</span>' : '<span class="pill warn">Basic scan</span>'}
          ${data.cached ? '<span class="pill">cached</span>' : ''}
        </div>
        <div class="stats">
          <div class="stat"><b>${fmt(stats.sourceFiles)}</b><span>C/C++ source files</span></div>
          <div class="stat"><b>${fmt(stats.loc)}</b><span>lines of code</span></div>
          <div class="stat"><b>${fmt(stats.totalFindings)}</b><span>${ai ? 'findings (scanner + Claude)' : 'pattern hits'}</span></div>
          <div class="stat"><b>${risk.density}</b><span>weighted hits / KLOC</span></div>
          <div class="stat"><b>${fmt(data.archive.ignoredNonSourceFiles)}</b><span>non-source files ignored</span></div>
        </div>
        <div class="bars" aria-label="Findings by severity">
          ${SEVERITIES.map((s) => `<div style="width:${(100 * (stats.bySeverity[s] || 0)) / sevTotal}%;background:${SEV_COLOR[s]}" title="${s}: ${stats.bySeverity[s] || 0}"></div>`).join('')}
        </div>
        <div class="sub">${SEVERITIES.map((s) => `<span style="white-space:nowrap"><span class="sev sev-${s}">${s}</span> ${fmt(stats.bySeverity[s] || 0)}</span>`).join(" &nbsp; ")}</div>
        ${stats.bySource ? `<div class="sub" style="margin-top:6px">Claude added <b>${fmt(stats.bySource.addedByClaude)}</b> finding${stats.bySource.addedByClaude === 1 ? '' : 's'} the scanner can't see, confirmed <b>${fmt(stats.bySource.confirmedByClaude)}</b> scanner hit${stats.bySource.confirmedByClaude === 1 ? '' : 's'} and dismissed <b>${fmt(stats.bySource.dismissedByClaude)}</b>.</div>` : ''}
      </div>
    </section>

    ${renderSummary(data)}

    ${ai && (ai.top_concerns || []).length ? fold('concerns-card', 'Top concerns', `${fmt(ai.top_concerns.length)} · most severe: ${sevPill(ai.top_concerns[0].severity)}`, renderConcerns(data)) : ''}

    ${ai && (ai.recommendations || []).length ? fold('recs-card', 'Before adopting', `${fmt(ai.recommendations.length)} recommendation${ai.recommendations.length === 1 ? '' : 's'}`,
      `<ul class="plain">${ai.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>`) : ''}

    ${fold('findings-card', 'Findings', '<span id="findings-count"></span>', `
      ${ai?.counts ? `<p class="sub" style="margin-top:0">Claude added ${fmt(ai.counts.added)} finding${ai.counts.added === 1 ? '' : 's'} the scanner can't detect, confirmed ${fmt(ai.counts.confirmed)} scanner hit${ai.counts.confirmed === 1 ? '' : 's'} (setting their severity) and dismissed ${fmt(ai.counts.dismissed)} as safe in context.${ai.counts.unverifiedLocations ? ` ${fmt(ai.counts.unverifiedLocations)} cited a location that doesn't exist (shown, not counted).` : ''}</p>` : ''}
      <div class="filters">
        ${SEVERITIES.map((s) => `<label><input type="checkbox" data-sev="${s}" ${s === 'low' && data.findings.some((f) => f.severity !== 'low') ? '' : 'checked'}> <span class="sev sev-${s}">${s}</span></label>`).join('')}
        <label><input type="checkbox" id="f-tests"> include test / example code</label>
        ${ai ? `<select id="f-source">
          <option value="">All sources</option>
          <option value="claude">Found by Claude</option>
          <option value="confirmed">Confirmed by Claude</option>
          <option value="scanner">Scanner only (not reviewed)</option>
          <option value="dismissed">Dismissed by Claude</option>
        </select>
        <label><input type="checkbox" id="f-dismissed"> show dismissed</label>
        ${unreviewed ? `<label><input type="checkbox" id="f-unreviewed"> show ${fmt(unreviewed)} unreviewed pattern hit${unreviewed === 1 ? '' : 's'}</label>` : ''}` : ''}
        <select id="f-rule"><option value="">All issue types</option>${data.ruleSummary.map((r) => `<option value="${esc(r.ruleId)}">${esc(r.title)}</option>`).join('')}</select>
        <input type="search" id="f-text" placeholder="Filter by path or code…">
      </div>
      <div id="findings-list"></div>
      ${stats.findingsTruncated ? `<p class="sub">Showing the first ${fmt(data.findings.length)} findings (most severe first).</p>` : ''}`)}

    ${fold('types-card', 'Issue types', `${fmt(data.ruleSummary.length)} type${data.ruleSummary.length === 1 ? '' : 's'}`, `
      <p class="sub" style="margin-top:0">Click a row to see its findings.${ai ? ' Rows marked <span class="pill claude">Claude</span> were found by reading the code; the rest are scanner patterns.' : ''}</p>
      <div class="table-scroll"><table>
        <thead><tr><th>Severity</th><th>Issue</th><th class="hide-sm">CWE</th><th class="num">Non-test</th><th class="num">Total</th><th class="num hide-sm">Files</th></tr></thead>
        <tbody>${data.ruleSummary.map((r) => `<tr class="rule" data-rule="${esc(r.ruleId)}" title="${esc(r.description)}">
          <td><span class="sev sev-${r.severity}">${r.severity}</span></td>
          <td><b>${esc(r.title)}</b> ${r.source === 'claude' ? '<span class="pill claude">Claude</span>' : ''}
            <div class="sub">${esc(r.description)}${r.confirmed ? ` · ${fmt(r.confirmed)} confirmed by Claude` : ''}${r.dismissed ? ` · ${fmt(r.dismissed)} dismissed by Claude` : ''}</div></td>
          <td class="hide-sm mono">${/^CWE-\d+$/.test(r.cwe || '') ? `<a href="https://cwe.mitre.org/data/definitions/${esc(r.cwe.replace('CWE-', ''))}.html" target="_blank" rel="noopener">${esc(r.cwe)}</a>` : esc(r.cwe || '')}</td>
          <td class="num">${fmt(r.productionCount)}</td><td class="num">${fmt(r.count)}</td><td class="num hide-sm">${fmt(r.files)}</td>
        </tr>`).join('') || '<tr><td colspan="6" class="sub">Nothing flagged.</td></tr>'}</tbody>
      </table></div>`)}

    ${fold('hotspots-card', 'Hotspot files', data.hotspots.length ? `${fmt(Math.min(10, data.hotspots.length))} file${data.hotspots.length === 1 ? '' : 's'} · top: <code>${esc(data.hotspots[0].file.split('/').pop())}</code>` : 'none',
      data.hotspots.length ? `<div class="table-scroll"><table>
          <thead><tr><th>File</th><th class="num">Findings</th><th class="num">Weight</th></tr></thead>
          <tbody>${data.hotspots.slice(0, 10).map((h) => `<tr>
            <td class="mono" style="word-break:break-all">${repo.blobBase ? `<a href="${esc(repo.blobBase + h.file)}" target="_blank" rel="noopener">${esc(h.file)}</a>` : esc(h.file)}
              ${h.kind !== 'production' ? `<span class="pill">${esc(h.kind)}</span>` : ''}</td>
            <td class="num">${fmt(h.findings)}</td><td class="num">${h.weighted}</td></tr>`).join('')}</tbody>
        </table></div>` : '<p class="sub">No risky patterns found.</p>')}

    ${ai
      ? fold('signals-card', 'Pattern scan signals', `patterns alone rate it ${esc(risk.level)}`,
          `<ul class="plain">${risk.rationale.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>${renderMitigations(data)}`)
      : fold('signals-card', 'Safer-idiom signals', `${fmt(Object.keys(data.mitigations || {}).length)} found`, renderMitigations(data, false))}

    <section class="actions">
      <button id="dl-json" type="button">Download full report (JSON)</button>
      <button id="copy-link" type="button">Copy link to this scan</button>
    </section>
  `;

  resultsEl.hidden = false;
  wireFindings(data);
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
      : `Claude read ${fmt(ai.coverage.filesInFull)} of ${fmt(ai.coverage.totalFiles)} non-test source files in full (highest-risk first)${ai.coverage.excerpts ? ` plus ${fmt(ai.coverage.excerpts)} excerpts` : ''}`
    : '';
  const cost = typeof ai.costUsd === 'number' ? ` · cost $${ai.costUsd < 0.01 ? ai.costUsd.toFixed(4) : ai.costUsd.toFixed(2)}` : '';
  return `<section class="card summary">
    <h2>Summary</h2>
    <div class="ai-summary">${paras}</div>
    <p class="sub">${cov} · ${esc(ai.model || '')}${cost}. Open the sections below for details.</p>
  </section>`;
}

function renderConcerns(data) {
  return (data.ai.top_concerns || []).map((c) => `
    <div class="concern ${esc(c.severity)}">
      <div class="t">${sevPill(c.severity)} ${esc(c.title)}</div>
      <div>${esc(c.detail)}</div>
      ${(c.locations || []).length ? `<div class="locs">${c.locations.map((l) => locFromString(data, l)).join('')}</div>` : ''}
    </div>`).join('');
}

function renderMitigations(data, heading = true) {
  const labels = {
    'smart-pointers': 'Smart pointers',
    'safe-views': 'span / string_view',
    containers: 'Standard containers',
    'checked-access': 'Checked .at() access',
    'fuzz-harness': 'Fuzz harnesses',
  };
  const entries = Object.entries(data.mitigations || {});
  const h = heading ? '<h3>Safer-idiom signals</h3>' : '';
  if (!entries.length) return `${h}<p class="sub">None detected.</p>`;
  return `${h}<ul class="plain">${entries.map(([k, v]) => `<li>${esc(labels[k] || k)}: ${fmt(v)}</li>`).join('')}</ul>`;
}

function wireFindings(data) {
  const list = $('#findings-list');
  const PAGE = 150;
  let shown = PAGE;

  const apply = () => {
    const sevs = new Set([...document.querySelectorAll('[data-sev]')].filter((c) => c.checked).map((c) => c.dataset.sev));
    const tests = $('#f-tests').checked;
    const source = $('#f-source')?.value || '';
    const showDismissed = $('#f-dismissed')?.checked || source === 'dismissed';
    // On full reviews, pattern hits Claude didn't look at are hidden unless asked for.
    const showUnreviewed = !data.ai || $('#f-unreviewed')?.checked || source === 'scanner';
    const sourceOf = (f) => (f.source === 'claude' ? 'claude' : f.verdict || 'scanner');
    const rule = $('#f-rule').value;
    const text = $('#f-text').value.trim().toLowerCase();
    const titles = Object.fromEntries(data.ruleSummary.map((r) => [r.ruleId, r.title]));
    const items = data.findings.filter(
      (f) =>
        sevs.has(f.severity) &&
        (tests || f.kind !== 'test') &&
        (!rule || f.ruleId === rule) &&
        (showDismissed || f.verdict !== 'dismissed') &&
        (showUnreviewed || f.source !== 'scanner' || f.verdict) &&
        (!source || sourceOf(f) === source) &&
        (!text || `${f.file} ${f.code} ${f.ai?.title || ''} ${f.ai?.detail || ''}`.toLowerCase().includes(text)),
    );
    const live = items.filter((f) => f.verdict !== 'dismissed' && f.locationVerified !== false);
    const bySev = SEVERITIES.map((s) => [s, live.filter((f) => f.severity === s).length]).filter(([, n]) => n);
    $('#findings-count').innerHTML = `${fmt(live.length)} shown${bySev.length ? ' · ' + bySev.map(([s, n]) => `${sevPill(s)} ${fmt(n)}`).join(' ') : ''}`;
    list.innerHTML =
      (items.length ? '' : '<p class="sub">No findings match these filters.</p>') +
      items
        .slice(0, shown)
        .map(
          (f) => `<div class="finding${f.verdict === 'dismissed' ? ' dismissed' : ''}">
          <div class="head"><span class="sev sev-${f.severity}">${f.severity}</span>
            <span class="loc">${f.locationVerified === false ? `<code>${esc(f.file)}:${f.line}</code>` : locLink(data, f.file, f.line)}</span>
            <span class="pill">${esc(titles[f.ruleId] || f.ai?.category || f.ruleId)}</span>
            ${f.source === 'claude' ? '<span class="pill claude">Found by Claude</span>' : ''}
            ${f.verdict === 'confirmed' ? '<span class="pill claude">Confirmed by Claude</span>' : ''}
            ${f.verdict === 'dismissed' ? '<span class="pill">Dismissed by Claude</span>' : ''}
            ${f.locationVerified === false ? '<span class="pill warn">Location not found in source</span>' : ''}
            ${f.scannerSeverity && f.scannerSeverity !== f.severity ? `<span class="pill">scanner said ${esc(f.scannerSeverity)}</span>` : ''}
            ${f.kind !== 'production' ? `<span class="pill">${esc(f.kind)}</span>` : ''}</div>
          ${f.ai ? `<div class="ai-note">${f.verdict === 'dismissed' ? '' : `<b>${esc(f.ai.title)}.</b> `}${esc(f.ai.detail)}</div>` : ''}
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

  document.querySelectorAll('#findings-card [data-sev], #f-tests, #f-rule, #f-source, #f-dismissed, #f-unreviewed').forEach((el) => el.addEventListener('change', () => ((shown = PAGE), apply())));
  $('#f-text').addEventListener('input', () => ((shown = PAGE), apply()));
  apply();
}

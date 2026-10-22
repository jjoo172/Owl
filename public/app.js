const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmt = (n) => Number(n || 0).toLocaleString();
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEV_COLOR = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };

const form = $('#scan-form');
const statusEl = $('#status');
const statusText = $('#status-text');
const errorEl = $('#error');
const resultsEl = $('#results');
const btn = $('#scan-btn');

let current = null;

// ---------- setup ----------
fetch('/api/health')
  .then((r) => r.json())
  .then(({ ai }) => {
    if (!ai) {
      $('#ai').checked = false;
      $('#ai').disabled = true;
      const hint = $('#ai-hint');
      hint.hidden = false;
      hint.textContent = 'Expert review is off on this server (set ANTHROPIC_API_KEY to enable it). The pattern scan still runs.';
    }
  })
  .catch(() => {});

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
  runScan($('#repo').value.trim(), $('#ref').value.trim(), $('#ai').checked);
});

// ---------- scanning ----------
async function runScan(repo, ref, ai) {
  if (!repo) return;
  const url = new URL(location.href);
  url.searchParams.set('repo', repo);
  ref ? url.searchParams.set('ref', ref) : url.searchParams.delete('ref');
  history.replaceState(null, '', url);

  btn.disabled = true;
  errorEl.hidden = true;
  resultsEl.hidden = true;
  statusEl.hidden = false;
  statusText.textContent = 'Starting…';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo, ref: ref || undefined, ai }),
    });
    if (!res.body) throw new Error('No response from server.');
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
        const msg = JSON.parse(line);
        if (msg.type === 'progress') statusText.textContent = msg.message + '…';
        else if (msg.type === 'error') throw new Error(msg.message);
        else if (msg.type === 'result') {
          current = msg.data;
          render(msg.data);
        }
      }
    }
    if (!current) throw new Error('The scan ended without a result.');
  } catch (err) {
    errorEl.textContent = err.message || String(err);
    errorEl.hidden = false;
  } finally {
    btn.disabled = false;
    statusEl.hidden = true;
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
  const level = ai?.overall_risk || risk.level;
  const headline = ['Low', 'Moderate', 'High', 'Critical'].includes(level) ? level : risk.level;
  const sevTotal = SEVERITIES.reduce((s, k) => s + (stats.bySeverity[k] || 0), 0) || 1;

  resultsEl.innerHTML = `
    <section class="card hero">
      <div class="verdict">
        <div class="label">Overall risk</div>
        <div class="level lvl-${esc(headline)}">${esc(headline)}</div>
        <div class="meter" title="Scanner score ${risk.score}/100"><div class="bg-${esc(risk.level)}" style="width:${Math.max(4, risk.score)}%"></div></div>
        <div class="sub" style="margin-top:6px">${ai ? `Claude's assessment · scanner: ${esc(risk.level)} (${risk.score}/100)` : `Scanner score ${risk.score}/100`}</div>
      </div>
      <div>
        <div class="repo-line">${repo.url ? `<a href="${esc(repo.url)}" target="_blank" rel="noopener">${esc(repo.owner)}/${esc(repo.name)}</a>` : esc(repo.name)}
          ${repo.ref ? `<span class="pill">${esc(repo.ref)}</span>` : ''}
          ${repo.sha ? `<span class="pill mono">${esc(repo.sha.slice(0, 10))}</span>` : ''}
          ${data.cached ? '<span class="pill">cached</span>' : ''}
        </div>
        <div class="stats">
          <div class="stat"><b>${fmt(stats.sourceFiles)}</b><span>C/C++ source files</span></div>
          <div class="stat"><b>${fmt(stats.loc)}</b><span>lines of code</span></div>
          <div class="stat"><b>${fmt(stats.totalFindings)}</b><span>pattern hits</span></div>
          <div class="stat"><b>${risk.density}</b><span>weighted hits / KLOC</span></div>
          <div class="stat"><b>${fmt(data.archive.ignoredNonSourceFiles)}</b><span>non-source files ignored</span></div>
        </div>
        <div class="bars" aria-label="Findings by severity">
          ${SEVERITIES.map((s) => `<div style="width:${(100 * (stats.bySeverity[s] || 0)) / sevTotal}%;background:${SEV_COLOR[s]}" title="${s}: ${stats.bySeverity[s] || 0}"></div>`).join('')}
        </div>
        <div class="sub">${SEVERITIES.map((s) => `<span style="white-space:nowrap"><span class="sev sev-${s}">${s}</span> ${fmt(stats.bySeverity[s] || 0)}</span>`).join(" &nbsp; ")}</div>
      </div>
    </section>

    ${renderAi(data)}

    <section class="two-col">
      <div class="card">
        <h2>Why this rating</h2>
        <ul class="plain">${risk.rationale.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
        ${renderMitigations(data)}
      </div>
      <div class="card">
        <h2>Hotspot files</h2>
        ${data.hotspots.length ? `<div class="table-scroll"><table>
          <thead><tr><th>File</th><th class="num">Hits</th><th class="num">Weight</th></tr></thead>
          <tbody>${data.hotspots.slice(0, 10).map((h) => `<tr>
            <td class="mono" style="word-break:break-all">${repo.blobBase ? `<a href="${esc(repo.blobBase + h.file)}" target="_blank" rel="noopener">${esc(h.file)}</a>` : esc(h.file)}
              ${h.kind !== 'production' ? `<span class="pill">${esc(h.kind)}</span>` : ''}</td>
            <td class="num">${fmt(h.findings)}</td><td class="num">${h.weighted}</td></tr>`).join('')}</tbody>
        </table></div>` : '<p class="sub">No risky patterns found.</p>'}
      </div>
    </section>

    <section class="card">
      <h2>What was found</h2>
      <p class="sub">Click a row to filter the findings below.</p>
      <div class="table-scroll"><table>
        <thead><tr><th>Severity</th><th>Pattern</th><th class="hide-sm">CWE</th><th class="num">Non-test</th><th class="num">Total</th><th class="num hide-sm">Files</th></tr></thead>
        <tbody>${data.ruleSummary.map((r) => `<tr class="rule" data-rule="${esc(r.ruleId)}" title="${esc(r.description)}">
          <td><span class="sev sev-${r.severity}">${r.severity}</span></td>
          <td><b>${esc(r.title)}</b><div class="sub">${esc(r.description)}</div></td>
          <td class="hide-sm mono"><a href="https://cwe.mitre.org/data/definitions/${esc(r.cwe.replace('CWE-', ''))}.html" target="_blank" rel="noopener">${esc(r.cwe)}</a></td>
          <td class="num">${fmt(r.productionCount)}</td><td class="num">${fmt(r.count)}</td><td class="num hide-sm">${fmt(r.files)}</td>
        </tr>`).join('') || '<tr><td colspan="6" class="sub">Nothing flagged.</td></tr>'}</tbody>
      </table></div>
    </section>

    <section class="card" id="findings-card">
      <h2>Findings</h2>
      <div class="filters">
        ${SEVERITIES.map((s) => `<label><input type="checkbox" data-sev="${s}" ${s === 'low' ? '' : 'checked'}> <span class="sev sev-${s}">${s}</span></label>`).join('')}
        <label><input type="checkbox" id="f-tests"> include test / example code</label>
        <select id="f-rule"><option value="">All patterns</option>${data.ruleSummary.map((r) => `<option value="${esc(r.ruleId)}">${esc(r.title)}</option>`).join('')}</select>
        <input type="search" id="f-text" placeholder="Filter by path or code…">
      </div>
      <div id="findings-list"></div>
      ${stats.findingsTruncated ? `<p class="sub">Showing the first ${fmt(data.findings.length)} of ${fmt(stats.totalFindings)} hits (most severe first).</p>` : ''}
    </section>

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
      $('#findings-card').scrollIntoView({ behavior: 'smooth' });
    }),
  );
}

function renderAi(data) {
  if (data.ai) {
    const ai = data.ai;
    const paras = String(ai.summary || '').split(/\n{2,}/).map((p) => `<p>${esc(p)}</p>`).join('');
    const concerns = (ai.top_concerns || []).map((c) => `
      <div class="concern ${esc(c.severity)}">
        <div class="t"><span class="sev sev-${esc(c.severity)}">${esc(c.severity)}</span> ${esc(c.title)}</div>
        <div>${esc(c.detail)}</div>
        ${(c.locations || []).length ? `<div class="locs">${c.locations.map((l) => locFromString(data, l)).join('')}</div>` : ''}
      </div>`).join('');
    return `<section class="card">
      <h2>Expert review</h2>
      <div class="ai-summary">${paras}</div>
      ${concerns ? `<h3>Top concerns</h3>${concerns}` : ''}
      <div class="two-col" style="margin-top:6px">
        ${(ai.recommendations || []).length ? `<div><h3>Before adopting</h3><ul class="plain">${ai.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}</ul></div>` : ''}
        ${(ai.likely_false_positives || []).length ? `<div><h3>Likely false positives</h3><ul class="plain">${ai.likely_false_positives.map((r) => `<li>${esc(r)}</li>`).join('')}</ul></div>` : ''}
      </div>
      <p class="sub">Reviewed ${fmt(ai.reviewedFindings)} of the most severe hits in context · ${esc(ai.model || '')}</p>
    </section>`;
  }
  if (data.aiError) return `<section class="card"><h2>Expert review</h2><p class="sub">${esc(data.aiError)} The pattern-based results below are still complete.</p></section>`;
  return '';
}

function renderMitigations(data) {
  const labels = {
    'smart-pointers': 'Smart pointers',
    'safe-views': 'span / string_view',
    containers: 'Standard containers',
    'checked-access': 'Checked .at() access',
    'fuzz-harness': 'Fuzz harnesses',
  };
  const entries = Object.entries(data.mitigations || {});
  if (!entries.length) return '<h3>Safer-idiom signals</h3><p class="sub">None detected.</p>';
  return `<h3>Safer-idiom signals</h3><ul class="plain">${entries.map(([k, v]) => `<li>${esc(labels[k] || k)}: ${fmt(v)}</li>`).join('')}</ul>`;
}

function wireFindings(data) {
  const list = $('#findings-list');
  const PAGE = 150;
  let shown = PAGE;

  const apply = () => {
    const sevs = new Set([...document.querySelectorAll('[data-sev]')].filter((c) => c.checked).map((c) => c.dataset.sev));
    const tests = $('#f-tests').checked;
    const rule = $('#f-rule').value;
    const text = $('#f-text').value.trim().toLowerCase();
    const titles = Object.fromEntries(data.ruleSummary.map((r) => [r.ruleId, r.title]));
    const items = data.findings.filter(
      (f) =>
        sevs.has(f.severity) &&
        (tests || f.kind !== 'test') &&
        (!rule || f.ruleId === rule) &&
        (!text || f.file.toLowerCase().includes(text) || f.code.toLowerCase().includes(text)),
    );
    list.innerHTML =
      (items.length ? '' : '<p class="sub">No findings match these filters.</p>') +
      items
        .slice(0, shown)
        .map(
          (f) => `<div class="finding">
          <div class="head"><span class="sev sev-${f.severity}">${f.severity}</span>
            <span class="loc">${locLink(data, f.file, f.line)}</span>
            <span class="pill">${esc(titles[f.ruleId] || f.ruleId)}</span>
            ${f.kind !== 'production' ? `<span class="pill">${esc(f.kind)}</span>` : ''}</div>
          <pre>${
            f.context
              ? f.context.map((l) => `<span class="${l.n === f.line ? 'hl' : ''}"><span class="ln">${l.n}</span>${esc(l.text)}</span>`).join('')
              : `<span class="hl"><span class="ln">${f.line}</span>${esc(f.code)}</span>`
          }</pre>
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

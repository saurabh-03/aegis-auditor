/* Aegis dashboard — vanilla JS client for the audit API. */
'use strict';

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, txt) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (txt != null) n.textContent = txt;
  return n;
};

const state = { report: null, reportId: null };

const SEV_COLOR = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--blue)', info: 'var(--text-mute)',
};

function scoreColor(score) {
  if (score >= 90) return 'var(--green)';
  if (score >= 75) return 'var(--yellow)';
  if (score >= 60) return 'var(--orange)';
  return 'var(--red)';
}

/* ---------- theme ---------- */
$('#theme-toggle').addEventListener('click', () => {
  const html = document.documentElement;
  html.dataset.theme = html.dataset.theme === 'dark' ? 'light' : 'dark';
});

/* ---------- scan flow ---------- */
$('#scan-btn').addEventListener('click', onScanClick);
$('#target').addEventListener('keydown', (e) => { if (e.key === 'Enter') onScanClick(); });

function onScanClick() {
  const target = $('#target').value.trim();
  if (!target) { $('#target').focus(); return; }
  runScan(target);
}

async function runScan(target) {
  $('#results').classList.add('hidden');
  $('#loading').classList.remove('hidden');
  $('#loading-text').textContent = `Scanning ${target}…`;
  $('#scan-btn').disabled = true;
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || data.error || 'Scan failed');
    state.report = data.report;
    state.reportId = data.id;
    render(data.report, data.id);
  } catch (err) {
    alert('Scan error: ' + err.message);
  } finally {
    $('#loading').classList.add('hidden');
    $('#scan-btn').disabled = false;
  }
}

/* ---------- rendering ---------- */
function render(report, id) {
  $('#results').classList.remove('hidden');
  $('#result-target').textContent = report.target;

  // gauge
  const score = report.overall.score;
  $('#overall-score').textContent = score;
  $('#overall-grade').textContent = report.overall.grade;
  const arc = $('#gauge-arc');
  const circ = 490;
  arc.style.stroke = scoreColor(score);
  arc.style.transition = 'stroke-dashoffset 1s ease';
  requestAnimationFrame(() => { arc.setAttribute('stroke-dashoffset', String(circ - (circ * score) / 100)); });

  // categories
  const cats = $('#cats');
  cats.innerHTML = '';
  report.categories
    .filter((c) => Object.values(c.findingCounts).reduce((a, b) => a + b, 0) > 0)
    .forEach((c) => {
      const card = el('div', 'cat');
      card.appendChild(el('div', 'name', c.category));
      const val = el('div', 'val', c.score);
      val.style.color = scoreColor(c.score);
      card.appendChild(val);
      const track = el('div', 'track');
      const fill = el('div', 'fill');
      fill.style.width = c.score + '%';
      fill.style.background = scoreColor(c.score);
      track.appendChild(fill);
      card.appendChild(track);
      cats.appendChild(card);
    });

  // summary chips
  const counts = { critical: 0, high: 0, medium: 0, low: 0, pass: 0 };
  report.findings.forEach((f) => {
    if (f.status === 'pass') counts.pass++;
    else if (f.severity in counts) counts[f.severity]++;
  });
  const chips = $('#chips');
  chips.innerHTML = '';
  [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['pass', 'Passing']].forEach(([k, label]) => {
    const chip = el('div', 'chip');
    const dot = el('span', 'dot');
    dot.style.background = k === 'pass' ? 'var(--green)' : SEV_COLOR[k];
    chip.appendChild(dot);
    chip.appendChild(el('span', null, `${counts[k]} ${label}`));
    chips.appendChild(chip);
  });

  // exports
  $('#export-md').href = `/api/reports/${id}/report.md`;
  $('#export-csv').href = `/api/reports/${id}/report.csv`;

  // category filter options
  const catSel = $('#filter-cat');
  catSel.innerHTML = '<option value="">All categories</option>';
  [...new Set(report.findings.map((f) => f.category))].forEach((c) => {
    const o = el('option', null, c);
    o.value = c;
    catSel.appendChild(o);
  });

  renderFindings();
}

['#filter-text', '#filter-sev', '#filter-cat', '#filter-pass'].forEach((sel) =>
  $(sel).addEventListener('input', renderFindings),
);

function renderFindings() {
  if (!state.report) return;
  const q = $('#filter-text').value.toLowerCase();
  const sev = $('#filter-sev').value;
  const cat = $('#filter-cat').value;
  const showPass = $('#filter-pass').checked;
  const container = $('#findings');
  container.innerHTML = '';

  const list = state.report.findings.filter((f) => {
    if (!showPass && f.status === 'pass') return false;
    if (sev && f.severity !== sev) return false;
    if (cat && f.category !== cat) return false;
    if (q && !(`${f.title} ${f.risk} ${f.technical}`.toLowerCase().includes(q))) return false;
    return true;
  });

  if (list.length === 0) {
    container.appendChild(el('p', 'muted', 'No findings match the current filters.'));
    return;
  }

  list.forEach((f) => container.appendChild(findingNode(f)));
}

function findingNode(f) {
  const wrap = el('div', `finding ${f.status === 'pass' ? 'status-pass' : 'sev-' + f.severity}`);
  const head = el('div', 'head');
  head.appendChild(el('span', 'sev', f.status === 'pass' ? 'pass' : f.severity));
  head.appendChild(el('span', 'title', f.title));
  head.appendChild(el('span', 'cat-tag', f.category));
  head.appendChild(el('span', 'caret', '▸'));
  head.addEventListener('click', () => wrap.classList.toggle('open'));
  wrap.appendChild(head);

  const body = el('div', 'body');
  const dl = el('dl');
  const add = (k, v) => { if (v) { dl.appendChild(el('dt', null, k)); dl.appendChild(el('dd', null, v)); } };
  add('Risk', f.risk);
  add('Why it matters', f.whyItMatters);
  add('Technical', f.technical);
  add('Business impact', f.businessImpact);
  add('Probability', f.probability);
  add('Remediation', f.remediation);
  add('Fix effort', f.estimatedFixTime);
  body.appendChild(dl);

  if ((f.owasp && f.owasp.length) || (f.cve && f.cve.length)) {
    const tags = el('div', 'tags');
    (f.owasp || []).forEach((o) => tags.appendChild(el('span', 'tag', o)));
    (f.cve || []).forEach((c) => tags.appendChild(el('span', 'tag', c)));
    body.appendChild(tags);
  }
  if (f.exampleCode) {
    const pre = el('pre');
    pre.textContent = f.exampleCode;
    body.appendChild(pre);
  }
  if (f.references && f.references.length) {
    const refs = el('div', 'refs');
    f.references.forEach((r) => {
      const a = el('a', null, r);
      a.href = r; a.target = '_blank'; a.rel = 'noopener';
      refs.appendChild(a);
    });
    body.appendChild(refs);
  }
  wrap.appendChild(body);
  return wrap;
}

$('#export-json').addEventListener('click', () => {
  if (!state.report) return;
  const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `aegis-${state.reportId || 'report'}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

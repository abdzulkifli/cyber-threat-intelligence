let KEV = null;
let NVD = null;
let EPSS = null;
let NVD_BY_ID = new Map();
let EPSS_BY_ID = new Map();

const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmt = n => Number(n || 0).toLocaleString();

function ageDays(dateStr) {
  if (!dateStr) return Infinity;
  const d = new Date(`${dateStr}T00:00:00Z`);
  return (Date.now() - d.getTime()) / 86400000;
}

function fmtDateTime(value) {
  if (!value) return 'Not collected yet';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function severityClass(severity) {
  const s = String(severity || 'UNKNOWN').toUpperCase();
  return `severity severity-${['CRITICAL','HIGH','MEDIUM','LOW'].includes(s) ? s.toLowerCase() : 'unknown'}`;
}

function priorityLabel(score) {
  if (score >= 75) return 'CRITICAL';
  if (score >= 55) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

function ctiPriority(v) {
  const nvd = v.nvd;
  const epss = v.epss;
  const severity = String(nvd?.cvss?.severity || 'UNKNOWN').toUpperCase();
  let score = ({ CRITICAL: 30, HIGH: 24, MEDIUM: 15, LOW: 8, UNKNOWN: 5 })[severity] ?? 5;

  const p = Number(epss?.epss ?? 0);
  if (p >= 0.70) score += 35;
  else if (p >= 0.50) score += 32;
  else if (p >= 0.20) score += 28;
  else if (p >= 0.10) score += 24;
  else if (p >= 0.05) score += 20;
  else if (p >= 0.01) score += 14;
  else score += 6;

  if (v.ransomware) score += 25;
  const age = ageDays(v.dateAdded);
  if (age <= 7) score += 10;
  else if (age <= 30) score += 6;
  else if (age <= 90) score += 3;

  score = Math.min(100, score);
  return { score, label: priorityLabel(score) };
}

function priorityClass(label) {
  return `priority priority-${String(label || 'LOW').toLowerCase()}`;
}

function buildUnifiedItems() {
  if (!KEV) return [];
  return (KEV.vulnerabilities || []).map(v => {
    const item = { ...v, nvd: NVD_BY_ID.get(v.id) || null, epss: EPSS_BY_ID.get(v.id) || null };
    item.priority = ctiPriority(item);
    return item;
  });
}

function renderMetrics() {
  if (KEV) {
    $('total').textContent = fmt(KEV.stats.total);
    $('today').textContent = fmt(KEV.stats.addedToday);
    $('week').textContent = fmt(KEV.stats.added7d);
    $('month').textContent = fmt(KEV.stats.added30d);
    $('ransomware').textContent = fmt(KEV.stats.ransomwareRelated);
  }

  const nvdReady = NVD?.meta?.status === 'ok';
  if (nvdReady) {
    $('nvdCoverage').textContent = `${Number(NVD.stats.coveragePercent || 0).toFixed(1)}%`;
    $('nvdCoverageHint').textContent = `${fmt(NVD.stats.withCvss)} of ${fmt(NVD.stats.total)} records with CVSS`;
    $('critical').textContent = fmt(NVD.stats.critical);
    $('high').textContent = fmt(NVD.stats.high);
  } else {
    $('nvdCoverage').textContent = 'PENDING';
    $('nvdCoverageHint').textContent = 'Run the NVD enrichment workflow';
    $('critical').textContent = '—';
    $('high').textContent = '—';
  }
}

function renderEpssSummary() {
  const ready = EPSS?.meta?.status === 'ok';
  if (!ready) {
    $('epssCoverage').textContent = 'PENDING';
    $('epssCoverageHint').textContent = 'Run FIRST EPSS workflow';
    ['epss50','epss10','epss99','priorityCritical'].forEach(id => $(id).textContent = '—');
    $('epssScoreDate').textContent = 'Waiting for EPSS collection';
    return;
  }

  $('epssCoverage').textContent = `${Number(EPSS.stats.coveragePercent || 0).toFixed(1)}%`;
  $('epssCoverageHint').textContent = `${fmt(EPSS.stats.matched)} of ${fmt(EPSS.stats.kevTotal)} KEVs scored`;
  $('epss50').textContent = fmt(EPSS.stats.epssGe50);
  $('epss10').textContent = fmt(EPSS.stats.epssGe10);
  $('epss99').textContent = fmt(EPSS.stats.percentileGe99);
  $('epssScoreDate').textContent = `Score date: ${EPSS.meta.scoreDate || 'current daily file'}`;

  const criticalCount = buildUnifiedItems().filter(x => x.priority.label === 'CRITICAL').length;
  $('priorityCritical').textContent = fmt(criticalCount);
}

function renderVendors() {
  if (!KEV) return;
  const list = KEV.stats.topVendors || [];
  const max = Math.max(...list.map(x => x.count), 1);
  $('vendors').innerHTML = list.map(v => `
    <div class="vendor-row">
      <div><strong>${esc(v.name)}</strong><div class="vendor-bar"><div class="vendor-fill" style="width:${Math.max(5, v.count/max*100)}%"></div></div></div>
      <strong>${fmt(v.count)}</strong>
    </div>`).join('') || '<div class="muted">No data yet.</div>';
  $('vendorCount').textContent = `${list.length} shown`;
}

function setBadge(id, ready, readyText = 'ONLINE', waitingText = 'NOT READY') {
  const el = $(id);
  el.textContent = ready ? readyText : waitingText;
  el.className = `badge ${ready ? 'green' : 'amber'}`;
}

function renderHealth() {
  const cisaOk = KEV?.meta?.status === 'ok';
  const nvdOk = NVD?.meta?.status === 'ok';
  const epssOk = EPSS?.meta?.status === 'ok';

  setBadge('cisaSourceBadge', cisaOk, 'ONLINE');
  setBadge('nvdSourceBadge', nvdOk, 'ONLINE', 'PENDING');
  setBadge('epssSourceBadge', epssOk, 'ONLINE', 'PENDING');

  $('cisaCollectedAt').textContent = cisaOk ? fmtDateTime(KEV.meta.collectedAt) : 'Not collected yet';
  $('sourceMode').textContent = cisaOk ? `${KEV.meta.sourceMode || '—'}${KEV.meta.fallbackUsed ? ' (official mirror)' : ''}` : '—';
  $('catalogVersion').textContent = cisaOk ? (KEV.meta.catalogVersion || '—') : '—';
  $('recordCount').textContent = cisaOk ? fmt(KEV.meta.count) : '—';

  $('nvdCollectedAt').textContent = nvdOk ? fmtDateTime(NVD.meta.collectedAt) : 'Not collected yet';
  $('nvdRecordCount').textContent = nvdOk ? fmt(NVD.meta.count) : '—';
  $('nvdCvssCount').textContent = nvdOk ? fmt(NVD.stats.withCvss) : '—';

  $('epssCollectedAt').textContent = epssOk ? fmtDateTime(EPSS.meta.collectedAt) : 'Not collected yet';
  $('epssDate').textContent = epssOk ? (EPSS.meta.scoreDate || 'Current') : '—';
  $('epssRecordCount').textContent = epssOk ? fmt(EPSS.meta.matchedKev || EPSS.stats.matched) : '—';
  $('epssModel').textContent = epssOk ? (EPSS.meta.modelVersion || 'Current') : '—';

  const liveCount = [cisaOk, nvdOk, epssOk].filter(Boolean).length;
  if (liveCount === 3) {
    $('feedStatus').textContent = '3 SOURCES LIVE';
    $('liveDot').className = 'dot';
  } else if (liveCount > 0) {
    $('feedStatus').textContent = `${liveCount} SOURCE${liveCount > 1 ? 'S' : ''} LIVE`;
    $('liveDot').className = 'dot amber-dot';
  } else {
    $('feedStatus').textContent = 'DATA NOT READY';
    $('liveDot').className = 'dot red-dot';
  }
}

function renderSeverity() {
  const ready = NVD?.meta?.status === 'ok';
  if (!ready) {
    ['sevCritical','sevHigh','sevMedium','sevLow','sevUnknown'].forEach(id => $(id).textContent = '—');
    $('severityCoverage').textContent = 'Run NVD enrichment to populate severity';
    return;
  }
  $('sevCritical').textContent = fmt(NVD.stats.critical);
  $('sevHigh').textContent = fmt(NVD.stats.high);
  $('sevMedium').textContent = fmt(NVD.stats.medium);
  $('sevLow').textContent = fmt(NVD.stats.low);
  $('sevUnknown').textContent = fmt(NVD.stats.unknown);
  $('severityCoverage').textContent = `${Number(NVD.stats.coveragePercent || 0).toFixed(1)}% CVSS coverage`;
}

function epssMatchesFilter(item, filter) {
  if (filter === 'all') return true;
  const p = item.epss?.epss;
  if (p === null || p === undefined) return false;
  if (filter === '50') return p >= 0.50;
  if (filter === '10') return p >= 0.10;
  if (filter === '1') return p >= 0.01;
  if (filter === 'lt1') return p < 0.01;
  return true;
}

function renderTable() {
  if (!KEV) return;
  const q = $('search').value.trim().toLowerCase();
  const ransom = $('ransomFilter').value;
  const period = $('periodFilter').value;
  const severity = $('severityFilter').value;
  const epssFilter = $('epssFilter').value;
  const priorityFilter = $('priorityFilter').value;

  const items = buildUnifiedItems().filter(v => {
    const nvd = v.nvd;
    const hay = `${v.id} ${v.vendor} ${v.product} ${v.vulnerabilityName} ${v.description} ${nvd?.description || ''} ${nvd?.cvss?.severity || ''}`.toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (ransom === 'yes' && !v.ransomware) return false;
    if (ransom === 'no' && v.ransomware) return false;
    if (period !== 'all' && ageDays(v.dateAdded) > Number(period)) return false;
    const sev = String(nvd?.cvss?.severity || 'UNKNOWN').toUpperCase();
    if (severity !== 'all' && sev !== severity) return false;
    if (!epssMatchesFilter(v, epssFilter)) return false;
    if (priorityFilter !== 'all' && v.priority.label !== priorityFilter) return false;
    return true;
  });

  const sourceState = [NVD?.meta?.status === 'ok' ? 'NVD' : null, EPSS?.meta?.status === 'ok' ? 'EPSS' : null].filter(Boolean).join(' + ') || 'enrichment pending';
  $('resultLabel').textContent = `${fmt(items.length)} matching records · newest first · ${sourceState}`;
  $('rows').innerHTML = items.slice(0, 1000).map(v => {
    const nvd = v.nvd;
    const cvss = nvd?.cvss || {};
    const sev = String(cvss.severity || 'UNKNOWN').toUpperCase();
    const score = cvss.score === null || cvss.score === undefined ? '—' : Number(cvss.score).toFixed(1);
    const epss = v.epss;
    const epssPct = epss ? `${(Number(epss.epss) * 100).toFixed(2)}%` : '—';
    const percentilePct = epss ? `${(Number(epss.percentile) * 100).toFixed(2)}%` : '—';
    const description = nvd?.description || v.description;
    const nvdLink = nvd?.sourceUrl ? `<a class="source-link" href="${esc(nvd.sourceUrl)}" target="_blank" rel="noopener">NVD ↗</a>` : '';
    return `
      <tr>
        <td>${esc(v.dateAdded || '—')}</td>
        <td><strong class="source">${esc(v.id)}</strong><div class="source-links">${nvdLink}</div></td>
        <td><strong>${esc(v.vendor)}</strong><br><span class="muted">${esc(v.product)}</span></td>
        <td><span class="cvss-score">${score}</span>${cvss.version ? `<small class="cvss-version">v${esc(cvss.version)}</small>` : ''}</td>
        <td><span class="${severityClass(sev)}">${esc(sev)}</span></td>
        <td><strong class="epss-score">${epssPct}</strong></td>
        <td>${percentilePct}</td>
        <td><span class="badge ${v.ransomware ? 'red' : 'green'}">${v.ransomware ? 'KNOWN' : 'NOT KNOWN'}</span></td>
        <td><span class="${priorityClass(v.priority.label)}">${esc(v.priority.label)}</span><div class="priority-score">${v.priority.score}/100</div></td>
        <td><strong>${esc(v.vulnerabilityName)}</strong><br><span class="muted">${esc(description)}</span>${cvss.vector ? `<div class="vector">${esc(cvss.vector)}</div>` : ''}</td>
        <td>${esc(v.requiredAction)}</td>
      </tr>`;
  }).join('') || '<tr><td colspan="11" class="muted">No records match the current filters.</td></tr>';
}

async function fetchJson(path) {
  const res = await fetch(`${path}?t=${Date.now()}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

async function load() {
  const [kevResult, nvdResult, epssResult] = await Promise.allSettled([
    fetchJson('data/kev.json'),
    fetchJson('data/nvd.json'),
    fetchJson('data/epss.json')
  ]);

  if (kevResult.status === 'fulfilled') KEV = kevResult.value;
  if (nvdResult.status === 'fulfilled') NVD = nvdResult.value;
  if (epssResult.status === 'fulfilled') EPSS = epssResult.value;

  NVD_BY_ID = NVD?.meta?.status === 'ok' ? new Map((NVD.vulnerabilities || []).map(v => [v.id, v])) : new Map();
  EPSS_BY_ID = EPSS?.meta?.status === 'ok' ? new Map((EPSS.vulnerabilities || []).map(v => [v.id, v])) : new Map();

  if (!KEV) {
    $('feedStatus').textContent = 'CISA DATA ERROR';
    $('liveDot').className = 'dot red-dot';
    $('resultLabel').textContent = kevResult.reason?.message || 'Unable to load CISA KEV data.';
    return;
  }

  renderMetrics();
  renderEpssSummary();
  renderVendors();
  renderHealth();
  renderSeverity();
  renderTable();
}

['search','severityFilter','epssFilter','priorityFilter','ransomFilter','periodFilter'].forEach(id => $(id).addEventListener(id === 'search' ? 'input' : 'change', renderTable));
load();
setInterval(load, 5 * 60 * 1000);

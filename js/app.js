let DATA = null;
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmt = n => Number(n || 0).toLocaleString();

function ageDays(dateStr) {
  if (!dateStr) return Infinity;
  const d = new Date(`${dateStr}T00:00:00Z`);
  return (Date.now() - d.getTime()) / 86400000;
}

function renderMetrics(d) {
  $('total').textContent = fmt(d.stats.total);
  $('today').textContent = fmt(d.stats.addedToday);
  $('week').textContent = fmt(d.stats.added7d);
  $('month').textContent = fmt(d.stats.added30d);
  $('ransomware').textContent = fmt(d.stats.ransomwareRelated);
  $('ransomware30').textContent = fmt(d.stats.ransomwareAdded30d);
}

function renderVendors(d) {
  const list = d.stats.topVendors || [];
  const max = Math.max(...list.map(x => x.count), 1);
  $('vendors').innerHTML = list.map(v => `
    <div class="vendor-row">
      <div><strong>${esc(v.name)}</strong><div class="vendor-bar"><div class="vendor-fill" style="width:${Math.max(5, v.count/max*100)}%"></div></div></div>
      <strong>${fmt(v.count)}</strong>
    </div>`).join('') || '<div class="muted">No data yet.</div>';
  $('vendorCount').textContent = `${list.length} shown`;
}

function renderHealth(d) {
  const ok = d.meta.status === 'ok';
  $('feedStatus').textContent = ok ? 'LIVE DATA' : 'NO DATA';
  $('sourceBadge').textContent = ok ? 'ONLINE' : 'NOT READY';
  $('sourceBadge').className = `badge ${ok ? 'green' : 'red'}`;
  $('collectedAt').textContent = d.meta.collectedAt ? new Date(d.meta.collectedAt).toLocaleString() : 'Not collected yet';
  $('sourceMode').textContent = d.meta.sourceMode ? `${d.meta.sourceMode}${d.meta.fallbackUsed ? ' (official mirror)' : ''}` : '—';
  $('catalogVersion').textContent = d.meta.catalogVersion || '—';
  $('recordCount').textContent = fmt(d.meta.count);
}

function renderTable() {
  if (!DATA) return;
  const q = $('search').value.trim().toLowerCase();
  const ransom = $('ransomFilter').value;
  const period = $('periodFilter').value;

  let items = DATA.vulnerabilities.filter(v => {
    const hay = `${v.id} ${v.vendor} ${v.product} ${v.vulnerabilityName} ${v.description}`.toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (ransom === 'yes' && !v.ransomware) return false;
    if (ransom === 'no' && v.ransomware) return false;
    if (period !== 'all' && ageDays(v.dateAdded) > Number(period)) return false;
    return true;
  });

  $('resultLabel').textContent = `${fmt(items.length)} matching records · newest first`;
  $('rows').innerHTML = items.slice(0, 1000).map(v => `
    <tr>
      <td>${esc(v.dateAdded || '—')}</td>
      <td><strong class="source">${esc(v.id)}</strong></td>
      <td>${esc(v.vendor)}</td>
      <td>${esc(v.product)}</td>
      <td><span class="badge ${v.ransomware ? 'red' : 'green'}">${v.ransomware ? 'KNOWN' : 'NOT KNOWN'}</span></td>
      <td><strong>${esc(v.vulnerabilityName)}</strong><br><span class="muted">${esc(v.description)}</span></td>
      <td>${esc(v.requiredAction)}</td>
    </tr>`).join('') || '<tr><td colspan="7" class="muted">No records match the current filters.</td></tr>';
}

async function load() {
  try {
    const res = await fetch(`data/kev.json?t=${Date.now()}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    DATA = await res.json();
    renderMetrics(DATA);
    renderVendors(DATA);
    renderHealth(DATA);
    renderTable();
  } catch (err) {
    $('feedStatus').textContent = 'ERROR';
    $('sourceBadge').textContent = 'ERROR';
    $('sourceBadge').className = 'badge red';
    $('resultLabel').textContent = `Unable to load data: ${err.message}`;
  }
}

['search','ransomFilter','periodFilter'].forEach(id => $(id).addEventListener(id === 'search' ? 'input' : 'change', renderTable));
load();
setInterval(load, 5 * 60 * 1000);

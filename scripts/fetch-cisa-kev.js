const fs = require('fs/promises');
const path = require('path');

const PRIMARY_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const FALLBACK_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const OUTPUT = path.join(__dirname, '..', 'data', 'kev.json');

async function fetchJson(url, timeoutMs = 20000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'CTI-Phase1/1.0 (+GitHub Actions; public threat intelligence collector)',
        'Accept': 'application/json'
      },
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

function normalise(v) {
  return {
    id: v.cveID,
    vendor: v.vendorProject || 'Unknown',
    product: v.product || 'Unknown',
    vulnerabilityName: v.vulnerabilityName || '',
    dateAdded: v.dateAdded || null,
    description: v.shortDescription || '',
    requiredAction: v.requiredAction || '',
    dueDate: v.dueDate || null,
    ransomware: String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
    ransomwareRaw: v.knownRansomwareCampaignUse || 'Unknown',
    notes: v.notes || '',
    cwes: Array.isArray(v.cwes) ? v.cwes : [],
    source: 'CISA KEV'
  };
}

function dateOnlyUtc(value) {
  if (!value) return null;
  const d = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

function withinDays(dateStr, days, now = new Date()) {
  const d = dateOnlyUtc(dateStr);
  if (!d) return false;
  const age = now - d;
  return age >= 0 && age <= days * 86400000;
}

function topBy(items, key, limit = 8) {
  const counts = new Map();
  for (const item of items) {
    const value = item[key] || 'Unknown';
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

async function main() {
  let raw;
  let sourceUrl;
  let sourceMode;
  const attempts = [];

  for (const [mode, url] of [['primary', PRIMARY_URL], ['fallback', FALLBACK_URL]]) {
    try {
      raw = await fetchJson(url);
      sourceUrl = url;
      sourceMode = mode;
      break;
    } catch (err) {
      attempts.push({ mode, url, error: err.message });
      console.warn(`[${mode}] ${url} failed: ${err.message}`);
    }
  }

  if (!raw) {
    throw new Error(`All CISA KEV sources failed: ${JSON.stringify(attempts)}`);
  }

  const vulnerabilities = (raw.vulnerabilities || [])
    .map(normalise)
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)) || String(a.id).localeCompare(String(b.id)));

  const now = new Date();
  const ransomware = vulnerabilities.filter(v => v.ransomware);
  const output = {
    meta: {
      dataset: 'CISA Known Exploited Vulnerabilities',
      phase: 1,
      status: 'ok',
      collectedAt: now.toISOString(),
      sourcePublished: raw.dateReleased || null,
      catalogVersion: raw.catalogVersion || null,
      count: vulnerabilities.length,
      primarySource: PRIMARY_URL,
      actualSource: sourceUrl,
      sourceMode,
      fallbackUsed: sourceMode === 'fallback',
      attempts
    },
    stats: {
      total: vulnerabilities.length,
      addedToday: vulnerabilities.filter(v => withinDays(v.dateAdded, 1, now)).length,
      added7d: vulnerabilities.filter(v => withinDays(v.dateAdded, 7, now)).length,
      added30d: vulnerabilities.filter(v => withinDays(v.dateAdded, 30, now)).length,
      ransomwareRelated: ransomware.length,
      ransomwareAdded30d: ransomware.filter(v => withinDays(v.dateAdded, 30, now)).length,
      topVendors: topBy(vulnerabilities, 'vendor')
    },
    vulnerabilities
  };

  await fs.mkdir(path.dirname(OUTPUT), { recursive: true });
  await fs.writeFile(OUTPUT, JSON.stringify(output, null, 2) + '\n', 'utf8');
  console.log(`Saved ${vulnerabilities.length} KEV records to ${OUTPUT}`);
  console.log(`Source: ${sourceMode} -> ${sourceUrl}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

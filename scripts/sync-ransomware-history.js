const fs = require('fs');
const path = require('path');

const API_KEY = process.env.RANSOMWARE_LIVE_API_KEY || '';
const BASE = (process.env.RANSOMWARE_LIVE_PRO_BASE || 'https://api-pro.ransomware.live').replace(/\/$/, '');
const OUT = path.join(__dirname, '..', 'data', 'ransomware-history.json');
const CURRENT = path.join(__dirname, '..', 'data', 'ransomware.json');
const START_YEAR = 2013;
const CURRENT_YEAR = new Date().getUTCFullYear();
const ASEAN = ['BN','KH','ID','LA','MY','MM','PH','SG','TH','TL','VN'];

const sleep = ms => new Promise(r => setTimeout(r, ms));
const str = (...values) => {
  const v = values.find(x => x !== undefined && x !== null && String(x).trim() !== '');
  return v === undefined ? '' : String(v).trim();
};

function toIso(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function arrayFrom(raw) {
  if (Array.isArray(raw)) return raw;
  for (const k of ['victims', 'data', 'result', 'results', 'items']) {
    if (Array.isArray(raw?.[k])) return raw[k];
  }
  return [];
}

function countryValue(v) {
  const raw = v.country ?? v.country_code ?? v.countrycode ?? v.country_name;
  if (raw && typeof raw === 'object') {
    return str(raw.code, raw.alpha2, raw.iso2, raw.name, raw.country);
  }
  return str(raw, 'Unknown');
}

function normalizeVictim(v, idx = 0) {
  return {
    id: str(v.id, v.victim_id, v.uuid, `${str(v.victim, v.name, v.post_title)}-${idx}`),
    victim: str(v.victim, v.name, v.post_title, v.title, 'Unknown victim'),
    group: str(v.group, v.group_name, v.ransomware, v.ransomware_group, 'Unknown'),
    country: countryValue(v),
    sector: str(v.sector, v.activity, v.industry, v.business_sector, 'Unspecified'),
    discovered: toIso(v.discovered || v.discovered_at || v.date || v.published || v.created_at || v.firstseen || v.first_seen),
    attacked: toIso(v.attackdate || v.attacked || v.attack_date),
    website: str(v.website, v.domain, v.url),
    screenshot: str(v.screenshot, v.screenshot_url),
    infostealer: str(v.infostealer, v.infostealer_status, v.stealer),
    press: str(v.press, v.press_coverage, v.presscoverage),
    description: str(v.description, v.summary),
    sourceUrl: str(v.permalink, v.source_url, v.link, v.post_url)
  };
}

function stableKey(v) {
  if (v.id && !String(v.id).startsWith('Unknown')) return `id:${v.id}`;
  return [
    str(v.victim).toLowerCase(),
    str(v.group).toLowerCase(),
    str(v.country).toUpperCase(),
    str(v.discovered).slice(0, 19),
    str(v.website).toLowerCase()
  ].join('|');
}

async function fetchJson(url, attempts = 3) {
  let last;
  for (let i = 1; i <= attempts; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 180000);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          accept: 'application/json',
          'X-API-KEY': API_KEY,
          'user-agent': 'Cyber-Threat-Intelligence-Command-Centre/1.6'
        }
      });
      clearTimeout(timer);
      const text = await res.text();
      const contentType = String(res.headers.get('content-type') || '').toLowerCase();

      if (!res.ok) {
        const e = new Error(`HTTP ${res.status}: ${text.slice(0, 320).replace(/\s+/g, ' ')}`);
        e.status = res.status;
        throw e;
      }

      const trimmed = text.trim();
      if (!contentType.includes('json') && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
        throw new Error(`Expected JSON but received ${contentType || 'non-JSON'} from ${url}: ${trimmed.slice(0, 220).replace(/\s+/g, ' ')}`);
      }

      try {
        return JSON.parse(text);
      } catch (parseErr) {
        throw new Error(`Invalid JSON from ${url}: ${parseErr.message}. Response begins: ${trimmed.slice(0, 220).replace(/\s+/g, ' ')}`);
      }
    } catch (err) {
      clearTimeout(timer);
      last = err;
      const retryable = err.name === 'AbortError' || !err.status || err.status === 429 || err.status >= 500;
      console.warn(`Attempt ${i}/${attempts} failed: ${err.message}`);
      if (!retryable || i === attempts) break;
      await sleep(2500 * i);
    }
  }
  throw last;
}

async function validateApiKey() {
  console.log(`Validating ransomware.live Pro API key against ${BASE}/validate`);
  const raw = await fetchJson(`${BASE}/validate`, 1);
  console.log(`API key valid${raw?.client_id || raw?.clientId ? ` for ${raw.client_id || raw.clientId}` : ''}.`);
  return raw;
}

async function fetchVictims(params) {
  const qs = new URLSearchParams(params).toString();
  // Pro API list-victims endpoint. At least one filter is required.
  const url = `${BASE}/victims/?${qs}`;
  console.log(`GET ${url}`);
  const raw = await fetchJson(url);
  return arrayFrom(raw);
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function countBy(items, key) {
  const m = new Map();
  for (const x of items) {
    const v = str(x[key], 'Unknown');
    m.set(v, (m.get(v) || 0) + 1);
  }
  return [...m.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

async function main() {
  if (!API_KEY) {
    throw new Error('RANSOMWARE_LIVE_API_KEY is missing. Add it under GitHub repository Settings → Secrets and variables → Actions.');
  }

  await validateApiKey();

  const existing = readJson(OUT, { meta: {}, victims: [] });
  const current = readJson(CURRENT, { victims: [] });
  const map = new Map();

  const add = raw => {
    arrayFrom(raw)
      .map(normalizeVictim)
      .filter(v => v.victim && v.victim !== 'Unknown victim')
      .forEach(v => {
        const k = stableKey(v);
        const prev = map.get(k) || {};
        map.set(k, { ...prev, ...v });
      });
  };

  add(existing.victims || []);
  add(current.victims || []);

  const years = [];
  const currentMonth = new Date().getUTCMonth() + 1;

  // ransomware.live requires month whenever year is supplied.
  // Sync month-by-month so we can build a complete historical mirror.
  for (let year = START_YEAR; year <= CURRENT_YEAR; year++) {
    console.log(`\n=== Historical sync ${year} ===`);
    const maxMonth = year === CURRENT_YEAR ? currentMonth : 12;
    let yearCount = 0;
    const months = [];

    for (let month = 1; month <= maxMonth; month++) {
      const mm = String(month).padStart(2, '0');
      console.log(`--- ${year}-${mm} ---`);
      const rows = await fetchVictims({
        year: String(year),
        month: mm,
        date: 'discovered'
      });
      console.log(`${year}-${mm}: ${rows.length} victim records`);
      add(rows);
      yearCount += rows.length;
      months.push({ month: mm, count: rows.length });
      await sleep(250);
    }

    console.log(`${year}: ${yearCount} victim records across ${maxMonth} month(s)`);
    years.push({ year, count: yearCount, months });
  }

  // Verify ASEAN independently so Malaysia/ASEAN counts do not depend on a country-name mapping guess.
  const aseanVerification = {};
  for (const code of ASEAN) {
    console.log(`\n=== ASEAN verification ${code} ===`);
    const rows = await fetchVictims({ country: code, date: 'discovered' });
    aseanVerification[code] = rows.length;
    console.log(`${code}: ${rows.length} victim records`);
    add(rows);
    await sleep(400);
  }

  let stats = {};
  try {
    stats = await fetchJson(`${BASE}/stats`);
  } catch (err) {
    console.warn(`Stats endpoint unavailable: ${err.message}`);
  }

  const victims = [...map.values()].sort((a, b) => String(b.discovered || '').localeCompare(String(a.discovered || '')));
  const malaysia = victims.filter(v => {
    const c = String(v.country || '').trim().toUpperCase();
    return c === 'MY' || c === 'MALAYSIA';
  });
  const asean = victims.filter(v => ASEAN.includes(String(v.country || '').trim().toUpperCase()));

  const sourceTotalVictims = Number(stats.total_victims ?? stats.totalVictims ?? stats.victims ?? 0) || null;
  const sourceTotalGroups = Number(stats.total_groups ?? stats.totalGroups ?? stats.groups ?? 0) || null;

  const output = {
    meta: {
      status: 'ok',
      source: 'ransomware.live Pro API',
      sourceUrl: 'https://www.ransomware.live/',
      apiBase: BASE,
      upstream: 'ransomware.live',
      fullSync: true,
      fullSyncedAt: new Date().toISOString(),
      collectedAt: new Date().toISOString(),
      archiveScope: `historical victim mirror ${START_YEAR}-${CURRENT_YEAR} + incremental recent-feed updates`,
      sourceTotalVictims,
      sourceTotalGroups,
      yearsSynced: years,
      aseanVerification,
      authentication: 'X-API-KEY via GitHub Secret (not exposed to dashboard)',
      methodology: 'Historical victim claims are mirrored from the authenticated ransomware.live victim API using year filters, then ASEAN countries are independently verified with ISO alpha-2 country filters. Claims are public ransomware/extortion leak-site observations and are not independently verified incidents.'
    },
    stats: {
      retainedClaims: victims.length,
      malaysiaClaims: malaysia.length,
      aseanClaims: asean.length,
      uniqueCountries: countBy(victims, 'country').filter(x => x.name !== 'Unknown').length,
      uniqueGroups: countBy(victims, 'group').filter(x => x.name !== 'Unknown').length
    },
    topCountries: countBy(victims, 'country').slice(0, 30),
    topGroups: countBy(victims, 'group').slice(0, 30),
    topSectors: countBy(victims, 'sector').slice(0, 30),
    victims
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');

  console.log('\n=== FULL HISTORY SYNC COMPLETE ===');
  console.log(`Local mirrored claims: ${victims.length}`);
  console.log(`Malaysia claims: ${malaysia.length}`);
  console.log(`ASEAN claims: ${asean.length}`);
  console.log(`Ransomware.live reported total victims: ${sourceTotalVictims ?? 'not supplied'}`);
  console.log(`Saved: ${OUT}`);
}

main().catch(err => {
  console.error('Full ransomware history sync failed:', err.message || err);
  process.exit(1);
});

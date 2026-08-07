const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'data', 'ransomware.json');
const PROXY_BASE = 'https://ransomwhere.org';
const DIRECT_BASE = 'https://api.ransomware.live/v2';
const API_KEY = String(process.env.RANSOMWARE_LIVE_API_KEY || '').trim();

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function fetchJson(url, { apiKey = '', attempts = 4 } = {}) {
  let lastError;
  for (let i = 1; i <= attempts; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 120000);
    try {
      console.log(`GET ${url} (attempt ${i}/${attempts})`);
      const headers = {
        accept: 'application/json',
        'user-agent': 'Cyber-Threat-Intelligence-Command-Centre/1.1'
      };
      if (apiKey) headers['X-API-KEY'] = apiKey;

      const res = await fetch(url, { signal: controller.signal, headers });
      clearTimeout(timer);

      if (!res.ok) {
        const text = await res.text().catch(() => '');
        const err = new Error(`HTTP ${res.status}: ${text.slice(0, 220)}`);
        err.status = res.status;
        throw err;
      }

      const text = await res.text();
      try {
        return JSON.parse(text);
      } catch {
        throw new Error(`Expected JSON from ${url} but received: ${text.slice(0, 180)}`);
      }
    } catch (err) {
      clearTimeout(timer);
      lastError = err;
      const retryable = err.name === 'AbortError' || !err.status || err.status === 429 || err.status >= 500;
      console.error(`Request failed: ${err.message}`);
      if (!retryable || i === attempts) break;
      await sleep(3000 * i);
    }
  }
  throw lastError;
}

function str(...values) {
  const v = values.find(x => x !== undefined && x !== null && String(x).trim() !== '');
  return v === undefined ? '' : String(v).trim();
}

function num(...values) {
  const v = values.find(x => x !== undefined && x !== null && x !== '' && Number.isFinite(Number(x)));
  return v === undefined ? 0 : Number(v);
}

function toIso(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function arrayFrom(raw, keys = []) {
  if (Array.isArray(raw)) return raw;
  for (const k of keys) if (Array.isArray(raw?.[k])) return raw[k];
  if (Array.isArray(raw?.data)) return raw.data;
  if (Array.isArray(raw?.result)) return raw.result;
  return [];
}

function normalizeVictim(v, idx) {
  return {
    id: str(v.id, v.victim_id, v.uuid, `${str(v.victim, v.name, v.post_title)}-${idx}`),
    victim: str(v.victim, v.name, v.post_title, v.title, 'Unknown victim'),
    group: str(v.group, v.group_name, v.ransomware, v.ransomware_group, 'Unknown'),
    country: str(v.country, v.country_name, v.country_code, v.countrycode, 'Unknown'),
    sector: str(v.sector, v.activity, v.industry, v.business_sector, 'Unspecified'),
    discovered: toIso(v.discovered || v.discovered_at || v.date || v.published || v.created_at || v.firstseen),
    attacked: toIso(v.attacked || v.attackdate || v.attack_date),
    website: str(v.website, v.domain, v.url),
    sourceUrl: str(v.permalink, v.source_url, v.link)
  };
}

function normalizeGroup(g) {
  const rawStatus = str(g.status, g.state).toLowerCase();
  let active;
  if (typeof g.active === 'boolean') active = g.active;
  else if (rawStatus) active = ['active', 'online', 'up'].includes(rawStatus);
  else active = true;

  return {
    name: str(g.name, g.group, g.slug, g.group_name, 'Unknown'),
    active,
    status: rawStatus || (active ? 'active' : 'unknown'),
    description: str(g.description, g.profile?.description, Array.isArray(g.profile) ? g.profile.join(' ') : ''),
    locations: Array.isArray(g.locations) ? g.locations.length : num(g.locations),
    victims: num(g.victims, g.victim_count, g.count)
  };
}

function countBy(items, key, limit = 8) {
  const m = new Map();
  for (const item of items) {
    const value = str(item[key], 'Unknown');
    m.set(value, (m.get(value) || 0) + 1);
  }
  return [...m.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

function buildDaily(items) {
  const m = new Map();
  for (const v of items) {
    if (!v.discovered) continue;
    const day = v.discovered.slice(0, 10);
    m.set(day, (m.get(day) || 0) + 1);
  }
  return [...m.entries()]
    .map(([date, count]) => ({ date, count }))
    .sort((a, b) => a.date.localeCompare(b.date))
    .slice(-14);
}

function uniqueCount(items, key) {
  return new Set(items.map(x => str(x[key])).filter(x => x && x !== 'Unknown' && x !== 'Unspecified')).size;
}

function statsValue(raw, ...keys) {
  for (const k of keys) {
    if (raw?.[k] !== undefined && raw?.[k] !== null) return num(raw[k]);
    if (raw?.stats?.[k] !== undefined && raw?.stats?.[k] !== null) return num(raw.stats[k]);
    if (raw?.data?.[k] !== undefined && raw?.data?.[k] !== null) return num(raw.data[k]);
  }
  return 0;
}

function statsDate(raw, ...keys) {
  for (const k of keys) {
    const v = raw?.[k] ?? raw?.stats?.[k] ?? raw?.data?.[k];
    if (v) return toIso(v);
  }
  return null;
}

async function collectDirect() {
  if (!API_KEY) throw new Error('RANSOMWARE_LIVE_API_KEY is not configured.');

  console.log('Using direct ransomware.live API v2.');
  const [statsRaw, victimsRaw, groupsRaw] = await Promise.all([
    fetchJson(`${DIRECT_BASE}/stats`, { apiKey: API_KEY }),
    fetchJson(`${DIRECT_BASE}/victims/recent`, { apiKey: API_KEY }),
    fetchJson(`${DIRECT_BASE}/groups`, { apiKey: API_KEY })
  ]);

  return {
    mode: 'direct',
    source: 'ransomware.live API v2',
    sourceUrl: 'https://www.ransomware.live/',
    upstream: 'ransomware.live',
    statsRaw,
    victimsRaw,
    groupsRaw
  };
}

async function collectProxy() {
  console.log('Trying Ransomwhere.org convenience proxy.');
  const [statsRaw, victimsRaw, groupsRaw] = await Promise.all([
    fetchJson(`${PROXY_BASE}/api/stats`),
    fetchJson(`${PROXY_BASE}/api/victims`),
    fetchJson(`${PROXY_BASE}/api/groups`)
  ]);

  return {
    mode: 'proxy',
    source: 'Ransomwhere.org API',
    sourceUrl: `${PROXY_BASE}/developers`,
    upstream: str(statsRaw?.source, 'ransomware.live'),
    statsRaw,
    victimsRaw,
    groupsRaw
  };
}

async function getSourceData() {
  // Prefer the upstream source whenever a key is configured.
  if (API_KEY) {
    try {
      return await collectDirect();
    } catch (err) {
      console.error(`Direct ransomware.live collection failed: ${err.message}`);
      console.log('Falling back to the public proxy...');
    }
  }

  try {
    return await collectProxy();
  } catch (proxyErr) {
    if (proxyErr.status === 403 && !API_KEY) {
      throw new Error(
        'Ransomwhere.org returned HTTP 403 to the GitHub Actions runner. ' +
        'Add repository secret RANSOMWARE_LIVE_API_KEY, then re-run this workflow.'
      );
    }
    throw proxyErr;
  }
}

async function main() {
  const src = await getSourceData();

  const victimsSource = arrayFrom(src.victimsRaw, ['victims', 'recentvictims', 'recentVictims']);
  const groupsSource = arrayFrom(src.groupsRaw, ['groups']);

  const victims = victimsSource
    .map(normalizeVictim)
    .sort((a, b) => String(b.discovered || '').localeCompare(String(a.discovered || '')));

  const groups = groupsSource
    .map(normalizeGroup)
    .sort((a, b) => Number(b.active) - Number(a.active) || b.victims - a.victims || a.name.localeCompare(b.name));

  if (!victims.length) throw new Error('Ransomware source returned no victim records; refusing to overwrite the existing dataset.');

  const cutoff24 = Date.now() - 24 * 3600 * 1000;
  const claims24h = victims.filter(v => v.discovered && new Date(v.discovered).getTime() >= cutoff24).length;

  const totalVictims = statsValue(src.statsRaw, 'totalVictims', 'totalvictims', 'victims', 'total_victims') || victims.length;
  const totalGroups = statsValue(src.statsRaw, 'totalGroups', 'totalgroups', 'groups', 'total_groups') || groups.length;
  const totalAttacks = statsValue(src.statsRaw, 'totalAttacks', 'totalattacks', 'attacks', 'press', 'total_press');
  const lastSourceUpdate = statsDate(src.statsRaw, 'lastUpdate', 'lastupdate', 'last_update', 'lastvictim', 'last_discovered');

  const output = {
    meta: {
      status: 'ok',
      source: src.source,
      sourceUrl: src.sourceUrl,
      upstream: src.upstream,
      mode: src.mode,
      collectedAt: new Date().toISOString(),
      lastSourceUpdate,
      methodology: 'Victim records are public ransomware/extortion leak-site claims and are not independently verified incidents.'
    },
    stats: {
      totalVictims,
      sourceAttacksMetric: totalAttacks,
      trackedGroups: groups.length || totalGroups,
      activeGroups: groups.filter(g => g.active).length,
      recentClaims: victims.length,
      claims24h,
      countriesRecent: uniqueCount(victims, 'country'),
      sectorsRecent: uniqueCount(victims, 'sector')
    },
    topGroups: countBy(victims, 'group', 8),
    topCountries: countBy(victims, 'country', 8),
    topSectors: countBy(victims, 'sector', 8),
    dailyActivity: buildDaily(victims),
    victims,
    groups
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');
  console.log(`Saved ${victims.length} recent ransomware claims and ${groups.length} groups to ${OUT}`);
  console.log(`Collection mode: ${src.mode}; active groups: ${output.stats.activeGroups}; claims in 24h: ${claims24h}`);
}

main().catch(err => {
  console.error('Ransomware collection failed:', err.message || err);
  process.exit(1);
});

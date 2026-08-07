const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'data', 'ransomware.json');
const HIST_OUT = path.join(__dirname, '..', 'data', 'ransomware-history.json');
const HISTORY_DAYS = 365;
const HISTORY_MAX = 10000;

const SOURCES = [
  {
    mode: 'direct-v2',
    source: 'ransomware.live API v2',
    sourceUrl: 'https://www.ransomware.live/',
    upstream: 'ransomware.live',
    urls: {
      victims: 'https://api.ransomware.live/v2/recentvictims',
      groups: 'https://api.ransomware.live/v2/groups',
      info: 'https://api.ransomware.live/v2/info'
    }
  },
  {
    // Kept as a compatibility fallback in case the upstream redirects/retains legacy paths.
    mode: 'direct-legacy',
    source: 'ransomware.live public API',
    sourceUrl: 'https://www.ransomware.live/',
    upstream: 'ransomware.live',
    urls: {
      victims: 'https://api.ransomware.live/recentvictims',
      groups: 'https://api.ransomware.live/groups',
      info: 'https://api.ransomware.live/info'
    }
  },
  {
    // Last-resort convenience proxy. It may be blocked by Cloudflare on GitHub runners,
    // so it is deliberately tried only after the direct upstream endpoints.
    mode: 'proxy',
    source: 'Ransomwhere.org API',
    sourceUrl: 'https://ransomwhere.org/developers',
    upstream: 'ransomware.live',
    urls: {
      victims: 'https://ransomwhere.org/api/victims',
      groups: 'https://ransomwhere.org/api/groups',
      info: 'https://ransomwhere.org/api/stats'
    }
  }
];

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function fetchJson(url, attempts = 3) {
  let lastError;
  for (let i = 1; i <= attempts; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 120000);
    try {
      console.log(`GET ${url} (attempt ${i}/${attempts})`);
      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          accept: 'application/json',
          'user-agent': 'Cyber-Threat-Intelligence-Command-Centre/1.2'
        }
      });
      clearTimeout(timer);

      const text = await res.text();
      if (!res.ok) {
        const err = new Error(`HTTP ${res.status}: ${text.slice(0, 220)}`);
        err.status = res.status;
        throw err;
      }

      try {
        return JSON.parse(text);
      } catch {
        throw new Error(`Expected JSON from ${url}, received: ${text.slice(0, 180)}`);
      }
    } catch (err) {
      clearTimeout(timer);
      lastError = err;
      const retryable = err.name === 'AbortError' || !err.status || err.status === 429 || err.status >= 500;
      console.error(`Request failed: ${err.message}`);
      if (!retryable || i === attempts) break;
      await sleep(2500 * i);
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
  for (const k of keys) {
    if (Array.isArray(raw?.[k])) return raw[k];
  }
  if (Array.isArray(raw?.data)) return raw.data;
  if (Array.isArray(raw?.result)) return raw.result;
  return [];
}

function normalizeVictim(v, idx) {
  return {
    id: str(v.id, v.victim_id, v.uuid, `${str(v.victim, v.name, v.post_title, v.post_title)}-${idx}`),
    victim: str(v.victim, v.name, v.post_title, v.title, 'Unknown victim'),
    group: str(v.group, v.group_name, v.ransomware, v.ransomware_group, 'Unknown'),
    country: str(v.country, v.country_name, v.country_code, v.countrycode, 'Unknown'),
    sector: str(v.sector, v.activity, v.industry, v.business_sector, 'Unspecified'),
    discovered: toIso(v.discovered || v.discovered_at || v.date || v.published || v.created_at || v.firstseen || v.first_seen),
    attacked: toIso(v.attacked || v.attackdate || v.attack_date),
    website: str(v.website, v.domain, v.url),
    sourceUrl: str(v.permalink, v.source_url, v.link, v.post_url)
  };
}

function normalizeGroup(g) {
  const rawStatus = str(g.status, g.state).toLowerCase();
  let active;
  if (typeof g.active === 'boolean') active = g.active;
  else if (rawStatus) active = ['active', 'online', 'up'].includes(rawStatus);
  else active = true;

  const profileText = Array.isArray(g.profile)
    ? g.profile.map(x => typeof x === 'string' ? x : (x?.description || x?.title || '')).filter(Boolean).join(' ')
    : '';

  return {
    name: str(g.name, g.group, g.slug, g.group_name, 'Unknown'),
    active,
    status: rawStatus || (active ? 'active' : 'unknown'),
    description: str(g.description, g.profile?.description, profileText),
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
  return new Set(
    items.map(x => str(x[key]))
      .filter(x => x && x !== 'Unknown' && x !== 'Unspecified')
  ).size;
}

function deepFindNumber(raw, candidates) {
  if (!raw || typeof raw !== 'object') return 0;
  const wanted = new Set(candidates.map(x => x.toLowerCase().replace(/[^a-z0-9]/g, '')));
  const stack = [raw];
  const seen = new Set();
  while (stack.length) {
    const obj = stack.pop();
    if (!obj || typeof obj !== 'object' || seen.has(obj)) continue;
    seen.add(obj);
    for (const [k, v] of Object.entries(obj)) {
      const nk = k.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (wanted.has(nk) && Number.isFinite(Number(v))) return Number(v);
      if (v && typeof v === 'object') stack.push(v);
    }
  }
  return 0;
}

function deepFindDate(raw, candidates) {
  if (!raw || typeof raw !== 'object') return null;
  const wanted = new Set(candidates.map(x => x.toLowerCase().replace(/[^a-z0-9]/g, '')));
  const stack = [raw];
  const seen = new Set();
  while (stack.length) {
    const obj = stack.pop();
    if (!obj || typeof obj !== 'object' || seen.has(obj)) continue;
    seen.add(obj);
    for (const [k, v] of Object.entries(obj)) {
      const nk = k.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (wanted.has(nk) && v) {
        const iso = toIso(v);
        if (iso) return iso;
      }
      if (v && typeof v === 'object') stack.push(v);
    }
  }
  return null;
}

async function collectSource(source) {
  console.log(`Trying ${source.source} (${source.mode}) — no authentication.`);

  // Victims and groups are required. Info/stats is optional because all visible
  // dashboard metrics can be derived from the two primary datasets if necessary.
  const [victimsRaw, groupsRaw] = await Promise.all([
    fetchJson(source.urls.victims),
    fetchJson(source.urls.groups)
  ]);

  let infoRaw = {};
  try {
    infoRaw = await fetchJson(source.urls.info, 2);
  } catch (err) {
    console.warn(`Info/stats endpoint unavailable (${err.message}); continuing with derived statistics.`);
  }

  const victimsSource = arrayFrom(victimsRaw, ['victims', 'recentvictims', 'recentVictims', 'posts']);
  const groupsSource = arrayFrom(groupsRaw, ['groups', 'ransomware_groups']);

  if (!victimsSource.length) throw new Error('Source returned no recent victim records.');
  if (!groupsSource.length) console.warn('Source returned no group list; victim feed will still be used.');

  return { ...source, victimsRaw, groupsRaw, infoRaw, victimsSource, groupsSource };
}

async function getSourceData() {
  let lastError;
  for (const source of SOURCES) {
    try {
      return await collectSource(source);
    } catch (err) {
      lastError = err;
      console.error(`${source.mode} failed: ${err.message}`);
    }
  }
  throw new Error(`All ransomware public sources failed. Last error: ${lastError?.message || 'unknown error'}`);
}

function victimKey(v) {
  return str(v.id) || [str(v.victim), str(v.group), str(v.country), str(v.discovered)].join('|').toLowerCase();
}

function readHistory() {
  try {
    const raw = JSON.parse(fs.readFileSync(HIST_OUT, 'utf8'));
    return Array.isArray(raw?.victims) ? raw.victims : [];
  } catch {
    return [];
  }
}

function mergeHistory(current) {
  const map = new Map();
  for (const v of [...readHistory(), ...current]) {
    const k = victimKey(v);
    if (!k) continue;
    const prev = map.get(k) || {};
    map.set(k, { ...prev, ...v });
  }
  const cutoff = Date.now() - HISTORY_DAYS * 86400000;
  return [...map.values()]
    .filter(v => !v.discovered || new Date(v.discovered).getTime() >= cutoff)
    .sort((a,b) => String(b.discovered || '').localeCompare(String(a.discovered || '')))
    .slice(0, HISTORY_MAX);
}

async function main() {
  const src = await getSourceData();

  const victims = src.victimsSource
    .map(normalizeVictim)
    .filter(v => v.victim && v.victim !== 'Unknown victim')
    .sort((a, b) => String(b.discovered || '').localeCompare(String(a.discovered || '')));

  const groups = src.groupsSource
    .map(normalizeGroup)
    .sort((a, b) => Number(b.active) - Number(a.active) || b.victims - a.victims || a.name.localeCompare(b.name));

  if (!victims.length) {
    throw new Error('No usable ransomware victim records were returned; existing data/ransomware.json was left untouched.');
  }

  const cutoff24 = Date.now() - 24 * 3600 * 1000;
  const claims24h = victims.filter(v => v.discovered && new Date(v.discovered).getTime() >= cutoff24).length;

  const totalVictims = deepFindNumber(src.infoRaw, ['totalVictims', 'total_victims', 'victims']) || victims.length;
  const totalGroups = deepFindNumber(src.infoRaw, ['totalGroups', 'total_groups', 'groups']) || groups.length;
  const totalAttacks = deepFindNumber(src.infoRaw, ['totalAttacks', 'total_attacks', 'attacks', 'press', 'total_press']);
  const lastSourceUpdate = deepFindDate(src.infoRaw, ['lastUpdate', 'last_update', 'lastVictim', 'last_victim', 'updatedAt']);

  const output = {
    meta: {
      status: 'ok',
      source: src.source,
      sourceUrl: src.sourceUrl,
      upstream: src.upstream,
      mode: src.mode,
      authentication: 'none',
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

  const historyVictims = mergeHistory(victims);
  const historyOutput = {
    meta: {
      status: 'ok',
      source: src.source,
      sourceUrl: src.sourceUrl,
      upstream: src.upstream,
      collectedAt: new Date().toISOString(),
      retentionDays: HISTORY_DAYS,
      maxRecords: HISTORY_MAX,
      methodology: 'Rolling archive built by merging each public recent-victims collection. Claims are not independently verified incidents.'
    },
    stats: { retainedClaims: historyVictims.length },
    victims: historyVictims
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');
  fs.writeFileSync(HIST_OUT, JSON.stringify(historyOutput, null, 2) + '\n');

  console.log(`SUCCESS: ${src.source}`);
  console.log(`Rolling history retained: ${historyVictims.length} claims (${HISTORY_DAYS} days max)`);
  console.log(`Saved ${victims.length} recent ransomware claims and ${groups.length} groups to ${OUT}`);
  console.log(`Authentication: none`);
  console.log(`Active groups: ${output.stats.activeGroups}; claims within 24h: ${claims24h}`);
}

main().catch(err => {
  console.error('Ransomware collection failed:', err.message || err);
  process.exit(1);
});

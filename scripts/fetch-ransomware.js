const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'data', 'ransomware.json');
const BASE = 'https://ransomwhere.org';

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function fetchJson(url, attempts = 4) {
  let lastError;
  for (let i = 1; i <= attempts; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 90000);
    try {
      console.log(`GET ${url} (attempt ${i}/${attempts})`);
      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          'accept': 'application/json',
          'user-agent': 'Cyber-Threat-Intelligence-Command-Centre/1.0'
        }
      });
      clearTimeout(timer);
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        const err = new Error(`HTTP ${res.status}: ${text.slice(0, 160)}`);
        err.status = res.status;
        throw err;
      }
      return await res.json();
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

function toIso(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function normalizeVictim(v, idx) {
  return {
    id: str(v.id, v.victim_id, `${str(v.victim, v.name, v.post_title)}-${idx}`),
    victim: str(v.victim, v.name, v.post_title, 'Unknown victim'),
    group: str(v.group, v.group_name, v.ransomware, 'Unknown'),
    country: str(v.country, v.country_name, v.country_code, 'Unknown'),
    sector: str(v.sector, v.activity, v.industry, 'Unspecified'),
    discovered: toIso(v.discovered || v.discovered_at || v.date || v.published || v.created_at),
    attacked: toIso(v.attacked || v.attack_date),
    website: str(v.website, v.domain, v.url),
    sourceUrl: str(v.permalink, v.source_url, v.link)
  };
}

function normalizeGroup(g) {
  const rawStatus = str(g.status, g.state).toLowerCase();
  const active = typeof g.active === 'boolean' ? g.active : rawStatus === 'active' || rawStatus === 'online';
  return {
    name: str(g.name, g.group, g.slug, 'Unknown'),
    active,
    status: active ? 'active' : (rawStatus || 'unknown'),
    description: str(g.description, g.profile?.description, Array.isArray(g.profile) ? g.profile.join(' ') : ''),
    locations: Array.isArray(g.locations) ? g.locations.length : Number(g.locations || 0),
    victims: Number(g.victims || g.victim_count || 0)
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
    .sort((a,b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

function buildDaily(items) {
  const m = new Map();
  for (const v of items) {
    if (!v.discovered) continue;
    const day = v.discovered.slice(0,10);
    m.set(day, (m.get(day) || 0) + 1);
  }
  return [...m.entries()]
    .map(([date, count]) => ({ date, count }))
    .sort((a,b) => a.date.localeCompare(b.date))
    .slice(-14);
}

function uniqueCount(items, key) {
  return new Set(items.map(x => str(x[key])).filter(x => x && x !== 'Unknown' && x !== 'Unspecified')).size;
}

async function main() {
  const [statsRaw, victimsRaw, groupsRaw] = await Promise.all([
    fetchJson(`${BASE}/api/stats`),
    fetchJson(`${BASE}/api/victims`),
    fetchJson(`${BASE}/api/groups`)
  ]);

  const victimsSource = Array.isArray(victimsRaw) ? victimsRaw : (victimsRaw.victims || victimsRaw.data || []);
  const groupsSource = Array.isArray(groupsRaw) ? groupsRaw : (groupsRaw.groups || groupsRaw.data || []);
  const victims = victimsSource.map(normalizeVictim).sort((a,b) => String(b.discovered || '').localeCompare(String(a.discovered || '')));
  const groups = groupsSource.map(normalizeGroup).sort((a,b) => Number(b.active) - Number(a.active) || b.victims - a.victims || a.name.localeCompare(b.name));

  const cutoff24 = Date.now() - 24 * 3600 * 1000;
  const claims24h = victims.filter(v => v.discovered && new Date(v.discovered).getTime() >= cutoff24).length;

  const output = {
    meta: {
      status: 'ok',
      source: 'Ransomwhere.org API',
      sourceUrl: `${BASE}/developers`,
      upstream: str(statsRaw.source, 'ransomware.live'),
      collectedAt: new Date().toISOString(),
      lastSourceUpdate: toIso(statsRaw.lastUpdate),
      methodology: 'Recent victim feed contains the latest public ransomware/extortion leak-site claims. Claims are not independently verified incidents.'
    },
    stats: {
      totalVictims: Number(statsRaw.totalVictims || statsRaw.victims || 0),
      sourceAttacksMetric: Number(statsRaw.totalAttacks || statsRaw.attacks || 0),
      trackedGroups: groups.length || Number(statsRaw.totalGroups || 0),
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
  console.log(`Active groups: ${output.stats.activeGroups}; claims in latest feed within 24h: ${claims24h}`);
}

main().catch(err => {
  console.error('Ransomware collection failed:', err);
  process.exit(1);
});

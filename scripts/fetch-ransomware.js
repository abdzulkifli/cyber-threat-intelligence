const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'data', 'ransomware.json');
const HIST_OUT = path.join(__dirname, '..', 'data', 'ransomware-history.json');
// Keep the complete historical mirror once it has been bootstrapped.
// The separate full-sync job seeds the archive; this 5-minute job only appends/refreshes it.
const HISTORY_DAYS = null;
const HISTORY_MAX = null;

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
      const requestUrl = `${url}${url.includes('?') ? '&' : '?'}_cti=${Date.now()}`;
      console.log(`GET ${requestUrl} (attempt ${i}/${attempts})`);
      const res = await fetch(requestUrl, {
        signal: controller.signal,
        headers: {
          accept: 'application/json',
          'user-agent': 'Cyber-Threat-Intelligence-Command-Centre/1.4',
          'cache-control': 'no-cache, no-store, max-age=0',
          pragma: 'no-cache'
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
    screenshot: str(v.screenshot, v.screenshot_url),
    infostealer: str(v.infostealer, v.infostealer_status, v.stealer),
    press: str(v.press, v.press_coverage, v.presscoverage),
    description: str(v.description, v.summary),
    sourceUrl: str(v.permalink, v.source_url, v.link, v.post_url)
  };
}

function flatStrings(value) {
  if (value === undefined || value === null) return [];
  const input = Array.isArray(value) ? value : [value];
  const out = [];
  for (const item of input) {
    if (typeof item === 'string' || typeof item === 'number') out.push(String(item).trim());
    else if (item && typeof item === 'object') {
      const candidate = str(item.id, item.name, item.technique, item.cve, item.tool, item.title, item.description);
      if (candidate) out.push(candidate);
    }
  }
  return [...new Set(out.filter(Boolean))];
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
    locationCount: Array.isArray(g.locations) ? g.locations.length : num(g.locations),
    locations: flatStrings(g.locations),
    victims: num(g.victims, g.victim_count, g.count),
    firstSeen: toIso(g.first_seen || g.firstseen || g.firstSeen),
    lastSeen: toIso(g.last_seen || g.lastseen || g.lastSeen),
    profileUrl: str(g.url, g.profile_url, g.link),
    ttps: flatStrings(g.ttps || g.ttp || g.techniques || g.mitre || g.mitre_attack),
    vulnerabilities: flatStrings(g.vulnerabilities || g.cves || g.cve || g.exploits),
    tools: flatStrings(g.tools || g.software || g.utilities)
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

async function probeSource(source) {
  console.log(`Probing ${source.source} (${source.mode}) for freshest victim data.`);
  const victimsRaw = await fetchJson(source.urls.victims);
  const victimsSource = arrayFrom(victimsRaw, ['victims', 'recentvictims', 'recentVictims', 'posts']);
  if (!victimsSource.length) throw new Error('Source returned no recent victim records.');
  const victims = victimsSource
    .map(normalizeVictim)
    .filter(v => v.victim && v.victim !== 'Unknown victim')
    .sort((a, b) => String(b.discovered || '').localeCompare(String(a.discovered || '')));
  if (!victims.length) throw new Error('Source returned no usable victim records.');
  const latest = victims.find(v => v.discovered)?.discovered || null;
  console.log(`${source.mode}: ${victims.length} victims; latest=${latest || 'unknown'}`);
  return { ...source, victimsRaw, victimsSource, victims, latest };
}

async function loadAuxiliary(selected, successfulProbes) {
  let groupsRaw = {}, infoRaw = {}, groupsSource = [];
  const ordered = [selected, ...successfulProbes.filter(x => x.mode !== selected.mode)];

  for (const candidate of ordered) {
    try {
      groupsRaw = await fetchJson(candidate.urls.groups, 2);
      groupsSource = arrayFrom(groupsRaw, ['groups', 'ransomware_groups']);
      if (groupsSource.length) {
        console.log(`Group metadata loaded via ${candidate.mode}.`);
        break;
      }
    } catch (err) {
      console.warn(`Groups via ${candidate.mode} unavailable: ${err.message}`);
    }
  }

  for (const candidate of ordered) {
    try {
      infoRaw = await fetchJson(candidate.urls.info, 2);
      console.log(`Stats/info loaded via ${candidate.mode}.`);
      break;
    } catch (err) {
      console.warn(`Info/stats via ${candidate.mode} unavailable: ${err.message}`);
    }
  }

  return { groupsRaw, infoRaw, groupsSource };
}

async function getSourceData() {
  const probes = await Promise.allSettled(SOURCES.map(probeSource));
  const successful = probes.filter(x => x.status === 'fulfilled').map(x => x.value);
  const failed = probes.filter(x => x.status === 'rejected');
  failed.forEach((x, i) => console.warn(`Ransomware source probe failed #${i + 1}: ${x.reason?.message || x.reason}`));
  if (!successful.length) throw new Error('All ransomware public victim feeds failed.');

  // IMPORTANT: select the freshest successful feed, not merely the first endpoint that returned HTTP 200.
  successful.sort((a, b) => dateValue(b.latest) - dateValue(a.latest) || b.victims.length - a.victims.length);
  const selected = successful[0];
  console.log(`Selected freshest feed: ${selected.source} (${selected.mode}), latest victim ${selected.latest || 'unknown'}`);

  const aux = await loadAuxiliary(selected, successful);
  return {
    ...selected,
    ...aux,
    candidates: successful.map(x => ({
      mode: x.mode,
      source: x.source,
      latestVictimDiscovered: x.latest,
      victimCount: x.victims.length
    }))
  };
}

function dateValue(v) {
  const t = v ? new Date(v).getTime() : 0;
  return Number.isFinite(t) ? t : 0;
}

function stableVictimKey(v) {
  return [
    str(v.victim).toLowerCase(),
    str(v.group).toLowerCase(),
    str(v.country).toLowerCase(),
    str(v.discovered).slice(0, 19),
    str(v.website).toLowerCase()
  ].join('|');
}

function victimKey(v) {
  return stableVictimKey(v);
}

function readPreviousCurrent() {
  try {
    return JSON.parse(fs.readFileSync(OUT, 'utf8'));
  } catch {
    return null;
  }
}


function readHistoryDoc() {
  try {
    const raw = JSON.parse(fs.readFileSync(HIST_OUT, 'utf8'));
    return raw && typeof raw === 'object' ? raw : { meta: {}, victims: [] };
  } catch {
    return { meta: {}, victims: [] };
  }
}

function mergeHistory(current, historyDoc) {
  const map = new Map();
  for (const v of [...(Array.isArray(historyDoc?.victims) ? historyDoc.victims : []), ...current]) {
    const k = victimKey(v);
    if (!k) continue;
    const prev = map.get(k) || {};
    map.set(k, { ...prev, ...v });
  }
  return [...map.values()]
    .sort((a,b) => String(b.discovered || '').localeCompare(String(a.discovered || '')));
}

async function main() {
  const previous = readPreviousCurrent();
  const src = await getSourceData();

  const victims = src.victims;
  const groups = src.groupsSource
    .map(normalizeGroup)
    .sort((a, b) => Number(b.active) - Number(a.active) || b.victims - a.victims || a.name.localeCompare(b.name));

  if (!victims.length) {
    throw new Error('No usable ransomware victim records were returned; existing data/ransomware.json was left untouched.');
  }

  const historyDoc = readHistoryDoc();
  const historyVictims = mergeHistory(victims, historyDoc);
  const previousKeys = new Set((previous?.victims || []).map(stableVictimKey));
  const newlyObserved = victims.filter(v => !previousKeys.has(stableVictimKey(v)));
  const latestVictim = victims.find(v => v.discovered) || victims[0];
  const latestVictimDiscovered = latestVictim?.discovered || null;
  const latestAgeMinutes = latestVictimDiscovered
    ? Math.max(0, Math.round((Date.now() - new Date(latestVictimDiscovered).getTime()) / 60000))
    : null;
  const feedFreshness = latestAgeMinutes == null ? 'unknown' : latestAgeMinutes <= 24 * 60 ? 'fresh' : latestAgeMinutes <= 72 * 60 ? 'aging' : 'stale';

  const cutoff24 = Date.now() - 24 * 3600 * 1000;
  const claims24h = historyVictims.filter(v => v.discovered && new Date(v.discovered).getTime() >= cutoff24).length;

  const totalVictims = deepFindNumber(src.infoRaw, ['totalVictims', 'total_victims', 'victims']) || victims.length;
  const totalGroups = deepFindNumber(src.infoRaw, ['totalGroups', 'total_groups', 'groups']) || groups.length;
  const totalAttacks = deepFindNumber(src.infoRaw, ['totalAttacks', 'total_attacks', 'attacks', 'press', 'total_press']);
  const lastSourceUpdate = deepFindDate(src.infoRaw, ['lastUpdate', 'last_update', 'lastVictim', 'last_victim', 'updatedAt']) || latestVictimDiscovered;
  const dataChanged = newlyObserved.length > 0 || !previous || previous?.meta?.latestVictimDiscovered !== latestVictimDiscovered;
  const dataUpdatedAt = dataChanged ? new Date().toISOString() : (previous?.meta?.dataUpdatedAt || previous?.meta?.collectedAt || new Date().toISOString());

  const output = {
    meta: {
      status: 'ok',
      source: src.source,
      sourceUrl: src.sourceUrl,
      upstream: src.upstream,
      mode: src.mode,
      authentication: 'none',
      collectedAt: new Date().toISOString(),
      checkedAt: new Date().toISOString(),
      dataUpdatedAt,
      lastSourceUpdate,
      latestVictimDiscovered,
      latestVictimName: latestVictim?.victim || null,
      latestVictimGroup: latestVictim?.group || null,
      latestVictimCountry: latestVictim?.country || null,
      sourceDataAgeMinutes: latestAgeMinutes,
      feedFreshness,
      newClaimsSincePreviousCollection: newlyObserved.length,
      selectedBy: 'freshest-latest-victim',
      candidates: src.candidates || [],
      methodology: 'Victim records are public ransomware/extortion leak-site claims and are not independently verified incidents.'
    },
    stats: {
      totalVictims,
      sourceAttacksMetric: totalAttacks,
      trackedGroups: groups.length || totalGroups,
      activeGroups: groups.filter(g => g.active).length,
      recentClaims: victims.length,
      retainedClaims: historyVictims.length,
      claims24h,
      newClaimsSincePreviousCollection: newlyObserved.length,
      countriesRecent: uniqueCount(victims, 'country'),
      sectorsRecent: uniqueCount(victims, 'sector')
    },
    topGroups: countBy(victims, 'group', 8),
    topCountries: countBy(victims, 'country', 8),
    topSectors: countBy(victims, 'sector', 8),
    dailyActivity: buildDaily(historyVictims),
    victims,
    groups
  };

  const historyOutput = {
    meta: {
      status: 'ok',
      source: src.source,
      sourceUrl: src.sourceUrl,
      upstream: src.upstream,
      collectedAt: new Date().toISOString(),
      latestVictimDiscovered,
      retentionDays: null,
      maxRecords: null,
      fullSync: Boolean(historyDoc?.meta?.fullSync),
      fullSyncedAt: historyDoc?.meta?.fullSyncedAt || null,
      archiveScope: historyDoc?.meta?.fullSync ? 'full historical Ransomware.live mirror + incremental updates' : 'incremental archive from recent-victims feed',
      sourceTotalVictims: historyDoc?.meta?.sourceTotalVictims || totalVictims || null,
      methodology: 'Historical archive is preserved without time truncation. The 5-minute collector merges newly observed public victim claims into the existing mirror. Claims are not independently verified incidents.'
    },
    stats: { retainedClaims: historyVictims.length, claims24h },
    victims: historyVictims
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');
  fs.writeFileSync(HIST_OUT, JSON.stringify(historyOutput, null, 2) + '\n');

  console.log(`SUCCESS: ${src.source} (${src.mode})`);
  console.log(`Latest claim: ${latestVictim?.victim || 'unknown'} · ${latestVictimDiscovered || 'unknown'} · age ${latestAgeMinutes ?? 'unknown'} min`);
  console.log(`Feed freshness: ${feedFreshness}; new claims since previous collection: ${newlyObserved.length}`);
  console.log(`Historical archive retained: ${historyVictims.length} claims; fullSync=${Boolean(historyDoc?.meta?.fullSync)}`);
  console.log(`Saved ${victims.length} recent ransomware claims and ${groups.length} groups to ${OUT}`);
  console.log(`Active groups: ${output.stats.activeGroups}; retained claims within 24h: ${claims24h}`);
}

main().catch(err => {
  console.error('Ransomware collection failed:', err.message || err);
  process.exit(1);
});

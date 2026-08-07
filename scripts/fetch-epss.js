const fs = require('fs/promises');
const path = require('path');
const zlib = require('zlib');

const SOURCE_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
const KEV_FILE = path.join(__dirname, '..', 'data', 'kev.json');
const OUTPUT = path.join(__dirname, '..', 'data', 'epss.json');
const REQUEST_TIMEOUT_MS = 180000;
const MAX_RETRIES = 4;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fetchBuffer(url, attempt = 1) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const started = Date.now();
  try {
    console.log(`EPSS download attempt ${attempt}/${MAX_RETRIES}`);
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'CTI-Phase1C/1.0 (+GitHub Actions; public vulnerability intelligence collector)',
        'Accept': 'application/gzip, application/octet-stream, */*'
      },
      redirect: 'follow',
      signal: controller.signal
    });

    console.log(`EPSS responded HTTP ${res.status} after ${Math.round((Date.now() - started) / 1000)}s`);
    if (!res.ok) {
      const retryable = res.status === 408 || res.status === 429 || res.status >= 500;
      if (retryable && attempt < MAX_RETRIES) {
        const wait = 15000 * attempt;
        console.warn(`EPSS HTTP ${res.status}; retrying in ${wait / 1000}s...`);
        await sleep(wait);
        return fetchBuffer(url, attempt + 1);
      }
      throw new Error(`EPSS HTTP ${res.status} ${res.statusText}`);
    }

    return Buffer.from(await res.arrayBuffer());
  } catch (err) {
    const retryable = err?.name === 'AbortError' || err instanceof TypeError;
    if (retryable && attempt < MAX_RETRIES) {
      const wait = 15000 * attempt;
      console.warn(`EPSS ${err?.name === 'AbortError' ? 'timeout' : 'network error'}; retrying in ${wait / 1000}s...`);
      await sleep(wait);
      return fetchBuffer(url, attempt + 1);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function parseComment(line = '') {
  const clean = line.replace(/^#\s*/, '').trim();
  const meta = {};
  for (const piece of clean.split(',')) {
    const idx = piece.indexOf(':');
    if (idx === -1) continue;
    const key = piece.slice(0, idx).trim().toLowerCase().replace(/\s+/g, '_');
    const value = piece.slice(idx + 1).trim();
    if (key) meta[key] = value;
  }
  return meta;
}

function bucket(score) {
  if (score >= 0.50) return 'GE_50';
  if (score >= 0.10) return 'GE_10';
  if (score >= 0.01) return 'GE_01';
  return 'LT_01';
}

async function main() {
  const kev = JSON.parse(await fs.readFile(KEV_FILE, 'utf8'));
  const wanted = new Set((kev.vulnerabilities || []).map(v => v.id).filter(Boolean));
  if (!wanted.size) throw new Error('data/kev.json contains no KEV CVE IDs. Run CISA collection first.');

  const gz = await fetchBuffer(SOURCE_URL);
  const text = zlib.gunzipSync(gz).toString('utf8');
  const lines = text.split(/\r?\n/).filter(Boolean);

  let commentMeta = {};
  let headerIndex = -1;
  for (let i = 0; i < Math.min(lines.length, 10); i++) {
    if (lines[i].startsWith('#')) commentMeta = { ...commentMeta, ...parseComment(lines[i]) };
    if (/^cve,epss,percentile/i.test(lines[i])) {
      headerIndex = i;
      break;
    }
  }
  if (headerIndex === -1) throw new Error('EPSS CSV header not found. Existing data/epss.json was preserved.');

  const matches = [];
  let totalScoredPopulation = 0;

  for (let i = headerIndex + 1; i < lines.length; i++) {
    const parts = lines[i].split(',');
    if (parts.length < 3) continue;
    const id = parts[0].trim();
    const epss = Number(parts[1]);
    const percentile = Number(parts[2]);
    if (!id || !Number.isFinite(epss) || !Number.isFinite(percentile)) continue;
    totalScoredPopulation += 1;
    if (!wanted.has(id)) continue;
    matches.push({
      id,
      epss,
      percentile,
      epssPercent: Math.round(epss * 100000) / 1000,
      percentilePercent: Math.round(percentile * 10000) / 100,
      band: bucket(epss)
    });
  }

  matches.sort((a, b) => b.epss - a.epss || a.id.localeCompare(b.id));
  const byId = new Map(matches.map(x => [x.id, x]));
  const missing = [...wanted].filter(id => !byId.has(id)).sort();

  const stats = {
    kevTotal: wanted.size,
    matched: matches.length,
    coveragePercent: wanted.size ? Math.round(matches.length / wanted.size * 1000) / 10 : 0,
    epssGe50: matches.filter(x => x.epss >= 0.50).length,
    epssGe10: matches.filter(x => x.epss >= 0.10).length,
    epssGe01: matches.filter(x => x.epss >= 0.01).length,
    epssLt01: matches.filter(x => x.epss < 0.01).length,
    percentileGe99: matches.filter(x => x.percentile >= 0.99).length,
    maxEpss: matches.length ? Math.max(...matches.map(x => x.epss)) : 0,
    averageEpss: matches.length ? Math.round(matches.reduce((sum, x) => sum + x.epss, 0) / matches.length * 1000000) / 1000000 : 0
  };

  const output = {
    meta: {
      dataset: 'FIRST EPSS Daily Scores — CISA KEV Enrichment',
      phase: '1C',
      status: 'ok',
      source: 'FIRST EPSS',
      sourceUrl: 'https://www.first.org/epss/',
      dataUrl: SOURCE_URL,
      collectedAt: new Date().toISOString(),
      scoreDate: commentMeta.score_date || commentMeta.date || null,
      modelVersion: commentMeta.model_version || commentMeta.version || null,
      totalScoredPopulation,
      matchedKev: matches.length,
      refreshPolicy: 'Daily after FIRST publishes new scores',
      note: 'EPSS estimates the probability that a published CVE will be exploited in the wild in the next 30 days.'
    },
    stats,
    vulnerabilities: matches,
    missing
  };

  await fs.mkdir(path.dirname(OUTPUT), { recursive: true });
  await fs.writeFile(OUTPUT, JSON.stringify(output, null, 2) + '\n', 'utf8');
  console.log(`EPSS scored population: ${totalScoredPopulation.toLocaleString()}`);
  console.log(`Matched ${matches.length}/${wanted.size} CISA KEVs (${stats.coveragePercent}%).`);
  console.log(`EPSS >= 50%: ${stats.epssGe50}; EPSS >= 10%: ${stats.epssGe10}; Top 1 percentile: ${stats.percentileGe99}`);
}

main().catch(err => {
  console.error('EPSS collector failed:', err?.stack || err);
  process.exit(1);
});

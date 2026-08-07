const fs = require('fs/promises');
const path = require('path');

const BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const OUTPUT = path.join(__dirname, '..', 'data', 'nvd.json');
const REQUEST_TIMEOUT_MS = 240000; // NVD bulk KEV responses can take > 60s.
const PAGE_DELAY_MS = 6500;
const MAX_RETRIES = 4;
const API_KEY = (process.env.NVD_API_KEY || '').trim();

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function waitForAttempt(attempt, retryAfterSeconds = 0) {
  return Math.max(retryAfterSeconds * 1000, 15000 * attempt);
}

async function fetchJson(url, attempt = 1) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const started = Date.now();

  const headers = {
    'User-Agent': 'CTI-Phase1B/1.1 (+GitHub Actions; public vulnerability intelligence collector)',
    'Accept': 'application/json'
  };
  if (API_KEY) headers.apiKey = API_KEY;

  try {
    console.log(`NVD request attempt ${attempt}/${MAX_RETRIES}`);
    const res = await fetch(url, { headers, signal: controller.signal });
    const elapsed = Math.round((Date.now() - started) / 1000);
    console.log(`NVD responded HTTP ${res.status} after ${elapsed}s`);

    if (!res.ok) {
      const message = res.headers.get('message') || `${res.status} ${res.statusText}`;
      const retryAfter = Number(res.headers.get('retry-after') || 0);
      const retryable = res.status === 403 || res.status === 408 || res.status === 429 || res.status >= 500;

      if (retryable && attempt < MAX_RETRIES) {
        const wait = waitForAttempt(attempt, retryAfter);
        console.warn(`NVD request failed (${message}). Retrying in ${Math.round(wait / 1000)}s...`);
        await sleep(wait);
        return fetchJson(url, attempt + 1);
      }
      throw new Error(`NVD API HTTP ${message}`);
    }

    return await res.json();
  } catch (err) {
    const isAbort = err?.name === 'AbortError';
    const isNetwork = err instanceof TypeError || ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN'].includes(err?.cause?.code);

    if ((isAbort || isNetwork) && attempt < MAX_RETRIES) {
      const wait = waitForAttempt(attempt);
      console.warn(`${isAbort ? 'NVD request timed out' : 'NVD network error'} on attempt ${attempt}. Retrying in ${Math.round(wait / 1000)}s...`);
      await sleep(wait);
      return fetchJson(url, attempt + 1);
    }

    if (isAbort) {
      throw new Error(`NVD request timed out after ${REQUEST_TIMEOUT_MS / 1000}s on all attempts.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function englishText(entries) {
  if (!Array.isArray(entries)) return '';
  return (entries.find(x => String(x.lang || '').toLowerCase() === 'en') || entries[0] || {}).value || '';
}

function pickMetric(metrics = {}) {
  const candidates = [
    ['cvssMetricV40', '4.0'],
    ['cvssMetricV31', '3.1'],
    ['cvssMetricV30', '3.0'],
    ['cvssMetricV2', '2.0']
  ];

  for (const [key, fallbackVersion] of candidates) {
    const list = Array.isArray(metrics[key]) ? metrics[key] : [];
    if (!list.length) continue;

    const metric = list.find(x => x.type === 'Primary' && x.source === 'nvd@nist.gov')
      || list.find(x => x.type === 'Primary')
      || list.find(x => x.source === 'nvd@nist.gov')
      || list[0];

    const d = metric.cvssData || {};
    return {
      version: d.version || fallbackVersion,
      score: d.baseScore !== undefined && d.baseScore !== null && Number.isFinite(Number(d.baseScore)) ? Number(d.baseScore) : null,
      severity: String(d.baseSeverity || metric.baseSeverity || 'UNKNOWN').toUpperCase(),
      vector: d.vectorString || '',
      exploitabilityScore: metric.exploitabilityScore !== undefined && metric.exploitabilityScore !== null && Number.isFinite(Number(metric.exploitabilityScore)) ? Number(metric.exploitabilityScore) : null,
      impactScore: metric.impactScore !== undefined && metric.impactScore !== null && Number.isFinite(Number(metric.impactScore)) ? Number(metric.impactScore) : null,
      source: metric.source || null,
      type: metric.type || null
    };
  }

  return {
    version: null,
    score: null,
    severity: 'UNKNOWN',
    vector: '',
    exploitabilityScore: null,
    impactScore: null,
    source: null,
    type: null
  };
}

function flattenCwes(weaknesses) {
  const out = [];
  for (const weakness of Array.isArray(weaknesses) ? weaknesses : []) {
    for (const d of Array.isArray(weakness.description) ? weakness.description : []) {
      if (d.value && !out.includes(d.value)) out.push(d.value);
    }
  }
  return out;
}

function normalise(wrapper) {
  const cve = wrapper?.cve || {};
  const id = cve.id || '';
  const cvss = pickMetric(cve.metrics || {});
  const references = (Array.isArray(cve.references) ? cve.references : [])
    .slice(0, 12)
    .map(r => ({
      url: r.url || '',
      source: r.source || '',
      tags: Array.isArray(r.tags) ? r.tags : []
    }));

  return {
    id,
    source: 'NVD CVE API 2.0',
    sourceUrl: id ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` : 'https://nvd.nist.gov/',
    published: cve.published || null,
    lastModified: cve.lastModified || null,
    vulnStatus: cve.vulnStatus || null,
    description: englishText(cve.descriptions),
    cvss,
    cwes: flattenCwes(cve.weaknesses),
    references,
    cisaKev: {
      dateAdded: cve.cisaExploitAdd || null,
      actionDue: cve.cisaActionDue || null,
      requiredAction: cve.cisaRequiredAction || '',
      vulnerabilityName: cve.cisaVulnerabilityName || ''
    }
  };
}

function severityStats(items) {
  const base = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const item of items) {
    const severity = base[item.cvss.severity] === undefined ? 'UNKNOWN' : item.cvss.severity;
    base[severity] += 1;
  }
  return base;
}

async function main() {
  const collected = [];
  let startIndex = 0;
  let totalResults = null;
  let nvdTimestamp = null;
  let requestCount = 0;

  do {
    // NVD recommends its optimized default resultsPerPage. The current KEV set
    // is below the default 2,000-page ceiling, so this normally completes in one request.
    const query = startIndex === 0 ? '?hasKev' : `?hasKev&startIndex=${startIndex}`;
    const url = `${BASE_URL}${query}`;
    console.log(`Fetching NVD KEV enrichment: startIndex=${startIndex}`);

    const raw = await fetchJson(url);
    requestCount += 1;

    const page = Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : [];
    collected.push(...page);

    totalResults = Number(raw.totalResults ?? collected.length);
    nvdTimestamp = raw.timestamp || nvdTimestamp;
    const pageSize = Number(raw.resultsPerPage || page.length || 2000);
    const returnedStart = Number(raw.startIndex ?? startIndex);
    startIndex = returnedStart + pageSize;

    console.log(`Received ${page.length} records (${Math.min(startIndex, totalResults)}/${totalResults}).`);

    if (startIndex < totalResults) await sleep(PAGE_DELAY_MS);
  } while (startIndex < totalResults);

  const vulnerabilities = collected
    .map(normalise)
    .filter(v => v.id)
    .sort((a, b) => a.id.localeCompare(b.id));

  if (!vulnerabilities.length) {
    throw new Error('NVD returned zero KEV records. Existing data/nvd.json was preserved.');
  }

  const severity = severityStats(vulnerabilities);
  const withCvss = vulnerabilities.filter(v => v.cvss.score !== null).length;
  const versions = {};

  for (const v of vulnerabilities) {
    const key = v.cvss.version || 'Unknown';
    versions[key] = (versions[key] || 0) + 1;
  }

  const output = {
    meta: {
      dataset: 'NVD CVE API — CISA KEV Enrichment',
      phase: '1B',
      status: 'ok',
      collectedAt: new Date().toISOString(),
      nvdTimestamp,
      count: vulnerabilities.length,
      totalResults,
      requestCount,
      apiKeyUsed: Boolean(API_KEY),
      baseUrl: BASE_URL,
      query: 'hasKev',
      refreshPolicy: 'Every 2 hours',
      attribution: 'This product uses data from the NVD API but is not endorsed or certified by the NVD.'
    },
    stats: {
      total: vulnerabilities.length,
      withCvss,
      coveragePercent: vulnerabilities.length ? Math.round(withCvss / vulnerabilities.length * 1000) / 10 : 0,
      critical: severity.CRITICAL,
      high: severity.HIGH,
      medium: severity.MEDIUM,
      low: severity.LOW,
      unknown: severity.UNKNOWN,
      cvssVersions: versions
    },
    vulnerabilities
  };

  await fs.mkdir(path.dirname(OUTPUT), { recursive: true });
  await fs.writeFile(OUTPUT, JSON.stringify(output, null, 2) + '\n', 'utf8');

  console.log(`Saved ${vulnerabilities.length} NVD KEV records to ${OUTPUT}`);
  console.log(`CVSS coverage: ${withCvss}/${vulnerabilities.length} (${output.stats.coveragePercent}%)`);
}

main().catch(err => {
  console.error('NVD collector failed:', err?.stack || err);
  process.exit(1);
});

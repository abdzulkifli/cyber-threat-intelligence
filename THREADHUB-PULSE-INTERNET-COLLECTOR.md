# ThreadHub Pulse — Internet Signal Collector V1

## What this adds

ThreadHub Pulse now reads `data/pulse.json`, which is produced automatically from curated public Internet security feeds. The collector retains original source URLs, extracts CVE/ransomware entities, classifies signals, deduplicates source items, clusters related items into topics, and calculates a transparent Signal Score and momentum.

This V1 intentionally does **not** claim to crawl the entire Internet. It monitors only sources explicitly registered in `data/pulse-sources.json`.

## Files added

- `scripts/sync-pulse.js` — feed collector, normalizer, classifier, topic clusterer, scorer.
- `data/pulse-sources.json` — curated source registry.
- `data/pulse.json` — generated output consumed by the browser.
- `.github/workflows/update-pulse.yml` — runs every 15 minutes and commits fresh Pulse data.

## Files updated

- `index.html`
- `css/style.css`
- `js/app.js`
- `package.json`

## First deployment

Push all files to the default GitHub branch. Then open **Actions → Update ThreadHub Pulse → Run workflow** once manually. After the first successful run, `data/pulse.json` will contain live Internet-sourced topics and the workflow will continue every 15 minutes.

## Add a source

Edit `data/pulse-sources.json` and add another RSS/Atom feed:

```json
{
  "id": "unique-source-id",
  "name": "Source Name",
  "type": "rss",
  "url": "https://example.org/security-feed.xml",
  "homepage": "https://example.org/security",
  "sourceType": "vendor",
  "credibility": 0.95,
  "enabled": true
}
```

Use only public feeds whose collection and reuse terms are appropriate for ThreadHub. Preserve original-source links.

## Local commands

```bash
npm run validate:pulse
npm run collect:pulse
```

Environment controls:

- `PULSE_RETENTION_DAYS` default `30`
- `PULSE_MAX_PER_SOURCE` default `120`
- `PULSE_FETCH_TIMEOUT_MS` default `20000`
- `PULSE_SOURCES` alternate registry path
- `PULSE_OUTPUT` alternate output path

## Signal Score V1

The score is a 0–100 composite of:

- mention volume: 20
- velocity: 20
- source diversity: 15
- source credibility: 15
- severity hints: 10
- exploitation hints: 10
- recency: 10

Momentum is shown separately as **SURGING**, **RISING**, **ACTIVE**, or **COOLING**.

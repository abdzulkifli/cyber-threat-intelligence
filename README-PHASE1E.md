# Phase 1E — Malaysia & ASEAN Threat Intelligence

This patch upgrades the existing Phase 1A–1D Cyber Threat Intelligence Command Centre with a regional intelligence layer.

## Adds

- Malaysia cyber signal panel
- ASEAN ransomware activity across all 11 ASEAN member states
- Malaysia / ASEAN 24h, 7d and loaded-feed metrics
- ASEAN country signal matrix
- ASEAN ransomware group ranking
- ASEAN sector ranking
- MyCERT advisory collector and advisory feed
- MyCERT source-health monitoring
- Graceful preservation of the previous MyCERT dataset if a temporary refresh attempt fails

## Important data interpretation

Ransomware entries are public victim claims from the existing ransomware intelligence feed. They are OSINT signals and are not automatically verified incidents. ASEAN counts are calculated only from the ransomware claims currently loaded by Phase 1D, so they are not complete country incident totals.

The Malaysia Signal Score is a dashboard-derived prioritisation signal. It is not an official national cyber threat level published by MyCERT or CyberSecurity Malaysia.

## Install

Add these NEW files:

```text
.github/workflows/update-mycert.yml
scripts/fetch-mycert.js
data/mycert.json
```

Replace these EXISTING dashboard files:

```text
index.html
js/app.js
css/style.css
```

Keep all current Phase 1A–1D collectors and live JSON files unchanged.

## Repository structure after installation

```text
.github/workflows/
  update-intel.yml
  update-nvd.yml
  update-epss.yml
  update-ransomware.yml
  update-mycert.yml

scripts/
  fetch-cisa-kev.js
  fetch-nvd-kev.js
  fetch-epss.js
  fetch-ransomware.js
  fetch-mycert.js

data/
  kev.json
  nvd.json
  epss.json
  ransomware.json
  mycert.json
```

## First run

GitHub → Actions → **Update MyCERT Intelligence** → **Run workflow**.

A successful run populates `data/mycert.json`. The dashboard refreshes its datasets every five minutes.

## Automatic schedule

MyCERT is checked at minute 07 and 37 of every hour (approximately every 30 minutes). GitHub scheduled actions can start later than the exact cron time during periods of high platform load.

## Source resilience

The collector attempts multiple official MyCERT endpoints and browser-like request headers. If a future refresh fails but a successful dataset already exists, the collector preserves the previous dataset, records the failed attempt, and the dashboard displays the MyCERT source as degraded rather than deleting the last known intelligence.

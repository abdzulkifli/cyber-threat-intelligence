# Phase 1G — Executive Intelligence Briefing

This patch adds a management-focused briefing layer to the existing Phase 1A–1F Cyber Threat Intelligence Command Centre.

## What it adds

- Auto-generated executive situation brief from the five existing datasets
- Three priority cards: vulnerability, ransomware, Malaysia/ASEAN
- "What changed" and "What to watch" summaries
- Top 5 CTI-priority KEV watchlist
- Malaysia/ASEAN executive snapshot
- Source-confidence panel
- Copy-to-clipboard management brief
- Print-friendly executive brief
- Clearer header source status: e.g. `4 LIVE · 1 DEGRADED`
- No new API, secret, collector or GitHub Action

## Important

The briefing is deterministic/rule-based from the data already collected by the dashboard. It is not presented as AI-generated analysis. This keeps Phase 1 fully static-host compatible and avoids API keys.

## Install

Replace only:

- `index.html`
- `js/app.js`
- `css/style.css`

Keep all current data and collectors unchanged:

- `data/kev.json`
- `data/nvd.json`
- `data/epss.json`
- `data/ransomware.json`
- `data/mycert.json`
- all existing `scripts/`
- all existing `.github/workflows/`

GitHub Pages will redeploy after the files are committed. No Phase 1G workflow needs to be run.

## Behaviour

The executive briefing is regenerated whenever the dashboard loads and every five-minute dashboard refresh. It uses current values from CISA KEV, NVD, FIRST EPSS, ransomware OSINT and MyCERT.

The CTI score remains an external-intelligence prioritisation score, not organisational risk. Ransomware leak-site entries remain claims, not automatically verified incidents.

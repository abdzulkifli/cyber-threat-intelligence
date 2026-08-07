# Phase 1H — Command Centre UI/UX Refinement

This patch is a presentation-only upgrade. It does **not** replace your collectors, workflows, or live JSON datasets.

## Replace only
- `index.html`
- `css/style.css`
- `js/app.js`

## Keep all existing live data and collectors
- `data/kev.json`
- `data/nvd.json`
- `data/epss.json`
- `data/ransomware.json`
- `data/mycert.json`
- all `scripts/*.js`
- all `.github/workflows/*.yml`

## Major UI changes
- Tabbed navigation to reduce information overload.
- Executive posture gauge and clean KPI rail.
- “Top 3 things that matter now” decision cards.
- 30-day CISA KEV momentum chart.
- Interactive CVSS × EPSS exploit-risk scatter plot.
- Clickable CVE drill-down drawer.
- Source links on feeds, advisories and vulnerability records.
- Ransomware links go to the trusted intelligence source rather than hostile criminal infrastructure.
- ASEAN heat matrix and Malaysia radar visual.
- Cleaner ransomware, vulnerability and live-feed pages.
- Dedicated source assurance page.
- Print-friendly executive briefing.

## Source traceability
CVE records can be opened directly in NVD. CISA, FIRST EPSS, MyCERT, and ransomware intelligence sections all expose their source links.

## Deployment
Upload the three replacement files to the same locations in the existing repository. GitHub Pages will redeploy automatically.

# Phase 1H.7 — Visual Vulnerability Intelligence + Final UI Balance

This is a UI-only upgrade for the existing Cyber Threat Intelligence Command Centre.

## Replace only

- `index.html`
- `css/style.css`
- `js/app.js`

## Keep unchanged

Do not replace or delete your live intelligence data, collectors, workflows, map assets, or ransomware history:

- `data/kev.json`
- `data/nvd.json`
- `data/epss.json`
- `data/ransomware.json`
- `data/ransomware-history.json`
- `data/mycert.json`
- `data/country-meta.json`
- `assets/world-map.svg`
- `scripts/`
- `.github/workflows/`

## What is new

### Vulnerability Intelligence command deck

- Vulnerability Pressure visual indicator
- Critical CTI, EPSS >=50%, ransomware KEV, new-7-day KEV, NVD coverage and EPSS coverage KPIs
- Top-six clickable CVE watchlist
- Larger CVSS x EPSS exploit-risk matrix
- Combined CVSS severity and EPSS probability view
- 90-day KEV momentum chart
- Clickable top-vendor concentration list
- Quick presets: All, Critical CTI, EPSS >=50%, Ransomware, New 7D
- Evidence links directly from the table to NVD, CISA KEV search and FIRST EPSS

### Rich CVE detail drawer

Click a CVE row, risk-matrix point or watchlist card to open:

- CTI priority
- CVSS / severity
- EPSS / percentile
- CISA KEV status
- ransomware association
- NVD description
- CISA required action
- evidence timeline
- CVSS vector
- authoritative source links

### Visual system

The existing responsive Phase 1H.3 typography and enterprise colour system are retained across the entire dashboard, including the Phase 1H.6 live ransomware map.

## Important

The CTI Priority / Vulnerability Pressure values are dashboard-derived external-intelligence prioritisation. They are not organisational risk until internal asset exposure and business criticality are correlated.

# Cyber Threat Intelligence Command Centre — Phase 1A + 1B

Developed by **Abdullah Zulkifli**.

Phase 1 proves that a GitHub-hosted dashboard can collect cyber intelligence directly from authoritative internet sources and enrich it automatically without a database.

## Current architecture

```text
CISA KEV (15 min) ───────┐
                          ├─> Normalised JSON ─> GitHub Pages Dashboard
NVD CVE API (2 hours) ───┘
```

### Phase 1A — CISA KEV

- CISA Known Exploited Vulnerabilities
- ransomware campaign-use flag
- date added
- vendor / product
- vulnerability name
- required action and due date
- source health and collection timestamp

### Phase 1B — NVD enrichment

- CVSS score and severity
- CVSS version and vector
- NVD vulnerability description
- CWE identifiers
- NVD status / published / last modified metadata
- NVD source health
- critical/high/medium/low distribution
- severity filtering in the live intelligence table

## Files added in Phase 1B

```text
.github/
└── workflows/
    ├── update-intel.yml
    └── update-nvd.yml       NEW

scripts/
├── fetch-cisa-kev.js
└── fetch-nvd-kev.js         NEW

data/
├── kev.json
└── nvd.json                 NEW
```

The dashboard files `index.html`, `js/app.js` and `css/style.css` are also updated for the NVD view.

## Deploy Phase 1B to your existing GitHub repository

Copy the Phase 1B patch into the repository root so that the folder structure remains exactly as shown above. Replace the existing versions of:

- `index.html`
- `css/style.css`
- `js/app.js`
- `package.json`
- `README.md`

Add these new files:

- `.github/workflows/update-nvd.yml`
- `scripts/fetch-nvd-kev.js`
- `data/nvd.json`

Do **not** delete `.github/workflows/update-intel.yml`; it remains the CISA collector.

## First NVD collection

After committing the files:

1. Open **GitHub → Actions**.
2. Select **Enrich NVD Vulnerability Intelligence**.
3. Click **Run workflow**.
4. Wait for a green check mark.
5. Open `data/nvd.json` and confirm `meta.status` is `ok`.
6. GitHub Pages will redeploy after the data commit.
7. Refresh the dashboard. The top status should change from `CISA LIVE · NVD PENDING` to `2 SOURCES LIVE`.

## NVD API key — optional for Phase 1B

The Phase 1B collector makes a very small number of requests because it asks NVD directly for CVEs that appear in CISA KEV and uses up to 2,000 results per page. An API key is therefore not required for the proof of concept, but the collector supports one.

To add a key later:

1. Request an NVD API key from the official NVD developer site.
2. In GitHub open **Settings → Secrets and variables → Actions**.
3. Select **New repository secret**.
4. Name it exactly `NVD_API_KEY`.
5. Paste the key and save.

The workflow automatically passes this secret to the collector without exposing it in the repository.

## Refresh cadence

| Source | Workflow | Cadence |
|---|---|---:|
| CISA KEV | Update Threat Intelligence | Every 15 minutes |
| NVD CVE API | Enrich NVD Vulnerability Intelligence | Every 2 hours |
| Browser dashboard | Client refresh | Every 5 minutes |

The NVD collector follows NVD's published maintenance guidance: automated local-repository updates should not be requested more than about every two hours. If more than one API page is ever required, the collector waits more than six seconds between pages.

## NVD attribution

The dashboard includes the notice required/recommended by NVD:

> This product uses the NVD API but is not endorsed or certified by the NVD.

## What success looks like

After both workflows have run, the dashboard should show:

```text
CISA KEV          ONLINE
NVD CVE API       ONLINE

TOTAL KEV         current CISA count
NVD CVSS COVERAGE percentage
CRITICAL CVSS     populated
HIGH CVSS         populated
```

The live table then combines the two feeds by CVE ID:

```text
CISA
CVE + Vendor + Product + KEV + Ransomware + Required Action
                          │
                          ├── CVE ID correlation
                          │
NVD
CVSS + Severity + Description + Vector + CWE
                          │
                          ▼
              Unified Vulnerability View
```

## Next planned step

Phase 1C will add **FIRST EPSS** so the intelligence model can distinguish:

- **Known exploited** — CISA KEV
- **Technical severity** — NVD CVSS
- **Probability of exploitation** — FIRST EPSS
- **Known ransomware use** — CISA

This will support the first practical prioritisation score before a PostgreSQL database is introduced.

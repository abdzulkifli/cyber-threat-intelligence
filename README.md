# Cyber Threat Intelligence Command Centre — Phase 1

Phase 1 proves the end-to-end intelligence path:

**CISA KEV → Node.js collector → normalised JSON → GitHub Pages dashboard**

## 1. Test locally

Requires Node.js 20+ (Node 24 recommended).

```powershell
npm run collect:cisa
```

Then serve the folder with any local web server. One easy option:

```powershell
npx serve .
```

Open the localhost address displayed by `serve`.

> Do not double-click `index.html` directly if your browser blocks `fetch()` from local files.

## 2. GitHub setup

1. Create a new GitHub repository.
2. Upload/push all files in this project.
3. Open **Settings → Actions → General** and ensure workflows can have read/write repository permission (or keep the workflow's `contents: write` permission if allowed by repository policy).
4. Open **Actions → Update Threat Intelligence → Run workflow** once.
5. Confirm `data/kev.json` is populated and committed.
6. Open **Settings → Pages**.
7. Deploy from the repository branch/root containing `index.html`.

The workflow is scheduled every 15 minutes. GitHub scheduled Actions are best-effort and can be delayed during platform load; the dashboard therefore displays the actual `collectedAt` timestamp.

## Data-source strategy

Primary:
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Fallback (official CISA GitHub mirror):
`https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`

The collector records which source was actually used on every run.

## Phase 1 scope

Included now:
- automated CISA KEV collection
- normalised threat JSON
- ransomware association flag
- source traceability
- source health/status
- recent additions metrics
- vendor ranking
- searchable/filterable KEV table
- GitHub Actions automation
- GitHub Pages-ready dashboard

Next connectors:
- NVD/CVE enrichment
- FIRST EPSS
- MyCERT
- ThreatFox / URLhaus

Database, organisational asset matching, AI copilot and response workflows are intentionally later phases.

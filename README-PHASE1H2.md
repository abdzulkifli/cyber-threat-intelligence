# Phase 1H.2 — Ransomware Intelligence Map & Explorer

This patch expands the existing Phase 1H / 1H.1 dashboard into an interactive global ransomware explorer while keeping the command-centre UI clean.

## What is new

- Interactive world ransomware activity map built from the retained rolling public-claim archive.
- 30D / 90D / 365D / ALL time-window selector.
- Clickable countries with claim history, top ransomware groups, sectors and source links.
- Clickable ransomware group profiles with country/sector concentration and any public TTP/CVE/tool metadata returned by the upstream feed.
- Clickable victim claims with evidence/source drawer.
- Rolling-history metrics instead of only the latest 100 claims.
- Global map coverage indicator showing how many retained claims could be mapped to countries.
- Existing Malaysia/ASEAN country cards continue to open country intelligence drawers.
- Safe source-link handling: the UI links to trusted ransomware intelligence sources rather than directly to criminal leak infrastructure.

## Files to replace

Upload/replace these files in your existing repository:

```text
index.html
css/style.css
js/app.js
scripts/fetch-ransomware.js
.github/workflows/update-ransomware.yml
```

## New files to add

```text
assets/world-map.svg
data/country-meta.json
```

`country-meta.json` is static country/alias metadata used only for mapping public victim-country labels to the world map. It is not threat-intelligence data and is not updated by GitHub Actions.

## Do NOT replace/delete

Keep your existing live intelligence files, especially:

```text
data/kev.json
data/nvd.json
data/epss.json
data/ransomware.json
data/ransomware-history.json
data/mycert.json
```

Do not upload an empty `ransomware-history.json` over your existing history.

## First run after installation

Go to:

**GitHub → Actions → Update Ransomware Intelligence → Run workflow**

The collector will continue to update:

```text
data/ransomware.json
data/ransomware-history.json
```

The updated collector also preserves optional public metadata when the source supplies it, including group TTP/CVE/tool fields and victim infostealer/press/screenshot fields. The UI remains functional if those optional fields are absent.

## How the map works

```text
ransomware.live recent public claim feed
            ↓
GitHub collector every 10 minutes
            ↓
rolling ransomware-history.json
            ↓
country alias normalisation
            ↓
interactive global map
            ↓
Country → Group → Victim drill-down
```

The archive is capped at 365 days / 10,000 retained records by the current Phase 1 collector. It grows from the point rolling retention was enabled; it is not a complete historical copy of ransomware.live.

## Important data caveat

Victim entries are public ransomware/extortion claims and are not automatically confirmed incidents. Country, sector and group counts describe the retained public-claim dataset, not complete national or sector incident totals.

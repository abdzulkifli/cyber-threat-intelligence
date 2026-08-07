# Phase 1F — Unified Live Intelligence Feed

This patch adds the unified operational feed to the existing Phase 1A–1E dashboard. It does **not** add a new external source or workflow; it correlates the five datasets that are already being collected automatically.

## Replace only

- `index.html`
- `js/app.js`
- `css/style.css`

Keep all existing JSON data, collectors and GitHub Actions workflows exactly as they are.

## New capabilities

- Single chronological intelligence stream across CISA, NVD, FIRST EPSS, ransomware OSINT and MyCERT.
- Filters: All, Critical, Ransomware, Malaysia, Vulnerabilities.
- Live ticker showing the newest available signal.
- Signal snapshot: 24-hour signals, critical signals, ransomware signals and Malaysia signals.
- Automatic source-freshness assessment based on each collector's expected cadence.
- `NEW` highlighting when the open dashboard detects a new event during a later 5-minute refresh.
- No new API keys or GitHub Secrets required.

## Important interpretation

The feed merges source records by their available timestamps. CISA and MyCERT items may be date-level rather than minute-level events, while NVD and ransomware feeds commonly include precise timestamps. Ransomware victim entries remain public leak-site claims / OSINT signals and are not automatically confirmed incidents.

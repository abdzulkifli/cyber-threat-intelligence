# Phase 1H.6 — Live Ransomware Map

Replace only:

- `index.html`
- `css/style.css`
- `js/app.js`

Do not replace collectors, workflows, JSON data, world map asset, or ransomware history.

## What changes

- Ransomware page defaults to **LIVE 24H**.
- Filters: **LIVE 24H / 7D / 30D / 90D / ALL**.
- Country heat shows claim concentration for the selected window.
- Pulsing map markers show claims discovered within the last 24 hours.
  - red: <1 hour
  - orange: 1–6 hours
  - yellow: 6–24 hours
  - grey: latest known claim only when no ≤24h claims are present
- Malaysia gets a distinct green live marker and country outline.
- A live claims panel appears beside the map. Every item is clickable and opens the evidence drawer.
- Live pulse cards show latest claim age, claims ≤24h, countries ≤24h, active groups ≤24h, and Malaysia ≤24h.
- The dashboard still auto-refreshes every 5 minutes.

Important: these are public ransomware/extortion **victim claims**, not automatically confirmed attacks.

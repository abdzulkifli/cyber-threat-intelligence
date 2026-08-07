# Phase 1H.8 — Colourful Map + Automatic Ransomware Refresh

Replace only:
- `index.html`
- `css/style.css`
- `js/app.js`

Keep all `data/`, `scripts/`, `.github/workflows/`, and `assets/world-map.svg` files unchanged.

## What changed
- World map now uses a colourful muted base palette across countries.
- Claim volume overrides the base map with a clear cyan → green → amber → red heat scale.
- Latest ransomware markers continue to pulse by age; newly detected records get a stronger temporary pulse.
- Browser polls `data/ransomware.json` every 60 seconds with cache-busting/no-store.
- Browser also checks immediately when the tab becomes visible again or the window regains focus.
- Recent ransomware data is merged in-browser with the retained historical mirror, so a new recent claim can appear without waiting for the large history file to refresh.
- Full dashboard still performs its normal 5-minute refresh.

## Important timing
The browser can only show a new record after the GitHub ransomware collector has written it to the repository/GitHub Pages. The collector is scheduled every 5 minutes, while the browser checks for the updated ransomware JSON every 60 seconds. No manual browser refresh should be required.

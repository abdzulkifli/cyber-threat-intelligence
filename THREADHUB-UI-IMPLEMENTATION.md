# ThreadHub Command Centre UI — First Pass

This build applies the approved ThreadHub command-centre visual direction to the existing project without changing the collectors or source data model.

## Changed

- Rebranded the public shell to **THREADHUB · GLOBAL CYBER THREAT INTELLIGENCE**.
- Replaced the horizontal navigation with a command-centre left sidebar.
- Added a top global intelligence search bar.
- Added live/source status controls in the top bar.
- Rebuilt the Overview page with:
  - Active threat signals
  - Ransomware victims
  - Critical CVEs
  - Threat actor/group activity
  - Data-source health
  - Global threat landscape map
  - Live intelligence feed
  - Top ransomware groups
  - Vulnerability intelligence
  - Top targeted countries
  - Threat actor activity
- Kept Malaysia/ASEAN as a **regional lens**, not the product identity.
- Preserved the existing Ransomware, Vulnerabilities, Live Feed, Executive Brief, Regional and Sources workflows.
- Existing ransomware browser auto-sync remains enabled.

## Map semantics

The overview map uses the locally retained ransomware claim dataset for geographic heat and uses the newest <=24h claims for pulsing markers. It does **not** draw fabricated country-to-country attack paths.

## Global search

The top search currently supports the data already present in this repository:

- Exact CVE IDs -> Vulnerabilities
- Ransomware victim/domain text -> victim evidence drawer
- Ransomware group -> actor/group profile
- Country -> country ransomware intelligence drawer
- Other text -> vulnerability search fallback

IOC/IP/domain-wide cross-source search can be expanded later when those datasets are connected.

## Files changed

- `index.html`
- `css/style.css`
- `js/app.js`

No collector scripts or intelligence JSON files were modified.

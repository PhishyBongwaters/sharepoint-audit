# SharePoint Permissions Audit

Audit SharePoint permissions and inheritance to find data-privacy "oopsies"
(leaks). The built-in SharePoint admin reports throttle and lack detail; this
scans tenant-wide, stores everything in SQLite, and reports offline.

## Contents

- `get-sharepointSites.ps1` — the scanner (PowerShell 7+, PnP.PowerShell, PSSQLite)
- `view.html` — offline results viewer: open in a browser, drop the `.db` file in

## How it works

1. `-Refresh` — site inventory via `Get-PnPTenantSite` into the `Sites` table
   (personal/OneDrive `-my` sites excluded). Everything starts as `Pending`.
2. `-ScanNext` / `-ScanAll` — per site: root web, site-level role assignments,
   lists/libraries, then role assignments for every object with unique
   (broken) permissions. `ScanStatus` checkpoints progress, so an interrupted
   run resumes instead of restarting (`InProgress` rows reset to `Pending`
   on startup).
3. `-Report` — console reports: effective permissions, site permissions,
   inheritance state, Full Control assignments, direct user grants.

## Schema

`Sites` → `Objects` (Site/Library/List tree via `ParentObjectId`,
`HasUniquePermissions` flags broken inheritance) → `Permissions` →
`Principals`. `SecurityFindings` is reserved for the rules engine (not yet
populated by the scanner).

## Requirements

- PowerShell 7+, `PnP.PowerShell`, `PSSQLite`
- An Entra app registration with certificate authentication. Reading role
  assignments tenant-wide needs an elevated SharePoint scope — the decision
  between `Sites.Selected` and `Sites.FullControl.All` is still open
  (see the design outline).

## Configuration

| Parameter       | Purpose                                              |
|-----------------|------------------------------------------------------|
| `-SiteUrl`      | Site to connect to (tenant admin site for `-Refresh`) |
| `-Thumbprint`   | Certificate thumbprint for app-only auth              |
| `-ClientId`     | Entra app (client) ID                                 |
| `-TenantId`     | Tenant ID                                             |
| `-DatabasePath` | SQLite database file                                  |
| `-Refresh`      | Rebuild the site inventory                            |
| `-ScanNext`     | Scan the next pending site                             |
| `-ScanAll`      | Scan all pending sites                                 |
| `-Report`       | Print the console reports                              |

**Do not commit real values.** Pass `-Thumbprint`, `-ClientId`, and
`-TenantId` at runtime or via a local config file — never in the repo.

## Viewer

Open `view.html` in a browser and drop the scanner's `.db` file onto it.
Everything runs locally (sql.js in the browser); the file is never uploaded,
and the query console only accepts read-only `SELECT`/`WITH`/`EXPLAIN`.

> Setup note: the page currently ships only the sql.js loader stub. Add the
> engine before the first `<script>` block, e.g.
> `<script src="https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.8.0/sql-wasm.js"></script>`,
> or vendor `sql-wasm.wasm` alongside the page.

## Status / roadmap

Done: site inventory, site- and library-level permission capture,
checkpoint/resume scanning, console reports, viewer shell.

Not yet: the findings rules engine (anonymous links, org-wide links on
sensitive libraries, broken inheritance + broad-group grants, guest access,
permission sprawl, stale access, excess owners), item-level crawl,
throttle-aware backoff, delta/incremental scans, scheduled runs and alerting.

## Security notes

- The scanner is read-only: it inspects permissions, never modifies them.
- Keep certificate thumbprints, client IDs, and tenant identifiers out of
  version control.

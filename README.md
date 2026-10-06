# SharePoint Permissions Audit

Audit SharePoint permissions and inheritance to find data-privacy "oopsies"
(leaks). The built-in SharePoint admin reports throttle and lack detail; this
scans tenant-wide, stores everything in SQLite, and reports offline.

## Contents

- `get-sharepointSites.ps1` — the scanner (PowerShell 7+, PnP.PowerShell, PSSQLite)
- `view.html` — offline results viewer: open in a browser, drop the `.db` file in

## How it works

1. `-Refresh` — site inventory via `Get-PnPTenantSite` into the `Sites` table
   (personal/OneDrive `-my` sites excluded). New sites start as `Pending`;
   existing sites keep their scan status (only the title is refreshed).
2. `-ScanNext` / `-ScanAll` / `-ScanN <number>` — per site: root web, site-level role assignments,
   lists/libraries, then role assignments for every object with unique
   (broken) permissions. `ScanStatus` checkpoints progress, so an interrupted
   run resumes instead of restarting (`InProgress` rows reset to `Pending`
   on startup). REST calls are throttle-aware (429/503 → honor `Retry-After`,
   else exponential backoff with jitter); a site that stays throttled is
   requeued as `Pending` rather than marked `Failed`.
3. `-Analyze` — (re)generates `SecurityFindings` from the collected data
   (also runs automatically after each successful site scan).
4. `-Report` — console reports: direct grants, site permissions,
   inheritance state, Full Control assignments, direct user grants, and
   security findings. Read-only: never creates or modifies the database.

## Schema

`Sites` → `Objects` (Site/Library/List tree via `ParentObjectId`,
`HasUniquePermissions` flags broken inheritance) → `Permissions` →
`Principals`. Principals are keyed per site collection
(`UNIQUE (SiteId, SharePointId)`) because SharePoint `Member.Id` is only
unique within a site collection; `Permissions.PrincipalId` references the
surrogate `Principals.Id`. `SecurityFindings` holds the findings rules
output (see below). `SharingLinks` holds the per-site sharing-link
inventory (backing-group title, file GUID, type hint).

### Severity ratings

Findings are rated Critical → High → Medium → Low. A site/object takes the
rating of its highest-severity finding; reports sort by severity.

| Severity | Why a site/object gets this rating | Rule |
|----------|------------------------------------|------|
| Critical | Anonymous sharing link detected (anyone with the link can access) | `SharingLinkDetected` |
| High | Any Full Control grant | `FullControlGrant` |
| High | B2B guest (`LoginName` contains `#ext#`) holds a direct grant | `GuestDirectAccess` |
| High | More than 3 distinct principals hold Full Control on one object | `ExcessOwners` |
| High | "Everyone except external users" (or "Everyone") holds Full Control, Contribute, or Edit | `OrgWideExposure` |
| High | Organization-scoped sharing link detected | `SharingLinkDetected` |
| Medium | Non-guest user holds a direct grant (review debt) | `DirectUserGrant` |
| Medium | "Everyone except external users" holds a read/view-only grant | `OrgWideExposure` |
| Medium | Sharing link detected with unknown/other type hint | `SharingLinkDetected` |
| Low | Object has unique permissions (broken inheritance -- sprawl signal) | `BrokenInheritance` |

Sharing-link severities come from the backing-group type hint, which is not
authoritative -- verify scope in SharePoint.

Sharing-link inventory: each scan enumerates the hidden backing groups
SharePoint creates per link (`SharingLinks.<fileGuid>.<type>.<linkId>`, one
`sitegroups` call per site) into the `SharingLinks` table. Authoritative
per-link scope/access/expiry (`GetSharingInformation`) is a future increment.

Not yet covered (need more data capture): authoritative per-link details,
stale access (needs Entra sign-in data).

## Requirements

- PowerShell 7+, `PnP.PowerShell`, `PSSQLite`
- An Entra app registration with certificate authentication. Reading role
  assignments tenant-wide needs an elevated SharePoint scope — the decision
  between `Sites.Selected` and `Sites.FullControl.All` is still open
  (see the design outline).

## Configuration

| Parameter       | Purpose                                              |
|-----------------|------------------------------------------------------|
| `-SiteUrl`      | Site to connect to (`-Refresh` works from any site; `Get-PnPTenantSite` elevates to the tenant admin context itself) |
| `-Thumbprint`   | Certificate thumbprint for app-only auth (required at runtime) |
| `-ClientId`     | Entra app (client) ID (required at runtime)           |
| `-TenantId`     | Tenant ID (required at runtime)                       |
| `-DatabasePath` | SQLite database file (default `.\SharePoint-Audit.db`) |
| `-ConfigPath`   | YAML config file (default `./audit-config.yaml`) |
| `-Refresh`      | Rebuild the site inventory                            |
| `-ScanNext`     | Scan the next pending site                             |
| `-ScanAll`      | Scan all pending sites                                 |
| `-ScanN`        | Scan the next N pending sites (e.g. `-ScanN 25`)        |
| `-Analyze`      | (Re)generate security findings for the whole database  |
| `-Report`       | Print the console reports                              |

**Do not commit real values.** Pass `-Thumbprint`, `-ClientId`, and
`-TenantId` at runtime or via `audit-config.yaml` — never in the repo.
The script refuses to connect without them.

Copy `audit-config.yaml.example` to `audit-config.yaml` and fill in your
values (flat `key: value` lines; the file is gitignored). Explicit parameters
override file values. `-ConfigPath` points at a different file.

## Usage

```powershell
# With audit-config.yaml in place, auth comes from the file (explicit
# -Thumbprint/-ClientId/-TenantId still work and override it).

# 1. Build the site inventory
.\get-sharepointSites.ps1 -Refresh

# 2. Scan in bounded batches; safe to re-run, resumes where it left off
.\get-sharepointSites.ps1 -ScanN 50

# Or scan everything pending in one go
.\get-sharepointSites.ps1 -ScanAll

# 3. Console reports (read-only)
.\get-sharepointSites.ps1 -Report

# 4. Rebuild all findings from the collected data
.\get-sharepointSites.ps1 -Analyze
```

All commands default to `.\SharePoint-Audit.db`; override with `-DatabasePath`.
Switches can be combined (e.g. `-Refresh -ScanAll` refreshes the inventory,
then scans everything pending).

## Viewer

Open `view.html` in a browser and drop the scanner's `.db` file onto it.
Everything runs locally (sql.js in the browser, loaded from CDN); the file
is never uploaded, and the query console only accepts read-only
`SELECT`/`WITH`/`EXPLAIN`.

## Planned

- Priority report: ranked site-level findings so SecOps can pick deep-scan targets
- Single-site deep scan (second script): on-demand list/library/item-level crawl, scoped to broken-inheritance subtrees
- Authoritative per-link scope and expiry (`GetSharingInformation`) for
  link-bearing files found by the backing-group inventory
- Stale access detection (needs Entra sign-in data)
- Delta/incremental scans, scheduled runs, alerting

## Security notes

- The scanner is read-only: it inspects permissions, never modifies them.
- Keep certificate thumbprints, client IDs, and tenant identifiers out of
  version control.

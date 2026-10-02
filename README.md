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
2. `-ScanNext` / `-ScanAll` — per site: root web, site-level role assignments,
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
output (see below).

### Findings rules (v1)

| FindingType        | Severity | Trigger                                              |
|--------------------|----------|------------------------------------------------------|
| `FullControlGrant` | High     | Any Full Control grant                               |
| `GuestDirectAccess`| High     | B2B guest (`LoginName` contains `#ext#`) with a direct grant |
| `DirectUserGrant`  | Medium   | Non-guest user with a direct grant (review debt)     |
| `BrokenInheritance`| Low      | Object with unique permissions (sprawl signal)       |
| `ExcessOwners`     | High     | More than 3 distinct Full Control principals on one object |
| `OrgWideExposure`  | High/Medium | "Everyone except external users" (or "Everyone") with a direct grant — how org-wide links surface in role assignments; High for Full Control/Contribute/Edit |
| `SharingLinkDetected` | Critical/High/Medium | Sharing-link backing group found (`SharingLinks.*`); severity from type hint (Anonymous → Critical); hint is not authoritative — verify scope |

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
| `-Refresh`      | Rebuild the site inventory                            |
| `-ScanNext`     | Scan the next pending site                             |
| `-ScanAll`      | Scan all pending sites                                 |
| `-Analyze`      | (Re)generate security findings for the whole database  |
| `-Report`       | Print the console reports                              |

**Do not commit real values.** Pass `-Thumbprint`, `-ClientId`, and
`-TenantId` at runtime or via a local config file — never in the repo.
The script refuses to connect without them.

## Viewer

Open `view.html` in a browser and drop the scanner's `.db` file onto it.
Everything runs locally (sql.js in the browser, loaded from CDN); the file
is never uploaded, and the query console only accepts read-only
`SELECT`/`WITH`/`EXPLAIN`.

## Status / roadmap

Done: site inventory, site- and library-level permission capture,
checkpoint/resume scanning, console reports, viewer, findings rules engine
(v1), throttle-aware backoff with requeue, per-site principal keying,
parameterized SQL.

Not yet: sharing-link capture (anonymous/org-wide links), stale access
detection, item-level crawl, delta/incremental scans, scheduled runs and
alerting.

> Schema note: databases created before the per-site principal keying change
> are rejected at startup with instructions to recreate them — their
> cross-site identity data cannot be unmerged.

## Security notes

- The scanner is read-only: it inspects permissions, never modifies them.
- Keep certificate thumbprints, client IDs, and tenant identifiers out of
  version control.

# Review fix spec — round 1 (2026-10-01)

Source: code review of `get-sharepointSites.ps1` + `view.html` at
`d1c3565`/`e60043e`. Finding F2 (Refresh/admin connection) was investigated
against the PnP.PowerShell source and **retracted** — `Get-PnPTenantSite`
auto-elevates to the `<tenant>-admin` context, so `-Refresh` works as written.

Each item: problem → fix → acceptance. The review loop repeats until every
acceptance holds and a fresh full read surfaces nothing new.

## Verification map

How each fix was verified (2026-10-02). Levels: **Executed** = ran for real
(sqlite3 harness on the script's actual SQL, or pwsh + real PSSQLite 1.1.0);
**Parsed** = clean pass with the real PowerShell 7.6.6 parser; **Inspected** =
careful code review; **Live-only** = needs a tenant run to confirm.

| ID | Fix | Verification |
|----|-----|--------------|
| F1 | Site excluded from permission loop | Executed |
| F3 | Per-site principal keying | Executed (sqlite3 + real PSSQLite) |
| F4 | Throttle retry / requeue | Inspected; throttle shapes are Live-only |
| F5 | Refresh preserves scan status | Executed |
| F6 | Findings engine (7 rules) | Executed (rules fire, idempotent, scoped) |
| F7 | `@()` collection wrapping | Inspected + Parsed |
| F8 | Viewer CDN engine + join fixes | CDN URLs return HTTP 200; joins grepped |
| F9 | `-ScanAll`/`-Analyze` in no-action guard | Inspected + Parsed |
| F10 | Report renamed to "Direct Grants" | Inspected |
| F11 | Library URLs via RootFolder expand | Inspected; REST shape is Live-only |
| F12 | Parameterized SQL | Executed (real PSSQLite 1.1.0) |
| F13 | Init only on write actions | Inspected + Parsed |
| F14 | Explicit `-DatabasePath` | Inspected + Parsed |
| F15 | Clear auth-missing error | Inspected + Parsed |
| F16 | `IF NOT EXISTS` on all tables | Executed |
| — | Whole script syntax | Parsed clean (PS 7.6.6) |

## F1 — Site objects poison the permission loop (blocker)

**Problem:** `Get-ScannableObjects` returns every object with
`HasUniquePermissions = 1`, including the `Site` row. `Add-ObjectPermissions`
then calls `/_api/web/lists(guid'<web-id>')/roleassignments` — a list URL
built from a web GUID → 404 → the `catch` in `ScanNextSite` marks the whole
site `Failed`, after its data was already collected. Root webs of site
collections normally report `HasUniqueRoleAssignments = 1`, so this hits
nearly every site.

**Fix:** exclude `ObjectType = 'Site'` in `Get-ScannableObjects`. Site-level
permissions are already captured by `Add-SitePermissions`; the loop must only
handle list/library objects.

**Acceptance:** the permission loop never issues a `lists(guid'…')` call for a
web GUID; a site whose root web has unique role assignments completes with
`ScanStatus = 'Complete'`.

## F3 — Principals keyed by per-site-collection Member.Id (data corruption)

**Problem:** SharePoint `Member.Id` is unique only within a site collection.
`ON CONFLICT(PrincipalId)` therefore merges different people/groups from
different sites into one row (e.g. Id 5 = Alice on site A, Bob on site B),
and later scans overwrite earlier identity attributes.

**Fix:** scope principal identity per site.
- `Principals` gets a surrogate PK `Id INTEGER PRIMARY KEY AUTOINCREMENT`,
  keeps the SharePoint per-site id as `SharePointId`, adds `SiteId`, and
  declares `UNIQUE (SiteId, SharePointId)`.
- `Permissions.PrincipalId` becomes a FK to `Principals.Id`.
- Upsert on `(SiteId, SharePointId)`; resolve the surrogate `Id` with a
  follow-up `SELECT` and use it for `Permissions` rows.
- Old schema (no `Id`/`SiteId` columns on `Principals`) is rejected by
  `Test-DatabaseSchema` with a clear "recreate the database" message —
  existing rows are already merged and cannot be unmerged.
- All joins (`Show-PermissionReports`, `view.html`) move to `p.Id`.

**Acceptance:** two sites with the same SharePoint `Member.Id` for different
identities produce two `Principals` rows; no cross-site overwrite; joins
resolve correctly.

## F4 — No throttle handling (blocker at scale)

**Problem:** the scan is sequential across ~1,500 sites with zero 429/503
handling. Throttle-awareness is this project's core differentiator per the
design outline; currently a throttled run just marks sites `Failed`.

**Fix:** new `Invoke-ResilientRestMethod` wrapper used for every
`Invoke-PnPSPRestMethod` call:
- catch 429/503 (status code via `WebException.Response` with a message-text
  fallback for `429|Too Many Requests|throttl`),
- honor `Retry-After` when present, else exponential backoff with jitter
  (`2^attempt` seconds + up to 1s random), max 5 retries,
- on exhaustion throw a `THROTTLE_EXHAUSTED`-prefixed error; `ScanNextSite`
  catches it and resets the site to `Pending` (requeued for the next run)
  instead of `Failed`.
- `Connect-SharePointSite` gets 3 connect attempts with backoff.

**Acceptance:** a 429/503 with `Retry-After` pauses for the advertised
duration; repeated throttling requeues the site as `Pending`, never `Failed`.

## F5 — Refresh wipes all scan progress

**Problem:** `Update-SiteInventory`'s upsert sets `ScanStatus = 'Pending'` on
every existing site, discarding completed scans and forcing a full rescan.

**Fix:** on conflict, update only `Title`. (Requeue-everything becomes an
explicit future switch, not a side effect of refresh.)

**Acceptance:** `-Refresh` after a completed scan leaves `ScanStatus`,
`LastScanned`, and `ErrorMessage` untouched.

## F6 — SecurityFindings never populated

**Problem:** the table, the viewer's findings dashboard, and the severity
charts exist, but nothing ever writes findings. The "oopsie" rules are the
point of the tool.

**Fix:** new `Invoke-FindingsAnalysis [-SiteId]` (idempotent:
`DELETE` scope findings first, then insert), wired to a new `-Analyze`
switch (whole DB) and to the end of a successful `ScanNextSite` (that site).
v1 rules, all evaluable from the current schema:
- `FullControlGrant` (High): any `Full Control` permission row.
- `GuestDirectAccess` (High): principal `LoginName LIKE '%#ext#%'`
  (B2B guest claim marker) holding a direct grant.
- `DirectUserGrant` (Medium): non-guest `User` principal with a direct grant
  (review debt).
- `BrokenInheritance` (Low): every object with `HasUniquePermissions = 1`
  (sprawl signal).
- `ExcessOwners` (High): >3 distinct `Full Control` principals on one object.
- `OrgWideExposure` (High/Medium): "Everyone except external users" (or
  "Everyone") claim holding a direct grant — organization-wide sharing links
  surface as this claim in role assignments. High for Full
  Control/Contribute/Edit, Medium otherwise.
- `SharingLinkDetected` (Critical/High/Medium): sharing-link backing group
  (`SharingLinks.<fileGuid>.<type>.<linkId>`) found via the per-site
  `sitegroups` inventory. Severity from the type hint
  (Anonymous → Critical, Organization → High, other → Medium); the hint is
  not authoritative — verify scope in SharePoint.
- `DetectedDate = datetime('now')`; `FindingType` values are the stable
  strings above; severities use the viewer's `Critical/High/Medium/Low/Info`
  set.

Out of scope (data not yet captured — phase 2, see F17): authoritative
per-link details (which need `GetSharingInformation` /
`Get-PnPFileSharingLink` per file), stale access (needs Entra sign-in data).

**Acceptance:** after `-Analyze`, each rule fires on crafted sample data and
stays silent when the condition is absent; re-running produces no duplicates.

## F7 — Single-object sites crash the progress math

**Problem:** with exactly one scannable object, `$Objects` is a scalar,
`.Count` is `$null`, and `($Current / $Total)` throws → site marked `Failed`.

**Fix:** wrap collection assignments in `@(...)`
(`$Sites`, `$Objects`).

**Acceptance:** single-object and single-site edge cases complete normally.

## F8 — view.html ships without the sql.js engine

**Problem:** the page contains only the Emscripten loader stub — no CDN
script tag, no WASM — so `boot()` rejects and no database can ever open.

**Fix:** load the engine from CDN before the stub:
`<script src="https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.8.0/sql-wasm.js"></script>`.
Also update its `Principals` joins for the F3 schema change.

**Acceptance:** opening the page loads the engine with no console error;
dropping a scanner DB populates dashboard, sites, permissions, findings.

## F9 — `-ScanAll` missing from the no-action guard

**Problem:** the guard checks `$Refresh -or $ScanNext -or $Report` but not
`$ScanAll`, so `-ScanAll` alone prints "No action specified." and then scans
anyway.

**Fix:** include `$ScanAll` (and the new `$Analyze`) in the guard.

**Acceptance:** `-ScanAll` alone prints no "No action specified." message.

## F10 — "Effective Permissions" report overpromises

**Problem:** the report lists only direct grants on unique-permission objects
(inherited grants are never expanded), but the title claims effective
permissions.

**Fix:** rename to "Direct Grants (unique-permission objects)".

**Acceptance:** no report title claims effective/inherited permission
expansion.

## F11 — Library ObjectUrl always empty

**Problem:** `Add-SiteLibraries` stores `''`, so reports and the viewer
cannot deep-link to the object.

**Fix:** extend the lists query with `$expand=RootFolder` /
`$select=RootFolder/ServerRelativeUrl` and store the absolute URL
(`scheme://authority` + `ServerRelativeUrl`).

**Acceptance:** library/list rows carry a working absolute URL.

## F12 — String-interpolated SQL

**Problem:** every query is built by interpolation with manual
single-quote doubling. Correct for SQLite today, fragile for every future
edit.

**Fix:** convert all value interpolation to `-SqlParameters` (`@Name`
placeholders). Table/column names and SQL keywords stay inline.

**Acceptance:** no `$`-interpolated values inside SQL text; a title
containing a single quote round-trips intact.

## F13 — Init/schema/reset run even for `-Report`

**Problem:** a read-only report creates the DB file, validates, and resets
`InProgress` rows.

**Fix:** run init/schema/reset only when a write action
(`-Refresh`/`-ScanNext`/`-ScanAll`/`-Analyze`) is requested. `-Report` alone
validates schema read-only and errors clearly if the DB file is missing.

**Acceptance:** `-Report` never creates or modifies the database file.

## F14 — ScanNextSite relies on script-scope $DatabasePath

**Problem:** works via PowerShell scoping, fragile and implicit.

**Fix:** explicit `[string]$DatabasePath` parameter, passed at both call
sites.

**Acceptance:** both call sites pass `-DatabasePath` explicitly.

## F15 — Redacted defaults fail ValidatePattern (found during implementation)

**Problem:** after the thumbprint redaction, the default values no longer
match the `ValidatePattern` attributes, so the script throws a validation
error on startup unless all three auth parameters are passed explicitly.

**Fix:** defaults are now empty strings; `Connect-SharePointSite` throws a
clear "pass -Thumbprint, -ClientId and -TenantId at runtime" error instead.

**Acceptance:** running without auth parameters yields the clear error, not
a pattern-validation failure.

## F16 — SecurityFindings table lacked IF NOT EXISTS (found during implementation)

**Problem:** `Initialize-Database` runs on every invocation and the
`SecurityFindings` `CREATE TABLE` had no `IF NOT EXISTS`, so the second run
would throw "table already exists".

**Fix:** `IF NOT EXISTS` on all five tables.

**Acceptance:** repeated initialization is a no-op.

## F17 — Authoritative per-link details (next increment)

**Problem:** R7 detects sharing links via backing-group type hints, but the
hint is not authoritative. True scope/access/expiry per link needs
`GetSharingInformation` (SharePoint REST, per file/folder — the pnp
script-samples `spo-audit-sharing-links` pattern) or
`Get-PnPFileSharingLink` (needs file-identity resolution from the group
name's file GUID).

**Scope decision needed:** per-library `GetSharingInformation` on root
folders (bounded: one call per library, misses file-level links) vs. full
per-file enumeration (authoritative, expensive — item-level crawl). The
backing-group inventory (R7) already tells you *where* links exist, so a
targeted follow-up only on link-bearing files is the efficient middle path.

**Acceptance:** TBD once scoped.

## Also updated in this round

- `README.md`: findings engine now populated (was "reserved"), viewer setup
  note corrected, `-Analyze` documented, roadmap statuses updated.

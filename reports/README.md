# Prepacked reports

Ready-made SQL reports against the audit database. Each file answers one
triage question (see its header comment).

## Running them

**Viewer (easiest):** open `NBCC-SharepointAudit-Viewer.html`, drop the
`.db` file in, paste a report into the query console, run. The console only
accepts read-only `SELECT`/`WITH`/`EXPLAIN` — every report here is a plain
`SELECT`.

**PowerShell (PSSQLite)** — the included helper is the template block.
Run a prepacked report by number or name fragment, or paste SQL into
`-Query`:

```powershell
.\reports\Invoke-Report.ps1 -Name 01-priority-sites
.\reports\Invoke-Report.ps1 -Name guest-access -GridView
.\reports\Invoke-Report.ps1 -Query "SELECT COUNT(*) AS Sites FROM Sites;"
```

With no arguments it lists the available reports. `-GridView` opens the
results in an interactive filterable grid instead of a console table.
`-DatabasePath` defaults to `SharePoint-Audit.db` next to the scripts, or
to `databasepath` from `audit-config.yaml` (the same config file the main
scripts use) when present.

## Scoping to one site

Most reports run tenant-wide. Each has a commented-out filter near the
bottom:

```sql
-- AND s.SiteUrl = 'https://tenant.sharepoint.com/sites/YourSite'
```

Uncomment it and set the URL to scope that report to one site.

## The set

| # | File | Question it answers |
|---|------|---------------------|
| 01 | `01-priority-sites.sql` | Where do I deep-scan next? |
| 02 | `02-critical-findings.sql` | What needs attention right now? |
| 03 | `03-item-level-highs.sql` | What did the deep scan actually find? |
| 04 | `04-guest-access.sql` | Where do external users have access? |
| 05 | `05-full-control-grants.sql` | Who can do anything, anywhere? |
| 06 | `06-org-wide-exposure.sql` | What is exposed org-wide? |
| 07 | `07-sharing-links.sql` | Where are sharing links in play? |
| 08 | `08-broken-inheritance.sql` | Where is inheritance broken all over the place? |
| 09 | `09-direct-user-grants.sql` | Who was granted access one-off? |
| 10 | `10-excess-owners.sql` | Where are there too many owners? |
| 11 | `11-site-findings-detail.sql` | Full severity-ordered findings (scope to a site to hand over) |
| 12 | `12-deep-scan-status.sql` | Did the deep scan finish, and where did it stop? |

#Requires -Modules PnP.PowerShell
#Requires -Modules PSSQLite

<#
.SYNOPSIS
    Single-site deep scan: item-level permission crawl for one SharePoint site.

.DESCRIPTION
    Second script in the audit pair. NBCC-SharepointAudit.ps1 (Tier 1) maps
    site-level permissions across the tenant; this script deep-dives one site
    flagged by the priority report:

    - every list/library from the Tier 1 inventory is enumerated (paged),
      streaming each page straight into Objects (memory stays flat),
    - folders and files become Objects rows (ObjectType 'Folder'/'File')
      parented under their list via ParentObjectId; a parent folder that
      hasn't streamed in yet is fixed up once paging ends,
    - per-list progress is tracked in DeepScanProgress, so an interrupted
      run resumes by skipping finished lists (re-running a partial list is
      safe: objects upsert, role assignments are replaced per object),
    - role assignments are captured for everything with broken inheritance,
    - findings are re-derived for the site, so the priority report and
      NBCC-SharepointAudit-Viewer.html pick the item-level results up with no schema changes.

    Actions:
    -SiteUrl <url>   deep scan one site (must be in Sites from Tier 1 -Refresh)
    -PriorityReport  read-only ranking of sites by finding severity, so
                     SecOps can pick deep-scan targets (no SharePoint call).
                     Add -MaxResults <n> to show only the top n rows.

    Authentication is Entra app-only via certificate, same as Tier 1: pass
    -Thumbprint, -ClientId and -TenantId at runtime, or put them in
    audit-config.yaml (see audit-config.yaml.example); never commit real values.
#>

param(
    [Parameter()]
    [string]$SiteUrl = "",

    [Parameter()]
    [string]$Thumbprint = "",

    [Parameter()]
    [string]$ClientId = "",

    [Parameter()]
    [string]$TenantId = "",

    [Parameter()]
    [string]$DatabasePath = (Join-Path $PSScriptRoot "SharePoint-Audit.db"),

    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot "audit-config.yaml"),

    [Parameter()]
    [switch]$PriorityReport,

    [Parameter()]
    [int]$MaxResults = 0
)

###############################################################################################
#   Optional YAML config ######################################################################
###############################################################################################
# Flat "key: value" config file (gitignored). Values fill in for parameters
# not passed explicitly; explicit parameters always win.
$__Config = @{}
if (Test-Path $ConfigPath) {
    Get-Content $ConfigPath | ForEach-Object {
        if ($_ -match '^\s*([^:#\s][^:]*?)\s*:\s*(.+?)\s*$') {
            $__Config[$matches[1].Trim().ToLower()] = $matches[2].Trim().Trim('"').Trim("'")
        }
    }
}
$__ParamMap = @{
    'thumbprint'    = 'Thumbprint'
    'clientid'      = 'ClientId'
    'client_id'     = 'ClientId'
    'tenantid'      = 'TenantId'
    'tenant_id'     = 'TenantId'
    'databasepath'  = 'DatabasePath'
    'database_path' = 'DatabasePath'
}
foreach ($__entry in $__ParamMap.GetEnumerator()) {
    if ($__Config.ContainsKey($__entry.Key) -and -not $PSBoundParameters.ContainsKey($__entry.Value)) {
        Set-Variable -Name $__entry.Value -Value $__Config[$__entry.Key] -Scope Script
    }
}
Remove-Variable -Name __Config, __ParamMap, __entry -ErrorAction SilentlyContinue

# Shared functions (throttle-aware REST, schema, auth, principals, role
# assignments, findings) — the exact same logic Tier 1 uses.
. "$PSScriptRoot\NBCC-SharepointAudit-Common.ps1"

###############################################################################################
#   Site resolution ###########################################################################
###############################################################################################
function Resolve-DeepScanSite {

    param(
        [string]$SiteUrl,
        [string]$DatabasePath
    )

    $Norm = $SiteUrl.TrimEnd('/')

    $Site = Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT *
FROM Sites
WHERE SiteUrl = @U1 OR SiteUrl = @U2
LIMIT 1;
"@ `
        -SqlParameters @{ U1 = $Norm; U2 = "$Norm/" }

    if (-not $Site) {
        throw "Site not found in inventory: $SiteUrl. Run NBCC-SharepointAudit.ps1 -Refresh first."
    }

    return $Site
}
###############################################################################################
###############################################################################################

###############################################################################################
#   Paged item enumeration ####################################################################
###############################################################################################
function Initialize-DeepScanProgress {

    param(
        [string]$DatabasePath
    )

    # Bookkeeping only: existing tables and the viewer are untouched.
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
CREATE TABLE IF NOT EXISTS DeepScanProgress (
    SiteId       INTEGER NOT NULL,
    ListObjectId INTEGER NOT NULL,
    ListGuid     TEXT NOT NULL,
    Status       TEXT NOT NULL,
    ItemsSeen    INTEGER NOT NULL DEFAULT 0,
    UpdatedAt    TEXT NOT NULL,
    PRIMARY KEY (SiteId, ListObjectId)
);
"@
}

function Test-DeepScanListComplete {

    param(
        [int]$SiteId,
        [int]$ListObjectId,
        [string]$DatabasePath
    )

    $row = Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT Status
FROM DeepScanProgress
WHERE SiteId = @SiteId AND ListObjectId = @ListObjectId
LIMIT 1;
"@ `
        -SqlParameters @{ SiteId = $SiteId; ListObjectId = $ListObjectId }

    return ($null -ne $row -and $row.Status -eq 'Complete')
}

function Set-DeepScanListStatus {

    param(
        [int]$SiteId,
        [int]$ListObjectId,
        [string]$ListGuid,
        [string]$Status,
        [int]$ItemsSeen,
        [string]$DatabasePath
    )

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO DeepScanProgress (SiteId, ListObjectId, ListGuid, Status, ItemsSeen, UpdatedAt)
VALUES (@SiteId, @ListObjectId, @ListGuid, @Status, @ItemsSeen, datetime('now'))
ON CONFLICT(SiteId, ListObjectId)
DO UPDATE SET Status = excluded.Status,
              ItemsSeen = excluded.ItemsSeen,
              UpdatedAt = excluded.UpdatedAt;
"@ `
        -SqlParameters @{
            SiteId       = $SiteId
            ListObjectId = $ListObjectId
            ListGuid     = $ListGuid
            Status       = $Status
            ItemsSeen    = $ItemsSeen
        }
}

function Get-ListItemPage {

    <#
    .SYNOPSIS
        Fetches one page of list items. Returns @{ Items = [object[]]; NextUrl = [string] };
        NextUrl is empty when paging is done (or stopped early with a warning).
    #>
    param(
        [string]$Url,
        [string]$ListGuid,
        [string]$SiteRelativeUrl,
        [hashtable]$SeenNext
    )

    $Resp = Invoke-ResilientRestMethod -Url $Url
    $Items = @()
    if ($Resp.Value) {
        $Items = @($Resp.Value)
    }

    $NextUrl = ""
    $Next = $Resp.'__next'
    if (-not $Next) {
        $Next = $Resp.'odata.nextLink'
    }
    if ($Next) {
        if ($SeenNext.ContainsKey($Next)) {
            Write-Warning "Next-page link repeated for list $ListGuid. Stopping paging to avoid a loop."
        }
        else {
            $SeenNext[$Next] = $true
            $NextUri = $null
            try { $NextUri = [uri]$Next } catch { $NextUri = $null }
            if ($NextUri -and $NextUri.IsAbsoluteUri) {
                $Abs = $NextUri.AbsolutePath
                if ($Abs.StartsWith($SiteRelativeUrl, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $NextUrl = $Abs.Substring($SiteRelativeUrl.Length) + $NextUri.Query
                }
                else {
                    Write-Warning "Unexpected next-page path: $Next. Stopping paging for list $ListGuid."
                }
            }
            elseif ($Next.StartsWith('/')) {
                # Already server-relative; use as-is.
                $NextUrl = $Next
            }
            else {
                Write-Warning "Unrecognized next-page link format: $Next. Stopping paging for list $ListGuid."
            }
        }
    }

    return @{ Items = $Items; NextUrl = $NextUrl }
}

function Add-DeepScanItem {

    <#
    .SYNOPSIS
        Writes one streamed item to Objects immediately. A parent folder that
        hasn't streamed in yet is recorded in Pending and fixed up later by
        Resolve-PendingParents, so the end state matches parents-first order.
    #>
    param(
        [int]$SiteId,
        $List,
        $Item,
        [string]$BaseUri,
        [hashtable]$FolderMap,
        [System.Collections.Generic.List[object]]$Pending,
        [string]$DatabasePath,
        [ref]$TotalFolders,
        [ref]$TotalFiles,
        [ref]$TotalUnique
    )

    $IsFolder = ($Item.FileSystemObjectType -eq 2)
    $ObjectType = if ($IsFolder) { 'Folder' } else { 'File' }

    $ParentId = if ($FolderMap.ContainsKey($Item.FileDirRef)) {
        $FolderMap[$Item.FileDirRef]
    }
    else {
        $List.ObjectId
    }
    $HasUnique = if ($Item.HasUniqueRoleAssignments) { 1 } else { 0 }
    $ObjectDbId = Add-DeepScanObject `
        -SiteId $SiteId `
        -ParentObjectId $ParentId `
        -ObjectType $ObjectType `
        -ObjectUniqueId "$($List.ObjectUniqueId)|$($Item.Id)" `
        -Title ([string]$Item.FileLeafRef) `
        -Url ($BaseUri + $Item.FileRef) `
        -HasUnique $HasUnique `
        -DatabasePath $DatabasePath

    if ($IsFolder) {
        $FolderMap[$Item.FileRef] = $ObjectDbId
        $TotalFolders.Value++
    }
    else {
        $TotalFiles.Value++
    }

    if (-not $FolderMap.ContainsKey($Item.FileDirRef)) {
        # Parent not seen yet (or this sits at the library root): revisit
        # once more folders have streamed in.
        $Pending.Add(@{ ObjectDbId = $ObjectDbId; FileDirRef = [string]$Item.FileDirRef })
    }

    if ($HasUnique -eq 1) {
        Add-ItemRoleAssignments `
            -ListGuid $List.ObjectUniqueId `
            -ItemId $Item.Id `
            -ObjectDbId $ObjectDbId `
            -SiteId $SiteId `
            -DatabasePath $DatabasePath
        $TotalUnique.Value++
    }
}

function Resolve-PendingParents {

    param(
        [System.Collections.Generic.List[object]]$Pending,
        [hashtable]$FolderMap,
        [string]$DatabasePath
    )

    for ($i = $Pending.Count - 1; $i -ge 0; $i--) {
        $entry = $Pending[$i]
        if ($FolderMap.ContainsKey($entry.FileDirRef)) {
            Invoke-SqliteQuery `
                -DataSource $DatabasePath `
                -Query "UPDATE Objects SET ParentObjectId = @ParentId WHERE ObjectId = @ObjectDbId;" `
                -SqlParameters @{ ParentId = $FolderMap[$entry.FileDirRef]; ObjectDbId = $entry.ObjectDbId }
            $Pending.RemoveAt($i)
        }
    }
}

function Invoke-DeepScanList {

    <#
    .SYNOPSIS
        Streams one list/library page by page into Objects. Memory stays flat
        (one page plus a FileRef->ObjectId map); progress is tracked per list
        so an interrupted run resumes by skipping finished lists.
    #>
    param(
        [int]$SiteId,
        $List,
        [string]$SiteRel,
        [string]$BaseUri,
        [string]$DatabasePath,
        [ref]$TotalFolders,
        [ref]$TotalFiles,
        [ref]$TotalUnique
    )

    if (Test-DeepScanListComplete -SiteId $SiteId -ListObjectId $List.ObjectId -DatabasePath $DatabasePath) {
        Write-Host "Skipping $($List.ObjectTitle): already deep-scanned."
        return
    }

    Set-DeepScanListStatus -SiteId $SiteId -ListObjectId $List.ObjectId -ListGuid $List.ObjectUniqueId `
        -Status 'InProgress' -ItemsSeen 0 -DatabasePath $DatabasePath

    $FolderMap = @{}
    $Pending = [System.Collections.Generic.List[object]]::new()
    $SeenNext = @{}
    $PageUrl = "/_api/web/lists(guid'$($List.ObjectUniqueId)')/items?`$select=Id,FileSystemObjectType,FileLeafRef,FileRef,FileDirRef,HasUniqueRoleAssignments&`$top=2000"
    $Page = 0
    $ItemsSeen = 0

    while ($PageUrl) {
        $Page++
        $Paged = Get-ListItemPage -Url $PageUrl -ListGuid $List.ObjectUniqueId `
            -SiteRelativeUrl $SiteRel -SeenNext $SeenNext
        foreach ($Item in $Paged.Items) {
            Add-DeepScanItem -SiteId $SiteId -List $List -Item $Item -BaseUri $BaseUri `
                -FolderMap $FolderMap -Pending $Pending -DatabasePath $DatabasePath `
                -TotalFolders $TotalFolders -TotalFiles $TotalFiles -TotalUnique $TotalUnique
            $ItemsSeen++
        }
        Resolve-PendingParents -Pending $Pending -FolderMap $FolderMap -DatabasePath $DatabasePath
        Set-DeepScanListStatus -SiteId $SiteId -ListObjectId $List.ObjectId -ListGuid $List.ObjectUniqueId `
            -Status 'InProgress' -ItemsSeen $ItemsSeen -DatabasePath $DatabasePath
        Write-Progress `
            -Id 1 -ParentId 0 -Activity "Deep scan: $($List.ObjectTitle)" `
            -Status "Page $Page, $ItemsSeen items" `
            -PercentComplete -1
        $PageUrl = $Paged.NextUrl
    }

    # Anything still pending has no folder parent: it sits at the library
    # root and keeps the list-level fallback parent, matching non-streamed
    # behavior.
    $Pending.Clear()

    Set-DeepScanListStatus -SiteId $SiteId -ListObjectId $List.ObjectId -ListGuid $List.ObjectUniqueId `
        -Status 'Complete' -ItemsSeen $ItemsSeen -DatabasePath $DatabasePath
    Write-Progress -Id 1 -ParentId 0 -Activity "Deep scan: $($List.ObjectTitle)" -Completed
}
###############################################################################################
###############################################################################################

###############################################################################################
#   Upsert a deep-scan object, return its ObjectId ############################################
###############################################################################################
function Add-DeepScanObject {

    param(
        [int]$SiteId,
        $ParentObjectId,
        [string]$ObjectType,
        [string]$ObjectUniqueId,
        [string]$Title,
        [string]$Url,
        [int]$HasUnique,
        [string]$DatabasePath
    )

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO Objects (
    SiteId,
    ParentObjectId,
    ObjectType,
    ObjectUniqueId,
    ObjectTitle,
    ObjectUrl,
    HasUniquePermissions
)
VALUES (
    @SiteId,
    @ParentId,
    @ObjectType,
    @ObjectUniqueId,
    @Title,
    @Url,
    @HasUnique
)
ON CONFLICT(SiteId, ObjectUniqueId)
DO UPDATE SET
    ParentObjectId = excluded.ParentObjectId,
    ObjectType = excluded.ObjectType,
    ObjectTitle = excluded.ObjectTitle,
    ObjectUrl = excluded.ObjectUrl,
    HasUniquePermissions = excluded.HasUniquePermissions;
"@ `
        -SqlParameters @{
            SiteId         = $SiteId
            ParentId       = $ParentObjectId
            ObjectType     = $ObjectType
            ObjectUniqueId = $ObjectUniqueId
            Title          = $Title
            Url            = $Url
            HasUnique      = $HasUnique
        }

    return Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT ObjectId
FROM Objects
WHERE SiteId = @SiteId
  AND ObjectUniqueId = @Uid
LIMIT 1;
"@ `
        -SqlParameters @{ SiteId = $SiteId; Uid = $ObjectUniqueId } |
        Select-Object -ExpandProperty ObjectId
}
###############################################################################################
###############################################################################################

###############################################################################################
#   Item role assignments #####################################################################
###############################################################################################
function Add-ItemRoleAssignments {

    param(
        [string]$ListGuid,
        [int]$ItemId,
        [int]$ObjectDbId,
        [int]$SiteId,
        [string]$DatabasePath
    )

    $Assignments = Invoke-ResilientRestMethod `
        -Url "/_api/web/lists(guid'$ListGuid')/items($ItemId)/roleassignments?`$expand=Member,RoleDefinitionBindings"

    Save-RoleAssignments `
        -Assignments $Assignments `
        -ObjectDbId $ObjectDbId `
        -SiteId $SiteId `
        -DatabasePath $DatabasePath
}
###############################################################################################
###############################################################################################

###############################################################################################
#   Deep scan one site ########################################################################
###############################################################################################
function Invoke-SiteDeepScan {

    param(
        [string]$DatabasePath,
        $Site
    )

    Connect-SharePointSite -SiteUrl $Site.SiteUrl

    $SiteRel = ([uri]$Site.SiteUrl).AbsolutePath.TrimEnd('/')
    if ([string]::IsNullOrEmpty($SiteRel)) {
        $SiteRel = '/'
    }
    $BaseUri = ([uri]$Site.SiteUrl).GetLeftPart([System.UriPartial]::Authority).TrimEnd('/')

    $Lists = @(
        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
SELECT *
FROM Objects
WHERE SiteId = @SiteId
  AND ObjectType IN ('Library', 'List')
ORDER BY ObjectTitle;
"@ `
            -SqlParameters @{ SiteId = $Site.SiteId }
    )

    if ($Lists.Count -eq 0) {
        Write-Warning "No lists/libraries in inventory for $($Site.SiteUrl)."
        return
    }

    Initialize-DeepScanProgress -DatabasePath $DatabasePath

    $TotalFolders = 0
    $TotalFiles = 0
    $TotalUnique = 0
    $li = 0

    foreach ($List in $Lists) {

        $li++
        Write-Progress `
            -Id 0 -Activity "Deep scan: $($Site.Title)" `
            -Status "List $li of $($Lists.Count): $($List.ObjectTitle)" `
            -PercentComplete (($li / $Lists.Count) * 100)

        Invoke-DeepScanList `
            -SiteId $Site.SiteId `
            -List $List `
            -SiteRel $SiteRel `
            -BaseUri $BaseUri `
            -DatabasePath $DatabasePath `
            -TotalFolders ([ref]$TotalFolders) `
            -TotalFiles ([ref]$TotalFiles) `
            -TotalUnique ([ref]$TotalUnique)
    }

    Write-Progress -Id 0 -Activity "Deep scan: $($Site.Title)" -Completed

    # Findings are derived data: re-derive for this site so the priority
    # report and viewer pick up the item-level results.
    try {
        Invoke-FindingsAnalysis `
            -DatabasePath $DatabasePath `
            -SiteId $Site.SiteId `
            -Quiet
    }
    catch {
        Write-Warning "Findings analysis failed for $($Site.SiteUrl): $($_.Exception.Message)"
    }

    Write-Host "Deep scan complete: $TotalFolders folders, $TotalFiles files, $TotalUnique with unique permissions."
}
###############################################################################################
###############################################################################################

###############################################################################################
#   Priority report ###########################################################################
###############################################################################################
function Show-PriorityReport {

    param(
        [string]$DatabasePath,
        [int]$MaxResults = 0
    )

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Priority report: sites ranked by findings"
    Write-Host "========================================="

    $limitClause = ""
    if ($MaxResults -gt 0) {
        $limitClause = "LIMIT $MaxResults"
    }

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT
    s.Title AS Site,
    s.SiteUrl AS Url,
    SUM(CASE WHEN sf.Severity = 'Critical' THEN 1 ELSE 0 END) AS Critical,
    SUM(CASE WHEN sf.Severity = 'High' THEN 1 ELSE 0 END) AS High,
    SUM(CASE WHEN sf.Severity = 'Medium' THEN 1 ELSE 0 END) AS Medium,
    SUM(CASE WHEN sf.Severity = 'Low' THEN 1 ELSE 0 END) AS Low,
    COUNT(*) AS Total
FROM SecurityFindings sf
JOIN Sites s ON s.SiteId = sf.SiteId
GROUP BY s.SiteId, s.Title, s.SiteUrl
ORDER BY Critical DESC, High DESC, Medium DESC, Low DESC, s.Title
$limitClause;
"@ | Format-Table

    Write-Host "Deep-scan a site: .\NBCC-SharepointAudit-DeepScan.ps1 -SiteUrl <Url> [-DatabasePath <db>]"
    Write-Host ""
}
###############################################################################################
###############################################################################################

#   Main ######################################################################################
###############################################################################################

$DoScan = (-not $PriorityReport) -and (-not [string]::IsNullOrWhiteSpace($SiteUrl))

if ($PriorityReport) {
    # -PriorityReport is read-only: never creates or modifies the database.
    if (-not (Test-Path $DatabasePath)) {
        throw "Database file not found: $DatabasePath. Run NBCC-SharepointAudit.ps1 -Refresh/-ScanAll first."
    }
    Test-DatabaseSchema -DatabasePath $DatabasePath
    Show-PriorityReport -DatabasePath $DatabasePath -MaxResults $MaxResults
}
elseif ($DoScan) {
    if (-not (Test-Path $DatabasePath)) {
        throw "Database file not found: $DatabasePath. Run NBCC-SharepointAudit.ps1 -Refresh/-ScanAll first."
    }
    Test-DatabaseSchema -DatabasePath $DatabasePath
    $Site = Resolve-DeepScanSite -SiteUrl $SiteUrl -DatabasePath $DatabasePath
    Invoke-SiteDeepScan -DatabasePath $DatabasePath -Site $Site
}
else {
    Write-Host "No action specified."
    Write-Host "Available actions:"
    Write-Host "  -SiteUrl <url>     deep scan one site (item-level permissions)"
    Write-Host "  -PriorityReport    ranked findings per site (pick deep-scan targets)"
    return
}

###############################################################################################
###############################################################################################
try {
    Disconnect-PnPOnline -ErrorAction SilentlyContinue
}
catch {}

#Requires -Modules PnP.PowerShell
#Requires -Modules PSSQLite

<#
.SYNOPSIS
    Single-site deep scan: item-level permission crawl for one SharePoint site.

.DESCRIPTION
    Second script in the audit pair. get-sharepointSites.ps1 (Tier 1) maps
    site-level permissions across the tenant; this script deep-dives one site
    flagged by the priority report:

    - every list/library from the Tier 1 inventory is enumerated (paged),
    - folders and files become Objects rows (ObjectType 'Folder'/'File')
      parented under their list via ParentObjectId,
    - role assignments are captured for everything with broken inheritance,
    - findings are re-derived for the site, so the priority report and
      view.html pick the item-level results up with no schema changes.

    Actions:
    -SiteUrl <url>   deep scan one site (must be in Sites from Tier 1 -Refresh)
    -PriorityReport  read-only ranking of sites by finding severity, so
                     SecOps can pick deep-scan targets (no SharePoint call)

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
    [string]$DatabasePath = ".\SharePoint-Audit.db",

    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot "audit-config.yaml"),

    [Parameter()]
    [switch]$PriorityReport
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
. "$PSScriptRoot\SharePointAudit.Common.ps1"

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
        throw "Site not found in inventory: $SiteUrl. Run get-sharepointSites.ps1 -Refresh first."
    }

    return $Site
}
###############################################################################################
###############################################################################################

###############################################################################################
#   Paged item enumeration ####################################################################
###############################################################################################
function Get-AllListItems {

    param(
        [string]$ListGuid,
        [string]$SiteRelativeUrl
    )

    $Items = @()
    $Url = "/_api/web/lists(guid'$ListGuid')/items?`$select=Id,FileSystemObjectType,FileLeafRef,FileRef,FileDirRef,HasUniqueRoleAssignments&`$top=2000"

    while ($Url) {
        $Resp = Invoke-ResilientRestMethod -Url $Url
        if ($Resp.Value) {
            $Items += @($Resp.Value)
        }

        $Url = $null
        $Next = $Resp.'__next'
        if (-not $Next) {
            $Next = $Resp.'odata.nextLink'
        }
        if ($Next) {
            $NextUri = [uri]$Next
            $Abs = $NextUri.AbsolutePath
            if ($Abs.StartsWith($SiteRelativeUrl, [System.StringComparison]::OrdinalIgnoreCase)) {
                $Url = $Abs.Substring($SiteRelativeUrl.Length) + $NextUri.Query
            }
            else {
                Write-Warning "Unexpected next-page path: $Next. Stopping paging for list $ListGuid."
            }
        }
    }

    return $Items
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

        $Items = @(Get-AllListItems `
            -ListGuid $List.ObjectUniqueId `
            -SiteRelativeUrl $SiteRel)

        # Folders first, parents before children, so FileDirRef lookups hit.
        $Folders = @(
            $Items |
                Where-Object { $_.FileSystemObjectType -eq 2 } |
                Sort-Object { $_.FileRef.Length }
        )
        $Files = @(
            $Items |
                Where-Object { $_.FileSystemObjectType -ne 2 }
        )

        $FolderMap = @{}
        $fi = 0
        foreach ($Folder in $Folders) {
            $fi++
            Write-Progress `
                -Id 1 -ParentId 0 -Activity "Folders: $($List.ObjectTitle)" `
                -Status "$fi of $($Folders.Count)" `
                -PercentComplete (($fi / [math]::Max($Folders.Count, 1)) * 100)

            $ParentId = if ($FolderMap.ContainsKey($Folder.FileDirRef)) {
                $FolderMap[$Folder.FileDirRef]
            }
            else {
                $List.ObjectId
            }
            $HasUnique = if ($Folder.HasUniqueRoleAssignments) { 1 } else { 0 }
            $ObjectDbId = Add-DeepScanObject `
                -SiteId $Site.SiteId `
                -ParentObjectId $ParentId `
                -ObjectType 'Folder' `
                -ObjectUniqueId "$($List.ObjectUniqueId)|$($Folder.Id)" `
                -Title ([string]$Folder.FileLeafRef) `
                -Url ($BaseUri + $Folder.FileRef) `
                -HasUnique $HasUnique `
                -DatabasePath $DatabasePath
            $FolderMap[$Folder.FileRef] = $ObjectDbId
            $TotalFolders++

            if ($HasUnique -eq 1) {
                Add-ItemRoleAssignments `
                    -ListGuid $List.ObjectUniqueId `
                    -ItemId $Folder.Id `
                    -ObjectDbId $ObjectDbId `
                    -SiteId $Site.SiteId `
                    -DatabasePath $DatabasePath
                $TotalUnique++
            }
        }
        Write-Progress -Id 1 -Activity "Folders: $($List.ObjectTitle)" -Completed

        $fi = 0
        foreach ($File in $Files) {
            $fi++
            Write-Progress `
                -Id 1 -ParentId 0 -Activity "Files: $($List.ObjectTitle)" `
                -Status "$fi of $($Files.Count)" `
                -PercentComplete (($fi / [math]::Max($Files.Count, 1)) * 100)

            $ParentId = if ($FolderMap.ContainsKey($File.FileDirRef)) {
                $FolderMap[$File.FileDirRef]
            }
            else {
                $List.ObjectId
            }
            $HasUnique = if ($File.HasUniqueRoleAssignments) { 1 } else { 0 }
            $ObjectDbId = Add-DeepScanObject `
                -SiteId $Site.SiteId `
                -ParentObjectId $ParentId `
                -ObjectType 'File' `
                -ObjectUniqueId "$($List.ObjectUniqueId)|$($File.Id)" `
                -Title ([string]$File.FileLeafRef) `
                -Url ($BaseUri + $File.FileRef) `
                -HasUnique $HasUnique `
                -DatabasePath $DatabasePath
            $TotalFiles++

            if ($HasUnique -eq 1) {
                Add-ItemRoleAssignments `
                    -ListGuid $List.ObjectUniqueId `
                    -ItemId $File.Id `
                    -ObjectDbId $ObjectDbId `
                    -SiteId $Site.SiteId `
                    -DatabasePath $DatabasePath
                $TotalUnique++
            }
        }
        Write-Progress -Id 1 -Activity "Files: $($List.ObjectTitle)" -Completed
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
        [string]$DatabasePath
    )

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Priority report: sites ranked by findings"
    Write-Host "========================================="

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
ORDER BY Critical DESC, High DESC, Medium DESC, Low DESC, s.Title;
"@ | Format-Table

    Write-Host "Deep-scan a site: .\get-sharepointDeepScan.ps1 -SiteUrl <Url> [-DatabasePath <db>]"
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
        throw "Database file not found: $DatabasePath. Run get-sharepointSites.ps1 -Refresh/-ScanAll first."
    }
    Test-DatabaseSchema -DatabasePath $DatabasePath
    Show-PriorityReport -DatabasePath $DatabasePath
}
elseif ($DoScan) {
    if (-not (Test-Path $DatabasePath)) {
        throw "Database file not found: $DatabasePath. Run get-sharepointSites.ps1 -Refresh/-ScanAll first."
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

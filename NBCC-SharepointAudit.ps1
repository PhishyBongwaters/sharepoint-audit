#Requires -Modules PnP.PowerShell
# https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-pnp/sharepoint-pnp-cmdlets
#Requires -Modules PSSQLite
# https://www.powershellgallery.com/packages/PSSQLite/1.1.0

<#
.SYNOPSIS
    Scans SharePoint site permissions and inheritance into SQLite, then
    derives security findings ("oopsies") from the collected data.

.DESCRIPTION
    -Refresh  rebuilds the site inventory (personal/OneDrive sites excluded).
    -ScanNext / -ScanN / -ScanAll walk pending sites: root web, site role
               assignments, lists/libraries, role assignments for objects
               with unique (broken) permissions, and the sharing-link
               inventory. Progress checkpoints in SQLite; an interrupted
               run resumes instead of restarting.
    -Analyze  (re)generates security findings from the collected data.
    -Report   prints console reports. Read-only: never creates or modifies
               the database.
    -ConfigPath YAML config file for auth values (default audit-config.yaml
               next to the script); explicit parameters override it.

    Authentication is Entra app-only via certificate. Pass -Thumbprint,
    -ClientId and -TenantId at runtime, or put them in audit-config.yaml
    (see audit-config.yaml.example); never commit real values.
#>

param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [Alias("Url")]
    [string]$SiteUrl = "https://nbccollege.sharepoint.com/sites/MainSite/",

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
    [switch]$Refresh,
    [switch]$ScanNext,
    [switch]$Report,
    [switch]$ScanAll,
    [switch]$Analyze,

    [Parameter()]
    [int]$ScanN = 0
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
# assignments, findings). Dot-sourced so the deep-scan script reuses the
# exact same logic; no top-level code runs on load.
. "$PSScriptRoot\NBCC-SharepointAudit-Common.ps1"

function Reset-IncompleteScans {

    param(
        [string]$DatabasePath
    )

    Write-Output "Resetting incomplete scans"

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
UPDATE Sites
SET ScanStatus = 'Pending'
WHERE ScanStatus = 'InProgress';
"@
}


#   Get Sharepoint Sites ######################################################################
###############################################################################################
function Update-SiteInventory {

    param(
        [string]$DatabasePath
    )

    Write-Output "Refreshing Sites"

    $Sites = @(
        Get-PnPTenantSite |
            Where-Object {
                $_.Url -notlike "*-my.sharepoint.com*"
            }
    )

    $Total = $Sites.Count
    $Current = 0

    foreach ($Site in $Sites) {

        $Current++

        Write-Progress `
            -Activity "Updating Site Inventory" `
            -Status "$Current of $Total" `
            -PercentComplete (($Current / $Total) * 100)

        $Title = if ([string]::IsNullOrEmpty($Site.Title)) {
            $Site.Url
        }
        else {
            $Site.Title
        }

        # On conflict only the title is refreshed: ScanStatus, LastScanned
        # and ErrorMessage are scan progress and must survive a refresh.
        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
INSERT INTO Sites (
    SiteUrl,
    Title,
    SiteType,
    ScanStatus
)
VALUES (
    @Url,
    @Title,
    @SiteType,
    'Pending'
)
ON CONFLICT(SiteUrl)
DO UPDATE SET
    Title = excluded.Title,
    SiteType = excluded.SiteType;
"@ `
            -SqlParameters @{
                Url      = $Site.Url
                Title    = $Title
                SiteType = $Site.Template
            }
    }

    Write-Progress `
        -Activity "Updating Site Inventory" `
        -Completed

    Write-Host "Processed $Total sites."
}
###############################################################################################
###############################################################################################


#   Scan All Sites ############################################################################
###############################################################################################
function ScanAllSites {

    param(
        [string]$DatabasePath
    )

    $Total = [int](Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query "SELECT COUNT(*) AS C FROM Sites WHERE ScanStatus = 'Pending'" |
        Select-Object -ExpandProperty C)

    $done = 0
    while ($true) {

        $Site = Get-NextPendingSite `
            -DatabasePath $DatabasePath

        if (-not $Site) {
            break
        }

        $done++
        Write-Progress `
            -Id 0 -Activity "Scanning Sites" `
            -Status "Site $done of $Total : $($Site.SiteUrl)" `
            -PercentComplete (($done / $Total) * 100)

        ScanNextSite -DatabasePath $DatabasePath
    }

    Write-Progress -Id 0 -Activity "Scanning Sites" -Completed
    Write-Host "All sites processed."
}
###############################################################################################
###############################################################################################

#   Scan next N sites #########################################################################
###############################################################################################
function ScanNextNSites {

    param(
        [string]$DatabasePath,
        [int]$Count
    )

    if ($Count -lt 1) {
        throw "-ScanN must be a positive number of sites."
    }

    $done = 0
    while ($done -lt $Count) {

        $next = Get-NextPendingSite -DatabasePath $DatabasePath
        if (-not $next) {
            break
        }

        $done++
        Write-Progress `
            -Id 0 -Activity "Scanning Sites" `
            -Status "Site $done of $Count : $($next.SiteUrl)" `
            -PercentComplete (($done / $Count) * 100)
        ScanNextSite -DatabasePath $DatabasePath
    }

    Write-Progress -Id 0 -Activity "Scanning Sites" -Completed
    Write-Host "Scanned $done site(s)."
}
###############################################################################################
###############################################################################################

#   Get Next Site #############################################################################
###############################################################################################
function Get-NextPendingSite {

    param(
        [string]$DatabasePath
    )

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT *
FROM Sites
WHERE ScanStatus = 'Pending'
ORDER BY SiteId
LIMIT 1;
"@
}
###############################################################################################
###############################################################################################

#   Add site object ###########################################################################
###############################################################################################
function Add-SiteObject {

    param(
        $Site,
        $Web,
        [string]$DatabasePath
    )

    $Title = if ([string]::IsNullOrEmpty($Web.Title)) {
        $Site.Title
    }
    else {
        $Web.Title
    }

    $HasUnique = if ($Web.HasUniqueRoleAssignments) { 1 } else { 0 }

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
    NULL,
    'Site',
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
            SiteId         = $Site.SiteId
            ObjectUniqueId = $Web.Id.ToString()
            Title          = $Title
            Url            = $Site.SiteUrl
            HasUnique      = $HasUnique
        }
}
###############################################################################################
###############################################################################################

#   Mark site scan in progress ################################################################
###############################################################################################
function Start-SiteScan {

    param(
        [int]$SiteId,
        [string]$DatabasePath
    )

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
UPDATE Sites
SET
    ScanStatus = 'InProgress',
    ErrorMessage = NULL
WHERE SiteId = @SiteId;
"@ `
        -SqlParameters @{ SiteId = $SiteId }
}
###############################################################################################
###############################################################################################

#   Mark site scan complete ###################################################################
###############################################################################################
function Complete-SiteScan {

    param(
        [int]$SiteId,
        [string]$DatabasePath
    )

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
UPDATE Sites
SET
    ScanStatus = 'Complete',
    LastScanned = datetime('now')
WHERE SiteId = @SiteId;
"@ `
        -SqlParameters @{ SiteId = $SiteId }
}
###############################################################################################
###############################################################################################

#   Mark site scan failed #####################################################################
###############################################################################################
function Fail-SiteScan {

    param(
        [int]$SiteId,
        [string]$ErrorMessage,
        [string]$DatabasePath
    )

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
UPDATE Sites
SET
    ScanStatus = 'Failed',
    ErrorMessage = @ErrorMessage
WHERE SiteId = @SiteId;
"@ `
        -SqlParameters @{
            SiteId       = $SiteId
            ErrorMessage = $ErrorMessage
        }
}
###############################################################################################
###############################################################################################


#   Add Site Libraries ########################################################################
###############################################################################################
function Add-SiteLibraries {

    param(
        $Site,
        [string]$DatabasePath
    )

    # Get the Site Object we already created
    $SiteObjectId = Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT ObjectId
FROM Objects
WHERE SiteId = @SiteId
  AND ObjectType = 'Site'
LIMIT 1;
"@ `
        -SqlParameters @{ SiteId = $Site.SiteId } |
        Select-Object -ExpandProperty ObjectId

    $BaseUri = ([uri]$Site.SiteUrl).GetLeftPart([System.UriPartial]::Authority).TrimEnd('/')

    $Lists = Invoke-ResilientRestMethod `
        -Url "/_api/web/lists?`$select=Id,Title,BaseTemplate,Hidden,HasUniqueRoleAssignments,RootFolder/ServerRelativeUrl&`$expand=RootFolder"

    foreach ($List in $Lists.Value) {

        if ($List.Hidden) {
            continue
        }

        $ObjectType = switch ($List.BaseTemplate) {
            101 { 'Library' }
            default { 'List' }
        }

        $ObjectUrl = if ($List.RootFolder -and $List.RootFolder.ServerRelativeUrl) {
            $BaseUri + $List.RootFolder.ServerRelativeUrl
        }
        else {
            ''
        }

        $HasUnique = if ($List.HasUniqueRoleAssignments) { 1 } else { 0 }

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
                SiteId         = $Site.SiteId
                ParentId       = $SiteObjectId
                ObjectType     = $ObjectType
                ObjectUniqueId = $List.Id.ToString()
                Title          = $List.Title
                Url            = $ObjectUrl
                HasUnique      = $HasUnique
            }
    }
}
###############################################################################################
###############################################################################################

#   Add Object Permissions ####################################################################
###############################################################################################
function Add-ObjectPermissions {

    param(
        $Object,
        [int]$SiteId,
        [string]$DatabasePath
    )

    $Assignments = Invoke-ResilientRestMethod `
        -Url "/_api/web/lists(guid'$($Object.ObjectUniqueId)')/roleassignments?`$expand=Member,RoleDefinitionBindings"

    Save-RoleAssignments `
        -Assignments $Assignments `
        -ObjectDbId $Object.ObjectId `
        -SiteId $SiteId `
        -DatabasePath $DatabasePath
}

###############################################################################################
###############################################################################################

#   Get Scannable Objects #####################################################################
###############################################################################################
function Get-ScannableObjects {

    param(
        [string]$DatabasePath,
        [int]$SiteId
    )

    # Site-level objects are excluded: their permissions are captured by
    # Add-SitePermissions, and treating a web GUID as a list GUID 404s.
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT *
FROM Objects
WHERE SiteId = @SiteId
  AND HasUniquePermissions = 1
  AND ObjectType <> 'Site'
ORDER BY ObjectId;
"@ `
        -SqlParameters @{ SiteId = $SiteId }
}

###############################################################################################
###############################################################################################

#   Add Site Permissions ######################################################################
###############################################################################################
function Add-SitePermissions {

    param(
        $Site,
        [string]$DatabasePath
    )

    $SiteObjectId = Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT ObjectId
FROM Objects
WHERE SiteId = @SiteId
  AND ObjectType = 'Site'
LIMIT 1;
"@ `
        -SqlParameters @{ SiteId = $Site.SiteId } |
        Select-Object -ExpandProperty ObjectId

    $Assignments = Invoke-ResilientRestMethod `
        -Url "/_api/web/roleassignments?`$expand=Member,RoleDefinitionBindings"

    Save-RoleAssignments `
        -Assignments $Assignments `
        -ObjectDbId $SiteObjectId `
        -SiteId $Site.SiteId `
        -DatabasePath $DatabasePath
}
###############################################################################################
###############################################################################################

#   Sharing-link inventory ####################################################################
###############################################################################################
function Add-SharingLinkInventory {

    param(
        $Site,
        [string]$DatabasePath
    )

    <#
    .SYNOPSIS
        Records sharing links via the hidden backing groups SharePoint creates
        for them (SharingLinks.<fileGuid>.<type>.<linkId>).

    .DESCRIPTION
        Enumerating every file's links would require an item-level crawl. The
        backing groups give a cheap per-site inventory instead: one call that
        scales with how much is actually shared, not with library size. The
        <type> segment is a hint, not authoritative -- findings tell the
        analyst to verify scope. Authoritative per-link details
        (GetSharingInformation / Get-PnPFileSharingLink) are a separate,
        more expensive step.
    #>

    $Groups = Invoke-ResilientRestMethod `
        -Url "/_api/web/sitegroups?`$select=Id,Title&`$filter=startswith(Title,'SharingLinks.')"

    if ($null -eq $Groups.Value) {
        return
    }

    foreach ($Group in $Groups.Value) {

        # SharingLinks.<fileGuid>.<type>.<linkId>
        $parts = $Group.Title.Split('.')
        $FileGuid = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        $TypeHint = if ($parts.Count -gt 2) { $parts[2] } else { '' }

        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
INSERT INTO SharingLinks (
    SiteId,
    GroupTitle,
    FileGuid,
    TypeHint,
    DetectedDate
)
VALUES (
    @SiteId,
    @GroupTitle,
    @FileGuid,
    @TypeHint,
    datetime('now')
)
ON CONFLICT(SiteId, GroupTitle)
DO UPDATE SET
    FileGuid = excluded.FileGuid,
    TypeHint = excluded.TypeHint,
    DetectedDate = excluded.DetectedDate;
"@ `
            -SqlParameters @{
                SiteId     = $Site.SiteId
                GroupTitle = $Group.Title
                FileGuid   = $FileGuid
                TypeHint   = $TypeHint
            }
    }
}
###############################################################################################
###############################################################################################

#   Scan next site ############################################################################
###############################################################################################
function ScanNextSite {

    param(
        [string]$DatabasePath
    )

    $Site = Get-NextPendingSite -DatabasePath $DatabasePath

    if (-not $Site) {
        Write-Host "No pending sites found."
        return
    }


    try {
        Connect-SharePointSite -SiteUrl $Site.SiteUrl

        Start-SiteScan `
            -SiteId $Site.SiteId `
            -DatabasePath $DatabasePath

        $Web = Invoke-ResilientRestMethod -Url "/_api/web"

        # Create root Site object
        Add-SiteObject `
            -Site $Site `
            -Web $Web `
            -DatabasePath $DatabasePath

        # Capture Site-level permissions
        Add-SitePermissions `
            -Site $Site `
            -DatabasePath $DatabasePath

        # Inventory sharing links via their backing groups (cheap: one call
        # per site, scales with sharing activity not library size)
        Add-SharingLinkInventory `
            -Site $Site `
            -DatabasePath $DatabasePath

        # Discover Lists / Libraries
        Add-SiteLibraries `
            -Site $Site `
            -DatabasePath $DatabasePath

        # Get all scannable objects (unique permissions, excluding the Site
        # object itself -- its permissions were captured above)
        $Objects = @(
            Get-ScannableObjects `
                -DatabasePath $DatabasePath `
                -SiteId $Site.SiteId
        )

        $Total = $Objects.Count
        $Current = 0

        foreach ($Object in $Objects) {

            $Current++

            Write-Progress `
                -Id 1 -ParentId 0 -Activity "Scanning Object Permissions" `
                -Status "$Current of $Total : $($Object.ObjectTitle)" `
                -PercentComplete (($Current / $Total) * 100)

            Add-ObjectPermissions `
                -Object $Object `
                -SiteId $Site.SiteId `
                -DatabasePath $DatabasePath
        }

        Write-Progress `
            -Id 1 -Activity "Scanning Object Permissions" `
            -Completed

        # Findings are derived data: a failure here must not fail the site
        # whose permissions were just captured successfully.
        try {
            Invoke-FindingsAnalysis `
                -DatabasePath $DatabasePath `
                -SiteId $Site.SiteId `
                -Quiet
        }
        catch {
            Write-Warning "Findings analysis failed for $($Site.SiteUrl): $($_.Exception.Message)"
        }

        Complete-SiteScan `
            -SiteId $Site.SiteId `
            -DatabasePath $DatabasePath

    }
    catch {

        if ($_.Exception.Message -match '^THROTTLE_EXHAUSTED') {
            # Throttling is transient: requeue instead of failing so the
            # next run retries the site.
            Invoke-SqliteQuery `
                -DataSource $DatabasePath `
                -Query @"
UPDATE Sites
SET ScanStatus = 'Pending',
    ErrorMessage = 'Throttled; requeued'
WHERE SiteId = @SiteId;
"@ `
                -SqlParameters @{ SiteId = $Site.SiteId }
            Write-Warning "Throttled while scanning $($Site.SiteUrl); site requeued as Pending."
        }
        else {
            Fail-SiteScan `
                -SiteId $Site.SiteId `
                -ErrorMessage $_.Exception.Message `
                -DatabasePath $DatabasePath

            Write-Host "FAILED: $($Site.SiteUrl)"
            Write-Host $_.Exception.Message
        }
    }
}
###############################################################################################
###############################################################################################

#   Generate site report ######################################################################
###############################################################################################
function Show-PermissionReports {

    param(
        [string]$DatabasePath
    )

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Direct Grants (unique-permission objects)"
    Write-Host "========================================="

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT DISTINCT
    s.Title AS SiteName,
    o.ObjectType,
    o.ObjectTitle,
    CASE
        WHEN o.HasUniquePermissions = 1 THEN 'Broken'
        ELSE 'Inherited'
    END AS InheritanceStatus,
    p.Title AS Principal,
    p.PrincipalTypeName,
    perms.PermissionLevel
FROM Permissions perms
JOIN Objects o
    ON perms.ObjectId = o.ObjectId
JOIN Principals p
    ON p.Id = perms.PrincipalId
JOIN Sites s
    ON o.SiteId = s.SiteId
ORDER BY
    s.Title,
    o.ObjectTitle,
    p.Title;
"@ | Format-Table

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Site Permissions"
    Write-Host "========================================="

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT DISTINCT
    s.Title AS SiteName,
    o.ObjectTitle,
    p.Title AS Principal,
    p.PrincipalTypeName,
    perms.PermissionLevel
FROM Permissions perms
JOIN Objects o
    ON perms.ObjectId = o.ObjectId
JOIN Principals p
    ON p.Id = perms.PrincipalId
JOIN Sites s
    ON o.SiteId = s.SiteId
WHERE o.ObjectType = 'Site'
ORDER BY
    s.Title,
    p.Title,
    perms.PermissionLevel;
"@ | Format-Table

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Inheritance"
    Write-Host "========================================="

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT DISTINCT
    s.Title AS SiteName,
    o.ObjectType,
    o.ObjectTitle,
    CASE
        WHEN o.HasUniquePermissions = 1 THEN 'Broken'
        ELSE 'Inherited'
    END AS InheritanceStatus
FROM Objects o
JOIN Sites s
    ON o.SiteId = s.SiteId
ORDER BY
    s.Title,
    o.ObjectTitle;
"@ | Format-Table

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Full Control Assignments"
    Write-Host "========================================="

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT DISTINCT
    s.Title AS SiteName,
    o.ObjectTitle,
    CASE
        WHEN o.HasUniquePermissions = 1 THEN 'Broken'
        ELSE 'Inherited'
    END AS InheritanceStatus,
    p.Title AS Principal,
    perms.PermissionLevel
FROM Permissions perms
JOIN Objects o
    ON perms.ObjectId = o.ObjectId
JOIN Principals p
    ON p.Id = perms.PrincipalId
JOIN Sites s
    ON o.SiteId = s.SiteId
WHERE perms.PermissionLevel = 'Full Control'
ORDER BY
    s.Title,
    o.ObjectTitle,
    p.Title;
"@ | Format-Table

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Direct User Permissions"
    Write-Host "========================================="

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT DISTINCT
    s.Title AS SiteName,
    o.ObjectTitle,
    CASE
        WHEN o.HasUniquePermissions = 1 THEN 'Broken'
        ELSE 'Inherited'
    END AS InheritanceStatus,
    p.Title,
    perms.PermissionLevel
FROM Permissions perms
JOIN Objects o
    ON perms.ObjectId = o.ObjectId
JOIN Principals p
    ON p.Id = perms.PrincipalId
JOIN Sites s
    ON o.SiteId = s.SiteId
WHERE p.PrincipalTypeName = 'User'
ORDER BY
    s.Title,
    o.ObjectTitle,
    p.Title;
"@ | Format-Table

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Security Findings"
    Write-Host "========================================="

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT
    s.Title AS SiteName,
    sf.Severity,
    sf.FindingType,
    o.ObjectTitle,
    p.Title AS Principal,
    sf.PermissionLevel,
    sf.Details,
    sf.DetectedDate
FROM SecurityFindings sf
JOIN Sites s
    ON s.SiteId = sf.SiteId
LEFT JOIN Objects o
    ON o.ObjectId = sf.ObjectId
LEFT JOIN Principals p
    ON p.Id = sf.PrincipalId
ORDER BY
    CASE sf.Severity
        WHEN 'Critical' THEN 0
        WHEN 'High' THEN 1
        WHEN 'Medium' THEN 2
        WHEN 'Low' THEN 3
        ELSE 4
    END,
    sf.DetectedDate DESC;
"@ | Format-Table
}

###############################################################################################
###############################################################################################

#   Main ######################################################################################
###############################################################################################

$WriteAction = $Refresh -or $ScanNext -or $ScanAll -or $Analyze -or ($ScanN -gt 0)

if ($WriteAction) {
    Initialize-Database -DatabasePath $DatabasePath
    Test-DatabaseSchema -DatabasePath $DatabasePath
    Reset-IncompleteScans -DatabasePath $DatabasePath
}

if ($Refresh) {
    Connect-SharePointSite -SiteUrl $SiteUrl
    Update-SiteInventory -DatabasePath $DatabasePath
}

if ($ScanNext) {
    ScanNextSite -DatabasePath $DatabasePath
}

if ($Report) {
    # -Report is read-only: never create or modify the database.
    if (-not (Test-Path $DatabasePath)) {
        throw "Database file not found: $DatabasePath. Run with -Refresh first."
    }
    Test-DatabaseSchema -DatabasePath $DatabasePath
    Show-PermissionReports -DatabasePath $DatabasePath
}

if ($ScanAll) {
    ScanAllSites -DatabasePath $DatabasePath
}

if ($ScanN -gt 0) {
    ScanNextNSites -DatabasePath $DatabasePath -Count $ScanN
}

if ($Analyze) {
    Invoke-FindingsAnalysis -DatabasePath $DatabasePath
}

if (-not ($Refresh -or $ScanNext -or $Report -or $ScanAll -or $Analyze -or ($ScanN -gt 0))) {
    Write-Host "No action specified."
    Write-Host "Available actions:"
    Write-Host "  -Refresh"
    Write-Host "  -ScanNext"
    Write-Host "  -ScanAll"
    Write-Host "  -ScanN <number>   (scan the next N pending sites)"
    Write-Host "  -Analyze"
    Write-Host "  -Report"
    return
}

###############################################################################################
###############################################################################################
try {
    Disconnect-PnPOnline -ErrorAction SilentlyContinue
}
catch {}

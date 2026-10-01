#Requires -Modules PnP.PowerShell
# https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-pnp/sharepoint-pnp-cmdlets
#Requires -Modules PSSQLite
# https://www.powershellgallery.com/packages/PSSQLite/1.1.0



param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [Alias("Url")]
    [string]$SiteUrl = "https://nbccollege.sharepoint.com/sites/MainSite/",

    [Parameter()]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$Thumbprint = "66F554380EED5866003577C6BB52409662A05CB4",

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$ClientId = "57cb229",

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$TenantId = "26c9169c",

    [Parameter()]
    [string]$DatabasePath = "C:\Users\Rob.MacDonald\OneDrive - NBCC\Documents\Documentation\git\powershell\NBCC-SharePoint.db",

    [Parameter()]
    [switch]$Refresh,
    [switch]$ScanNext,
    [switch]$Report,
    [switch]$ScanAll
)
###############################################################################################
###############################################################################################
#Import-Module PSSQLite


function Initialize-Database {
    param(
        [string]$DatabasePath
    )

    Write-Output "Initializing $DatabasePath"

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
CREATE TABLE IF NOT EXISTS Sites (
    SiteId INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteUrl TEXT NOT NULL UNIQUE,
    Title TEXT,
    LastScanned DATETIME,
    ScanStatus TEXT,
    InheritanceEnabled INTEGER,
    SiteType TEXT,
    ErrorMessage TEXT
);

CREATE TABLE IF NOT EXISTS Objects (
    ObjectId INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteId INTEGER NOT NULL,
    ParentObjectId INTEGER,
    ObjectType TEXT NOT NULL,
    ObjectUniqueId TEXT NOT NULL,
    ObjectTitle TEXT,
    ObjectUrl TEXT,
    HasUniquePermissions INTEGER,
    FOREIGN KEY (SiteId) REFERENCES Sites(SiteId),
    FOREIGN KEY (ParentObjectId) REFERENCES Objects(ObjectId),
    UNIQUE (SiteId, ObjectUniqueId)
);

CREATE TABLE IF NOT EXISTS Principals (
    PrincipalId INTEGER PRIMARY KEY,
    LoginName TEXT,
    Title TEXT,
    PrincipalTypeId INTEGER,
    PrincipalTypeName TEXT,
    Email TEXT,
    UserPrincipalName TEXT,
    IsSiteAdmin INTEGER
);

CREATE TABLE IF NOT EXISTS Permissions (
    PermissionId INTEGER PRIMARY KEY AUTOINCREMENT,
    ObjectId INTEGER NOT NULL,
    PrincipalId INTEGER NOT NULL,
    PermissionLevel TEXT NOT NULL,
    GrantedDirectly INTEGER NOT NULL,
    FOREIGN KEY (ObjectId) REFERENCES Objects(ObjectId),
    FOREIGN KEY (PrincipalId) REFERENCES Principals(PrincipalId),
    UNIQUE (ObjectId, PrincipalId, PermissionLevel)
);

CREATE TABLE SecurityFindings (
    FindingId INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteId INTEGER NOT NULL,
    ObjectId INTEGER,
    PrincipalId INTEGER,
    Severity TEXT,
    FindingType TEXT,
    PermissionLevel TEXT,
    Details TEXT,
    DetectedDate DATETIME
);

"@
}

function Test-DatabaseSchema {
    param(
        [string]$DatabasePath
    )

    Write-Output "Validating DB Schema for $DatabasePath"  

    $RequiredTables = @(
        'Sites',
        'Objects',
        'Principals',
        'Permissions',
        'SecurityFindings'
    )

    $ExistingTables =
        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
SELECT name
FROM sqlite_master
WHERE type='table';
"@ |
        Select-Object -ExpandProperty name

    $MissingTables =
        $RequiredTables |
        Where-Object {
            $_ -notin $ExistingTables
        }

    if ($MissingTables) {
        throw (
            "Database schema validation failed. " +
            "Missing tables: " +
            ($MissingTables -join ', ')
        )        
    }

    Write-Host "Database schema validated."
}

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

    $Sites = Get-PnPTenantSite |
        Where-Object {
            $_.Url -notlike "*-my.sharepoint.com*"
        }

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
            $Site.Title.Replace("'", "''")
        }

        $Url = $Site.Url.Replace("'", "''")

        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
INSERT INTO Sites (
    SiteUrl,
    Title,
    ScanStatus
)
VALUES (
    '$Url',
    '$Title',
    'Pending'
)
ON CONFLICT(SiteUrl)
DO UPDATE SET
    Title = excluded.Title,
    ScanStatus = excluded.ScanStatus,
    ErrorMessage = NULL;
"@
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

    while ($true) {

        $Site = Get-NextPendingSite `
            -DatabasePath $DatabasePath

        if (-not $Site) {
            break
        }

        ScanNextSite
    }

    Write-Host "All sites processed."
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
        $Site.Title.Replace("'", "''")
    }
    else {
        $Web.Title.Replace("'", "''")
    }

    $Url   = $Site.SiteUrl.Replace("'", "''")

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
    $($Site.SiteId),
    NULL,
    'Site',
    '$($Web.Id)',
    '$Title',
    '$Url',
    $(if ($Web.HasUniqueRoleAssignments) { 1 } else { 0 })
)
ON CONFLICT(SiteId, ObjectUniqueId)
DO UPDATE SET
    ParentObjectId = excluded.ParentObjectId,
    ObjectType = excluded.ObjectType,
    ObjectTitle = excluded.ObjectTitle,
    ObjectUrl = excluded.ObjectUrl,
    HasUniquePermissions = excluded.HasUniquePermissions;
"@
}

#    add-SiteObject `
#        -Site $Site `
#        -Web $Web `
#        -DatabasePath $DatabasePath
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
WHERE SiteId = $SiteId;
"@
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
WHERE SiteId = $SiteId;
"@
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

    $ErrorMessage = $ErrorMessage.Replace("'", "''")

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
UPDATE Sites
SET
    ScanStatus = 'Failed',
    ErrorMessage = '$ErrorMessage'
WHERE SiteId = $SiteId;
"@
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
    $SiteObject = Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT ObjectId
FROM Objects
WHERE SiteId = $($Site.SiteId)
  AND ObjectType = 'Site'
LIMIT 1;
"@

    $Lists = Invoke-PnPSPRestMethod `
        -Url "/_api/web/lists?`$select=Id,Title,BaseTemplate,Hidden,HasUniqueRoleAssignments"

    foreach ($List in $Lists.Value) {

        if ($List.Hidden) {
            continue
        }

        $Title = $List.Title.Replace("'", "''")

        $ObjectType = switch ($List.BaseTemplate) {
            101 { 'Library' }
            default { 'List' }
        }

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
    $($Site.SiteId),
    $($SiteObject.ObjectId),
    '$ObjectType',
    '$($List.Id)',
    '$Title',
    '',
    $(if ($List.HasUniqueRoleAssignments) { 1 } else { 0 })
)
ON CONFLICT(SiteId, ObjectUniqueId)
DO UPDATE SET
    ParentObjectId = excluded.ParentObjectId,
    ObjectType = excluded.ObjectType,
    ObjectTitle = excluded.ObjectTitle,
    ObjectUrl = excluded.ObjectUrl,
    HasUniquePermissions = excluded.HasUniquePermissions;
"@
    }
}

###############################################################################################
###############################################################################################

#   Add Oject Permissions #####################################################################
###############################################################################################
function Add-ObjectPermissions {

    param(
        $Object,
        [string]$DatabasePath
    )

    $Assignments = Invoke-PnPSPRestMethod `
        -Url "/_api/web/lists(guid'$($Object.ObjectUniqueId)')/roleassignments?`$expand=Member,RoleDefinitionBindings"

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
    DELETE FROM Permissions
    WHERE ObjectId = $($Object.ObjectId);
"@

    foreach ($Assignment in $Assignments.Value) {

        $Member = $Assignment.Member

        $PrincipalTypeName = switch ($Member.PrincipalType) {
            1 { 'User' }
            4 { 'SharePointGroup' }
            8 { 'SecurityGroup' }
            15 { 'Claim' }
            default { 'Unknown' }
        }

        $LoginName = ($Member.LoginName ?? '').Replace("'", "''")
        $Title     = ($Member.Title ?? '').Replace("'", "''")
        $Email     = ($Member.Email ?? '').Replace("'", "''")
        $UPN       = ($Member.UserPrincipalName ?? '').Replace("'", "''")

        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
INSERT INTO Principals (
    PrincipalId,
    LoginName,
    Title,
    PrincipalTypeId,
    PrincipalTypeName,
    Email,
    UserPrincipalName,
    IsSiteAdmin
)
VALUES (
    $($Member.Id),
    '$LoginName',
    '$Title',
    $($Member.PrincipalType),
    '$PrincipalTypeName',
    '$Email',
    '$UPN',
    $(if ($Member.IsSiteAdmin) { 1 } else { 0 })
)
ON CONFLICT(PrincipalId)
DO UPDATE SET
    LoginName = excluded.LoginName,
    Title = excluded.Title,
    PrincipalTypeId = excluded.PrincipalTypeId,
    PrincipalTypeName = excluded.PrincipalTypeName,
    Email = excluded.Email,
    UserPrincipalName = excluded.UserPrincipalName,
    IsSiteAdmin = excluded.IsSiteAdmin;
"@

        foreach ($Role in $Assignment.RoleDefinitionBindings) {

            if ($Role.Name -eq 'Limited Access') {
                continue
            }

            $PermissionLevel = $Role.Name.Replace("'", "''")

            Invoke-SqliteQuery `
                -DataSource $DatabasePath `
                -Query @"
INSERT INTO Permissions (
    ObjectId,
    PrincipalId,
    PermissionLevel,
    GrantedDirectly
)
VALUES (
    $($Object.ObjectId),
    $($Member.Id),
    '$PermissionLevel',
    1
)
ON CONFLICT(ObjectId, PrincipalId, PermissionLevel)
DO UPDATE SET
    GrantedDirectly = excluded.GrantedDirectly;
"@
        }
    }
}

###############################################################################################
###############################################################################################

#   Add Get Scannable Objects #################################################################
###############################################################################################
function Get-ScannableObjects {

    param(
        [string]$DatabasePath,
        [int]$SiteId
    )

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT *
FROM Objects
WHERE SiteId = $SiteId
  AND HasUniquePermissions = 1
ORDER BY ObjectId;
"@
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

    $SiteObject = Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT ObjectId
FROM Objects
WHERE SiteId = $($Site.SiteId)
  AND ObjectType = 'Site'
LIMIT 1;
"@

    $Assignments = Invoke-PnPSPRestMethod `
        -Url "/_api/web/roleassignments?`$expand=Member,RoleDefinitionBindings"

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
    DELETE FROM Permissions
    WHERE ObjectId = $($SiteObject.ObjectId);
"@

    foreach ($Assignment in $Assignments.Value) {

        $Member = $Assignment.Member

        $PrincipalTypeName = switch ($Member.PrincipalType) {
            1  { 'User' }
            4  { 'SharePointGroup' }
            8  { 'SecurityGroup' }
            15 { 'Claim' }
            default { 'Unknown' }
        }

        $LoginName = ($Member.LoginName ?? '').Replace("'", "''")
        $Title     = ($Member.Title ?? '').Replace("'", "''")
        $Email     = ($Member.Email ?? '').Replace("'", "''")
        $UPN       = ($Member.UserPrincipalName ?? '').Replace("'", "''")

        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
INSERT INTO Principals (
    PrincipalId,
    LoginName,
    Title,
    PrincipalTypeId,
    PrincipalTypeName,
    Email,
    UserPrincipalName,
    IsSiteAdmin
)
VALUES (
    $($Member.Id),
    '$LoginName',
    '$Title',
    $($Member.PrincipalType),
    '$PrincipalTypeName',
    '$Email',
    '$UPN',
    $(if ($Member.IsSiteAdmin) { 1 } else { 0 })
)
ON CONFLICT(PrincipalId)
DO UPDATE SET
    LoginName = excluded.LoginName,
    Title = excluded.Title,
    PrincipalTypeId = excluded.PrincipalTypeId,
    PrincipalTypeName = excluded.PrincipalTypeName,
    Email = excluded.Email,
    UserPrincipalName = excluded.UserPrincipalName,
    IsSiteAdmin = excluded.IsSiteAdmin;
"@

        foreach ($Role in $Assignment.RoleDefinitionBindings) {

            if ($Role.Name -eq 'Limited Access') {
                continue
            }

            $PermissionLevel = $Role.Name.Replace("'", "''")

            Invoke-SqliteQuery `
                -DataSource $DatabasePath `
                -Query @"
INSERT INTO Permissions (
    ObjectId,
    PrincipalId,
    PermissionLevel,
    GrantedDirectly
)
VALUES (
    $($SiteObject.ObjectId),
    $($Member.Id),
    '$PermissionLevel',
    1
)
ON CONFLICT(ObjectId, PrincipalId, PermissionLevel)
DO UPDATE SET
    GrantedDirectly = excluded.GrantedDirectly;
"@
        }
    }
}
###############################################################################################
###############################################################################################

#   Scan next site ############################################################################
###############################################################################################
function ScanNextSite {
    $Site = Get-NextPendingSite -DatabasePath $DatabasePath

    if (-not $Site) {
        Write-Host "No pending sites found."
        return
    }

    Write-Host "Processing $($Site.SiteUrl)"
    
    try {
        Connect-SharePointSite -SiteUrl $Site.SiteUrl

        Start-SiteScan `
            -SiteId $Site.SiteId `
            -DatabasePath $DatabasePath

        $Web = Invoke-PnPSPRestMethod -Url "/_api/web"

        # Create root Site object
        Add-SiteObject `
            -Site $Site `
            -Web $Web `
            -DatabasePath $DatabasePath

        # Capture Site-level permissions
        Add-SitePermissions `
            -Site $Site `
            -DatabasePath $DatabasePath

        # Discover Lists / Libraries
        Add-SiteLibraries `
            -Site $Site `
            -DatabasePath $DatabasePath

        # Get all objects with unique permissions
        $Objects = Get-ScannableObjects `
            -DatabasePath $DatabasePath `
            -SiteId $Site.SiteId

        $Total = $Objects.Count
        $Current = 0

        foreach ($Object in $Objects) {

            $Current++

            Write-Progress `
                -Activity "Scanning Object Permissions" `
                -Status "$Current of $Total : $($Object.ObjectTitle)" `
                -PercentComplete (($Current / $Total) * 100)

            Add-ObjectPermissions `
                -Object $Object `
                -DatabasePath $DatabasePath
        }

        Write-Progress `
            -Activity "Scanning Object Permissions" `
            -Completed

        Complete-SiteScan `
            -SiteId $Site.SiteId `
            -DatabasePath $DatabasePath

        Write-Host "Completed $($Site.SiteUrl)"
    }
    catch {

        Fail-SiteScan `
            -SiteId $Site.SiteId `
            -ErrorMessage $_.Exception.Message `
            -DatabasePath $DatabasePath

        Write-Host "FAILED: $($Site.SiteUrl)"
        Write-Host $_.Exception.Message
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
    Write-Host "Effective Permissions"
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
    ON perms.PrincipalId = p.PrincipalId
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
    ON perms.PrincipalId = p.PrincipalId
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
    ON perms.PrincipalId = p.PrincipalId
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
    ON perms.PrincipalId = p.PrincipalId
JOIN Sites s
    ON o.SiteId = s.SiteId
WHERE p.PrincipalTypeName = 'User'
ORDER BY
    s.Title,
    o.ObjectTitle,
    p.Title;
"@ | Format-Table
}

#Show-PermissionReports -DatabasePath $DatabasePath
###############################################################################################
###############################################################################################

#   Connect to Sharepoint #####################################################################
###############################################################################################
function Connect-SharePointSite {

    param(
        [string]$SiteUrl
    )

    try {
        Write-Host "Connecting to SharePoint: $SiteUrl"

        Connect-PnPOnline `
            -Url $SiteUrl `
            -ClientId $ClientId `
            -Tenant $TenantId `
            -Thumbprint $Thumbprint `
            -ErrorAction Stop

        Write-Host "Connected."
    }
    catch {
        throw "Failed to connect to SharePoint site '$SiteUrl'. $($_.Exception.Message)"
    }
}

###############################################################################################
###############################################################################################

Initialize-Database -DatabasePath $DatabasePath
Test-DatabaseSchema -DatabasePath $DatabasePath
Reset-IncompleteScans -DatabasePath $DatabasePath

#   Switch ####################################################################################
###############################################################################################
if ($Refresh) {
    Connect-SharePointSite -SiteUrl $SiteUrl
    Update-SiteInventory -DatabasePath $DatabasePath
}

if ($ScanNext) {
    ScanNextSite
}

if ($Report) {
    Show-PermissionReports -DatabasePath $DatabasePath
}

if ($ScanAll) {
    ScanAllSites -DatabasePath $DatabasePath
}

if (-not ($Refresh -or $ScanNext -or $Report)) {
    Write-Host "No action specified."
    Write-Host "Available actions:"
    Write-Host "  -Refresh"
    Write-Host "  -ScanNext"
    Write-Host "  -Report"
    return
}
###############################################################################################
###############################################################################################
try {
    Disconnect-PnPOnline -ErrorAction SilentlyContinue
}
catch {}

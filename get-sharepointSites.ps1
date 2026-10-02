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
    -ScanNext / -ScanAll walk pending sites: root web, site role assignments,
               lists/libraries, and role assignments for objects with unique
               (broken) permissions. Progress checkpoints in SQLite; an
               interrupted run resumes instead of restarting.
    -Analyze  (re)generates security findings from the collected data.
    -Report   prints console reports. Read-only: never creates or modifies
               the database.

    Authentication is Entra app-only via certificate. Pass -Thumbprint,
    -ClientId and -TenantId at runtime; never commit real values.
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
    [string]$DatabasePath = ".\SharePoint-Audit.db",

    [Parameter()]
    [string]$ConfigPath = "./audit-config.yaml",

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
    'tenantid'      = 'TenantId'
    'databasepath'  = 'DatabasePath'
    'database_path' = 'DatabasePath'
}
foreach ($__entry in $__ParamMap.GetEnumerator()) {
    if ($__Config.ContainsKey($__entry.Key) -and -not $PSBoundParameters.ContainsKey($__entry.Value)) {
        Set-Variable -Name $__entry.Value -Value $__Config[$__entry.Key] -Scope Script
    }
}
Remove-Variable -Name __Config, __ParamMap, __entry -ErrorAction SilentlyContinue

###############################################################################################
#   Throttle-aware REST wrapper ###############################################################
###############################################################################################

function Get-ThrottleStatusCode {
    param($ErrorRecord)

    $ex = $ErrorRecord.Exception
    while ($ex) {
        if ($ex -is [System.Net.WebException] -and $null -ne $ex.Response) {
            try { return [int]$ex.Response.StatusCode } catch { return $null }
        }
        $ex = $ex.InnerException
    }
    return $null
}

function Get-RetryAfterSeconds {
    param($ErrorRecord)

    $ex = $ErrorRecord.Exception
    while ($ex) {
        if ($ex -is [System.Net.WebException] -and $null -ne $ex.Response) {
            $val = $ex.Response.Headers['Retry-After']
            if ($val -match '^\d+$') { return [int]$val }
        }
        $ex = $ex.InnerException
    }
    return $null
}

function Invoke-ResilientRestMethod {
    <#
    .SYNOPSIS
        Invoke-PnPSPRestMethod with 429/503 retry: honors Retry-After,
        otherwise exponential backoff with jitter (max 5 retries).
        Throws a THROTTLE_EXHAUSTED-prefixed error when retries run out.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [int]$MaxRetries = 5
    )

    $attempt = 0
    while ($true) {
        try {
            return Invoke-PnPSPRestMethod -Url $Url
        }
        catch {
            $attempt++
            $statusCode = Get-ThrottleStatusCode -ErrorRecord $_
            $message = $_.Exception.Message
            $throttled = ($statusCode -eq 429 -or $statusCode -eq 503) -or
                         ($message -match '429|Too Many Requests|throttl')

            if ($throttled -and $attempt -le $MaxRetries) {
                $retryAfter = Get-RetryAfterSeconds -ErrorRecord $_
                if ($retryAfter) {
                    $delay = $retryAfter
                }
                else {
                    $delay = [math]::Pow(2, $attempt) + ((Get-Random -Maximum 1000) / 1000.0)
                }
                Write-Warning ("Throttled (HTTP {0}). Waiting {1:N1}s before retry {2} of {3}: {4}" -f
                    $statusCode, $delay, $attempt, $MaxRetries, $Url)
                Start-Sleep -Seconds $delay
                continue
            }
            if ($throttled) {
                throw [System.Exception]::new("THROTTLE_EXHAUSTED: $Url")
            }
            throw
        }
    }
}

###############################################################################################
#   Database ##################################################################################
###############################################################################################

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
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteId INTEGER NOT NULL,
    SharePointId INTEGER,
    LoginName TEXT NOT NULL,
    Title TEXT,
    PrincipalTypeId INTEGER,
    PrincipalTypeName TEXT,
    Email TEXT,
    UserPrincipalName TEXT,
    IsSiteAdmin INTEGER,
    FOREIGN KEY (SiteId) REFERENCES Sites(SiteId),
    UNIQUE (SiteId, SharePointId)
);

CREATE TABLE IF NOT EXISTS Permissions (
    PermissionId INTEGER PRIMARY KEY AUTOINCREMENT,
    ObjectId INTEGER NOT NULL,
    PrincipalId INTEGER NOT NULL,
    PermissionLevel TEXT NOT NULL,
    GrantedDirectly INTEGER NOT NULL,
    FOREIGN KEY (ObjectId) REFERENCES Objects(ObjectId),
    FOREIGN KEY (PrincipalId) REFERENCES Principals(Id),
    UNIQUE (ObjectId, PrincipalId, PermissionLevel)
);

CREATE TABLE IF NOT EXISTS SecurityFindings (
    FindingId INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteId INTEGER NOT NULL,
    ObjectId INTEGER,
    PrincipalId INTEGER,
    Severity TEXT,
    FindingType TEXT,
    PermissionLevel TEXT,
    Details TEXT,
    DetectedDate DATETIME,
    FOREIGN KEY (SiteId) REFERENCES Sites(SiteId)
);

CREATE TABLE IF NOT EXISTS SharingLinks (
    SharingLinkId INTEGER PRIMARY KEY AUTOINCREMENT,
    SiteId INTEGER NOT NULL,
    GroupTitle TEXT NOT NULL,
    FileGuid TEXT,
    TypeHint TEXT,
    DetectedDate DATETIME,
    FOREIGN KEY (SiteId) REFERENCES Sites(SiteId),
    UNIQUE (SiteId, GroupTitle)
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
        'SecurityFindings',
        'SharingLinks'
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

    # v2 schema: Principals must be keyed per site (surrogate Id, SiteId,
    # SharePointId). Databases built by older versions merged identities
    # across sites and cannot be unmerged.
    $PrincipalColumns =
        Invoke-SqliteQuery `
            -DataSource $DatabasePath `
            -Query @"
PRAGMA table_info(Principals);
"@ |
        Select-Object -ExpandProperty name

    foreach ($col in @('Id', 'SiteId', 'SharePointId')) {
        if ($col -notin @($PrincipalColumns)) {
            throw (
                "Database was created by an older version of this script " +
                "(Principals table lacks '$col'). Identity data from that " +
                "version is unreliable across sites. Move the database file " +
                "aside and let the script create a fresh one, then rescan."
            )
        }
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
            -Activity "Scanning Sites" `
            -Status "Site $done of $Total : $($Site.SiteUrl)" `
            -PercentComplete (($done / $Total) * 100)

        ScanNextSite -DatabasePath $DatabasePath
    }

    Write-Progress -Activity "Scanning Sites" -Completed
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
            -Activity "Scanning Sites" `
            -Status "Site $done of $Count : $($next.SiteUrl)" `
            -PercentComplete (($done / $Count) * 100)
        ScanNextSite -DatabasePath $DatabasePath
    }

    Write-Progress -Activity "Scanning Sites" -Completed
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

#   Upsert principal, return its database Id ###################################################
###############################################################################################
function Get-PrincipalDbId {
    <#
    .SYNOPSIS
        Upserts a principal scoped to its site collection and returns the
        Principals.Id surrogate key.

    .DESCRIPTION
        SharePoint Member.Id is unique only within a site collection, so the
        identity key is (SiteId, SharePointId). Permissions reference the
        surrogate Id, never the SharePoint id directly.
    #>

    param(
        [int]$SiteId,
        $Member,
        [string]$DatabasePath
    )

    $PrincipalTypeName = switch ($Member.PrincipalType) {
        1 { 'User' }
        4 { 'SharePointGroup' }
        8 { 'SecurityGroup' }
        15 { 'Claim' }
        default { 'Unknown' }
    }

    $IsSiteAdmin = if ($Member.IsSiteAdmin) { 1 } else { 0 }

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO Principals (
    SiteId,
    SharePointId,
    LoginName,
    Title,
    PrincipalTypeId,
    PrincipalTypeName,
    Email,
    UserPrincipalName,
    IsSiteAdmin
)
VALUES (
    @SiteId,
    @SharePointId,
    @LoginName,
    @Title,
    @PrincipalTypeId,
    @PrincipalTypeName,
    @Email,
    @UPN,
    @IsSiteAdmin
)
ON CONFLICT(SiteId, SharePointId)
DO UPDATE SET
    LoginName = excluded.LoginName,
    Title = excluded.Title,
    PrincipalTypeId = excluded.PrincipalTypeId,
    PrincipalTypeName = excluded.PrincipalTypeName,
    Email = excluded.Email,
    UserPrincipalName = excluded.UserPrincipalName,
    IsSiteAdmin = excluded.IsSiteAdmin;
"@ `
        -SqlParameters @{
            SiteId          = $SiteId
            SharePointId    = $Member.Id
            LoginName       = [string]$Member.LoginName
            Title           = [string]$Member.Title
            PrincipalTypeId = $Member.PrincipalType
            PrincipalTypeName = $PrincipalTypeName
            Email           = [string]$Member.Email
            UPN             = [string]$Member.UserPrincipalName
            IsSiteAdmin     = $IsSiteAdmin
        }

    return Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT Id
FROM Principals
WHERE SiteId = @SiteId
  AND SharePointId = @SharePointId
LIMIT 1;
"@ `
        -SqlParameters @{
            SiteId       = $SiteId
            SharePointId = $Member.Id
        } |
        Select-Object -ExpandProperty Id
}
###############################################################################################
###############################################################################################

#   Persist a set of role assignments #########################################################
###############################################################################################
function Save-RoleAssignments {

    param(
        $Assignments,
        [int]$ObjectDbId,
        [int]$SiteId,
        [string]$DatabasePath
    )

    # The REST call happens before this delete (see callers), so a failed
    # fetch never wipes previously captured grants.
    if ($null -eq $Assignments.Value) {
        Write-Warning "Unexpected role-assignment response for object $ObjectDbId; keeping existing permissions."
        return
    }

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
DELETE FROM Permissions
WHERE ObjectId = @ObjectId;
"@ `
        -SqlParameters @{ ObjectId = $ObjectDbId }

    foreach ($Assignment in $Assignments.Value) {

        $Member = $Assignment.Member
        $PrincipalDbId = Get-PrincipalDbId `
            -SiteId $SiteId `
            -Member $Member `
            -DatabasePath $DatabasePath

        # Direct = user (1) or claim (15, e.g. "Everyone except external
        # users" -- the claim itself is the assignment target). Group
        # grants (4 = SharePoint group, 8 = security group) flow through
        # membership and are not direct.
        $GrantedDirectly = if ($Member.PrincipalType -in @(4, 8)) { 0 } else { 1 }

        foreach ($Role in $Assignment.RoleDefinitionBindings) {

            if ($Role.Name -eq 'Limited Access') {
                continue
            }

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
    @ObjectId,
    @PrincipalId,
    @PermissionLevel,
    @GrantedDirectly
)
ON CONFLICT(ObjectId, PrincipalId, PermissionLevel)
DO UPDATE SET
    GrantedDirectly = excluded.GrantedDirectly;
"@ `
                -SqlParameters @{
                    ObjectId        = $ObjectDbId
                    PrincipalId     = $PrincipalDbId
                    PermissionLevel = $Role.Name
                    GrantedDirectly = $GrantedDirectly
                }
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


#   Findings analysis ("oopsies") ##############################################################
###############################################################################################
function Invoke-FindingsAnalysis {

    param(
        [string]$DatabasePath,
        [int]$SiteId = 0
    )

    <#
    .SYNOPSIS
        (Re)generates SecurityFindings from the collected permission data.

    .DESCRIPTION
        Idempotent: findings in scope are deleted first, then re-derived.
        SiteId = 0 means the whole database; otherwise just that site.
        v1 rules (all evaluable from the current schema):
          FullControlGrant  (High)   any Full Control grant
          GuestDirectAccess (High)   B2B guest (LoginName contains #ext#)
                                     holding a direct grant
          DirectUserGrant   (Medium) non-guest user with a direct grant
                                     (review debt)
          BrokenInheritance (Low)    object with unique permissions
                                     (sprawl signal)
          ExcessOwners      (High)   >3 distinct Full Control principals
                                     on one object
          OrgWideExposure   (High/Medium) "Everyone except external users"
                                     (or "Everyone") holding a direct grant --
                                     org-wide links surface as this claim in
                                     role assignments. High for
                                     Full Control/Contribute/Edit, Medium
                                     otherwise.
          SharingLinkDetected (Critical/High/Medium) sharing-link backing
                                     group (SharingLinks.*) found on the site.
                                     Severity from the type hint (Anonymous /
                                     Organization / other); the hint is not
                                     authoritative -- verify scope.
        Not yet covered (need more capture): authoritative per-link details
        (GetSharingInformation / Get-PnPFileSharingLink), stale access
        (needs Entra sign-in data).
    #>

    $scope = "(@SiteId = 0 OR s.SiteId = @SiteId)"
    $params = @{ SiteId = $SiteId }

    if ($SiteId -gt 0) {
        Write-Output "Analyzing findings for site $SiteId"
    }
    else {
        Write-Output "Analyzing findings for all sites"
    }

    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
DELETE FROM SecurityFindings
WHERE @SiteId = 0 OR SiteId = @SiteId;
"@ `
        -SqlParameters $params

    # R1: Full Control grants
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO SecurityFindings (SiteId, ObjectId, PrincipalId, Severity, FindingType, PermissionLevel, Details, DetectedDate)
SELECT s.SiteId, o.ObjectId, p.Id, 'High', 'FullControlGrant', perms.PermissionLevel,
       'Principal ''' || p.Title || ''' holds Full Control on ' || o.ObjectType || ' ''' || o.ObjectTitle || ''' (' || s.Title || ')',
       datetime('now')
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE perms.PermissionLevel = 'Full Control'
  AND $scope;
"@ `
        -SqlParameters $params

    # R2: guest/external direct access
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO SecurityFindings (SiteId, ObjectId, PrincipalId, Severity, FindingType, PermissionLevel, Details, DetectedDate)
SELECT s.SiteId, o.ObjectId, p.Id, 'High', 'GuestDirectAccess', perms.PermissionLevel,
       'Guest principal ''' || p.Title || ''' holds ' || perms.PermissionLevel || ' on ' || o.ObjectType || ' ''' || o.ObjectTitle || ''' (' || s.Title || ')',
       datetime('now')
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE p.LoginName LIKE '%#ext#%'
  AND perms.GrantedDirectly = 1
  AND $scope;
"@ `
        -SqlParameters $params

    # R3: direct user grants (review debt)
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO SecurityFindings (SiteId, ObjectId, PrincipalId, Severity, FindingType, PermissionLevel, Details, DetectedDate)
SELECT s.SiteId, o.ObjectId, p.Id, 'Medium', 'DirectUserGrant', perms.PermissionLevel,
       'User ''' || p.Title || ''' holds a direct ' || perms.PermissionLevel || ' grant on ' || o.ObjectType || ' ''' || o.ObjectTitle || ''' (' || s.Title || ')',
       datetime('now')
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE p.PrincipalTypeName = 'User'
  AND p.LoginName NOT LIKE '%#ext#%'
  AND perms.GrantedDirectly = 1
  AND $scope;
"@ `
        -SqlParameters $params

    # R4: broken inheritance sprawl
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO SecurityFindings (SiteId, ObjectId, Severity, FindingType, Details, DetectedDate)
SELECT s.SiteId, o.ObjectId, 'Low', 'BrokenInheritance',
       o.ObjectType || ' ''' || o.ObjectTitle || ''' has unique permissions (inheritance broken)',
       datetime('now')
FROM Objects o
JOIN Sites s ON s.SiteId = o.SiteId
WHERE o.HasUniquePermissions = 1
  AND $scope;
"@ `
        -SqlParameters $params

    # R5: excess owners
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO SecurityFindings (SiteId, ObjectId, Severity, FindingType, Details, DetectedDate)
SELECT s.SiteId, o.ObjectId, 'High', 'ExcessOwners',
       CAST(COUNT(DISTINCT p.Id) AS TEXT) || ' distinct principals hold Full Control on ' || o.ObjectType || ' ''' || o.ObjectTitle || ''' (' || s.Title || ')',
       datetime('now')
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE perms.PermissionLevel = 'Full Control'
  AND $scope
GROUP BY s.SiteId, o.ObjectId
HAVING COUNT(DISTINCT p.Id) > 3;
"@ `
        -SqlParameters $params

    # R6: organization-wide exposure via the "Everyone except external users"
    # claim (org-wide sharing links surface as this grant in role assignments)
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO SecurityFindings (SiteId, ObjectId, PrincipalId, Severity, FindingType, PermissionLevel, Details, DetectedDate)
SELECT s.SiteId, o.ObjectId, p.Id,
       CASE WHEN perms.PermissionLevel IN ('Full Control','Contribute','Edit') THEN 'High' ELSE 'Medium' END,
       'OrgWideExposure', perms.PermissionLevel,
       'Organization-wide exposure: ''' || p.Title || ''' holds ' || perms.PermissionLevel || ' on ' || o.ObjectType || ' ''' || o.ObjectTitle || ''' (' || s.Title || ')',
       datetime('now')
FROM Permissions perms
JOIN Objects o ON o.ObjectId = perms.ObjectId
JOIN Principals p ON p.Id = perms.PrincipalId
JOIN Sites s ON s.SiteId = o.SiteId
WHERE (p.LoginName LIKE '%spo-grid-all-users%' OR p.Title IN ('Everyone except external users','Everyone'))
  AND perms.GrantedDirectly = 1
  AND $scope;
"@ `
        -SqlParameters $params

    # R7: sharing links detected via their backing groups. The type hint is
    # not authoritative -- the analyst verifies scope in SharePoint.
    Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
INSERT INTO SecurityFindings (SiteId, Severity, FindingType, Details, DetectedDate)
SELECT SiteId,
       CASE WHEN TypeHint LIKE '%Anonymous%' THEN 'Critical'
            WHEN TypeHint LIKE '%Organization%' THEN 'High'
            ELSE 'Medium' END,
       'SharingLinkDetected',
       'Sharing link backing group ''' || GroupTitle || ''' (type hint: ' || COALESCE(NULLIF(TypeHint,''), 'unknown') || ', file ' || COALESCE(NULLIF(FileGuid,''), 'unknown') || ') -- verify link scope',
       datetime('now')
FROM SharingLinks
WHERE @SiteId = 0 OR SiteId = @SiteId;
"@ `
        -SqlParameters $params

    $count = Invoke-SqliteQuery `
        -DataSource $DatabasePath `
        -Query @"
SELECT COUNT(*) AS C FROM SecurityFindings WHERE @SiteId = 0 OR SiteId = @SiteId;
"@ `
        -SqlParameters $params |
        Select-Object -ExpandProperty C

    Write-Host "Findings in scope: $count"
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

    Write-Host "Processing $($Site.SiteUrl)"

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
                -Activity "Scanning Object Permissions" `
                -Status "$Current of $Total : $($Object.ObjectTitle)" `
                -PercentComplete (($Current / $Total) * 100)

            Add-ObjectPermissions `
                -Object $Object `
                -SiteId $Site.SiteId `
                -DatabasePath $DatabasePath
        }

        Write-Progress `
            -Activity "Scanning Object Permissions" `
            -Completed

        # Findings are derived data: a failure here must not fail the site
        # whose permissions were just captured successfully.
        try {
            Invoke-FindingsAnalysis `
                -DatabasePath $DatabasePath `
                -SiteId $Site.SiteId
        }
        catch {
            Write-Warning "Findings analysis failed for $($Site.SiteUrl): $($_.Exception.Message)"
        }

        Complete-SiteScan `
            -SiteId $Site.SiteId `
            -DatabasePath $DatabasePath

        Write-Host "Completed $($Site.SiteUrl)"
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

#   Connect to Sharepoint #####################################################################
###############################################################################################
function Connect-SharePointSite {

    param(
        [string]$SiteUrl
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint) -or
        [string]::IsNullOrWhiteSpace($ClientId) -or
        [string]::IsNullOrWhiteSpace($TenantId)) {
        throw "Missing authentication parameters. Pass -Thumbprint, -ClientId and -TenantId at runtime (never commit real values to the repo)."
    }

    $attempt = 0
    while ($true) {
        try {
            Write-Host "Connecting to SharePoint: $SiteUrl"

            Connect-PnPOnline `
                -Url $SiteUrl `
                -ClientId $ClientId `
                -Tenant $TenantId `
                -Thumbprint $Thumbprint `
                -ErrorAction Stop

            Write-Host "Connected."
            return
        }
        catch {
            $attempt++
            if ($attempt -ge 3) {
                throw "Failed to connect to SharePoint site '$SiteUrl'. $($_.Exception.Message)"
            }
            $delay = [math]::Pow(2, $attempt)
            Write-Warning "Connect failed (attempt $attempt of 3). Retrying in ${delay}s: $($_.Exception.Message)"
            Start-Sleep -Seconds $delay
        }
    }
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

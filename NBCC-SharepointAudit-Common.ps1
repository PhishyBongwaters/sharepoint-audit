# NBCC-SharepointAudit-Common.ps1 — shared functions for the audit scripts.
# Dot-source only: this file defines functions and performs no actions.
# Both NBCC-SharepointAudit.ps1 (Tier 1) and NBCC-SharepointAudit-DeepScan.ps1
# (single-site deep scan) dot-source it.


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


#   Findings analysis ("oopsies") ##############################################################
###############################################################################################
function Invoke-FindingsAnalysis {

    param(
        [string]$DatabasePath,
        [int]$SiteId = 0,
        [switch]$Quiet
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
        if (-not $Quiet) { Write-Output "Analyzing findings for site $SiteId" }
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

    if (-not $Quiet) { Write-Host "Findings in scope: $count" }
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
            Write-Verbose "Connecting to SharePoint: $SiteUrl"

            Connect-PnPOnline `
                -Url $SiteUrl `
                -ClientId $ClientId `
                -Tenant $TenantId `
                -Thumbprint $Thumbprint `
                -ErrorAction Stop

            Write-Verbose "Connected."
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

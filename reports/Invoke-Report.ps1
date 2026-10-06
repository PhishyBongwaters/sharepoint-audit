#Requires -Modules PSSQLite
<#
.SYNOPSIS
    Run a prepacked report (or pasted SQL) against the audit database.

.DESCRIPTION
    Template block this wraps (paste any SELECT into -Query):

        Invoke-SqliteQuery -DataSource "SharePoint-Audit.db" -Query @"
        <PASTE SQL HERE>
        "@ | Format-Table -AutoSize

    Or run a prepacked report by number/name fragment:

        .\Invoke-Report.ps1 -Name 01-priority-sites
        .\Invoke-Report.ps1 -Name guest-access
        .\Invoke-Report.ps1 -Query "SELECT COUNT(*) AS Sites FROM Sites;"

    Reads databasepath from audit-config.yaml (same file as the main
    scripts) when -DatabasePath isn't passed explicitly.

.EXAMPLE
    .\Invoke-Report.ps1 -Name 03-item-level-highs -GridView
#>
param(
    [Parameter()]
    [string]$Name = "",

    [Parameter()]
    [string]$Query = "",

    [Parameter()]
    [string]$DatabasePath = (Join-Path (Split-Path $PSScriptRoot -Parent) "SharePoint-Audit.db"),

    [Parameter()]
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "audit-config.yaml"),

    [Parameter()]
    [switch]$GridView
)

# Same flat "key: value" config file as the main scripts. Explicit parameters win.
$__Config = @{}
if (Test-Path $ConfigPath) {
    Get-Content $ConfigPath | ForEach-Object {
        if ($_ -match '^\s*([^:#\s][^:]*?)\s*:\s*(.+?)\s*$') {
            $__Config[$matches[1].Trim().ToLower()] = $matches[2].Trim().Trim('"').Trim("'")
        }
    }
}
foreach ($__key in @('databasepath', 'database_path')) {
    if ($__Config.ContainsKey($__key) -and -not $PSBoundParameters.ContainsKey('DatabasePath')) {
        $DatabasePath = $__Config[$__key]
        break
    }
}
Remove-Variable -Name __Config, __key -ErrorAction SilentlyContinue

if ([string]::IsNullOrWhiteSpace($Name) -and [string]::IsNullOrWhiteSpace($Query)) {
    Write-Host "Usage:"
    Write-Host "  .\Invoke-Report.ps1 -Name <report>   # prepacked report from reports/"
    Write-Host "  .\Invoke-Report.ps1 -Query <sql>      # pasted SQL"
    Write-Host ""
    Write-Host "Available reports:"
    Get-ChildItem (Join-Path $PSScriptRoot "*.sql") | ForEach-Object {
        Write-Host ("  " + $_.BaseName)
    }
    return
}

if (-not (Test-Path $DatabasePath)) {
    throw "Database file not found: $DatabasePath. Run NBCC-SharepointAudit.ps1 -Refresh/-ScanAll first."
}

if ([string]::IsNullOrWhiteSpace($Query)) {
    $hits = @(Get-ChildItem (Join-Path $PSScriptRoot "*.sql") |
        Where-Object { $_.BaseName -like "*$Name*" })
    if ($hits.Count -eq 0) {
        throw "No report matches '$Name'."
    }
    if ($hits.Count -gt 1) {
        Write-Host "Multiple reports match '$Name':"
        $hits | ForEach-Object { Write-Host ("  " + $_.BaseName) }
        throw "Be more specific."
    }
    $reportFile = $hits[0]
    Write-Host "Running $($reportFile.BaseName) ..."
    Write-Host ""
    $Query = Get-Content $reportFile.FullName -Raw
}

$result = Invoke-SqliteQuery -DataSource $DatabasePath -Query $Query

if ($GridView) {
    $result | Out-GridView -Title "SharePoint Audit Report"
}
else {
    $result | Format-Table -AutoSize
}

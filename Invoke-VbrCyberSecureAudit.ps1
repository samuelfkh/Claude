#Requires -Version 5.1
<#
.SYNOPSIS
    Automated Cyber Secure compliance audit for Veeam Backup & Replication (VBR) v13
    running on Windows Server, mapped item-by-item to the VDP v13 Cyber Secure Checklist.

.DESCRIPTION
    Every numbered checklist item (1.1 - 10.17) is represented in the output, tagged with
    its checklist number and exact name. Items that can be verified programmatically from
    the Windows VBR host are checked automatically via:

        * Windows registry / WMI / CIM
        * Local security policy (secedit) and audit policy (auditpol)
        * The Veeam v13 PowerShell SDK (Veeam.Backup.PowerShell)

    Items that are inherently manual (physical security, staff training, network topology,
    the Linux VSA appliance section, off-host process, etc.) are reported with a "Manual"
    status and actionable guidance so the report remains a complete, traceable mirror of
    the checklist rather than a partial one.

    Checklist sections:
        1  Components
        2  Components - Windows Build
        3  Components - VSA Build            (Linux appliance - verify on the VSA)
        4  Repositories
        5  Accounts and Permissions
        6  Encryption
        7  Operational
        8  NAS-specific
        9  Disaster Recovery & Testing
        10 Detection

.PARAMETER Credential
    Optional [PSCredential] used with Connect-VBRServer (remote / explicit auth). If
    omitted, the script connects under the current user context and only prompts via
    Get-Credential if that non-interactive attempt fails.

.PARAMETER VBRServer
    Host name / IP of the VBR server. Defaults to 'localhost'.

.PARAMETER ReportPath
    Directory for the HTML / CSV report(s). Defaults to the current directory.

.PARAMETER ReportFormat
    HTML, CSV, or Both (default).

.PARAMETER IncludeManual
    Include inherently-manual checklist items in the report (default $true). Set to $false
    to emit only script-verifiable items.

.PARAMETER LatestKnownVbrBuild
    Latest known VBR v13 build for the version comparison (see KB2680).

.EXAMPLE
    .\Invoke-VbrCyberSecureAudit.ps1

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-VbrCyberSecureAudit.ps1 -VBRServer 'vbr01.corp.local' -Credential $cred -ReportFormat HTML

.NOTES
    Author : Windows Security Engineer / Veeam Certified Architect
    Target : Veeam Backup & Replication v13 on Windows Server (LTSC)
    Module : Veeam.Backup.PowerShell
#>

[CmdletBinding()]
param(
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential,

    [string]$VBRServer = 'localhost',

    [string]$ReportPath = (Get-Location).Path,

    [ValidateSet('HTML', 'CSV', 'Both')]
    [string]$ReportFormat = 'Both',

    [bool]$IncludeManual = $true,

    [string]$LatestKnownVbrBuild = '13.0.0.4967'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ----------------------------------------------------------------------- Infrastructure

$script:Results     = [System.Collections.Generic.List[object]]::new()
$script:VbrConnected = $false

# --- Caches (SDK / OS queries reused by several checklist items) ----------------------
$script:_repos = $null                     # Get-VBRBackupRepository (+ object storage)
$script:_jobs  = $null                     # Get-VBRJob
$script:_mw = $null; $script:_mwLoaded = $false          # malware detection options
$script:_admins = $null; $script:_adminsLoaded = $false  # local Administrators members
$script:_secpol = $null                    # secedit [System Access] export

<#
    Add-AuditResult - the single PSCustomObject factory + color-coded console writer.
    Shape (per requirement, now carrying the checklist number + exact name):
        Item # | Topic | Rule Name | Status | Current Value | Recommendation
#>
function Add-AuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ItemNumber,
        [Parameter(Mandatory)][string]$Topic,
        [Parameter(Mandatory)][string]$RuleName,
        [Parameter(Mandatory)][ValidateSet('Passed', 'Failed', 'Warning', 'Error', 'Manual', 'Info')][string]$Status,
        [Parameter()][string]$CurrentValue = 'N/A',
        [Parameter()][string]$Recommendation = ''
    )
    $result = [PSCustomObject]@{
        'Item #'         = $ItemNumber
        Topic            = $Topic
        'Rule Name'      = $RuleName
        Status           = $Status
        'Current Value'  = $CurrentValue
        Recommendation   = $Recommendation
    }
    $script:Results.Add($result)

    $color = switch ($Status) {
        'Passed'  { 'Green' }
        'Failed'  { 'Red' }
        'Warning' { 'Yellow' }
        'Error'   { 'Magenta' }
        'Manual'  { 'DarkCyan' }
        default   { 'Cyan' }
    }
    Write-Host ('  {0,-6} [{1,-7}] ' -f $ItemNumber, $Status) -ForegroundColor $color -NoNewline
    Write-Host $RuleName -ForegroundColor Gray
    if ($CurrentValue -and $CurrentValue -ne 'N/A') {
        Write-Host ('              -> {0}' -f $CurrentValue) -ForegroundColor DarkGray
    }
}

<#
    Invoke-Item - runs a single checklist item.
      * No -Check scriptblock          -> emitted as "Manual".
      * -Check present                 -> executed in a try/catch; must return a
                                          [hashtable] @{ Status=..; Value=..; [Recommendation=..] }.
    Wrapping each item individually means one failing check degrades to "Error" for that
    row only - the rest of the audit still completes.
#>
function Invoke-Item {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Num,
        [Parameter(Mandatory)][string]$Topic,
        [Parameter(Mandatory)][string]$Name,
        [string]$Recommendation = 'Verify manually against the VDP v13 Cyber Secure Checklist.',
        [scriptblock]$Check
    )
    if (-not $Check) {
        if ($IncludeManual) {
            Add-AuditResult -ItemNumber $Num -Topic $Topic -RuleName $Name -Status 'Manual' `
                -CurrentValue 'Not script-verifiable' -Recommendation $Recommendation
        }
        return
    }
    try {
        $r = & $Check
        if ($r -is [System.Array]) { $r = $r[-1] }              # tolerate stray pipeline output
        if ($r -isnot [hashtable]) { throw 'Check did not return a hashtable.' }
        $val = if ($r.ContainsKey('Value') -and $r.Value) { [string]$r.Value } else { 'N/A' }
        $rec = if ($r.ContainsKey('Recommendation') -and $r.Recommendation) { $r.Recommendation } else { $Recommendation }
        Add-AuditResult -ItemNumber $Num -Topic $Topic -RuleName $Name -Status $r.Status -CurrentValue $val -Recommendation $rec
    }
    catch {
        Add-AuditResult -ItemNumber $Num -Topic $Topic -RuleName $Name -Status 'Error' `
            -CurrentValue $_.Exception.Message -Recommendation $Recommendation
    }
}

# --- Low-level helpers ----------------------------------------------------------------

function Get-RegistryValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    } catch { return $null }
}

# Returns the first present property value from a list of candidate names ($null if none).
function Get-PropSafe {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string[]]$Name)
    if ($null -eq $InputObject) { return $null }
    $props = ($InputObject | Get-Member -MemberType Properties -ErrorAction SilentlyContinue).Name
    foreach ($c in $Name) { if ($props -contains $c) { try { return $InputObject.$c } catch { } } }
    return $null
}

# Resolves the first available cmdlet from a candidate list (tolerates SDK renames).
function Test-VeeamCmdlet {
    param([Parameter(Mandatory)][string[]]$Name)
    foreach ($c in $Name) { $cmd = Get-Command -Name $c -ErrorAction SilentlyContinue; if ($cmd) { return $cmd.Name } }
    return $null
}

# Formats a possibly-null value for display.
function nv { param($v) if ($null -eq $v) { 'not set' } else { "$v" } }

# Evaluates whether a Windows service is disabled; returns an Invoke-Item hashtable.
# Defined at script scope so it resolves reliably from within passed-in check scriptblocks.
function Test-SvcDisabled {
    param([Parameter(Mandatory)][string]$Name, [string]$Severity = 'Failed')
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return @{ Status = 'Passed'; Value = "Service '$Name' not present" } }
    $mode = (Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop).StartMode
    @{ Status = $(if ($mode -eq 'Disabled') { 'Passed' } else { $Severity }); Value = ("StartMode={0}; Status={1}" -f $mode, $svc.Status) }
}

# --- Cached collections ---------------------------------------------------------------

function Get-Repos {
    if (-not $script:VbrConnected) { return @() }
    if ($null -ne $script:_repos) { return $script:_repos }
    $list = @()
    try { $list = @(Get-VBRBackupRepository -ErrorAction Stop) } catch { }
    $oc = Test-VeeamCmdlet -Name 'Get-VBRObjectStorageRepository'
    if ($oc) { try { $list += @(& $oc -ErrorAction SilentlyContinue) } catch { } }
    $script:_repos = $list
    return $script:_repos
}

function Get-Jobs {
    if (-not $script:VbrConnected) { return @() }
    if ($null -ne $script:_jobs) { return $script:_jobs }
    try { $script:_jobs = @(Get-VBRJob -ErrorAction Stop) } catch { $script:_jobs = @() }
    return $script:_jobs
}

function Get-MalwareOpts {
    if ($script:_mwLoaded) { return $script:_mw }
    $script:_mwLoaded = $true
    if (-not $script:VbrConnected) { return $null }
    $c = Test-VeeamCmdlet -Name @('Get-VBRMalwareDetectionOptions', 'Get-VBRMalwareDetection')
    if ($c) { try { $script:_mw = & $c -ErrorAction Stop } catch { } }
    return $script:_mw
}

function Get-Admins {
    if ($script:_adminsLoaded) { return $script:_admins }
    $script:_adminsLoaded = $true
    try { $script:_admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop) } catch { $script:_admins = $null }
    return $script:_admins
}

# Parses the [System Access] section of a secedit export (locale-independent password /
# lockout policy). Cached for the lifetime of the run.
function Get-SecPol {
    if ($null -ne $script:_secpol) { return $script:_secpol }
    $script:_secpol = @{}
    try {
        $tmp = Join-Path $env:TEMP ("vbrsec_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
        & secedit.exe /export /cfg $tmp /quiet 2>$null | Out-Null
        if (Test-Path -LiteralPath $tmp) {
            foreach ($line in (Get-Content -LiteralPath $tmp -Encoding Unicode -ErrorAction Stop)) {
                if ($line -match '^\s*([A-Za-z]\w+)\s*=\s*(.+?)\s*$') {
                    $script:_secpol[$matches[1]] = $matches[2]
                }
            }
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    } catch { }
    return $script:_secpol
}

#endregion

#region ----------------------------------------------------------------------- Pre-flight

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '  Veeam VBR v13 - VDP Cyber Secure Compliance Audit' -ForegroundColor Cyan
Write-Host ('  Host: {0}   Date: {1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan

# Administrative privilege check.
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'This script must be run ELEVATED (Run as Administrator). Aborting.'
    throw 'Administrative privileges required.'
}
Write-Host "`n[+] Administrative context confirmed." -ForegroundColor Green

# Import the Veeam PowerShell module (module first, then legacy snap-in).
$script:VeeamModuleLoaded = $false
try {
    if (Get-Module -Name 'Veeam.Backup.PowerShell') { $script:VeeamModuleLoaded = $true }
    elseif (Get-Module -ListAvailable -Name 'Veeam.Backup.PowerShell') {
        Import-Module 'Veeam.Backup.PowerShell' -DisableNameChecking -ErrorAction Stop
        $script:VeeamModuleLoaded = $true
    }
    elseif (Get-PSSnapin -Registered -Name 'VeeamPSSnapIn' -ErrorAction SilentlyContinue) {
        Add-PSSnapin -Name 'VeeamPSSnapIn' -ErrorAction Stop
        $script:VeeamModuleLoaded = $true
    }
    if ($script:VeeamModuleLoaded) { Write-Host '[+] Veeam PowerShell module loaded.' -ForegroundColor Green }
    else { Write-Warning 'Veeam.Backup.PowerShell not found - VBR-specific items degrade to Warning.' }
}
catch { Write-Warning ('Failed to import the Veeam PowerShell module: {0}' -f $_.Exception.Message) }

#endregion

#region ----------------------------------------------------------------------- VBR session

function Connect-VbrSession {
    if (-not $script:VeeamModuleLoaded) { return }
    if (-not (Test-VeeamCmdlet -Name 'Connect-VBRServer')) {
        Write-Warning 'Connect-VBRServer unavailable; cannot open a VBR session.'; return
    }

    # Reuse an existing session if the console/service already has one open.
    $sessCmd = Test-VeeamCmdlet -Name 'Get-VBRServerSession'
    if ($sessCmd) {
        try {
            if (& $sessCmd -ErrorAction SilentlyContinue) {
                Write-Host '[+] Reusing existing VBR server session.' -ForegroundColor Green
                $script:VbrConnected = $true; return
            }
        } catch { }
    }

    try {
        if ($Credential) {
            Write-Host ('[*] Connecting to VBR ({0}) with supplied credentials...' -f $VBRServer) -ForegroundColor Cyan
            Connect-VBRServer -Server $VBRServer -Credential $Credential -ErrorAction Stop
        }
        else {
            Write-Host ('[*] Connecting to VBR ({0}) under current user context...' -f $VBRServer) -ForegroundColor Cyan
            Connect-VBRServer -Server $VBRServer -ErrorAction Stop
        }
        $script:VbrConnected = $true
    }
    catch {
        Write-Warning ('Initial VBR connection failed: {0}' -f $_.Exception.Message)
        if (-not $Credential) {
            try {
                Write-Host '[*] Prompting for credentials to retry...' -ForegroundColor Yellow
                $promptCred = Get-Credential -Message ("Credentials for VBR server '{0}'" -f $VBRServer)
                if ($promptCred) { Connect-VBRServer -Server $VBRServer -Credential $promptCred -ErrorAction Stop; $script:VbrConnected = $true }
            } catch { Write-Warning ('VBR connection retry failed: {0}' -f $_.Exception.Message) }
        }
    }

    if ($script:VbrConnected) {
        try { $null = Get-VBRServer -ErrorAction Stop; Write-Host '[+] VBR session established and self-test passed.' -ForegroundColor Green }
        catch { Write-Warning ('VBR session self-test failed: {0}' -f $_.Exception.Message); $script:VbrConnected = $false }
    }
}
Connect-VbrSession

#endregion

#region ----------------------------------------------------------------------- 1. Components

function Invoke-ComponentChecks {
    Write-Host "`n--- 1. Components ---" -ForegroundColor White
    $T = 'Components'

    # 1.1 NTLM deprecation (LmCompatibilityLevel 5 / RestrictSendingNTLMTraffic 2).
    Invoke-Item -Num '1.1' -Topic $T -Name 'Has NTLM authentication been completely deprecated in favor of Kerberos?' `
        -Recommendation 'Set LmCompatibilityLevel=5 and RestrictSendingNTLMTraffic=2 (Deny all) so only Kerberos/NTLMv2 is honoured.' -Check {
            $lm = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
            $rs = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'RestrictSendingNTLMTraffic'
            $st = if ($rs -eq 2 -or $lm -ge 5) { 'Passed' } elseif ($lm -ge 3) { 'Warning' } else { 'Failed' }
            @{ Status = $st; Value = ("LmCompatibilityLevel={0}; RestrictSendingNTLMTraffic={1}" -f (nv $lm), (nv $rs)) }
        }

    # 1.2 OS patched / Veeam Updater configured.
    Invoke-Item -Num '1.2' -Topic $T -Name 'Are operating systems hosting Veeam components patched and up-to-date, or configured to auto-update using Veeam updater?' `
        -Recommendation 'Patch the OS within one cycle (<=35 days) and configure the Veeam Updater service/task.' -Check {
            $hf = Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
            $days = if ($hf) { (New-TimeSpan -Start $hf.InstalledOn -End (Get-Date)).Days } else { $null }
            $svc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Updater' -and $_.DisplayName -match 'Veeam' })
            $task = @()
            if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
                $task = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'Veeam' -and $_.TaskName -match 'Update' })
            }
            $updater = ($svc.Count -gt 0 -or $task.Count -gt 0)
            $st = if ($days -ne $null -and $days -le 35 -and $updater) { 'Passed' } elseif ($days -ne $null -and $days -le 35) { 'Warning' } else { 'Failed' }
            $v = "Last hotfix: {0}; Veeam Updater: {1}" -f `
                $(if ($hf) { "$($hf.HotFixID) ($days d ago)" } else { 'none dated' }), `
                $(if ($updater) { 'present' } else { 'absent' })
            @{ Status = $st; Value = $v }
        }

    # 1.3 LTS / LTSC OS build.
    Invoke-Item -Num '1.3' -Topic $T -Name 'Are operating systems hosting Veeam components built using LTS / LTSC OS versions (long-term support or service channel) or using Veeam JeOS?' `
        -Recommendation 'Run an LTSC Windows Server build (2016/2019/2022/2025) or Veeam JeOS for backup infrastructure.' -Check {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $b = [int]$os.BuildNumber
            $ltsc = @{ 14393 = 'Server 2016'; 17763 = 'Server 2019'; 20348 = 'Server 2022'; 26100 = 'Server 2025' }
            if ($ltsc.ContainsKey($b)) { @{ Status = 'Passed'; Value = ("{0} LTSC (build {1})" -f $ltsc[$b], $b) } }
            else { @{ Status = 'Warning'; Value = ("{0} (build {1}) - not a recognised LTSC build" -f $os.Caption, $b) } }
        }

    # 1.4 Veeam components patched (VBR build vs KB2680).
    Invoke-Item -Num '1.4' -Topic $T -Name 'Are Veeam components patched and up to date, or configured with auto-update using Veeam updater?' `
        -Recommendation 'Compare the installed build to KB2680 and apply the latest v13 cumulative patch.' -Check {
            $build = Get-RegistryValue 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication' 'CurrentVersion'
            $src = 'registry'
            if (-not $build) {
                $core = Get-RegistryValue 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication' 'CorePath'
                if ($core) { $dll = Join-Path $core 'Veeam.Backup.Core.dll'; if (Test-Path -LiteralPath $dll) { $build = (Get-Item -LiteralPath $dll).VersionInfo.ProductVersion; $src = 'Core.dll' } }
            }
            if (-not $build) { return @{ Status = 'Warning'; Value = 'VBR build could not be determined' } }
            $cur = $false
            try { $cur = [version](($build -split '\s')[0]) -ge [version]$LatestKnownVbrBuild } catch { }
            @{ Status = $(if ($cur) { 'Passed' } else { 'Warning' }); Value = ("Installed {0} (via {1}); latest known {2}" -f $build, $src, $LatestKnownVbrBuild) }
        }

    # 1.5 Sole tenant (no co-hosted server roles).
    Invoke-Item -Num '1.5' -Topic $T -Name 'Are Veeam components (including SQL if applicable) sole tenants on the relevant server (i.e. no additional services co-hosted on that instance)' `
        -Recommendation 'Dedicate the server to Veeam; remove co-hosted roles (IIS, DNS, DHCP, Exchange, Hyper-V, etc.).' -Check {
            $roles = @{ 'W3SVC' = 'IIS'; 'DNS' = 'DNS'; 'DHCPServer' = 'DHCP'; 'MSExchangeIS' = 'Exchange'; 'vmms' = 'Hyper-V'; 'MSSQLSERVER' = 'SQL(default)' }
            $found = @()
            foreach ($k in $roles.Keys) { if (Get-Service -Name $k -ErrorAction SilentlyContinue) { $found += $roles[$k] } }
            if ($found.Count -eq 0) { @{ Status = 'Passed'; Value = 'No common co-hosted server roles detected' } }
            else { @{ Status = 'Warning'; Value = ("Co-hosted roles detected: {0}" -f ($found -join ', ')) } }
        }

    # 1.6 Backup server separated from production authentication domain.
    Invoke-Item -Num '1.6' -Topic $T -Name 'Is the backup server separated from the production authentication domain (applicable only to Windows OS hosting VBR)?' `
        -Recommendation 'Host VBR in a workgroup or a dedicated management/backup domain, not the production AD domain.' -Check {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            if ($cs.PartOfDomain) { @{ Status = 'Warning'; Value = ("Domain-joined: {0} - confirm this is NOT the production domain" -f $cs.Domain) } }
            else { @{ Status = 'Passed'; Value = ("Workgroup: {0} (not domain-joined)" -f $cs.Workgroup) } }
        }

    # 1.7 VBR console within a DMZ - topology, manual.
    Invoke-Item -Num '1.7' -Topic $T -Name 'Is the VBR console within a DMZ?' `
        -Recommendation 'Network topology decision - verify console placement against hardening-zone guidance.'

    # 1.8 Inbound/Outbound access restricted (firewall enabled as a proxy signal).
    Invoke-Item -Num '1.8' -Topic $T -Name 'Is Inbound and Outbound access (e.g. from the internet) to the VBR server restricted to critical services i.e. Veeam Update Notification Server (dev.veeam.com), Veeam License Update Servers (vbr.butler.veeam.com, autolk.veeam.com)?' `
        -Recommendation 'Restrict inbound/outbound to required Veeam endpoints at the corporate/local firewall.' -Check {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { return @{ Status = 'Warning'; Value = 'Firewall cmdlets unavailable' } }
            $p = Get-NetFirewallProfile -ErrorAction Stop
            $off = @($p | Where-Object { -not $_.Enabled })
            if ($off.Count -eq 0) { @{ Status = 'Warning'; Value = 'Windows Firewall enabled on all profiles (confirm egress rules restrict to Veeam endpoints)' } }
            else { @{ Status = 'Failed'; Value = ("Firewall disabled on profile(s): {0}" -f (($off.Name) -join ', ')) } }
        }

    # 1.9 Configuration database encrypted (config backup encryption).
    Invoke-Item -Num '1.9' -Topic $T -Name 'Is the Veeam Configuration database encrypted?' `
        -Recommendation 'Enable encryption on the configuration backup job (config_backup_encrypted).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name 'Get-VBRConfigurationBackupJob'
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Get-VBRConfigurationBackupJob unavailable' } }
            $cfg = & $c -ErrorAction Stop
            $enc = Get-PropSafe -InputObject (Get-PropSafe -InputObject $cfg -Name @('EncryptionOptions')) -Name @('Enabled', 'IsEnabled')
            if ($null -eq $enc) { $enc = Get-PropSafe -InputObject $cfg -Name @('EncryptionEnabled') }
            @{ Status = $(if ($enc -eq $true) { 'Passed' } elseif ($null -eq $enc) { 'Warning' } else { 'Failed' }); Value = ("Config backup encryption={0}" -f (nv $enc)) }
        }

    # 1.10 Physically secured - manual.
    Invoke-Item -Num '1.10' -Topic $T -Name 'Are Veeam servers physically secured?' `
        -Recommendation 'Physical/data-centre control - verify with Facilities Security.'

    # 1.11 Hardware protection (UEFI Secure Boot / TPM).
    Invoke-Item -Num '1.11' -Topic $T -Name 'Are the Veeam servers hardware-protected e.g. UEFI, TPM?' `
        -Recommendation 'Enable TPM and UEFI Secure Boot on the backup server hardware.' -Check {
            $tpm = $null
            if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) { try { $tpm = (Get-Tpm).TpmPresent } catch { } }
            $sb = 'unknown'
            try { $sb = [string](Confirm-SecureBootUEFI) } catch { $sb = 'legacy BIOS / not supported' }
            $st = if ($tpm -eq $true -and $sb -eq 'True') { 'Passed' } else { 'Warning' }
            @{ Status = $st; Value = ("TPM present={0}; SecureBoot={1}" -f (nv $tpm), $sb) }
        }

    # 1.12 Only required ports open - firewall/policy, manual.
    Invoke-Item -Num '1.12' -Topic $T -Name 'Are only the required ports open and accessible via Firewall?' `
        -Recommendation 'Review firewall rules against the Veeam used-ports reference; open only required ports.'

    # 1.13 Restrict console/management connectivity - manual.
    Invoke-Item -Num '1.13' -Topic $T -Name 'Does the VBR server restrict console/management connectivity to just trusted systems?' `
        -Recommendation 'Restrict management access (firewall / jump host / Kerberos) to trusted admin systems only.'

    # 1.14 Enterprise Manager in DMZ - manual.
    Invoke-Item -Num '1.14' -Topic $T -Name 'Is Veeam Enterprise Manager deployed in the DMZ?' `
        -Recommendation 'Topology decision - verify EM placement against hardening-zone guidance.'

    # 1.15 OS-level MFA - manual.
    Invoke-Item -Num '1.15' -Topic $T -Name 'Are servers hosting the VBR components protected by MFA (OS-level)?' `
        -Recommendation 'Consult the OS vendor for OS-level MFA best practices.'

    # 1.16 VBR console MFA (SDK probe).
    Invoke-Item -Num '1.16' -Topic $T -Name 'Is the VBR console protected by MFA?' `
        -Recommendation 'Enforce MFA for VBR console logon (mfa.html).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRMFAConfiguration', 'Get-VBRSecurityMFAPolicy', 'Get-VBRMultiFactorAuthentication')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'MFA cmdlet unavailable - verify in console' } }
            $mfa = & $c -ErrorAction Stop
            $en = Get-PropSafe -InputObject $mfa -Name @('IsEnabled', 'Enabled', 'MfaEnabled')
            @{ Status = $(if ($en -eq $true) { 'Passed' } elseif ($null -eq $en) { 'Warning' } else { 'Failed' }); Value = ("Console MFA enabled={0}" -f (nv $en)) }
        }

    # 1.17 Console auto-logoff <=10 min - mostly console-side, manual.
    Invoke-Item -Num '1.17' -Topic $T -Name 'Is the VBR console configured to auto-logoff after a set period of 10 minutes or less?' `
        -Recommendation 'Enable auto-logoff (<=10 min) in VBR console security settings.'

    # 1.18 Outdated protocols disabled (SSL 2.0 + SMB 1.0).
    Invoke-Item -Num '1.18' -Topic $T -Name 'Are outdated protocols, components or services disabled / removed on all Veeam components in accordance with NIST guidelines (e.g. SSL 2.0, SMB 1.0)' `
        -Recommendation 'Disable SSL 2.0/3.0 in SCHANNEL and remove SMBv1; enforce TLS 1.2+ (NIST SP 800-52r2).' -Check {
            $smb1 = $null
            if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol }
            $ssl2 = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' 'Enabled'
            $smbOk = ($smb1 -eq $false)
            $sslOk = ($ssl2 -eq 0 -or $null -eq $ssl2)
            $st = if ($smbOk -and $sslOk) { 'Passed' } elseif ($smb1 -eq $true) { 'Failed' } else { 'Warning' }
            @{ Status = $st; Value = ("SMB1={0}; SSL2.0\Server\Enabled={1}" -f (nv $smb1), (nv $ssl2)) }
        }

    # 1.19 OS session timeout / re-authentication (machine inactivity limit).
    Invoke-Item -Num '1.19' -Topic $T -Name 'Are OS session timeouts and re-authentication configured for Veeam?' `
        -Recommendation 'Set an interactive-logon machine inactivity limit (e.g. <=600s) requiring re-authentication.' -Check {
            $t = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
            $st = if ($t -gt 0 -and $t -le 900) { 'Passed' } elseif ($t -gt 0) { 'Warning' } else { 'Failed' }
            @{ Status = $st; Value = ("InactivityTimeoutSecs={0}" -f (nv $t)) }
        }

    # 1.20 Anonymized naming (heuristic on hostname).
    Invoke-Item -Num '1.20' -Topic $T -Name "Are Veeam components 'anonymized' within the infrastructure? E.g. using a non-obvious naming convention" `
        -Recommendation "Avoid obvious names like 'BackupSrv1', 'Veeam', 'Repo1'." -Check {
            $n = $env:COMPUTERNAME
            if ($n -match '(?i)veeam|backup|repo|vbr|veeam') { @{ Status = 'Warning'; Value = ("Hostname '{0}' reveals its role" -f $n) } }
            else { @{ Status = 'Passed'; Value = ("Hostname '{0}' is non-obvious" -f $n) } }
        }

    # 1.21 Syslog / SIEM integration (SDK probe).
    Invoke-Item -Num '1.21' -Topic $T -Name 'Is Veeam configured to send log data to a syslog server for SIEM integration?' `
        -Recommendation 'Configure a syslog server for SIEM integration.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRSyslogServer', 'Get-VBRSyslogServerInfo')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Syslog cmdlet unavailable - verify in console' } }
            $s = @(& $c -ErrorAction Stop)
            @{ Status = $(if ($s.Count -gt 0) { 'Passed' } else { 'Failed' }); Value = ("{0} syslog server(s) configured" -f $s.Count) }
        }

    # 1.22 PKI-based authentication - manual.
    Invoke-Item -Num '1.22' -Topic $T -Name 'Is PKI-based authentication configured for service accounts and components?' `
        -Recommendation 'Verify PKI-based authentication configuration.'

    # 1.23 Backup integrity validation after each job (health check).
    Invoke-Item -Num '1.23' -Topic $T -Name 'Is backup integrity validation performed automatically after each backup job?' `
        -Recommendation 'Enable automatic health check / integrity validation on backup jobs.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $jobs = @(Get-Jobs)
            if ($jobs.Count -eq 0) { return @{ Status = 'Warning'; Value = 'No jobs found' } }
            $withHc = 0
            foreach ($j in $jobs) {
                try {
                    $o = Get-VBRJobOptions -Job $j -ErrorAction Stop
                    $gp = Get-PropSafe -InputObject $o -Name @('GenerationPolicy')
                    $hc = Get-PropSafe -InputObject $gp -Name @('EnableRechek', 'EnableRecheck', 'RecheckBackupEnabled')
                    if ($hc -eq $true) { $withHc++ }
                } catch { }
            }
            @{ Status = $(if ($withHc -eq $jobs.Count) { 'Passed' } elseif ($withHc -gt 0) { 'Warning' } else { 'Failed' }); Value = ("{0}/{1} jobs have health-check enabled" -f $withHc, $jobs.Count) }
        }

    # 1.24 CDP configured for critical replicas (SDK probe).
    Invoke-Item -Num '1.24' -Topic $T -Name 'Is Universal Continuous Data Protection (CDP) configured for critical VM replicas?' `
        -Recommendation 'Configure CDP policies for critical VM replicas where RPO requires it.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRCDPPolicy', 'Get-VBRCDPReplica')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'CDP cmdlet unavailable' } }
            $p = @(& $c -ErrorAction Stop)
            @{ Status = $(if ($p.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("{0} CDP policy/policies configured" -f $p.Count) }
        }
}

#endregion

#region ----------------------------------------------------------------------- 2. Windows Build

function Invoke-WindowsBuildChecks {
    Write-Host "`n--- 2. Components - Windows Build ---" -ForegroundColor White
    $T = 'Components - Windows Build'

    # 2.1 Malignant process/service detection - AV presence heuristic.
    Invoke-Item -Num '2.1' -Topic $T -Name 'Is there a process in place for malignant process/service detection?' `
        -Recommendation 'Deploy anti-malware / process monitoring (e.g. Defender + Sysinternals Procmon).' -Check {
            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                @{ Status = $(if ($mp.RealTimeProtectionEnabled) { 'Passed' } else { 'Warning' }); Value = ("Defender real-time protection={0}" -f $mp.RealTimeProtectionEnabled) }
            } else { @{ Status = 'Warning'; Value = 'Defender status cmdlet unavailable - verify third-party AV' } }
        }

    # 2.2 Guest interaction proxy instead of VBR server - SDK, manual-ish.
    Invoke-Item -Num '2.2' -Topic $T -Name 'Are you using guest interaction proxy instead of VBR server for application awareness ?' `
        -Recommendation 'Use dedicated guest interaction proxies rather than the VBR server for guest processing.'

    # 2.3 Config DB backup stored separately (SDK target vs local).
    Invoke-Item -Num '2.3' -Topic $T -Name 'Is the Veeam configuration database backup stored separately from the VBR server (non-appliance)?' `
        -Recommendation 'Target the configuration backup at a repository that is not local to the VBR server.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name 'Get-VBRConfigurationBackupJob'
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Config backup cmdlet unavailable' } }
            $cfg = & $c -ErrorAction Stop
            $target = Get-PropSafe -InputObject $cfg -Name @('Target', 'RepositoryName', 'Repository')
            @{ Status = 'Warning'; Value = ("Config backup target: {0} - confirm it is off the VBR host" -f (nv $target)) }
        }

    # 2.4 - 2.11 registry / service hardening.
    Invoke-Item -Num '2.4' -Topic $T -Name 'Remote Registry service (RemoteRegistry) should be disabled' `
        -Recommendation 'Disable the Remote Registry service.' -Check { Test-SvcDisabled -Name 'RemoteRegistry' -Severity 'Failed' }

    Invoke-Item -Num '2.5' -Topic $T -Name 'Windows Remote Management (WinRM) service should be disabled' `
        -Recommendation 'Disable WinRM unless explicitly required.' -Check { Test-SvcDisabled -Name 'WinRM' -Severity 'Warning' }

    Invoke-Item -Num '2.6' -Topic $T -Name 'WDigest credentials caching should be disabled' `
        -Recommendation 'Set WDigest\UseLogonCredential=0 to prevent plaintext credential caching.' -Check {
            $w = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
            @{ Status = $(if ($w -eq 0 -or $null -eq $w) { 'Passed' } else { 'Warning' }); Value = ("UseLogonCredential={0}" -f $(if ($null -eq $w) { 'not set (secure default)' } else { $w })) }
        }

    Invoke-Item -Num '2.7' -Topic $T -Name 'Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled' `
        -Recommendation 'Disable the WPAD service to prevent proxy hijacking.' -Check { Test-SvcDisabled -Name 'WinHttpAutoProxySvc' -Severity 'Warning' }

    Invoke-Item -Num '2.8' -Topic $T -Name 'Is anti-malware / anti-virus software in place with the necessary exclusions for Veeam functions?' `
        -Recommendation 'Install AV with Veeam exclusions per KB1999.' -Check {
            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                @{ Status = $(if ($mp.AntivirusEnabled) { 'Passed' } else { 'Warning' }); Value = ("AV enabled={0}; AM service running={1} (confirm KB1999 exclusions)" -f $mp.AntivirusEnabled, $mp.AMServiceEnabled) }
            } else { @{ Status = 'Warning'; Value = 'Defender status unavailable - verify third-party AV + exclusions' } }
        }

    Invoke-Item -Num '2.9' -Topic $T -Name 'Is RDP disabled on the Veeam Backup and Replication server?' `
        -Recommendation 'Set fDenyTSConnections=1 to disable RDP; use console/jump-host access.' -Check {
            $d = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
            @{ Status = $(if ($d -eq 1) { 'Passed' } else { 'Failed' }); Value = ("fDenyTSConnections={0}" -f $(if ($null -eq $d) { 'not set (RDP allowed)' } else { $d })) }
        }

    Invoke-Item -Num '2.10' -Topic $T -Name 'Windows Script Host should be disabled' `
        -Recommendation 'Set Windows Script Host\Settings\Enabled=0.' -Check {
            $s = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'
            @{ Status = $(if ($s -eq 0) { 'Passed' } else { 'Warning' }); Value = ("WSH Enabled={0}" -f $(if ($null -eq $s) { 'not set (enabled)' } else { $s })) }
        }

    Invoke-Item -Num '2.11' -Topic $T -Name 'Link-Local Multicast Name Resolution (LLMNR) should be disabled' `
        -Recommendation 'Set DNSClient\EnableMulticast=0 (GPO) to disable LLMNR.' -Check {
            $l = Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
            @{ Status = $(if ($l -eq 0) { 'Passed' } else { 'Warning' }); Value = ("EnableMulticast={0}" -f $(if ($null -eq $l) { 'not set (LLMNR enabled)' } else { $l })) }
        }
}

#endregion

#region ----------------------------------------------------------------------- 3. VSA Build (Linux appliance)

function Invoke-VsaBuildChecks {
    Write-Host "`n--- 3. Components - VSA Build (Linux appliance) ---" -ForegroundColor White
    $T = 'Components - VSA Build'
    # The Veeam Software Appliance is a hardened Linux (JeOS) appliance; these items cannot
    # be verified from a Windows PowerShell host. They are surfaced as Manual with guidance.
    $vsa = @(
        @('3.1', 'Are you using Veeam Integrated Appliance (VIA) for infrastructure components?', 'Verify appliance deployment model (hmc.html).'),
        @('3.2', 'Are you using Veeam Software Appliance (VSA) with pre-hardened Linux JeOS configuration following DISA STIG standards?', 'Verify DISA STIG-hardened JeOS deployment on the VSA.'),
        @('3.3', 'Is the VSA configured with services running under low-privilege accounts (non-root)?', 'Verify VSA services run under non-root accounts.'),
        @('3.4', 'Are VSA automatic security updates enabled for continuous patch management?', 'Enable VSA automatic security updates (em_update_linux.html).'),
        @('3.5', 'Is Lockdown Mode enabled on VSA to prevent unauthorized software installation?', 'Enable Lockdown Mode on the VSA.'),
        @('3.6', 'Is SSH access disabled on VSA in production environments?', 'Disable SSH on the VSA in production.'),
        @('3.7', 'Is high availability clustering configured for backup infrastructure resilience?', 'Configure HA clustering where licensed.'),
        @('3.8', 'Are Linux hosts and repositories manually verified for authentication?', 'Manually verify Linux host/repository authentication.'),
        @('3.9', 'Is SSH protected with 2FA/MFA or disabled post-deployment?', 'Protect SSH with MFA or disable it post-deployment.')
    )
    foreach ($i in $vsa) { Invoke-Item -Num $i[0] -Topic $T -Name $i[1] -Recommendation ("VSA/Linux appliance item - " + $i[2]) }
}

#endregion

#region ----------------------------------------------------------------------- 4. Repositories

function Invoke-RepositoryChecks {
    Write-Host "`n--- 4. Repositories ---" -ForegroundColor White
    $T = 'Repositories'

    # 4.1 Object Lock immutability on cloud (object) repositories.
    Invoke-Item -Num '4.1' -Topic $T -Name 'Is Object Lock immutability enabled for any cloud (object) repositories? (S3, Azure, Google, & IBM)' `
        -Recommendation 'Enable Object Lock (Compliance mode) on cloud object repositories.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $oc = Test-VeeamCmdlet -Name 'Get-VBRObjectStorageRepository'
            if (-not $oc) { return @{ Status = 'Warning'; Value = 'Object storage cmdlet unavailable' } }
            $obj = @(& $oc -ErrorAction Stop)
            if ($obj.Count -eq 0) { return @{ Status = 'Manual'; Value = 'No cloud object repositories configured' } }
            $imm = @($obj | Where-Object { (Get-PropSafe -InputObject $_ -Name @('IsImmutabilityEnabled', 'ImmutabilityEnabled', 'BackupImmutabilityEnabled')) -eq $true })
            @{ Status = $(if ($imm.Count -eq $obj.Count) { 'Passed' } elseif ($imm.Count -gt 0) { 'Warning' } else { 'Failed' }); Value = ("{0}/{1} object repos immutable" -f $imm.Count, $obj.Count) }
        }

    # 4.2 Repository separated from production auth domain - manual.
    Invoke-Item -Num '4.2' -Topic $T -Name 'Is the backup repository separated from the production authentication domain?' `
        -Recommendation 'Use certificate-based/local auth; keep the repository out of the production AD domain.'

    # 4.3 Repository hardened.
    Invoke-Item -Num '4.3' -Topic $T -Name 'Is the Repository Hardened as per Veeam or manufacturers instructions?' `
        -Recommendation 'Deploy a hardened repository (Linux XFS single-use creds / immutability).' -Check {
            $repos = @(Get-Repos)
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            if ($repos.Count -eq 0) { return @{ Status = 'Failed'; Value = 'No repositories configured' } }
            $hard = @($repos | Where-Object { (Get-PropSafe -InputObject $_ -Name @('IsHardened', 'UseHardenedRepository')) -eq $true -or (Get-PropSafe -InputObject $_ -Name @('IsImmutabilityEnabled', 'ImmutabilityEnabled')) -eq $true })
            @{ Status = $(if ($hard.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("{0}/{1} repositories hardened/immutable" -f $hard.Count, $repos.Count) }
        }

    # 4.4 At least one repository immutable.
    Invoke-Item -Num '4.4' -Topic $T -Name 'Is at least one Repository Immutable?' `
        -Recommendation 'Maintain at least one immutable repository (3-2-1-1-0).' -Check {
            $repos = @(Get-Repos)
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            if ($repos.Count -eq 0) { return @{ Status = 'Failed'; Value = 'No repositories configured' } }
            $imm = @($repos | Where-Object { (Get-PropSafe -InputObject $_ -Name @('IsImmutabilityEnabled', 'ImmutabilityEnabled', 'IsImmutable', 'BackupImmutabilityEnabled')) -eq $true })
            @{ Status = $(if ($imm.Count -ge 1) { 'Passed' } else { 'Failed' }); Value = ("{0}/{1} repositories immutable" -f $imm.Count, $repos.Count) }
        }

    # 4.5 - 4.8 storage / VM placement - manual.
    Invoke-Item -Num '4.5' -Topic $T -Name 'Is the storage (e.g. SAN) hosting the Repository secured?' -Recommendation 'Verify SAN security per storage policy.'
    Invoke-Item -Num '4.6' -Topic $T -Name 'Is the storage (e.g. SAN) hosting the Repository isolated?' -Recommendation 'Verify SAN isolation (zoning / limited access).'
    Invoke-Item -Num '4.7' -Topic $T -Name 'Is the storage (e.g. SAN) hosting the Repository used only for Veeam backup data?' -Recommendation 'Dedicate repository storage to Veeam backup data only.'
    Invoke-Item -Num '4.8' -Topic $T -Name 'Is the Repository NOT a Virtual Machine?' -Recommendation 'Prefer a physical hardened repository over a VM.'

    # 4.9 Linux repos single-use creds + SSH key - manual/semi.
    Invoke-Item -Num '4.9' -Topic $T -Name 'Do Linux repositories use Single Use Credential Accounts and SSH Private/Public Key with Passphrase?' `
        -Recommendation 'Use single-use credentials and SSH key + passphrase for Linux repositories.'

    # 4.10 Time services reliable (W32Time + source).
    Invoke-Item -Num '4.10' -Topic $T -Name 'Are time services reliable?' `
        -Recommendation 'Ensure W32Time is running and synced to a reliable NTP source (not local CMOS).' -Check {
            $svc = Get-Service -Name 'W32Time' -ErrorAction SilentlyContinue
            $source = ''
            try { $source = (& w32tm.exe /query /source 2>$null) -join '' } catch { }
            $ok = ($svc -and $svc.Status -eq 'Running' -and $source -and $source -notmatch 'Local CMOS Clock|Free-running')
            @{ Status = $(if ($ok) { 'Passed' } else { 'Warning' }); Value = ("W32Time={0}; Source={1}" -f $(if ($svc) { $svc.Status } else { 'absent' }), $(if ($source) { $source } else { 'unknown' })) }
        }

    # 4.11 Time services secure - manual.
    Invoke-Item -Num '4.11' -Topic $T -Name 'Are time services secure?' -Recommendation 'Verify NTP resilience / authentication / monitoring per policy.'

    # 4.12 IPMI/iDRAC disabled or isolated - manual.
    Invoke-Item -Num '4.12' -Topic $T -Name 'Are IPMI / iDRAC (or similar) services disabled or isolated on the Repository post-deployment?' `
        -Recommendation 'Disable or isolate out-of-band management (IPMI/iDRAC) on repositories.'

    # 4.13 Multiple copies of backup data (backup copy jobs).
    Invoke-Item -Num '4.13' -Topic $T -Name 'Are there multiple copies of backup data?' `
        -Recommendation 'Maintain multiple copies via backup copy jobs (3-2-1).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRBackupCopyJob')
            $bc = if ($c) { @(& $c -ErrorAction SilentlyContinue) } else { @(Get-Jobs | Where-Object { (Get-PropSafe -InputObject $_ -Name @('JobType')) -match 'BackupSync|Copy' }) }
            @{ Status = $(if ($bc.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("{0} backup copy job(s) configured" -f $bc.Count) }
        }

    # 4.14 Offsite copy - manual/semi.
    Invoke-Item -Num '4.14' -Topic $T -Name 'Is there a copy of backup data in an offsite location' `
        -Recommendation 'Ensure at least one copy is off-site (backup copy / capacity tier).'

    # 4.15 Object lock for Capacity Tier (SOBR).
    Invoke-Item -Num '4.15' -Topic $T -Name 'Is object lock (immutability) enabled for offloads to Capacity Tier when used?' `
        -Recommendation 'Enable immutability on the SOBR Capacity Tier object storage.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRScaleOutBackupRepository')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'SOBR cmdlet unavailable' } }
            $sobr = @(& $c -ErrorAction Stop)
            if ($sobr.Count -eq 0) { return @{ Status = 'Manual'; Value = 'No scale-out repositories / capacity tier configured' } }
            @{ Status = 'Warning'; Value = ("{0} SOBR(s) present - verify capacity-tier object lock in console" -f $sobr.Count) }
        }

    # 4.16 Object lock for Archive Tier - manual/semi.
    Invoke-Item -Num '4.16' -Topic $T -Name 'Is object lock (immutability) enabled for offloads to Archive Tier when used?' `
        -Recommendation 'Enable immutability on the SOBR Archive Tier when used.'

    # 4.17 S3 Object Lock Compliance mode (vs Governance) - manual/semi.
    Invoke-Item -Num '4.17' -Topic $T -Name "Where applicable, is S3 Object Lock configured to use 'Compliance' mode rather than 'Governance' mode?" `
        -Recommendation "Use S3 Object Lock 'Compliance' mode, not 'Governance'."

    # 4.18 Built-in immutability for Linux repositories.
    Invoke-Item -Num '4.18' -Topic $T -Name 'Is built-in repository immutability enabled if Linux-based backup repositories are in use?' `
        -Recommendation 'Enable built-in immutability on Linux (XFS) repositories.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $repos = @(Get-Repos | Where-Object { (Get-PropSafe -InputObject $_ -Name @('Type', 'TypeDisplay')) -match 'Linux|Hardened' })
            if ($repos.Count -eq 0) { return @{ Status = 'Manual'; Value = 'No Linux/hardened repositories detected' } }
            $imm = @($repos | Where-Object { (Get-PropSafe -InputObject $_ -Name @('IsImmutabilityEnabled', 'ImmutabilityEnabled')) -eq $true })
            @{ Status = $(if ($imm.Count -eq $repos.Count) { 'Passed' } elseif ($imm.Count -gt 0) { 'Warning' } else { 'Failed' }); Value = ("{0}/{1} Linux repos immutable" -f $imm.Count, $repos.Count) }
        }
}

#endregion

#region ----------------------------------------------------------------------- 5. Accounts & Permissions

function Invoke-AccountChecks {
    Write-Host "`n--- 5. Accounts and Permissions ---" -ForegroundColor White
    $T = 'Accounts and Permissions'

    Invoke-Item -Num '5.1' -Topic $T -Name 'Is Single Sign-On (SSO) configured using SAML 2.0 or OAuth 2.0?' -Recommendation 'Configure SSO (SAML/OAuth) where applicable (VSPC/EM).'

    Invoke-Item -Num '5.2' -Topic $T -Name 'Is Multi-Factor Authentication (MFA) mandatory for all user accounts accessing Veeam console?' `
        -Recommendation 'Make MFA mandatory for all console users.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRMFAConfiguration', 'Get-VBRSecurityMFAPolicy')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'MFA cmdlet unavailable' } }
            $en = Get-PropSafe -InputObject (& $c -ErrorAction Stop) -Name @('IsEnabled', 'Enabled', 'MfaEnabled')
            @{ Status = $(if ($en -eq $true) { 'Passed' } elseif ($null -eq $en) { 'Warning' } else { 'Failed' }); Value = ("MFA enabled={0}" -f (nv $en)) }
        }

    Invoke-Item -Num '5.3' -Topic $T -Name 'Is the Security Officer role configured and assigned for four-eyes authorization on critical operations?' `
        -Recommendation 'Configure and assign the Security Officer role (jeos_install_security_officer).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRSecurityOfficer', 'Get-VBRFourEyesAuthorization')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Security Officer cmdlet unavailable' } }
            $so = @(& $c -ErrorAction Stop)
            @{ Status = $(if ($so.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("Security Officer configured: {0}" -f ($so.Count -gt 0)) }
        }

    Invoke-Item -Num '5.4' -Topic $T -Name 'Is there a distinction between user accounts for day-to-day operation, and admin/configuration access to the backup server and infrastructure?' -Recommendation 'Separate day-to-day and admin/config accounts.'
    Invoke-Item -Num '5.5' -Topic $T -Name 'The backup and restore services accounts are different from the Veeam managed servers account' -Recommendation 'Use distinct service accounts (least privilege).'
    Invoke-Item -Num '5.6' -Topic $T -Name 'Is the security officer role defined and secured?' -Recommendation 'Define and secure the Security Officer role.'
    Invoke-Item -Num '5.7' -Topic $T -Name 'Does each relevant user have their own Veeam administrative account' -Recommendation 'Give each admin an individual account (no shared accounts).'

    Invoke-Item -Num '5.8' -Topic $T -Name 'Are separate backup and restore operators defined?' `
        -Recommendation 'Define separate Backup and Restore Operator roles.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRUserRoleAssignment', 'Get-VBRRbacRoleAssignment')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'RBAC assignment cmdlet unavailable' } }
            $a = @(& $c -ErrorAction Stop)
            $roles = @($a | ForEach-Object { Get-PropSafe -InputObject $_ -Name @('Role', 'RoleName') } | Sort-Object -Unique)
            @{ Status = $(if ($roles.Count -gt 1) { 'Passed' } else { 'Warning' }); Value = ("Distinct roles assigned: {0}" -f $(if ($roles) { ($roles -join ', ') } else { 'none' })) }
        }

    Invoke-Item -Num '5.9' -Topic $T -Name 'Are ONLY authorized accounts granted access to the VBR server' `
        -Recommendation 'Restrict local Administrators to authorized accounts only.' -Check {
            $admins = Get-Admins
            if ($null -eq $admins) { return @{ Status = 'Warning'; Value = 'Could not enumerate local Administrators' } }
            $dom = @($admins | Where-Object { $_.PrincipalSource -eq 'ActiveDirectory' })
            $st = if ($dom.Count -eq 0 -and $admins.Count -le 3) { 'Passed' } else { 'Warning' }
            @{ Status = $st; Value = ("{0} admin member(s): {1}" -f $admins.Count, (($admins.Name) -join ', ')) }
        }

    Invoke-Item -Num '5.10' -Topic $T -Name 'Are ONLY authorized accounts granted access to the backup repository' -Recommendation 'Restrict repository access to authorized accounts.'
    Invoke-Item -Num '5.11' -Topic $T -Name 'Is certificate-based authentication used in place of user-based authentication wherever possible?' -Recommendation 'Prefer certificate-based auth over passwords for remote access.'
    Invoke-Item -Num '5.12' -Topic $T -Name 'Do Linux systems leverage LDAP or AD?' -Recommendation 'Centralize Linux auth via LDAP/AD where applicable.'
    Invoke-Item -Num '5.13' -Topic $T -Name 'Do Linux/Unix Systems leverage NIS/NSS?' -Recommendation 'Centralize Linux/Unix account management (NIS/NSS) where applicable.'
    Invoke-Item -Num '5.14' -Topic $T -Name 'Do Linux/Unix Systems use SSH Private/Public Key with Passphrase credentials?' -Recommendation 'Use SSH key + passphrase for Linux/Unix credentials.'
    Invoke-Item -Num '5.15' -Topic $T -Name 'Does SSH use strong password enforcement where applicable? (min of 15 characters)' -Recommendation 'Enforce >=15-character SSH passwords where used.'
    Invoke-Item -Num '5.16' -Topic $T -Name 'Is a dedicated, audited account used for repository access' -Recommendation 'Use a dedicated audited repository access account.'
    Invoke-Item -Num '5.17' -Topic $T -Name 'Is the account for repository access NOT root, or a member of Sudoers' -Recommendation 'Repository account must not be root / in sudoers (KB2676).'
    Invoke-Item -Num '5.18' -Topic $T -Name 'Where required, is LINUX service account "NOT" root but leverages SUDOER, Firewall and PAM security?' -Recommendation 'Use non-root Linux service account with SUDOER/PAM/firewall controls (KB2676).'
    Invoke-Item -Num '5.19' -Topic $T -Name 'Is access to the VBR database restricted to only authorized users?' -Recommendation 'Restrict VBR (PostgreSQL) database access to authorized users.'
    Invoke-Item -Num '5.20' -Topic $T -Name 'Do only authorized users have access to all servers hosting VBR components?' `
        -Recommendation 'Restrict access to all VBR component servers.' -Check {
            $admins = Get-Admins
            if ($null -eq $admins) { return @{ Status = 'Warning'; Value = 'Could not enumerate local Administrators' } }
            @{ Status = 'Warning'; Value = ("Local Administrators ({0}): {1} - confirm all are authorized" -f $admins.Count, (($admins.Name) -join ', ')) }
        }

    Invoke-Item -Num '5.21' -Topic $T -Name 'Is user account auditing enabled at the OS-level?' `
        -Recommendation 'Enable Logon / Account Management audit policy (Success+Failure).' -Check {
            # Logon subcategory GUID (locale-independent lookup).
            $out = ''
            try { $out = (& auditpol.exe /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" 2>$null) -join ' ' } catch { }
            $on = ($out -match 'Success' -or $out -match 'Failure')
            @{ Status = $(if ($on) { 'Passed' } elseif ($out) { 'Failed' } else { 'Warning' }); Value = $(if ($out) { ($out -replace '\s+', ' ').Trim() } else { 'auditpol query failed' }) }
        }

    Invoke-Item -Num '5.22' -Topic $T -Name 'Is auditing enabled and functioning in Veeam ONE?' -Recommendation 'Verify auditing in Veeam ONE (separate product).'

    Invoke-Item -Num '5.23' -Topic $T -Name 'Passwords, where used, are complex (minimum 15 characters, mix of case and characters)' `
        -Recommendation 'Enforce >=15-character complex passwords (local security policy).' -Check {
            $sp = Get-SecPol
            $len = if ($sp.ContainsKey('MinimumPasswordLength')) { [int]$sp['MinimumPasswordLength'] } else { $null }
            $cplx = if ($sp.ContainsKey('PasswordComplexity')) { [int]$sp['PasswordComplexity'] } else { $null }
            $st = if ($len -ge 15 -and $cplx -eq 1) { 'Passed' } elseif ($len -ge 8) { 'Warning' } else { 'Failed' }
            @{ Status = $st; Value = ("MinPasswordLength={0}; Complexity={1}" -f (nv $len), (nv $cplx)) }
        }

    Invoke-Item -Num '5.24' -Topic $T -Name 'Is an account lockout policy (after unsuccessful login attempts) in place?' `
        -Recommendation 'Configure an account lockout threshold.' -Check {
            $sp = Get-SecPol
            $bad = if ($sp.ContainsKey('LockoutBadCount')) { [int]$sp['LockoutBadCount'] } else { $null }
            $st = if ($bad -gt 0) { 'Passed' } elseif ($null -eq $bad) { 'Warning' } else { 'Failed' }
            @{ Status = $st; Value = ("LockoutBadCount={0}" -f (nv $bad)) }
        }

    Invoke-Item -Num '5.25' -Topic $T -Name 'Do you have a safe, protected, air-gapped copy of all necessary credentials necessary to reach data (eg. Credentials for storage appliances).' -Recommendation 'Keep an air-gapped copy of recovery credentials in a secure vault.'

    Invoke-Item -Num '5.26' -Topic $T -Name 'Are group Managed Service Accounts (gMSA) used wherever applicable (in the case of AAIP on Windows Domain-joined resources)' `
        -Recommendation 'Use gMSA for applicable Windows domain-joined service accounts.' -Check {
            $svc = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartName -match '\$$' })
            @{ Status = $(if ($svc.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("{0} service(s) using a managed-service/gMSA-style account" -f $svc.Count) }
        }

    Invoke-Item -Num '5.27' -Topic $T -Name 'Is Active Directory server protected using an unmanaged agent or crash consistent backup to avoid storing Domain admin account in Veeam DB ?' -Recommendation 'Protect DCs via unmanaged agent / crash-consistent backup to avoid storing DA creds.'
    Invoke-Item -Num '5.28' -Topic $T -Name 'Is active alerting in place for unsuccessful login attempts?' -Recommendation 'Alert on failed login attempts.'
    Invoke-Item -Num '5.29' -Topic $T -Name 'Are permissions applied to the hypervisor control plane applied using the principle of least privilege?' -Recommendation 'Apply least privilege to hypervisor control-plane permissions.'
    Invoke-Item -Num '5.30' -Topic $T -Name 'Are permissions applied to protected recoverable applications being protected by Veeam using the principle of least privilege?' -Recommendation 'Apply least privilege to application processing accounts.'

    Invoke-Item -Num '5.31' -Topic $T -Name 'Is 4-eyes authorization configured for critical changes to the backup infrastructure and archives?' `
        -Recommendation 'Enable four-eyes authorization (four_eyes_authorization).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRFourEyesAuthorization', 'Get-VBRSecurityOfficer')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Four-eyes cmdlet unavailable' } }
            $r = @(& $c -ErrorAction Stop)
            @{ Status = $(if ($r.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("Four-eyes/Security Officer configured: {0}" -f ($r.Count -gt 0)) }
        }

    Invoke-Item -Num '5.32' -Topic $T -Name 'Are custom RBAC roles configured following least privilege principles?' `
        -Recommendation 'Assign granular RBAC roles instead of Administrator (configure_roles).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRSecurityRole', 'Get-VBRRbacRole', 'Get-VBRUserRoleMapping')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'RBAC role cmdlet unavailable' } }
            $roles = @(& $c -ErrorAction Stop)
            $names = @($roles | ForEach-Object { Get-PropSafe -InputObject $_ -Name @('Name', 'RoleName', 'DisplayName') })
            @{ Status = $(if ($roles.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("Roles: {0}" -f $(if ($names) { ($names -join ', ') } else { 'none' })) }
        }

    Invoke-Item -Num '5.33' -Topic $T -Name 'Are Backup Operators/Restore users scope limited to relevant data for their role?' -Recommendation 'Scope-limit Backup/Restore operators to relevant data (configure_roles).'
    Invoke-Item -Num '5.34' -Topic $T -Name 'Are recovery verification tokens used to authorize restore operations?' -Recommendation 'Use recovery verification tokens for restore authorization.'
    Invoke-Item -Num '5.35' -Topic $T -Name 'Are permissions applied to hypervisor control plane using the principle of least privilege? (copy)' -Recommendation 'Apply least privilege to the hypervisor control plane.'
}

#endregion

#region ----------------------------------------------------------------------- 6. Encryption

function Invoke-EncryptionChecks {
    Write-Host "`n--- 6. Encryption ---" -ForegroundColor White
    $T = 'Encryption'

    Invoke-Item -Num '6.1' -Topic $T -Name 'Is certificate thumbprint validation enabled for component-to-component authentication?' -Recommendation 'Enable certificate thumbprint validation (cloud_connect_ssl_verify).'

    Invoke-Item -Num '6.2' -Topic $T -Name 'Are private encryption keys stored securely? E.g. in a Key Management System (KMS)' `
        -Recommendation 'Store encryption keys in an external KMS (encryption_kms).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRKMSServer', 'Get-VBRKMSInfo')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'KMS cmdlet unavailable' } }
            $kms = @(& $c -ErrorAction Stop)
            @{ Status = $(if ($kms.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("{0} KMS server(s) configured" -f $kms.Count) }
        }

    Invoke-Item -Num '6.3' -Topic $T -Name 'Are backup encryption passwords regularly checked for strength?' -Recommendation 'Periodically verify encryption password strength (password_manager_verify).'

    Invoke-Item -Num '6.4' -Topic $T -Name 'Is SMBv3 signing and encryption enabled where applicable?' `
        -Recommendation 'Enable SMB signing and encryption on the server.' -Check {
            if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) { return @{ Status = 'Warning'; Value = 'SMB cmdlet unavailable' } }
            $s = Get-SmbServerConfiguration -ErrorAction Stop
            $st = if ($s.EncryptData -and $s.RequireSecuritySignature) { 'Passed' } elseif ($s.EncryptData -or $s.RequireSecuritySignature) { 'Warning' } else { 'Failed' }
            @{ Status = $st; Value = ("EncryptData={0}; RequireSecuritySignature={1}" -f $s.EncryptData, $s.RequireSecuritySignature) }
        }

    Invoke-Item -Num '6.5' -Topic $T -Name 'Are backups encrypted?' `
        -Recommendation 'Enable AES-256 storage encryption on all backup jobs (data_encryption).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $jobs = @(Get-Jobs)
            if ($jobs.Count -eq 0) { return @{ Status = 'Warning'; Value = 'No jobs found' } }
            $enc = 0; $un = @()
            foreach ($j in $jobs) {
                $e = $null
                try {
                    $o = Get-VBRJobOptions -Job $j -ErrorAction Stop
                    $e = Get-PropSafe -InputObject (Get-PropSafe -InputObject $o -Name @('BackupStorageOptions')) -Name @('StorageEncryptionEnabled', 'EncryptionEnabled')
                } catch { }
                if ($null -eq $e) { $e = Get-PropSafe -InputObject $j -Name @('IsEncrypted', 'EncryptionEnabled') }
                if ($e -eq $true) { $enc++ } else { $un += (Get-PropSafe -InputObject $j -Name @('Name')) }
            }
            @{ Status = $(if ($un.Count -eq 0) { 'Passed' } else { 'Failed' }); Value = ("{0}/{1} jobs encrypted{2}" -f $enc, $jobs.Count, $(if ($un) { '; unencrypted: ' + ($un -join ', ') } else { '' })) }
        }

    Invoke-Item -Num '6.6' -Topic $T -Name 'Is all backup network traffic encrypted?' `
        -Recommendation 'Enforce a network traffic encryption rule (enable_network_encryption).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name 'Get-VBRNetworkTrafficRule'
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Network traffic rule cmdlet unavailable' } }
            $rules = @(& $c -ErrorAction Stop)
            $enc = @($rules | Where-Object { (Get-PropSafe -InputObject $_ -Name @('EncryptionEnabled')) -eq $true })
            $st = if ($rules.Count -gt 0 -and $enc.Count -eq $rules.Count) { 'Passed' } elseif ($enc.Count -gt 0) { 'Warning' } else { 'Failed' }
            @{ Status = $st; Value = ("{0}/{1} traffic rule(s) enforce encryption" -f $enc.Count, $rules.Count) }
        }

    Invoke-Item -Num '6.7' -Topic $T -Name 'Is Enterprise Manager deployed and able to perform password loss protection?' -Recommendation 'Deploy Enterprise Manager for password loss protection.'
    Invoke-Item -Num '6.8' -Topic $T -Name 'Is Enterprise Manager deployed seperately from the VBR server?' -Recommendation 'Deploy Enterprise Manager separately from the VBR server.'
    Invoke-Item -Num '6.9' -Topic $T -Name 'Are verified public certificates in use or Veeam Self Signed Certificates?' -Recommendation 'Prefer verified public/CA certificates over self-signed.'
    Invoke-Item -Num '6.10' -Topic $T -Name 'Is OpenSSL 3.0 or higher in use for all cryptographic operations?' -Recommendation 'Verify OpenSSL 3.0+ via the Best Practice Analyzer.'
    Invoke-Item -Num '6.11' -Topic $T -Name 'Are backup plugins configured for source-side encryption before data transfer?' -Recommendation 'Enable source-side encryption on backup plugins.'

    Invoke-Item -Num '6.12' -Topic $T -Name 'Is encryption enabled for all backup repositories?' `
        -Recommendation 'Ensure backups written to every repository are encrypted (via job/repo encryption).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $jobs = @(Get-Jobs)
            if ($jobs.Count -eq 0) { return @{ Status = 'Warning'; Value = 'No jobs found - verify per repository' } }
            $un = 0
            foreach ($j in $jobs) {
                try { $o = Get-VBRJobOptions -Job $j -ErrorAction Stop; if ((Get-PropSafe -InputObject (Get-PropSafe -InputObject $o -Name @('BackupStorageOptions')) -Name @('StorageEncryptionEnabled')) -ne $true) { $un++ } } catch { $un++ }
            }
            @{ Status = $(if ($un -eq 0) { 'Passed' } else { 'Warning' }); Value = ("{0} job(s) write unencrypted data to repositories" -f $un) }
        }
}

#endregion

#region ----------------------------------------------------------------------- 7. Operational

function Invoke-OperationalChecks {
    Write-Host "`n--- 7. Operational ---" -ForegroundColor White
    $T = 'Operational'

    Invoke-Item -Num '7.1' -Topic $T -Name 'Is Veeam Security Analyzer configured for continuous compliance monitoring?' `
        -Recommendation 'Run/schedule the Security & Compliance (Best Practice) Analyzer.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name @('Get-VBRBestPracticeAnalyzer', 'Start-VBRSecurityComplianceAnalyzer', 'Get-VBRSecurityComplianceAnalyzer')
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Analyzer cmdlet unavailable - verify in console' } }
            @{ Status = 'Warning'; Value = ("Analyzer cmdlet present ({0}) - confirm it is scheduled" -f $c) }
        }

    Invoke-Item -Num '7.2' -Topic $T -Name 'Did you implement a honeypot/decoy VBR server ?' -Recommendation 'Consider a honeypot/decoy VBR server.'
    Invoke-Item -Num '7.3' -Topic $T -Name 'Does all backup traffic traverse an isolated network?' -Recommendation 'Route backup traffic over an isolated network (select_backup_network).'
    Invoke-Item -Num '7.4' -Topic $T -Name 'Is ransomware detection in place for perimeter infrstructure and for production data?' -Recommendation 'Deploy perimeter/production ransomware detection (front-end vendor).'
    Invoke-Item -Num '7.5' -Topic $T -Name 'Is there policy in place to train backup admins on avoidance of phishing or other social engineering attacks?' -Recommendation 'Maintain phishing/social-engineering training for backup admins.'
    Invoke-Item -Num '7.6' -Topic $T -Name 'Are you subscribed to Veeam Security Advisories?' -Recommendation 'Subscribe to Veeam Security Advisories.'
}

#endregion

#region ----------------------------------------------------------------------- 8. NAS-specific

function Invoke-NasChecks {
    Write-Host "`n--- 8. NAS-specific ---" -ForegroundColor White
    $T = 'NAS-specific'

    Invoke-Item -Num '8.1' -Topic $T -Name 'Are NAS shares accessible on an isolated/separated backup network from production network?' -Recommendation 'Place NAS shares on an isolated backup network.'

    Invoke-Item -Num '8.2' -Topic $T -Name 'Is/are there global network traffic rule(s) that encrypts traffic between cache repo, file proxies, repositories, archive gateway, object store?' `
        -Recommendation 'Add a global network traffic encryption rule (enable_network_encryption).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name 'Get-VBRNetworkTrafficRule'
            if (-not $c) { return @{ Status = 'Warning'; Value = 'Network traffic rule cmdlet unavailable' } }
            $rules = @(& $c -ErrorAction Stop)
            $enc = @($rules | Where-Object { (Get-PropSafe -InputObject $_ -Name @('EncryptionEnabled')) -eq $true })
            @{ Status = $(if ($enc.Count -gt 0) { 'Passed' } else { 'Failed' }); Value = ("{0}/{1} traffic rule(s) encrypt" -f $enc.Count, $rules.Count) }
        }

    Invoke-Item -Num '8.3' -Topic $T -Name 'Are firewall rules in place to only allow for necessary backup/restore traffic operations?' `
        -Recommendation 'Restrict firewall rules to required backup/restore traffic (used_ports).' -Check {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { return @{ Status = 'Warning'; Value = 'Firewall cmdlets unavailable' } }
            $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled })
            @{ Status = $(if ($off.Count -eq 0) { 'Passed' } else { 'Failed' }); Value = $(if ($off.Count -eq 0) { 'Firewall enabled on all profiles' } else { 'Disabled on: ' + (($off.Name) -join ', ') }) }
        }

    Invoke-Item -Num '8.4' -Topic $T -Name 'Are NAS backups encrypted?' -Recommendation 'Encrypt NAS (unstructured data) backup jobs.'
    Invoke-Item -Num '8.5' -Topic $T -Name 'Is there a secondary backup copy?' `
        -Recommendation 'Create a secondary backup copy (backup_copy).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name 'Get-VBRBackupCopyJob'
            $bc = if ($c) { @(& $c -ErrorAction SilentlyContinue) } else { @() }
            @{ Status = $(if ($bc.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("{0} backup copy job(s)" -f $bc.Count) }
        }
    Invoke-Item -Num '8.6' -Topic $T -Name 'Is backup Archiving in use (for NAS i.e. secondary copy)?' -Recommendation 'Use archiving for NAS secondary copies where applicable.'
    Invoke-Item -Num '8.7' -Topic $T -Name 'Are the appropriate and least privileges set for storage integration account?' -Recommendation 'Apply least privilege to the storage integration account.'
    Invoke-Item -Num '8.8' -Topic $T -Name 'Is the account used for NAS backup separate from the storage integration account?' -Recommendation 'Separate NAS backup and storage integration accounts.'
    Invoke-Item -Num '8.9' -Topic $T -Name 'Is the account used for SMB share backup restricted to "read-only/least privileges" permissions?' -Recommendation 'Restrict SMB backup account to read-only/least privilege.'
    Invoke-Item -Num '8.10' -Topic $T -Name 'Are NFS share''s "NFS hosts" list restricted to the file proxies only with "read only" permissions?' -Recommendation 'Restrict NFS hosts to file proxies with read-only access.'
    Invoke-Item -Num '8.11' -Topic $T -Name 'Are Share write permissions only manually granted upon restore operations?' -Recommendation 'Grant share write access only during restore operations.'
    Invoke-Item -Num '8.12' -Topic $T -Name 'Are there Share definitions for restore operations only?' -Recommendation 'Define restore-only share definitions.'
    Invoke-Item -Num '8.13' -Topic $T -Name 'Is a gateway server defined for NAS archive tier i.e. gateway moved away from SOBR extents hosting backup data?' -Recommendation 'Use a dedicated gateway for the NAS archive tier.'
    Invoke-Item -Num '8.14' -Topic $T -Name 'Is there a mount server defined away from the "production" network?' -Recommendation 'Place the mount server off the production network.'
}

#endregion

#region ----------------------------------------------------------------------- 9. DR & Testing

function Invoke-DrChecks {
    Write-Host "`n--- 9. Disaster Recovery & Testing ---" -ForegroundColor White
    $T = 'Disaster Recovery & Testing'

    Invoke-Item -Num '9.1' -Topic $T -Name 'Are cloud-based recovery options configured for disaster recovery scenarios?' -Recommendation 'Configure cloud-based DR recovery options where applicable.'
    Invoke-Item -Num '9.2' -Topic $T -Name 'Is the Veeam Orchestrator server secured?' -Recommendation 'Secure the Veeam Recovery Orchestrator server (apply VBR hardening).'
    Invoke-Item -Num '9.3' -Topic $T -Name 'Is your disaster recovery orchestrated through automation?' -Recommendation 'Automate DR via orchestrated recovery plans.'
    Invoke-Item -Num '9.4' -Topic $T -Name 'Are there disaster recovery plans, playbooks and/or runbooks for DR orchestration in place?' -Recommendation 'Maintain DR plans/runbooks.'
    Invoke-Item -Num '9.5' -Topic $T -Name 'Did you ever perform a DR test against existing runbooks?' -Recommendation 'Perform periodic DR tests against runbooks.'

    Invoke-Item -Num '9.6' -Topic $T -Name 'Is there a regular testing regimen in place for recovery from backup?' `
        -Recommendation 'Schedule SureBackup recovery verification jobs.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $c = Test-VeeamCmdlet -Name 'Get-VBRSureBackupJob'
            if (-not $c) { return @{ Status = 'Warning'; Value = 'SureBackup cmdlet unavailable' } }
            $sb = @(& $c -ErrorAction Stop)
            @{ Status = $(if ($sb.Count -gt 0) { 'Passed' } else { 'Warning' }); Value = ("{0} SureBackup job(s) configured" -f $sb.Count) }
        }

    Invoke-Item -Num '9.7' -Topic $T -Name 'Is there a regular testing regimen in place for recovery from replicas?' -Recommendation 'Test recovery from replicas regularly (SureReplica / DR tests).'
    Invoke-Item -Num '9.8' -Topic $T -Name 'Is your recovery response / SWAT team ready?' -Recommendation 'Maintain a ready recovery/SWAT team with drills.'
    Invoke-Item -Num '9.9' -Topic $T -Name 'Are you aware of the core applications that would allow business continuity after a blackout / service-loss event?' -Recommendation 'Document core applications for business continuity.'
    Invoke-Item -Num '9.10' -Topic $T -Name 'Are you aware of the support infrastructure that would allow business continuity after a blackout  service-loss event?' -Recommendation 'Document supporting infrastructure for business continuity.'
    Invoke-Item -Num '9.11' -Topic $T -Name 'Is there sufficient documentation in offline or printed form to support the restoration process that is available to the recovery response / SWAT team?' -Recommendation 'Keep offline/printed restoration documentation.'
    Invoke-Item -Num '9.12' -Topic $T -Name 'Is Universal Restore configured for cross-platform recovery (P2V, V2V, V2P)?' -Recommendation 'Prepare Universal Restore media for cross-platform recovery.'
}

#endregion

#region ----------------------------------------------------------------------- 10. Detection

function Invoke-DetectionChecks {
    Write-Host "`n--- 10. Detection ---" -ForegroundColor White
    $T = 'Detection'

    # Shared global malware detection options object.
    Invoke-Item -Num '10.1' -Topic $T -Name 'Is proactive malware scanning enabled before backup finalization?' `
        -Recommendation 'Enable malware detection / inline scanning (malware_detection).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $mw = Get-MalwareOpts
            if (-not $mw) { return @{ Status = 'Warning'; Value = 'Malware detection options unavailable' } }
            $en = Get-PropSafe -InputObject $mw -Name @('EnableMalwareDetection', 'IsEnabled', 'MalwareDetectionEnabled')
            @{ Status = $(if ($en -eq $true) { 'Passed' } elseif ($null -eq $en) { 'Warning' } else { 'Failed' }); Value = ("Malware detection enabled={0}" -f (nv $en)) }
        }

    Invoke-Item -Num '10.2' -Topic $T -Name 'Is Veeam inline entropy analysis enabled?' `
        -Recommendation 'Enable inline data-block entropy analysis.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $mw = Get-MalwareOpts
            if (-not $mw) { return @{ Status = 'Warning'; Value = 'Malware detection options unavailable' } }
            $e = Get-PropSafe -InputObject $mw -Name @('EnableInlineEntropyAnalysis', 'InlineEntropyEnabled', 'EnableDataBlockAnalysis', 'EnableInlineScan')
            @{ Status = $(if ($e -eq $true) { 'Passed' } elseif ($null -eq $e) { 'Warning' } else { 'Failed' }); Value = ("Inline entropy analysis={0}" -f (nv $e)) }
        }

    Invoke-Item -Num '10.3' -Topic $T -Name 'Is Veeam suspicious file activity detection enabled?' `
        -Recommendation 'Enable suspicious file activity (guest index) detection.' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $mw = Get-MalwareOpts
            if (-not $mw) { return @{ Status = 'Warning'; Value = 'Malware detection options unavailable' } }
            $s = Get-PropSafe -InputObject $mw -Name @('EnableSuspiciousFileDetection', 'SuspiciousActivityEnabled', 'EnableFileSystemActivityAnalysis')
            @{ Status = $(if ($s -eq $true) { 'Passed' } elseif ($null -eq $s) { 'Warning' } else { 'Failed' }); Value = ("Suspicious file activity detection={0}" -f (nv $s)) }
        }

    Invoke-Item -Num '10.4' -Topic $T -Name 'Is Veeam Threat Hunter or anti-virus installed and configured on the Veeam Mount Server(s)?' -Recommendation 'Install/enable Threat Hunter or AV on mount servers (secure_restore).'
    Invoke-Item -Num '10.5' -Topic $T -Name 'Are YARA rules configured on the Veeam Mount Server?' -Recommendation 'Deploy YARA rules on the mount server.'

    Invoke-Item -Num '10.6' -Topic $T -Name 'Is there a regimen in place for regular backup scans?' -Recommendation 'Schedule regular backup content scans.'
    Invoke-Item -Num '10.7' -Topic $T -Name 'Is Secure Restore configured with appropriate anti-virus and/or YARA rules?' -Recommendation 'Configure Secure Restore with AV/YARA scanning.'
    Invoke-Item -Num '10.8' -Topic $T -Name 'Are anti-malware and/or YARA rules kept up to date?' -Recommendation 'Keep AV/YARA rule definitions current.'
    Invoke-Item -Num '10.9' -Topic $T -Name 'Is there a regimen in place for regular testing of Secure Restore?' -Recommendation 'Regularly test Secure Restore.'
    Invoke-Item -Num '10.10' -Topic $T -Name 'Is there a process in place for marking (timestamp) specific restore points as infected or clean where applicable? i.e. using Veeam Backup browser' -Recommendation 'Mark restore points clean/infected via the backup browser.'

    Invoke-Item -Num '10.11' -Topic $T -Name 'Is Indicator of Compromise (tools) detection enabled?' `
        -Recommendation 'Enable Indicator-of-Compromise detection (malware_detection_guest_index_ioc).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $mw = Get-MalwareOpts
            if (-not $mw) { return @{ Status = 'Warning'; Value = 'Malware detection options unavailable' } }
            $i = Get-PropSafe -InputObject $mw -Name @('IndicatorOfCompromiseEnabled', 'EnableIoCDetection', 'EnableIndicatorOfCompromise')
            @{ Status = $(if ($i -eq $true) { 'Passed' } elseif ($null -eq $i) { 'Warning' } else { 'Failed' }); Value = ("IOC detection={0}" -f (nv $i)) }
        }

    Invoke-Item -Num '10.12' -Topic $T -Name 'Is Recon deployed?' -Recommendation 'Consider deploying Veeam Recon (Coveware).'
    Invoke-Item -Num '10.13' -Topic $T -Name 'Is there a process in place to regularly review Recon reports?' -Recommendation 'Regularly review Recon reports.'

    Invoke-Item -Num '10.14' -Topic $T -Name 'Is Linux malware detection enabled for Linux-based workloads?' `
        -Recommendation 'Enable malware detection for Linux agents/workloads (agents_malware_detection).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $mw = Get-MalwareOpts
            if (-not $mw) { return @{ Status = 'Warning'; Value = 'Malware detection options unavailable' } }
            $l = Get-PropSafe -InputObject $mw -Name @('EnableLinuxMalwareDetection', 'LinuxWorkloadScanEnabled', 'EnableAgentMalwareDetection')
            @{ Status = $(if ($l -eq $true) { 'Passed' } elseif ($null -eq $l) { 'Warning' } else { 'Failed' }); Value = ("Linux malware detection={0}" -f (nv $l)) }
        }

    Invoke-Item -Num '10.15' -Topic $T -Name 'Is cloud workload malware scanning enabled (AWS, Azure, GCP) if applicable?' -Recommendation 'Enable malware scanning for cloud workloads where applicable.'

    Invoke-Item -Num '10.16' -Topic $T -Name 'Is AI-based anomaly detection enabled for entropy analysis and ransomware detection?' `
        -Recommendation 'Enable AI-based anomaly detection thresholds (malware_detection_data_blocks).' -Check {
            if (-not $script:VbrConnected) { return @{ Status = 'Warning'; Value = 'No VBR session' } }
            $mw = Get-MalwareOpts
            if (-not $mw) { return @{ Status = 'Warning'; Value = 'Malware detection options unavailable' } }
            $a = Get-PropSafe -InputObject $mw -Name @('EnableAiAnomalyDetection', 'AnomalyDetectionEnabled', 'EnableInlineEntropyAnalysis', 'EnableDataBlockAnalysis')
            @{ Status = $(if ($a -eq $true) { 'Passed' } elseif ($null -eq $a) { 'Warning' } else { 'Failed' }); Value = ("AI/anomaly (data-block) detection={0}" -f (nv $a)) }
        }

    Invoke-Item -Num '10.17' -Topic $T -Name 'Is object-level threat detection enabled for file system changes?' -Recommendation 'Enable object-level / VSS file-system change detection where applicable.'
}

#endregion

#region ----------------------------------------------------------------------- Reporting

function Export-ComplianceReport {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not (Test-Path -LiteralPath $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }

    if ($ReportFormat -in @('CSV', 'Both')) {
        $csvFile = Join-Path $ReportPath ("VBR_CyberSecure_Audit_{0}_{1}.csv" -f $env:COMPUTERNAME, $timestamp)
        try { $script:Results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8; Write-Host ("[+] CSV report: {0}" -f $csvFile) -ForegroundColor Green }
        catch { Write-Warning ("Failed to write CSV: {0}" -f $_.Exception.Message) }
    }

    if ($ReportFormat -in @('HTML', 'Both')) {
        $htmlFile = Join-Path $ReportPath ("VBR_CyberSecure_Audit_{0}_{1}.html" -f $env:COMPUTERNAME, $timestamp)
        try {
            $pass = @($script:Results | Where-Object Status -eq 'Passed').Count
            $fail = @($script:Results | Where-Object Status -eq 'Failed').Count
            $warn = @($script:Results | Where-Object Status -eq 'Warning').Count
            $err  = @($script:Results | Where-Object Status -eq 'Error').Count
            $man  = @($script:Results | Where-Object Status -eq 'Manual').Count
            $auto = $pass + $fail + $warn + $err
            $score = if ($auto) { [math]::Round(($pass / $auto) * 100, 1) } else { 0 }

            $useWeb = $false
            try { Add-Type -AssemblyName System.Web -ErrorAction Stop; $useWeb = $true } catch { $useWeb = $false }
            function Convert-HtmlEncode {
                param([string]$Text)
                if ($null -eq $Text) { return '' }
                if ($useWeb) { return [System.Web.HttpUtility]::HtmlEncode($Text) }
                return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
            }

            $css = @'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2933;background:#f5f7fa;}
 h1{color:#0b5394;margin-bottom:4px;} .meta{color:#627d98;font-size:13px;margin-bottom:16px;}
 .cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;}
 .card{padding:14px 20px;border-radius:8px;color:#fff;min-width:96px;box-shadow:0 1px 3px rgba(0,0,0,.15);}
 .card b{display:block;font-size:24px;}
 .c-pass{background:#2e8b57;}.c-fail{background:#c0392b;}.c-warn{background:#d68910;}
 .c-err{background:#8e44ad;}.c-man{background:#4a6572;}.c-score{background:#0b5394;}
 table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1);}
 th{background:#334e68;color:#fff;text-align:left;padding:8px 10px;font-size:13px;position:sticky;top:0;}
 td{padding:7px 10px;border-bottom:1px solid #e4e7eb;font-size:13px;vertical-align:top;}
 tr:nth-child(even){background:#f8fafc;} td.num{white-space:nowrap;font-weight:bold;color:#334e68;}
 .s-Passed{color:#2e8b57;font-weight:bold;}.s-Failed{color:#c0392b;font-weight:bold;}
 .s-Warning{color:#b9770e;font-weight:bold;}.s-Error{color:#8e44ad;font-weight:bold;}
 .s-Manual{color:#4a6572;font-weight:bold;}.s-Info{color:#0b5394;font-weight:bold;}
</style>
'@
            $rows = foreach ($r in $script:Results) {
                $num = Convert-HtmlEncode $r.'Item #'
                $rn  = Convert-HtmlEncode $r.'Rule Name'
                $cv  = Convert-HtmlEncode $r.'Current Value'
                $rc  = Convert-HtmlEncode $r.Recommendation
                "<tr><td class='num'>$num</td><td>$($r.Topic)</td><td>$rn</td><td class='s-$($r.Status)'>$($r.Status)</td><td>$cv</td><td>$rc</td></tr>"
            }

            $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>VBR v13 Cyber Secure Audit</title>$css</head>
<body>
<h1>Veeam VBR v13 - VDP Cyber Secure Compliance Audit</h1>
<div class="meta">Host: <b>$env:COMPUTERNAME</b> &nbsp;|&nbsp; VBR server: <b>$VBRServer</b> &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; Items: $($script:Results.Count)</div>
<div class="cards">
 <div class="card c-score">Auto Score<b>$score%</b></div>
 <div class="card c-pass">Passed<b>$pass</b></div>
 <div class="card c-fail">Failed<b>$fail</b></div>
 <div class="card c-warn">Warning<b>$warn</b></div>
 <div class="card c-err">Error<b>$err</b></div>
 <div class="card c-man">Manual<b>$man</b></div>
</div>
<table>
<thead><tr><th>Item #</th><th>Topic</th><th>Rule Name</th><th>Status</th><th>Current Value</th><th>Recommendation</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
<p class="meta">Auto Score = Passed / (Passed+Failed+Warning+Error), excluding Manual items. Warning/Error/Manual rows require human verification against the VDP v13 Cyber Secure Checklist.</p>
</body></html>
"@
            $html | Out-File -FilePath $htmlFile -Encoding UTF8
            Write-Host ("[+] HTML report: {0}" -f $htmlFile) -ForegroundColor Green
        }
        catch { Write-Warning ("Failed to write HTML: {0}" -f $_.Exception.Message) }
    }
}

#endregion

#region ----------------------------------------------------------------------- Main

try {
    Invoke-ComponentChecks
    Invoke-WindowsBuildChecks
    Invoke-VsaBuildChecks
    Invoke-RepositoryChecks
    Invoke-AccountChecks
    Invoke-EncryptionChecks
    Invoke-OperationalChecks
    Invoke-NasChecks
    Invoke-DrChecks
    Invoke-DetectionChecks
}
finally {
    if ($script:VbrConnected -and (Test-VeeamCmdlet -Name 'Disconnect-VBRServer')) {
        try { Disconnect-VBRServer -ErrorAction SilentlyContinue } catch { }
    }

    Export-ComplianceReport

    $pass = @($script:Results | Where-Object Status -eq 'Passed').Count
    $fail = @($script:Results | Where-Object Status -eq 'Failed').Count
    $warn = @($script:Results | Where-Object Status -eq 'Warning').Count
    $err  = @($script:Results | Where-Object Status -eq 'Error').Count
    $man  = @($script:Results | Where-Object Status -eq 'Manual').Count

    Write-Host "`n===============================================================" -ForegroundColor Cyan
    Write-Host ('  Audit summary - {0} checklist items' -f $script:Results.Count) -ForegroundColor Cyan
    Write-Host ('  Passed : {0}' -f $pass) -ForegroundColor Green
    Write-Host ('  Failed : {0}' -f $fail) -ForegroundColor Red
    Write-Host ('  Warning: {0}' -f $warn) -ForegroundColor Yellow
    Write-Host ('  Error  : {0}' -f $err)  -ForegroundColor Magenta
    Write-Host ('  Manual : {0}' -f $man)  -ForegroundColor DarkCyan
    Write-Host '===============================================================' -ForegroundColor Cyan
}

#endregion

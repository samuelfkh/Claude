#Requires -Version 5.1
<#
.SYNOPSIS
    Automated Cyber Secure compliance audit for Veeam Backup & Replication (VBR) v13
    running on Windows Server.

.DESCRIPTION
    Evaluates the local Windows Server / VBR instance against a curated subset of the
    Veeam Data Platform (VDP) v13 Cyber Secure Checklist. Checks are grouped into the
    following topics:

        1. Components               - NTLM deprecation, OS patching / Veeam Updater,
                                       LTS/LTSC OS build, Veeam software version.
        2. Components - Windows Build - Legacy service / protocol hardening baseline
                                       (RemoteRegistry, WinRM, WDigest, WPAD, WSH,
                                       LLMNR, SMBv1, RDP, SSL 2.0).
        3. Repositories             - Hardened / immutable repository configuration.
        4. Accounts and Permissions - Local Administrators least-privilege review and
                                       Veeam RBAC (security role) assignments.
        5. Encryption               - Backup job encryption, network traffic encryption,
                                       KMS integration.
        6. Detection                - Malware detection, Guest Index / IOC scanning,
                                       Linux workload scanning, inline entropy / AI-based
                                       anomaly detection.

    The script auto-detects and imports the Veeam.Backup.PowerShell module, verifies it
    is running elevated, connects (and self-tests) to the local VBR server, executes the
    audit, prints a color-coded summary to the console, and exports an HTML and/or CSV
    compliance report to the local directory.

    Because Veeam SDK object/property names can differ slightly between v13 patch levels,
    the script uses defensive property probing (Get-Command / property discovery) so a
    renamed cmdlet or property degrades gracefully to a "Warning" instead of a hard error.

.PARAMETER Credential
    Optional [PSCredential] used with Connect-VBRServer. Supply this when running the
    audit remotely, or when the current user context is not authorized against the VBR
    server. If omitted, the script first attempts a connection under the current
    (administrative) user context and only prompts via Get-Credential if that fails.

.PARAMETER VBRServer
    Host name / IP of the VBR server to audit. Defaults to 'localhost' (local instance).

.PARAMETER ReportPath
    Directory in which the HTML / CSV report(s) are written. Defaults to the current
    working directory.

.PARAMETER ReportFormat
    Report output format: HTML, CSV, or Both (default).

.PARAMETER LatestKnownVbrBuild
    The latest known VBR v13 build number to compare the installed build against. Update
    this value from https://www.veeam.com/kb2680 when a new patch ships.

.EXAMPLE
    .\Invoke-VbrCyberSecureAudit.ps1

    Runs the full audit against the local VBR server under the current admin context and
    writes HTML + CSV reports to the current directory.

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-VbrCyberSecureAudit.ps1 -VBRServer 'vbr01.corp.local' -Credential $cred -ReportFormat HTML

    Connects to a remote VBR server with explicit credentials and writes only an HTML report.

.NOTES
    Author : Windows Security Engineer / Veeam Certified Architect
    Target : Veeam Backup & Replication v13 on Windows Server (LTSC)
    Module : Veeam.Backup.PowerShell

    Reference links (per checklist item) are embedded in each check's Recommendation field.
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Credentials for Connect-VBRServer (remote / explicit auth).')]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential,

    [Parameter(HelpMessage = 'VBR server to connect to. Defaults to localhost.')]
    [string]$VBRServer = 'localhost',

    [Parameter(HelpMessage = 'Directory for the compliance report(s).')]
    [string]$ReportPath = (Get-Location).Path,

    [Parameter(HelpMessage = 'Report format.')]
    [ValidateSet('HTML', 'CSV', 'Both')]
    [string]$ReportFormat = 'Both',

    [Parameter(HelpMessage = 'Latest known VBR v13 build (see KB2680).')]
    [string]$LatestKnownVbrBuild = '13.0.0.4967'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ----------------------------------------------------------------------- Infrastructure

# Master results collection. Every check appends a [PSCustomObject] here.
$script:Results = [System.Collections.Generic.List[object]]::new()

# Tracks whether we successfully opened a Veeam SDK session (so we can skip / warn on
# VBR-dependent checks and disconnect cleanly at the end).
$script:VbrConnected = $false

<#
    Add-AuditResult
    ---------------
    Central factory for the required PSCustomObject shape and the single point of
    color-coded live console output. Every individual check calls this exactly once.
#>
function Add-AuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Topic,
        [Parameter(Mandatory)][string]$RuleName,
        [Parameter(Mandatory)][ValidateSet('Passed', 'Failed', 'Warning', 'Error', 'Info')][string]$Status,
        [Parameter()][string]$CurrentValue = 'N/A',
        [Parameter()][string]$Recommendation = ''
    )

    $result = [PSCustomObject]@{
        Topic            = $Topic
        'Rule Name'      = $RuleName
        Status           = $Status
        'Current Value'  = $CurrentValue
        Recommendation   = $Recommendation
    }
    $script:Results.Add($result)

    # Live, color-coded feedback (Green pass / Red fail / Yellow warning / etc.).
    $color = switch ($Status) {
        'Passed'  { 'Green' }
        'Failed'  { 'Red' }
        'Warning' { 'Yellow' }
        'Error'   { 'Magenta' }
        default   { 'Cyan' }
    }
    Write-Host ('  [{0,-7}] ' -f $Status) -ForegroundColor $color -NoNewline
    Write-Host ('{0}' -f $RuleName) -ForegroundColor Gray
    if ($CurrentValue -and $CurrentValue -ne 'N/A') {
        Write-Host ('            -> {0}' -f $CurrentValue) -ForegroundColor DarkGray
    }
    return $result
}

<#
    Get-RegistryValue
    -----------------
    Safe registry read. Returns $null if the key/value is absent instead of throwing,
    so "value not set" can be treated as its own compliance state.
#>
function Get-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

<#
    Get-PropSafe
    ------------
    Returns the first matching property value from an object across a list of candidate
    names (Veeam property names drift across patch levels). Returns $null if none exist.
#>
function Get-PropSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string[]]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $props = ($InputObject | Get-Member -MemberType Properties -ErrorAction SilentlyContinue).Name
    foreach ($candidate in $Name) {
        if ($props -contains $candidate) {
            try { return $InputObject.$candidate } catch { }
        }
    }
    return $null
}

<#
    Test-VeeamCmdlet
    ----------------
    Returns the resolved cmdlet name from a list of candidates (or $null). Lets checks
    tolerate cmdlet renames between builds without failing the whole audit.
#>
function Test-VeeamCmdlet {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Name)
    foreach ($candidate in $Name) {
        $cmd = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Name }
    }
    return $null
}

#endregion

#region ----------------------------------------------------------------------- Pre-flight

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '  Veeam VBR v13 - VDP Cyber Secure Compliance Audit' -ForegroundColor Cyan
Write-Host ('  Host: {0}   Date: {1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan

# --- Administrative privilege check ---------------------------------------------------
# Registry hardening and VBR service inspection require elevation.
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ''
    Write-Warning 'This script must be run in an ELEVATED (Run as Administrator) PowerShell session.'
    Write-Warning 'Registry, service and VBR checks will be unreliable without elevation. Aborting.'
    throw 'Administrative privileges required.'
}
Write-Host "`n[+] Administrative context confirmed." -ForegroundColor Green

# --- Import the Veeam PowerShell module ----------------------------------------------
# v12+/v13 ships the module 'Veeam.Backup.PowerShell'. Older installs used the PSSnapin
# 'VeeamPSSnapIn'. We try the module first, then fall back to the snap-in.
$script:VeeamModuleLoaded = $false
try {
    if (Get-Module -Name 'Veeam.Backup.PowerShell') {
        $script:VeeamModuleLoaded = $true
    }
    elseif (Get-Module -ListAvailable -Name 'Veeam.Backup.PowerShell') {
        Import-Module 'Veeam.Backup.PowerShell' -DisableNameChecking -ErrorAction Stop
        $script:VeeamModuleLoaded = $true
    }
    elseif (Get-PSSnapin -Registered -Name 'VeeamPSSnapIn' -ErrorAction SilentlyContinue) {
        Add-PSSnapin -Name 'VeeamPSSnapIn' -ErrorAction Stop
        $script:VeeamModuleLoaded = $true
    }

    if ($script:VeeamModuleLoaded) {
        Write-Host '[+] Veeam PowerShell module loaded.' -ForegroundColor Green
    }
    else {
        Write-Warning 'Veeam.Backup.PowerShell module not found. VBR-specific checks will be skipped.'
    }
}
catch {
    Write-Warning ('Failed to import the Veeam PowerShell module: {0}' -f $_.Exception.Message)
}

#endregion

#region ----------------------------------------------------------------------- VBR session

<#
    Connect-VbrSession
    ------------------
    Establishes and self-tests a Veeam SDK session against $VBRServer.

    Precedence:
      1. If -Credential supplied  -> connect with it.
      2. Else connect under current user context (non-interactive).
      3. If that fails            -> prompt with Get-Credential and retry once.

    Sets $script:VbrConnected on success. Non-fatal: VBR-dependent checks degrade to
    "Warning" if no session can be opened.
#>
function Connect-VbrSession {
    [CmdletBinding()]
    param()

    if (-not $script:VeeamModuleLoaded) { return }

    $connectCmd = Test-VeeamCmdlet -Name 'Connect-VBRServer'
    if (-not $connectCmd) {
        Write-Warning 'Connect-VBRServer cmdlet unavailable; cannot open a VBR session.'
        return
    }

    # If a live session already exists (e.g. console already open), reuse it.
    $sessCmd = Test-VeeamCmdlet -Name 'Get-VBRServerSession'
    if ($sessCmd) {
        try {
            $existing = & $sessCmd -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host '[+] Reusing existing VBR server session.' -ForegroundColor Green
                $script:VbrConnected = $true
                return
            }
        }
        catch { <# no active session; proceed to connect #> }
    }

    # Attempt 1: explicit credentials, else current context.
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

        # Fallback: prompt interactively (only if no credential was supplied).
        if (-not $Credential) {
            try {
                Write-Host '[*] Prompting for credentials to retry the VBR connection...' -ForegroundColor Yellow
                $promptCred = Get-Credential -Message ("Credentials for VBR server '{0}'" -f $VBRServer)
                if ($promptCred) {
                    Connect-VBRServer -Server $VBRServer -Credential $promptCred -ErrorAction Stop
                    $script:VbrConnected = $true
                }
            }
            catch {
                Write-Warning ('VBR connection retry failed: {0}' -f $_.Exception.Message)
            }
        }
    }

    # Self-test: confirm the session actually responds to a benign query.
    if ($script:VbrConnected) {
        try {
            $null = Get-VBRServer -ErrorAction Stop
            Write-Host '[+] VBR session established and self-test passed.' -ForegroundColor Green
        }
        catch {
            Write-Warning ('VBR session self-test failed: {0}' -f $_.Exception.Message)
            $script:VbrConnected = $false
        }
    }
}

Connect-VbrSession

#endregion

#region ----------------------------------------------------------------------- 1. Components

function Invoke-ComponentChecks {
    Write-Host "`n--- 1. Components ---" -ForegroundColor White

    # 1.1 NTLM deprecation in favour of Kerberos ---------------------------------------
    # LmCompatibilityLevel 5 = "Send NTLMv2 response only. Refuse LM & NTLM."
    # RestrictSendingNTLMTraffic 2 = "Deny all" outbound NTLM (strongest deprecation).
    try {
        $lm  = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
        $restrict = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'

        $lmText = if ($null -eq $lm) { 'not set (OS default = 3)' } else { $lm }
        $restrictText = switch ($restrict) {
            0       { 'Allow all' }
            1       { 'Audit all' }
            2       { 'Deny all' }
            $null   { 'not set' }
            default { "$restrict" }
        }

        if ($restrict -eq 2 -or $lm -ge 5) {
            $status = 'Passed'
        }
        elseif ($lm -ge 3) {
            $status = 'Warning'
        }
        else {
            $status = 'Failed'
        }

        Add-AuditResult -Topic 'Components' -RuleName 'NTLM authentication deprecated in favour of Kerberos' `
            -Status $status `
            -CurrentValue ("LmCompatibilityLevel={0}; RestrictSendingNTLMTraffic={1}" -f $lmText, $restrictText) `
            -Recommendation 'Set LmCompatibilityLevel=5 and RestrictSendingNTLMTraffic=2 (Deny all) so only Kerberos/NTLMv2 is honoured. Validate no service breakage first.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Components' -RuleName 'NTLM authentication deprecated in favour of Kerberos' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Unable to read LSA registry keys; verify manually.' | Out-Null
    }

    # 1.2 OS patching + Veeam Updater --------------------------------------------------
    # Windows Update recency via Get-HotFix, plus presence of a Veeam Updater
    # service / scheduled task. (Ref: TechNet Windows Server patching best practices.)
    try {
        $latestHotfix = Get-HotFix -ErrorAction Stop |
            Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1

        $daysSince = if ($latestHotfix) { (New-TimeSpan -Start $latestHotfix.InstalledOn -End (Get-Date)).Days } else { $null }

        # Veeam Updater surfaces as a service (VeeamUpdaterSvc / Veeam.Updater) and/or a
        # scheduled task. Detect either.
        $updaterSvc = Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'Updater' -and $_.DisplayName -match 'Veeam' }
        $updaterTask = $null
        if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $updaterTask = Get-ScheduledTask -ErrorAction SilentlyContinue |
                Where-Object { $_.TaskName -match 'Veeam' -and $_.TaskName -match 'Update' }
        }

        $hotfixText = if ($latestHotfix) {
            "Last hotfix {0} on {1} ({2} days ago)" -f $latestHotfix.HotFixID, $latestHotfix.InstalledOn.ToString('yyyy-MM-dd'), $daysSince
        } else { 'No dated hotfixes found' }
        $updaterText = "Veeam Updater service: {0}; scheduled task: {1}" -f `
            $(if ($updaterSvc) { 'present' } else { 'absent' }), `
            $(if ($updaterTask) { 'present' } else { 'absent' })

        if ($daysSince -ne $null -and $daysSince -le 35 -and ($updaterSvc -or $updaterTask)) {
            $status = 'Passed'
        }
        elseif ($daysSince -ne $null -and $daysSince -le 35) {
            $status = 'Warning'
        }
        else {
            $status = 'Failed'
        }

        Add-AuditResult -Topic 'Components' -RuleName 'OS patched / auto-update via Veeam Updater' `
            -Status $status -CurrentValue ("{0}. {1}" -f $hotfixText, $updaterText) `
            -Recommendation 'Keep OS patched within one cycle (<=35 days) and configure the Veeam Updater service/task for continuous component patching.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Components' -RuleName 'OS patched / auto-update via Veeam Updater' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Verify Windows Update and Veeam Updater configuration manually.' | Out-Null
    }

    # 1.3 LTS / LTSC OS build ----------------------------------------------------------
    # Cross-reference the running build number against known Windows Server LTSC builds.
    # (Ref: helpcenter.veeam.com platform_support ver=13.)
    try {
        $os    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build = [int]($os.BuildNumber)

        # Known Windows Server LTSC build numbers.
        $ltscBuilds = @{
            14393 = 'Windows Server 2016 (LTSC)'
            17763 = 'Windows Server 2019 (LTSC)'
            20348 = 'Windows Server 2022 (LTSC)'
            26100 = 'Windows Server 2025 (LTSC)'
        }

        if ($ltscBuilds.ContainsKey($build)) {
            Add-AuditResult -Topic 'Components' -RuleName 'OS is a supported LTS/LTSC build' `
                -Status 'Passed' -CurrentValue ("{0} (build {1})" -f $ltscBuilds[$build], $build) `
                -Recommendation 'Continue running an LTSC channel OS or Veeam JeOS for backup infrastructure.' | Out-Null
        }
        else {
            Add-AuditResult -Topic 'Components' -RuleName 'OS is a supported LTS/LTSC build' `
                -Status 'Warning' -CurrentValue ("{0} (build {1}) - not a recognised LTSC build" -f $os.Caption, $build) `
                -Recommendation 'Backup infrastructure should run an LTSC Windows Server build (2016/2019/2022/2025) or Veeam JeOS, not the Semi-Annual Channel.' | Out-Null
        }
    }
    catch {
        Add-AuditResult -Topic 'Components' -RuleName 'OS is a supported LTS/LTSC build' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Confirm OS edition/build against the Veeam v13 platform support matrix.' | Out-Null
    }

    # 1.4 Veeam software version -------------------------------------------------------
    # Prefer the SDK; fall back to the Core DLL file version, then the registry.
    # (Ref: veeam.com/kb2680 for the latest v13 build.)
    try {
        $installedBuild = $null
        $source = ''

        # (a) Registry-recorded product version (fast, no session required).
        $regBuild = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication' -Name 'CurrentVersion'
        if ($regBuild) { $installedBuild = "$regBuild"; $source = 'registry' }

        # (b) File version of Veeam.Backup.Core.dll (authoritative build).
        if (-not $installedBuild) {
            $corePath = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication' -Name 'CorePath'
            if ($corePath) {
                $coreDll = Join-Path $corePath 'Veeam.Backup.Core.dll'
                if (Test-Path -LiteralPath $coreDll) {
                    $installedBuild = (Get-Item -LiteralPath $coreDll).VersionInfo.ProductVersion
                    $source = 'Veeam.Backup.Core.dll'
                }
            }
        }

        if ($installedBuild) {
            # Compare against the operator-supplied latest known build.
            $isCurrent = $false
            try {
                $installedVer = [version](($installedBuild -split '\s')[0])
                $latestVer    = [version]$LatestKnownVbrBuild
                $isCurrent    = $installedVer -ge $latestVer
            } catch { }

            Add-AuditResult -Topic 'Components' -RuleName 'Veeam VBR software is on the latest v13 build' `
                -Status $(if ($isCurrent) { 'Passed' } else { 'Warning' }) `
                -CurrentValue ("Installed {0} (via {1}); latest known {2}" -f $installedBuild, $source, $LatestKnownVbrBuild) `
                -Recommendation 'Cross-check the installed build against KB2680 and apply the latest v13 cumulative patch.' | Out-Null
        }
        else {
            Add-AuditResult -Topic 'Components' -RuleName 'Veeam VBR software is on the latest v13 build' `
                -Status 'Warning' -CurrentValue 'VBR build could not be determined' `
                -Recommendation 'Confirm VBR is installed and compare its build to KB2680.' | Out-Null
        }
    }
    catch {
        Add-AuditResult -Topic 'Components' -RuleName 'Veeam VBR software is on the latest v13 build' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Determine VBR build manually and compare to KB2680.' | Out-Null
    }
}

#endregion

#region ----------------------------------------------------------------------- 2. Windows Build hardening

function Invoke-WindowsBuildChecks {
    Write-Host "`n--- 2. Components - Windows Build (hardening baseline) ---" -ForegroundColor White

    # Helper: evaluate a Windows service's start mode against "should be disabled".
    function Test-ServiceDisabled {
        param([string]$RuleName, [string]$ServiceName, [string]$Recommendation, [string]$Severity = 'Failed')
        try {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $svc) {
                Add-AuditResult -Topic 'Components - Windows Build' -RuleName $RuleName `
                    -Status 'Passed' -CurrentValue "Service '$ServiceName' not present" `
                    -Recommendation $Recommendation | Out-Null
                return
            }
            # StartType Disabled is the compliant state.
            $startType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop).StartMode
            $isDisabled = $startType -eq 'Disabled'
            Add-AuditResult -Topic 'Components - Windows Build' -RuleName $RuleName `
                -Status $(if ($isDisabled) { 'Passed' } else { $Severity }) `
                -CurrentValue ("StartMode={0}; Status={1}" -f $startType, $svc.Status) `
                -Recommendation $Recommendation | Out-Null
        }
        catch {
            Add-AuditResult -Topic 'Components - Windows Build' -RuleName $RuleName `
                -Status 'Error' -CurrentValue $_.Exception.Message -Recommendation $Recommendation | Out-Null
        }
    }

    # 2.1 Remote Registry service disabled (Required).
    Test-ServiceDisabled -RuleName 'Remote Registry (RemoteRegistry) disabled' `
        -ServiceName 'RemoteRegistry' `
        -Recommendation 'Disable the Remote Registry service on VBR components (Veeam Cyber Secure registry hardening).' -Severity 'Failed'

    # 2.2 WinRM disabled (Advised).
    Test-ServiceDisabled -RuleName 'Windows Remote Management (WinRM) disabled' `
        -ServiceName 'WinRM' `
        -Recommendation 'Disable WinRM on backup infrastructure unless explicitly required for management.' -Severity 'Warning'

    # 2.3 WPAD / Web Proxy Auto-Discovery disabled (Advised).
    Test-ServiceDisabled -RuleName 'Web Proxy Auto-Discovery (WinHttpAutoProxySvc) disabled' `
        -ServiceName 'WinHttpAutoProxySvc' `
        -Recommendation 'Disable the WPAD service to prevent proxy hijacking attacks.' -Severity 'Warning'

    # 2.4 WDigest credential caching disabled (Advised).
    # UseLogonCredential must be 0 (Win2016+ default) so plaintext creds are not cached.
    try {
        $wdigest = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
        $compliant = ($wdigest -eq 0) -or ($null -eq $wdigest)  # absent = secure default on modern OS
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'WDigest credential caching disabled' `
            -Status $(if ($compliant) { 'Passed' } else { 'Warning' }) `
            -CurrentValue ("UseLogonCredential={0}" -f $(if ($null -eq $wdigest) { 'not set (secure default)' } else { $wdigest })) `
            -Recommendation 'Explicitly set WDigest\UseLogonCredential=0 to prevent plaintext credential caching in LSASS.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'WDigest credential caching disabled' `
            -Status 'Error' -CurrentValue $_.Exception.Message -Recommendation 'Verify WDigest hardening manually.' | Out-Null
    }

    # 2.5 Windows Script Host disabled (Advised).
    try {
        $wsh = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled'
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'Windows Script Host disabled' `
            -Status $(if ($wsh -eq 0) { 'Passed' } else { 'Warning' }) `
            -CurrentValue ("WSH Enabled={0}" -f $(if ($null -eq $wsh) { 'not set (enabled)' } else { $wsh })) `
            -Recommendation 'Set Windows Script Host\Settings\Enabled=0 to block .vbs/.js execution vectors.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'Windows Script Host disabled' `
            -Status 'Error' -CurrentValue $_.Exception.Message -Recommendation 'Verify WSH hardening manually.' | Out-Null
    }

    # 2.6 LLMNR disabled (Advised).
    try {
        $llmnr = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'Link-Local Multicast Name Resolution (LLMNR) disabled' `
            -Status $(if ($llmnr -eq 0) { 'Passed' } else { 'Warning' }) `
            -CurrentValue ("DNSClient\EnableMulticast={0}" -f $(if ($null -eq $llmnr) { 'not set (LLMNR enabled)' } else { $llmnr })) `
            -Recommendation 'Set DNSClient\EnableMulticast=0 (GPO) to disable LLMNR and reduce name-poisoning risk.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'Link-Local Multicast Name Resolution (LLMNR) disabled' `
            -Status 'Error' -CurrentValue $_.Exception.Message -Recommendation 'Verify LLMNR hardening manually.' | Out-Null
    }

    # 2.7 SMBv1 disabled (Required - NIST outdated-protocol guidance).
    try {
        $smb1 = $null
        if (Get-Command -Name Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
        }
        if ($null -ne $smb1) {
            Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'SMB 1.0 protocol disabled' `
                -Status $(if (-not $smb1) { 'Passed' } else { 'Failed' }) `
                -CurrentValue ("EnableSMB1Protocol={0}" -f $smb1) `
                -Recommendation 'Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false) per NIST outdated-protocol guidance.' | Out-Null
        }
        else {
            Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'SMB 1.0 protocol disabled' `
                -Status 'Warning' -CurrentValue 'Unable to query SMB server configuration' `
                -Recommendation 'Confirm SMBv1 is removed / disabled.' | Out-Null
        }
    }
    catch {
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'SMB 1.0 protocol disabled' `
            -Status 'Error' -CurrentValue $_.Exception.Message -Recommendation 'Verify SMBv1 status manually.' | Out-Null
    }

    # 2.8 SSL 2.0 disabled (Required - NIST SP 800-52r2).
    try {
        $ssl2Server = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'Enabled'
        # 0 (or 0xFFFFFFFF disabled semantics) = disabled. Absent = OS default (disabled on modern Server).
        $ssl2Disabled = ($ssl2Server -eq 0)
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'SSL 2.0 protocol disabled' `
            -Status $(if ($ssl2Disabled) { 'Passed' } else { 'Warning' }) `
            -CurrentValue ("SCHANNEL SSL 2.0\Server\Enabled={0}" -f $(if ($null -eq $ssl2Server) { 'not set (default)' } else { $ssl2Server })) `
            -Recommendation 'Explicitly disable SSL 2.0/3.0 in SCHANNEL and enforce TLS 1.2+ per NIST SP 800-52r2.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'SSL 2.0 protocol disabled' `
            -Status 'Error' -CurrentValue $_.Exception.Message -Recommendation 'Verify SCHANNEL protocol hardening manually.' | Out-Null
    }

    # 2.9 RDP disabled on the VBR server (Required).
    # fDenyTSConnections = 1 means RDP is denied (compliant for a hardened backup server).
    try {
        $denyRdp = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'RDP disabled on the VBR server' `
            -Status $(if ($denyRdp -eq 1) { 'Passed' } else { 'Failed' }) `
            -CurrentValue ("fDenyTSConnections={0}" -f $(if ($null -eq $denyRdp) { 'not set (RDP allowed)' } else { $denyRdp })) `
            -Recommendation 'Set fDenyTSConnections=1 to disable RDP on the backup server; use console/jump-host access only.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Components - Windows Build' -RuleName 'RDP disabled on the VBR server' `
            -Status 'Error' -CurrentValue $_.Exception.Message -Recommendation 'Verify RDP is disabled manually.' | Out-Null
    }
}

#endregion

#region ----------------------------------------------------------------------- 3. Repositories

function Invoke-RepositoryChecks {
    Write-Host "`n--- 3. Repositories (immutability / hardened) ---" -ForegroundColor White

    if (-not $script:VbrConnected) {
        Add-AuditResult -Topic 'Repositories' -RuleName 'Hardened / immutable repository configuration' `
            -Status 'Warning' -CurrentValue 'No VBR session' `
            -Recommendation 'Establish a VBR connection to enumerate repositories (Get-VBRBackupRepository).' | Out-Null
        return
    }

    try {
        # Get-VBRBackupRepository returns each backup repository object. Immutability and
        # hardening surface on the object under a few property names depending on repo
        # type (Linux hardened repo vs object storage). We probe defensively.
        $repos = @(Get-VBRBackupRepository -ErrorAction Stop)

        # Include object storage repositories (S3/Azure/etc.) if the cmdlet exists.
        $objCmd = Test-VeeamCmdlet -Name 'Get-VBRObjectStorageRepository'
        if ($objCmd) {
            $repos += @(& $objCmd -ErrorAction SilentlyContinue)
        }

        if (-not $repos -or $repos.Count -eq 0) {
            Add-AuditResult -Topic 'Repositories' -RuleName 'At least one immutable / hardened repository' `
                -Status 'Failed' -CurrentValue 'No repositories configured' `
                -Recommendation 'Configure at least one hardened Linux (XFS) or immutable object-lock repository.' | Out-Null
            return
        }

        $immutableCount = 0
        foreach ($repo in $repos) {
            # Immutability flag candidates across repo types / builds.
            $isImmutable = Get-PropSafe -InputObject $repo -Name @(
                'IsImmutabilityEnabled', 'ImmutabilityEnabled', 'IsImmutable', 'BackupImmutabilityEnabled'
            )
            # Immutability retention (days) if exposed.
            $immutableDays = Get-PropSafe -InputObject $repo -Name @(
                'ImmutabilityPeriod', 'ImmutabilityDays', 'ImmutabilityInterval'
            )
            # Hardened-repo indicator (Linux single-use credentials / XFS fast clone).
            $isHardened = Get-PropSafe -InputObject $repo -Name @('IsHardened', 'UseHardenedRepository')

            $repoName = Get-PropSafe -InputObject $repo -Name @('Name', 'FriendlyName')
            $repoType = Get-PropSafe -InputObject $repo -Name @('Type', 'TypeDisplay')

            $immutableTrue = ($isImmutable -eq $true)
            if ($immutableTrue) { $immutableCount++ }

            $detail = "Type={0}; Immutable={1}{2}{3}" -f `
                $repoType, `
                $(if ($null -eq $isImmutable) { 'unknown' } else { $isImmutable }), `
                $(if ($immutableDays) { "; Period=$immutableDays" } else { '' }), `
                $(if ($isHardened -eq $true) { '; Hardened=True' } else { '' })

            Add-AuditResult -Topic 'Repositories' -RuleName ("Repository immutability: {0}" -f $repoName) `
                -Status $(if ($immutableTrue) { 'Passed' } else { 'Warning' }) `
                -CurrentValue $detail `
                -Recommendation 'Enable immutability (hardened XFS repo or object-lock in Compliance mode) on production repositories.' | Out-Null
        }

        # Roll-up: the checklist requires at least one immutable repository.
        Add-AuditResult -Topic 'Repositories' -RuleName 'At least one immutable repository present' `
            -Status $(if ($immutableCount -ge 1) { 'Passed' } else { 'Failed' }) `
            -CurrentValue ("{0} of {1} repositories immutable" -f $immutableCount, $repos.Count) `
            -Recommendation 'Maintain at least one immutable copy (3-2-1-1-0). Prefer S3 Object Lock Compliance mode or a hardened Linux repository.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Repositories' -RuleName 'Hardened / immutable repository configuration' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Verify repository immutability via the VBR console.' | Out-Null
    }
}

#endregion

#region ----------------------------------------------------------------------- 4. Accounts & Permissions

function Invoke-AccountChecks {
    Write-Host "`n--- 4. Accounts and Permissions ---" -ForegroundColor White

    # 4.1 Local Administrators least-privilege review ----------------------------------
    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $names  = $admins | ForEach-Object { $_.Name }
        # Flag domain (non-local) principals - highlighted for least-privilege review.
        $domainMembers = @($admins | Where-Object { $_.PrincipalSource -eq 'ActiveDirectory' })

        # Isolated backup servers should have a minimal, mostly-local admin footprint.
        $status = if ($domainMembers.Count -eq 0 -and $admins.Count -le 3) {
            'Passed'
        } elseif ($domainMembers.Count -gt 0) {
            'Warning'
        } else {
            'Warning'
        }

        Add-AuditResult -Topic 'Accounts and Permissions' -RuleName 'Local Administrators group follows least privilege' `
            -Status $status `
            -CurrentValue ("{0} member(s): {1}{2}" -f $admins.Count, ($names -join ', '), `
                $(if ($domainMembers) { " | Domain members: " + (($domainMembers.Name) -join ', ') } else { '' })) `
            -Recommendation 'Remove high-privilege domain accounts from the local Administrators group; use restricted local / managed service accounts for VBR.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Accounts and Permissions' -RuleName 'Local Administrators group follows least privilege' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Review local Administrators membership manually.' | Out-Null
    }

    # 4.2 Veeam RBAC / security roles --------------------------------------------------
    if (-not $script:VbrConnected) {
        Add-AuditResult -Topic 'Accounts and Permissions' -RuleName 'Veeam RBAC roles follow least privilege' `
            -Status 'Warning' -CurrentValue 'No VBR session' `
            -Recommendation 'Establish a VBR connection to enumerate RBAC roles.' | Out-Null
        return
    }

    try {
        # Get-VBRSecurityRole (per the checklist) enumerates the RBAC roles defined in VBR.
        # Cmdlet naming drifts across builds, so resolve from a candidate list.
        $roleCmd = Test-VeeamCmdlet -Name @('Get-VBRSecurityRole', 'Get-VBRRbacRole', 'Get-VBRUserRoleMapping')
        if (-not $roleCmd) {
            Add-AuditResult -Topic 'Accounts and Permissions' -RuleName 'Veeam RBAC roles follow least privilege' `
                -Status 'Warning' -CurrentValue 'No RBAC cmdlet available in this build' `
                -Recommendation 'Review Users and Roles in the VBR console (Users_and_Roles).' | Out-Null
            return
        }

        $roles = @(& $roleCmd -ErrorAction Stop)

        # Also enumerate explicit user/role assignments where available.
        $assignCmd = Test-VeeamCmdlet -Name @('Get-VBRUserRoleAssignment', 'Get-VBRRbacRoleAssignment')
        $assignments = if ($assignCmd) { @(& $assignCmd -ErrorAction SilentlyContinue) } else { @() }

        # Highlight any assignment that maps a principal to the Administrator role - these
        # deserve scrutiny under least privilege.
        $adminAssignments = @($assignments | Where-Object {
            (Get-PropSafe -InputObject $_ -Name @('Role', 'RoleName')) -match 'Administrator'
        })

        $roleNames = $roles | ForEach-Object { Get-PropSafe -InputObject $_ -Name @('Name', 'RoleName', 'DisplayName') }
        $assignSummary = $assignments | ForEach-Object {
            "{0}->{1}" -f (Get-PropSafe -InputObject $_ -Name @('AccountName', 'Name', 'Account')),
                          (Get-PropSafe -InputObject $_ -Name @('Role', 'RoleName'))
        }

        Add-AuditResult -Topic 'Accounts and Permissions' -RuleName 'Veeam RBAC roles follow least privilege' `
            -Status $(if ($adminAssignments.Count -le 2) { 'Passed' } else { 'Warning' }) `
            -CurrentValue ("Roles: {0}. Assignments: {1}" -f `
                $(if ($roleNames) { ($roleNames -join ', ') } else { 'n/a' }), `
                $(if ($assignSummary) { ($assignSummary -join '; ') } else { 'none enumerated' })) `
            -Recommendation 'Assign granular RBAC roles (Backup/Restore Operator) instead of Administrator; limit Administrator-role principals and enforce four-eyes for critical operations.' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Accounts and Permissions' -RuleName 'Veeam RBAC roles follow least privilege' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Review Veeam Users and Roles manually.' | Out-Null
    }
}

#endregion

#region ----------------------------------------------------------------------- 5. Encryption

function Invoke-EncryptionChecks {
    Write-Host "`n--- 5. Encryption ---" -ForegroundColor White

    if (-not $script:VbrConnected) {
        Add-AuditResult -Topic 'Encryption' -RuleName 'Backup job / network / KMS encryption' `
            -Status 'Warning' -CurrentValue 'No VBR session' `
            -Recommendation 'Establish a VBR connection to evaluate encryption settings.' | Out-Null
        return
    }

    # 5.1 Backup job encryption --------------------------------------------------------
    try {
        # Get-VBRJob returns all configured jobs. Storage-level encryption lives on the
        # job's options object: (Get-VBRJobOptions $job).BackupStorageOptions.StorageEncryptionEnabled.
        $jobs = @(Get-VBRJob -ErrorAction Stop)

        if (-not $jobs -or $jobs.Count -eq 0) {
            Add-AuditResult -Topic 'Encryption' -RuleName 'Backup jobs are encrypted' `
                -Status 'Warning' -CurrentValue 'No backup jobs found' `
                -Recommendation 'Enable storage-level encryption on every backup job.' | Out-Null
        }
        else {
            $encrypted = 0; $unencrypted = @()
            foreach ($job in $jobs) {
                $enc = $null
                try {
                    $opts = Get-VBRJobOptions -Job $job -ErrorAction Stop
                    # BackupStorageOptions.StorageEncryptionEnabled is the canonical flag.
                    $storageOpts = Get-PropSafe -InputObject $opts -Name @('BackupStorageOptions')
                    $enc = Get-PropSafe -InputObject $storageOpts -Name @('StorageEncryptionEnabled', 'EncryptionEnabled')
                }
                catch { }
                # Fallback: some job objects expose encryption on the info/description.
                if ($null -eq $enc) {
                    $enc = Get-PropSafe -InputObject $job -Name @('IsEncrypted', 'EncryptionEnabled')
                }

                $jobName = Get-PropSafe -InputObject $job -Name @('Name')
                if ($enc -eq $true) { $encrypted++ } else { $unencrypted += $jobName }
            }

            Add-AuditResult -Topic 'Encryption' -RuleName 'Backup jobs are encrypted' `
                -Status $(if ($unencrypted.Count -eq 0) { 'Passed' } else { 'Failed' }) `
                -CurrentValue ("{0} of {1} jobs encrypted{2}" -f $encrypted, $jobs.Count, `
                    $(if ($unencrypted) { '. Unencrypted: ' + ($unencrypted -join ', ') } else { '' })) `
                -Recommendation 'Enable AES-256 storage encryption on all backup jobs; store passwords in a KMS / secure vault.' | Out-Null
        }
    }
    catch {
        Add-AuditResult -Topic 'Encryption' -RuleName 'Backup jobs are encrypted' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Review per-job encryption in the VBR console.' | Out-Null
    }

    # 5.2 Network traffic encryption ---------------------------------------------------
    try {
        # Get-VBRNetworkTrafficRule returns global network traffic rules; each exposes an
        # EncryptionEnabled flag governing in-flight encryption between components.
        $ruleCmd = Test-VeeamCmdlet -Name 'Get-VBRNetworkTrafficRule'
        if ($ruleCmd) {
            $rules = @(& $ruleCmd -ErrorAction Stop)
            $encRules = @($rules | Where-Object { (Get-PropSafe -InputObject $_ -Name @('EncryptionEnabled')) -eq $true })
            Add-AuditResult -Topic 'Encryption' -RuleName 'Backup network traffic is encrypted' `
                -Status $(if ($rules.Count -gt 0 -and $encRules.Count -eq $rules.Count) { 'Passed' } elseif ($encRules.Count -gt 0) { 'Warning' } else { 'Failed' }) `
                -CurrentValue ("{0} of {1} traffic rule(s) enforce encryption" -f $encRules.Count, $rules.Count) `
                -Recommendation 'Add/verify a network traffic rule that encrypts traffic between proxies, repositories, gateways and object stores.' | Out-Null
        }
        else {
            Add-AuditResult -Topic 'Encryption' -RuleName 'Backup network traffic is encrypted' `
                -Status 'Warning' -CurrentValue 'Get-VBRNetworkTrafficRule unavailable' `
                -Recommendation 'Verify network traffic encryption rules in the VBR console.' | Out-Null
        }
    }
    catch {
        Add-AuditResult -Topic 'Encryption' -RuleName 'Backup network traffic is encrypted' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Verify network traffic encryption manually.' | Out-Null
    }

    # 5.3 KMS integration --------------------------------------------------------------
    try {
        # Get-VBRKMSServer (v12.1+) lists configured Key Management Systems used to store
        # encryption keys outside the VBR configuration database.
        $kmsCmd = Test-VeeamCmdlet -Name @('Get-VBRKMSServer', 'Get-VBRKMSInfo')
        if ($kmsCmd) {
            $kms = @(& $kmsCmd -ErrorAction Stop)
            Add-AuditResult -Topic 'Encryption' -RuleName 'KMS integration for encryption keys' `
                -Status $(if ($kms.Count -gt 0) { 'Passed' } else { 'Warning' }) `
                -CurrentValue ("{0} KMS server(s) configured{1}" -f $kms.Count, `
                    $(if ($kms.Count) { ': ' + (($kms | ForEach-Object { Get-PropSafe -InputObject $_ -Name @('Name','ServerName') }) -join ', ') } else { '' })) `
                -Recommendation 'Store encryption keys in an external KMS rather than only in the VBR configuration database.' | Out-Null
        }
        else {
            Add-AuditResult -Topic 'Encryption' -RuleName 'KMS integration for encryption keys' `
                -Status 'Warning' -CurrentValue 'KMS cmdlet unavailable in this build' `
                -Recommendation 'Confirm KMS integration in the VBR console (encryption_kms).' | Out-Null
        }
    }
    catch {
        Add-AuditResult -Topic 'Encryption' -RuleName 'KMS integration for encryption keys' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Verify KMS integration manually.' | Out-Null
    }
}

#endregion

#region ----------------------------------------------------------------------- 6. Detection

function Invoke-DetectionChecks {
    Write-Host "`n--- 6. Detection (malware / IOC / anomaly) ---" -ForegroundColor White

    if (-not $script:VbrConnected) {
        Add-AuditResult -Topic 'Detection' -RuleName 'Malware / IOC / anomaly detection' `
            -Status 'Warning' -CurrentValue 'No VBR session' `
            -Recommendation 'Establish a VBR connection to evaluate malware detection settings.' | Out-Null
        return
    }

    try {
        # Get-VBRMalwareDetectionOptions (v12.1+/v13) returns the global malware detection
        # configuration object. Property names vary by build, so probe candidates.
        $mdCmd = Test-VeeamCmdlet -Name @('Get-VBRMalwareDetectionOptions', 'Get-VBRMalwareDetection')
        if (-not $mdCmd) {
            Add-AuditResult -Topic 'Detection' -RuleName 'Global malware detection enabled' `
                -Status 'Warning' -CurrentValue 'Malware detection cmdlet unavailable' `
                -Recommendation 'Verify Inline Scan / Guest Indexing malware detection in the VBR console.' | Out-Null
            return
        }

        $md = & $mdCmd -ErrorAction Stop

        # 6.1 Master malware detection toggle.
        $enabled = Get-PropSafe -InputObject $md -Name @('EnableMalwareDetection', 'IsEnabled', 'MalwareDetectionEnabled')
        Add-AuditResult -Topic 'Detection' -RuleName 'Global malware detection enabled' `
            -Status $(if ($enabled -eq $true) { 'Passed' } elseif ($null -eq $enabled) { 'Warning' } else { 'Failed' }) `
            -CurrentValue ("EnableMalwareDetection={0}" -f $(if ($null -eq $enabled) { 'unknown' } else { $enabled })) `
            -Recommendation 'Enable malware detection so restore points are scanned before finalisation.' | Out-Null

        # 6.2 Guest Index + IOC detection.
        $guestIndex = Get-PropSafe -InputObject $md -Name @('EnableGuestIndexAnalysis', 'GuestIndexAnalysisEnabled', 'GuestFileSystemAnalysis')
        $iocEnabled = Get-PropSafe -InputObject $md -Name @('EnableSuspiciousFileDetection', 'IndicatorOfCompromiseEnabled', 'EnableIoCDetection', 'SuspiciousActivityEnabled')
        Add-AuditResult -Topic 'Detection' -RuleName 'Guest Index & IOC (suspicious file) detection enabled' `
            -Status $(if ($guestIndex -eq $true -or $iocEnabled -eq $true) { 'Passed' } elseif ($null -eq $guestIndex -and $null -eq $iocEnabled) { 'Warning' } else { 'Failed' }) `
            -CurrentValue ("GuestIndex={0}; IOC={1}" -f `
                $(if ($null -eq $guestIndex) { 'unknown' } else { $guestIndex }), `
                $(if ($null -eq $iocEnabled) { 'unknown' } else { $iocEnabled })) `
            -Recommendation 'Enable Guest Indexing plus Indicator-of-Compromise / suspicious-file detection tools.' | Out-Null

        # 6.3 Inline entropy / AI-based anomaly detection.
        $entropy = Get-PropSafe -InputObject $md -Name @('EnableInlineEntropyAnalysis', 'InlineEntropyEnabled', 'EnableDataBlockAnalysis', 'EnableInlineScan')
        Add-AuditResult -Topic 'Detection' -RuleName 'Inline entropy / AI-based anomaly detection enabled' `
            -Status $(if ($entropy -eq $true) { 'Passed' } elseif ($null -eq $entropy) { 'Warning' } else { 'Failed' }) `
            -CurrentValue ("InlineEntropyAnalysis={0}" -f $(if ($null -eq $entropy) { 'unknown' } else { $entropy })) `
            -Recommendation 'Enable inline data-block entropy analysis to flag ransomware-style encryption anomalies in real time.' | Out-Null

        # 6.4 Linux workload malware scanning.
        # Linux/agent scanning may live on the global object or a dedicated agent cmdlet.
        $linux = Get-PropSafe -InputObject $md -Name @('EnableLinuxMalwareDetection', 'LinuxWorkloadScanEnabled', 'EnableAgentMalwareDetection')
        Add-AuditResult -Topic 'Detection' -RuleName 'Linux workload malware detection enabled' `
            -Status $(if ($linux -eq $true) { 'Passed' } elseif ($null -eq $linux) { 'Warning' } else { 'Failed' }) `
            -CurrentValue ("LinuxMalwareDetection={0}" -f $(if ($null -eq $linux) { 'unknown - verify agent settings' } else { $linux })) `
            -Recommendation 'Enable malware detection for Linux agents / workloads (agents_malware_detection).' | Out-Null
    }
    catch {
        Add-AuditResult -Topic 'Detection' -RuleName 'Malware / IOC / anomaly detection' `
            -Status 'Error' -CurrentValue $_.Exception.Message `
            -Recommendation 'Review malware detection settings in the VBR console.' | Out-Null
    }
}

#endregion

#region ----------------------------------------------------------------------- Reporting

function Export-ComplianceReport {
    [CmdletBinding()]
    param()

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not (Test-Path -LiteralPath $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }

    # --- CSV ---
    if ($ReportFormat -in @('CSV', 'Both')) {
        $csvFile = Join-Path $ReportPath ("VBR_CyberSecure_Audit_{0}_{1}.csv" -f $env:COMPUTERNAME, $timestamp)
        try {
            $script:Results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Host ("[+] CSV report written: {0}" -f $csvFile) -ForegroundColor Green
        }
        catch {
            Write-Warning ("Failed to write CSV report: {0}" -f $_.Exception.Message)
        }
    }

    # --- HTML ---
    if ($ReportFormat -in @('HTML', 'Both')) {
        $htmlFile = Join-Path $ReportPath ("VBR_CyberSecure_Audit_{0}_{1}.html" -f $env:COMPUTERNAME, $timestamp)
        try {
            $pass = @($script:Results | Where-Object Status -eq 'Passed').Count
            $fail = @($script:Results | Where-Object Status -eq 'Failed').Count
            $warn = @($script:Results | Where-Object Status -eq 'Warning').Count
            $err  = @($script:Results | Where-Object Status -eq 'Error').Count
            $total = $script:Results.Count
            $score = if ($total) { [math]::Round(($pass / $total) * 100, 1) } else { 0 }

            $css = @'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2933;background:#f5f7fa;}
 h1{color:#0b5394;margin-bottom:4px;} h2{color:#334e68;margin-top:28px;}
 .meta{color:#627d98;font-size:13px;margin-bottom:16px;}
 .cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;}
 .card{padding:14px 20px;border-radius:8px;color:#fff;min-width:120px;box-shadow:0 1px 3px rgba(0,0,0,.15);}
 .card b{display:block;font-size:26px;}
 .c-pass{background:#2e8b57;} .c-fail{background:#c0392b;} .c-warn{background:#d68910;}
 .c-err{background:#8e44ad;} .c-score{background:#0b5394;}
 table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1);}
 th{background:#334e68;color:#fff;text-align:left;padding:8px 10px;font-size:13px;}
 td{padding:7px 10px;border-bottom:1px solid #e4e7eb;font-size:13px;vertical-align:top;}
 tr:nth-child(even){background:#f8fafc;}
 .s-Passed{color:#2e8b57;font-weight:bold;} .s-Failed{color:#c0392b;font-weight:bold;}
 .s-Warning{color:#b9770e;font-weight:bold;} .s-Error{color:#8e44ad;font-weight:bold;}
 .s-Info{color:#0b5394;font-weight:bold;}
</style>
'@

            # Load System.Web for HtmlEncode BEFORE using it. If unavailable (Server Core
            # / .NET variations), fall back to a manual character-replacement encoder.
            $useWeb = $false
            try {
                Add-Type -AssemblyName System.Web -ErrorAction Stop
                $useWeb = $true
            } catch { $useWeb = $false }

            function Convert-HtmlEncode {
                param([string]$Text)
                if ($null -eq $Text) { return '' }
                if ($useWeb) { return [System.Web.HttpUtility]::HtmlEncode($Text) }
                return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
            }

            $rows = foreach ($r in $script:Results) {
                $cvEnc = Convert-HtmlEncode $r.'Current Value'
                $rnEnc = Convert-HtmlEncode $r.'Rule Name'
                $rcEnc = Convert-HtmlEncode $r.Recommendation
                "<tr><td>$($r.Topic)</td><td>$rnEnc</td><td class='s-$($r.Status)'>$($r.Status)</td><td>$cvEnc</td><td>$rcEnc</td></tr>"
            }

            $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>VBR v13 Cyber Secure Audit</title>$css</head>
<body>
<h1>Veeam VBR v13 - VDP Cyber Secure Compliance Audit</h1>
<div class="meta">Host: <b>$env:COMPUTERNAME</b> &nbsp;|&nbsp; VBR server: <b>$VBRServer</b> &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
<div class="cards">
 <div class="card c-score">Score<b>$score%</b></div>
 <div class="card c-pass">Passed<b>$pass</b></div>
 <div class="card c-fail">Failed<b>$fail</b></div>
 <div class="card c-warn">Warning<b>$warn</b></div>
 <div class="card c-err">Error<b>$err</b></div>
</div>
<table>
<thead><tr><th>Topic</th><th>Rule Name</th><th>Status</th><th>Current Value</th><th>Recommendation</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
<p class="meta">Report reflects automated checks only. Items marked Warning/Error require manual verification against the VDP v13 Cyber Secure Checklist.</p>
</body></html>
"@
            $html | Out-File -FilePath $htmlFile -Encoding UTF8
            Write-Host ("[+] HTML report written: {0}" -f $htmlFile) -ForegroundColor Green
        }
        catch {
            Write-Warning ("Failed to write HTML report: {0}" -f $_.Exception.Message)
        }
    }
}

#endregion

#region ----------------------------------------------------------------------- Main

try {
    Invoke-ComponentChecks
    Invoke-WindowsBuildChecks
    Invoke-RepositoryChecks
    Invoke-AccountChecks
    Invoke-EncryptionChecks
    Invoke-DetectionChecks
}
finally {
    # Always disconnect the VBR session we opened, then emit reports and summary.
    if ($script:VbrConnected) {
        try {
            if (Test-VeeamCmdlet -Name 'Disconnect-VBRServer') {
                Disconnect-VBRServer -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    Export-ComplianceReport

    # Console summary tally.
    $pass = @($script:Results | Where-Object Status -eq 'Passed').Count
    $fail = @($script:Results | Where-Object Status -eq 'Failed').Count
    $warn = @($script:Results | Where-Object Status -eq 'Warning').Count
    $err  = @($script:Results | Where-Object Status -eq 'Error').Count

    Write-Host "`n===============================================================" -ForegroundColor Cyan
    Write-Host '  Audit summary' -ForegroundColor Cyan
    Write-Host ('  Passed : {0}' -f $pass) -ForegroundColor Green
    Write-Host ('  Failed : {0}' -f $fail) -ForegroundColor Red
    Write-Host ('  Warning: {0}' -f $warn) -ForegroundColor Yellow
    Write-Host ('  Error  : {0}' -f $err)  -ForegroundColor Magenta
    Write-Host '===============================================================' -ForegroundColor Cyan
}

#endregion

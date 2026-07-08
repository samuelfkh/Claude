# VBR v13 Cyber Secure Compliance Audit

`Invoke-VbrCyberSecureAudit.ps1` audits a local (or remote) Veeam Backup & Replication
v13 server on Windows Server against the **Veeam Data Platform (VDP) v13 Cyber Secure
Checklist** (149 items). The Linux **"Components - VSA Build" section (3.1–3.9) is
intentionally excluded** — this script targets VBR on Windows Server. Every item appears
in the report tagged with its **checklist number, exact name, and Compliance level**
(`Required` / `Advised if applicable`, taken verbatim from the worksheet). Items a script
can verify are checked automatically; inherently manual items (physical security,
training, network topology, etc.) are reported with a `Manual` status and guidance, so
the report is a complete mirror of the checklist. Output is a color-coded console summary
plus an HTML/CSV compliance report.

## Requirements

- Windows Server hosting Veeam Backup & Replication **v13**
- Windows PowerShell **5.1** (or PowerShell 7 on the VBR host)
- **Elevated** session (Run as Administrator) — registry, service and VBR checks require it
- `Veeam.Backup.PowerShell` module (installed with VBR) — auto-imported by the script

## Usage

```powershell
# Local audit, current admin context, HTML + CSV report in the current directory
.\Invoke-VbrCyberSecureAudit.ps1

# Remote VBR server with explicit credentials, HTML only
$cred = Get-Credential
.\Invoke-VbrCyberSecureAudit.ps1 -VBRServer 'vbr01.corp.local' -Credential $cred -ReportFormat HTML

# Pin the "latest known" VBR build for the version comparison (see KB2680)
.\Invoke-VbrCyberSecureAudit.ps1 -LatestKnownVbrBuild '13.0.0.4967'
```

### Parameters

| Parameter              | Default            | Purpose                                                        |
|------------------------|--------------------|----------------------------------------------------------------|
| `-Credential`          | *(none)*           | `[PSCredential]` for `Connect-VBRServer` (remote/explicit auth) |
| `-VBRServer`           | `localhost`        | VBR host to connect to                                         |
| `-ReportPath`          | current directory  | Output directory for report(s)                                 |
| `-ReportFormat`        | `Both`             | `HTML`, `CSV`, or `Both`                                       |
| `-IncludeManual`       | `$true`            | Include inherently-manual items; `$false` = script-verifiable only |
| `-LatestKnownVbrBuild` | `13.0.0.4967`      | Reference build for the "up to date" comparison (KB2680)       |

## Authentication flow

1. If `-Credential` is supplied, it is used with `Connect-VBRServer`.
2. Otherwise the script connects under the **current user context** (non-interactive).
3. If that fails, it prompts once via `Get-Credential` and retries.
4. A `Get-VBRServer` self-test confirms the session before the audit runs.

VBR-dependent checks degrade to a **Warning** (not a hard failure) if no session can be
established, so the OS/registry checks still complete.

## Output

Each item is emitted as a `PSCustomObject` (the report shows the checklist number, name
and compliance level):

```
Item # | Compliance | Topic | Rule Name | Status | Current Value | Recommendation
```

Status values: **Passed / Failed / Warning / Error / Manual**. Reports are written as
`VBR_CyberSecure_Audit_<HOST>_<TIMESTAMP>.{html,csv}`. The HTML "Auto Score" =
`Passed / (Passed+Failed+Warning+Error)`, excluding Manual items.

## Checklist coverage (149 items; section 3 VSA Build excluded)

Every numbered item is represented. Highlights of what is **automatically verified**:

| Section                          | Automated checks                                                                                     |
|----------------------------------|------------------------------------------------------------------------------------------------------|
| **1 Components**                 | 1.1 NTLM, 1.2 patch recency + Veeam Updater, 1.3 LTS/LTSC build, 1.4 VBR build (KB2680), 1.5 sole-tenant roles, 1.6 domain separation, 1.8 firewall, 1.9 config-DB encryption, 1.11 TPM/Secure Boot, 1.16 console MFA, 1.18 SSL2/SMB1, 1.19 inactivity timeout, 1.20 naming, 1.21 syslog, 1.23 health check, 1.24 CDP |
| **2 Components – Windows Build** | 2.1/2.8 Defender/AV, 2.3 config-DB backup off-host, 2.4 RemoteRegistry, 2.5 WinRM (StartMode Disabled→Pass / Auto→Fail), 2.6 WDigest, 2.7 WPAD, 2.9 RDP, 2.10 WSH, 2.11 LLMNR |
| **4 Repositories**               | 4.1 object-lock, 4.3 hardened, 4.4 immutable roll-up, 4.10 time services, 4.13 backup copies, 4.15 SOBR capacity tier, 4.18 Linux immutability |
| **5 Accounts and Permissions**   | 5.2 MFA, 5.3/5.31 Security Officer / four-eyes, 5.8/5.32 RBAC roles, 5.9/5.20 local Administrators, 5.21 audit policy, 5.23 password policy, 5.24 lockout policy, 5.26 gMSA |
| **6 Encryption**                 | 6.2 KMS, 6.4 SMB signing/encryption, 6.5 job encryption, 6.6 network encryption, 6.12 repo encryption |
| **7 Operational**                | 7.1 Security/Best-Practice Analyzer presence                                                          |
| **8 NAS-specific**               | 8.2 network encryption rule, 8.3 firewall, 8.5 secondary copy                                         |
| **9 Disaster Recovery**          | 9.6 SureBackup recovery testing                                                                       |
| **10 Detection**                 | 10.1 malware scan, 10.2 entropy, 10.3 suspicious files, 10.11 IOC, 10.14 Linux, 10.16 AI anomaly      |

Remaining items (physical security, staff training, network topology, SAN isolation,
Linux SSH/PAM specifics, process/regimen questions, etc.) are reported as **Manual** with
guidance, since they cannot be determined from the Windows VBR host.

## Notes & limitations

- Uses **defensive property/cmdlet probing** because Veeam SDK object and property names
  can differ across v13 patch levels. Where a cmdlet/property cannot be resolved on the
  running build, the item degrades to **Warning** (not a hard failure).
- Each item runs in its own `try/catch`; a single failing check becomes an `Error` row
  and the rest of the audit still completes.
- `Manual` items require human attestation against the checklist — they are included so
  the report is a complete, traceable mirror of the spreadsheet.
- Local security/audit policy is read via `secedit` and `auditpol`; time source via
  `w32tm`. On non-English or heavily restricted systems these may degrade to `Warning`.
- Always validate hardening changes (e.g. NTLM/SMB/RDP) against service dependencies in a
  maintenance window before enforcing them in production.

# VBR v13 Cyber Secure Compliance Audit

`Invoke-VbrCyberSecureAudit.ps1` automates a subset of the **Veeam Data Platform (VDP)
v13 Cyber Secure Checklist** against a local (or remote) Veeam Backup & Replication v13
server running on Windows Server. It produces a color-coded console summary and an
HTML/CSV compliance report.

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
| `-LatestKnownVbrBuild` | `13.0.0.4967`      | Reference build for the "up to date" comparison (KB2680)       |

## Authentication flow

1. If `-Credential` is supplied, it is used with `Connect-VBRServer`.
2. Otherwise the script connects under the **current user context** (non-interactive).
3. If that fails, it prompts once via `Get-Credential` and retries.
4. A `Get-VBRServer` self-test confirms the session before the audit runs.

VBR-dependent checks degrade to a **Warning** (not a hard failure) if no session can be
established, so the OS/registry checks still complete.

## Output

Each rule is emitted as a `PSCustomObject`:

```
Topic | Rule Name | Status (Passed/Failed/Warning/Error) | Current Value | Recommendation
```

Reports are written as `VBR_CyberSecure_Audit_<HOST>_<TIMESTAMP>.{html,csv}`.

## Checklist coverage

| Topic                         | Checks performed                                                                                  |
|-------------------------------|---------------------------------------------------------------------------------------------------|
| **Components**                | NTLM deprecation (`LmCompatibilityLevel` / `RestrictSendingNTLMTraffic`); OS patch recency + Veeam Updater service/task; LTS/LTSC build cross-reference; VBR build vs. latest (KB2680) |
| **Components – Windows Build**| RemoteRegistry, WinRM, WPAD, WDigest, Windows Script Host, LLMNR, SMBv1, SSL 2.0, RDP hardening    |
| **Repositories**              | `Get-VBRBackupRepository` / object storage immutability & hardening; "≥1 immutable repo" roll-up   |
| **Accounts and Permissions**  | Local Administrators least-privilege review; Veeam RBAC roles/assignments (`Get-VBRSecurityRole`)  |
| **Encryption**                | Per-job storage encryption (`Get-VBRJobOptions`); network traffic encryption rules; KMS integration|
| **Detection**                 | Global malware detection; Guest Index + IOC/suspicious-file; inline entropy / AI anomaly; Linux workload scanning |

## Notes & limitations

- The script uses **defensive property/cmdlet probing** because Veeam SDK object and
  property names can differ across v13 patch levels. Where a property/cmdlet cannot be
  resolved on the running build, the item is reported as **Warning** for manual review
  rather than failing the audit.
- Automated checks cover the technically-verifiable checklist items only. Process,
  physical, and design items (DR runbooks, physical security, syslog/SIEM policy, etc.)
  still require manual attestation.
- Always validate hardening changes (e.g. NTLM/SMB) against service dependencies in a
  maintenance window before enforcing them in production.

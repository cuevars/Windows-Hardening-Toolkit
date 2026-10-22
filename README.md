# Windows Hardening Toolkit

PowerShell scripts that audit and harden **Windows 11** and **Windows Server 2022**
against baseline security controls grouped like the CIS Benchmarks (account policy,
network, system, logging).

| Script | What it does | Changes system? |
|---|---|---|
| `Invoke-WindowsHardeningAudit.ps1` | Runs ~40 checks, prints PASS/FAIL, writes CSV + HTML report with a score | No (read-only) |
| `Set-WindowsHardening.ps1` | Fixes the failing settings; backs up first; supports `-WhatIf` | Yes |

## Usage (run in an elevated PowerShell, in a test VM first)

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-WindowsHardeningAudit.ps1                 # 1. baseline score
.\Set-WindowsHardening.ps1 -WhatIf                 # 2. preview changes
.\Set-WindowsHardening.ps1                         # 3. apply (asks for YES)
.\Set-WindowsHardening.ps1 -IncludeAdvanced        #    optional riskier settings
.\Invoke-WindowsHardeningAudit.ps1                 # 4. after score (reboot first)
```

Reports land in `.\reports`. Backups land in `.\backup_<timestamp>`.

## Restore

```powershell
reg import .\backup_<timestamp>\reg_01.reg
auditpol /restore /file:.\backup_<timestamp>\auditpol_backup.csv
secedit /configure /db restore.sdb /cfg .\backup_<timestamp>\secpol_backup.inf /areas SECURITYPOLICY
```
Registry keys that did not exist before are not removed by a `.reg` import. A VM snapshot is the cleanest rollback.

## Compare against the official standards

This toolkit is a starting baseline, not a replacement for the published standards:

- **CIS Benchmarks** for Windows 11 and Windows Server 2022 (free PDF after registration at cisecurity.org).
  Fill in the `Ref` column of the CSV with the matching control number.
- **CIS-CAT Lite** (free CIS scanner). Check which benchmarks the Lite edition supports.
- **DISA STIGs** and STIG Viewer (free at public.cyber.mil/stigs).
- **Microsoft Security Compliance Toolkit** (Microsoft's own security baselines).

Good exercise: run CIS-CAT or a STIG checklist on the same VM, then compare its
findings to this script's report and note any gaps.

## Notes

- Domain Group Policy overwrites local settings on domain-joined machines.
- Tamper Protection or third-party antivirus can block the Defender checks and changes.
- Check IDs belong to this project, not to CIS or DISA.
- Only run on machines you own or have written approval to change.

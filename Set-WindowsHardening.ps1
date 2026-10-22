#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies baseline security hardening to Windows 11 or Windows Server 2022.

.DESCRIPTION
    Fixes the settings checked by Invoke-WindowsHardeningAudit.ps1. Backs up the
    registry keys, local security policy, and audit policy it touches before
    changing anything. Use -WhatIf first to preview every change.

    Riskier changes (LSA protection, required SMB signing, disabling Print Spooler
    on servers) only run with -IncludeAdvanced.

.EXAMPLE
    .\Set-WindowsHardening.ps1 -WhatIf              # preview only
    .\Set-WindowsHardening.ps1                      # apply baseline
    .\Set-WindowsHardening.ps1 -IncludeAdvanced     # baseline + advanced

.NOTES
    Test in a VM snapshot first. Domain Group Policy will overwrite local settings.
    Do not run on machines you do not own or have written approval to change.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IncludeAdvanced,
    [string]$BackupDir = ".\backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$BackupDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupDir)
$os   = Get-CimInstance Win32_OperatingSystem
$role = if ($os.ProductType -eq 1) { 'Workstation' } else { 'Server' }
$script:LogFile = Join-Path $BackupDir 'hardening_log.txt'

function Write-Log {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
    if (-not $WhatIfPreference -and (Test-Path $BackupDir)) {
        Add-Content -Path $script:LogFile -Value ("{0}  {1}" -f (Get-Date -Format 's'), $Message)
    }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# ---------- settings data ----------
$polSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lsa    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$registrySettings = @(
    @{ Name = 'Disable LLMNR';                       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Prop = 'EnableMulticast'; Value = 0; Advanced = $false; Applies = 'All' }
    @{ Name = 'NTLMv2 only';                         Path = $lsa; Prop = 'LmCompatibilityLevel'; Value = 5; Advanced = $false; Applies = 'All' }
    @{ Name = 'Require NLA for RDP';                 Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Prop = 'UserAuthentication'; Value = 1; Advanced = $false; Applies = 'All' }
    @{ Name = 'Restrict anonymous SAM enumeration';  Path = $lsa; Prop = 'RestrictAnonymousSAM'; Value = 1; Advanced = $false; Applies = 'All' }
    @{ Name = 'Restrict anonymous share enumeration'; Path = $lsa; Prop = 'RestrictAnonymous'; Value = 1; Advanced = $false; Applies = 'All' }
    @{ Name = 'Disallow unencrypted WinRM traffic';  Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Prop = 'AllowUnencryptedTraffic'; Value = 0; Advanced = $false; Applies = 'All' }
    @{ Name = 'Enable UAC';                          Path = $polSys; Prop = 'EnableLUA'; Value = 1; Advanced = $false; Applies = 'All' }
    @{ Name = 'UAC prompt on secure desktop';        Path = $polSys; Prop = 'PromptOnSecureDesktop'; Value = 1; Advanced = $false; Applies = 'All' }
    @{ Name = 'Lock session after 15 min idle';      Path = $polSys; Prop = 'InactivityTimeoutSecs'; Value = 900; Advanced = $false; Applies = 'All' }
    @{ Name = 'Hide last signed-in user';            Path = $polSys; Prop = 'DontDisplayLastUserName'; Value = 1; Advanced = $false; Applies = 'All' }
    @{ Name = 'Disable AutoRun on all drives';       Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Prop = 'NoDriveTypeAutoRun'; Value = 255; Advanced = $false; Applies = 'All' }
    @{ Name = 'Disable WDigest credential caching';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Prop = 'UseLogonCredential'; Value = 0; Advanced = $false; Applies = 'All' }
    @{ Name = 'PowerShell script block logging';     Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Prop = 'EnableScriptBlockLogging'; Value = 1; Advanced = $false; Applies = 'All' }
    @{ Name = 'LSA protection (needs reboot)';       Path = $lsa; Prop = 'RunAsPPL'; Value = 1; Advanced = $true; Applies = 'All' }
)

# Local policy values applied through secedit (single-quoted here-string: no expansion)
$secInf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
PasswordComplexity = 1
EnableGuestAccount = 0
'@

$auditSubcategories = @(
    'Credential Validation', 'User Account Management', 'Security Group Management',
    'Logon', 'Account Lockout', 'Process Creation', 'Audit Policy Change'
)

$commandActions = @(
    @{ Name = 'Password and lockout policy (length 14, history 24, lockout 5 tries / 15 min)'; Advanced = $false; Applies = 'All'; Run = {
        net accounts /minpwlen:14 /uniquepw:24 /maxpwage:365 /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'net accounts failed' }
    } }
    @{ Name = 'Password complexity on, Guest account off'; Advanced = $false; Applies = 'All'; Run = {
        $inf = Join-Path $env:TEMP 'harden_secpol.inf'
        $db  = Join-Path $env:TEMP 'harden_secpol.sdb'
        Set-Content -Path $inf -Value $secInf -Encoding Unicode
        secedit /configure /db $db /cfg $inf /areas SECURITYPOLICY | Out-Null
        $code = $LASTEXITCODE
        Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
        if ($code -ne 0) { throw 'secedit failed' }
    } }
    @{ Name = 'Enable firewall on all profiles, default inbound Block'; Advanced = $false; Applies = 'All'; Run = {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block
    } }
    @{ Name = 'Disable SMBv1 server'; Advanced = $false; Applies = 'All'; Run = {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    } }
    @{ Name = 'Disable Remote Registry service'; Advanced = $false; Applies = 'All'; Run = {
        Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
        Set-Service -Name RemoteRegistry -StartupType Disabled
    } }
    @{ Name = 'Set Security event log to 192 MB'; Advanced = $false; Applies = 'All'; Run = {
        wevtutil sl Security /ms:201326592
        if ($LASTEXITCODE -ne 0) { throw 'wevtutil failed' }
    } }
    @{ Name = 'Enable audit policy (logon, accounts, process creation, policy change)'; Advanced = $false; Applies = 'All'; Run = {
        foreach ($sub in $auditSubcategories) {
            $auditArgs = @('/set', "/subcategory:$sub", '/success:enable', '/failure:enable')
            & auditpol.exe @auditArgs | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $sub" }
        }
    } }
    @{ Name = 'Turn on Defender real-time protection and update signatures'; Advanced = $false; Applies = 'All'; Run = {
        Set-MpPreference -DisableRealtimeMonitoring $false
        try { Update-MpSignature } catch { Write-Warning 'Signature update skipped (offline or blocked).' }
    } }
    @{ Name = 'Require SMB signing (can break old clients)'; Advanced = $true; Applies = 'All'; Run = {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    } }
    @{ Name = 'Disable Print Spooler (skip on print servers)'; Advanced = $true; Applies = 'Server'; Run = {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    } }
)

# ---------- backup ----------
function Backup-State {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    secedit /export /cfg (Join-Path $BackupDir 'secpol_backup.inf') | Out-Null
    $auditBackup = Join-Path $BackupDir 'auditpol_backup.csv'
    auditpol /backup "/file:$auditBackup" | Out-Null
    $i = 0
    $keys = $registrySettings | ForEach-Object { $_.Path } | Sort-Object -Unique
    foreach ($key in $keys) {
        $i++
        $native = $key -replace '^HKLM:\\', 'HKLM\'
        $regFile = Join-Path $BackupDir ('reg_{0:00}.reg' -f $i)
        reg export $native $regFile /y 2>$null | Out-Null   # key may not exist yet; that is fine
    }
    Write-Log "Backup saved to $BackupDir" 'Cyan'
}

# ---------- run ----------
Write-Host ("{0} | {1} | role: {2}" -f $env:COMPUTERNAME, $os.Caption, $role) -ForegroundColor Cyan

if (-not $WhatIfPreference) {
    $answer = Read-Host 'This changes security settings on this machine. Type YES to continue'
    if ($answer -ne 'YES') { Write-Host 'Cancelled.'; return }
    Backup-State
}

$applied = 0; $failed = 0

foreach ($r in $registrySettings) {
    if ($r.Advanced -and -not $IncludeAdvanced) { continue }
    if ($r.Applies -ne 'All' -and $r.Applies -ne $role) { continue }
    if ($PSCmdlet.ShouldProcess("$($r.Path)\$($r.Prop)", "Set $($r.Name) = $($r.Value)")) {
        try   { Set-Reg -Path $r.Path -Name $r.Prop -Value $r.Value; Write-Log "OK      $($r.Name)" 'Green'; $applied++ }
        catch { Write-Log "FAILED  $($r.Name): $($_.Exception.Message)" 'Red'; $failed++ }
    }
}

foreach ($a in $commandActions) {
    if ($a.Advanced -and -not $IncludeAdvanced) { continue }
    if ($a.Applies -ne 'All' -and $a.Applies -ne $role) { continue }
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $a.Name)) {
        try   { & $a.Run; Write-Log "OK      $($a.Name)" 'Green'; $applied++ }
        catch { Write-Log "FAILED  $($a.Name): $($_.Exception.Message)" 'Red'; $failed++ }
    }
}

if (-not $WhatIfPreference) {
    Write-Log ("Done: {0} applied, {1} failed. Reboot, then re-run the audit script." -f $applied, $failed) 'Cyan'
}

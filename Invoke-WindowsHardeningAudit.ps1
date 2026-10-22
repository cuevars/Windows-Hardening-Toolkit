#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Read-only Windows security configuration audit with a PASS/FAIL report.

.DESCRIPTION
    Checks Windows 11 or Windows Server 2022 settings against hardening controls
    grouped the way the CIS Benchmarks are (account policy, network, system,
    logging). Changes nothing. Writes a CSV and an HTML report with a score.

.NOTES
    Check IDs (ACC-01, NET-03, ...) belong to this script. Map them to the control
    numbers in the CIS Benchmark or DISA STIG for your OS using the Ref column
    in the CSV. Language: auditpol checks assume English subcategory names.

.EXAMPLE
    .\Invoke-WindowsHardeningAudit.ps1
    .\Invoke-WindowsHardeningAudit.ps1 -OutputDir C:\Temp\reports
#>
[CmdletBinding()]
param(
    [string]$OutputDir = '.\reports'
)

$ErrorActionPreference = 'Stop'
$null = New-Item -ItemType Directory -Path $OutputDir -Force

$os    = Get-CimInstance Win32_OperatingSystem
$role  = if ($os.ProductType -eq 1) { 'Workstation' } else { 'Server' }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# ---------- helpers ----------
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# Export the local security policy once and read values from it
$infPath = Join-Path $env:TEMP ('secpol_{0}.inf' -f [guid]::NewGuid())
secedit /export /cfg $infPath /areas SECURITYPOLICY | Out-Null
$secpol = @{}
foreach ($line in (Get-Content $infPath)) {
    if ($line -match '^\s*(\w+)\s*=\s*(.+?)\s*$') { $secpol[$Matches[1]] = $Matches[2] }
}
Remove-Item $infPath -Force -ErrorAction SilentlyContinue

function Get-SecpolInt {
    param([string]$Key, [int]$Default = 0)
    if ($secpol.ContainsKey($Key)) { [int]$secpol[$Key] } else { $Default }
}

function Get-AuditSetting {
    param([string]$Subcategory)
    $auditArgs = @('/get', "/subcategory:$Subcategory", '/r')
    $csv = & auditpol.exe @auditArgs | ConvertFrom-Csv
    $csv.'Inclusion Setting'
}

function Test-Result {
    param($Actual, [string]$Op, $Expected)
    if ($null -eq $Actual) { return $false }
    switch ($Op) {
        'eq'    { return ("$Actual" -eq "$Expected") }
        'ge'    { return ([double]$Actual -ge [double]$Expected) }
        'le'    { return ([double]$Actual -le [double]$Expected) }
        'match' { return ("$Actual" -match "$Expected") }
    }
    return $false
}

# ---------- check registry ----------
$checks = New-Object System.Collections.Generic.List[object]
function Add-Check {
    param(
        [string]$Id,
        [string]$Category,
        [string]$Title,
        [scriptblock]$Get,
        $Expected,
        [string]$Op = 'eq',
        [string]$AppliesTo = 'All'
    )
    $checks.Add([pscustomobject]@{
        Id = $Id; Category = $Category; Title = $Title; Get = $Get
        Expected = $Expected; Op = $Op; AppliesTo = $AppliesTo
    })
}

$polSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lsa    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# Account policy
Add-Check 'ACC-01' 'Account Policy' 'Minimum password length' { Get-SecpolInt 'MinimumPasswordLength' } 14 'ge'
Add-Check 'ACC-02' 'Account Policy' 'Password complexity enabled' { Get-SecpolInt 'PasswordComplexity' } 1
Add-Check 'ACC-03' 'Account Policy' 'Password history remembered' { Get-SecpolInt 'PasswordHistorySize' } 24 'ge'
Add-Check 'ACC-04' 'Account Policy' 'Maximum password age (days)' {
    $v = Get-SecpolInt 'MaximumPasswordAge'; if ($v -le 0) { 99999 } else { $v } } 365 'le'
Add-Check 'ACC-05' 'Account Policy' 'Account lockout threshold (1-5 attempts)' {
    $v = Get-SecpolInt 'LockoutBadCount'; if ($v -eq 0) { 999 } else { $v } } 5 'le'
Add-Check 'ACC-06' 'Account Policy' 'Account lockout duration (minutes)' {
    $v = Get-SecpolInt 'LockoutDuration'; if ($v -eq -1) { 99999 } else { $v } } 15 'ge'
Add-Check 'ACC-07' 'Account Policy' 'Guest account disabled' { Get-SecpolInt 'EnableGuestAccount' } 0

# Network
Add-Check 'NET-01' 'Network' 'Windows Firewall enabled (Domain profile)' { (Get-NetFirewallProfile -Name Domain).Enabled } 'True'
Add-Check 'NET-02' 'Network' 'Windows Firewall enabled (Private profile)' { (Get-NetFirewallProfile -Name Private).Enabled } 'True'
Add-Check 'NET-03' 'Network' 'Windows Firewall enabled (Public profile)' { (Get-NetFirewallProfile -Name Public).Enabled } 'True'
Add-Check 'NET-04' 'Network' 'Firewall default inbound action Block (Public)' {
    (Get-NetFirewallProfile -Name Public).DefaultInboundAction } 'Block'
Add-Check 'NET-05' 'Network' 'SMBv1 server disabled' { (Get-SmbServerConfiguration).EnableSMB1Protocol } 'False'
Add-Check 'NET-06' 'Network' 'SMB signing required (server)' { (Get-SmbServerConfiguration).RequireSecuritySignature } 'True'
Add-Check 'NET-07' 'Network' 'LLMNR disabled' {
    Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' } 0
Add-Check 'NET-08' 'Network' 'NTLMv2 only (LmCompatibilityLevel = 5)' { Get-RegValue $lsa 'LmCompatibilityLevel' } 5 'ge'
Add-Check 'NET-09' 'Network' 'RDP requires Network Level Authentication' {
    Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' } 1
Add-Check 'NET-10' 'Network' 'Anonymous SAM enumeration restricted' { Get-RegValue $lsa 'RestrictAnonymousSAM' } 1
Add-Check 'NET-11' 'Network' 'Anonymous share enumeration restricted' { Get-RegValue $lsa 'RestrictAnonymous' } 1 'ge'
Add-Check 'NET-12' 'Network' 'WinRM unencrypted traffic disallowed' {
    Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic' } 0

# System
Add-Check 'SYS-01' 'System' 'Defender real-time protection on' { (Get-MpComputerStatus).RealTimeProtectionEnabled } 'True'
Add-Check 'SYS-02' 'System' 'Defender signatures updated within 7 days' { (Get-MpComputerStatus).AntivirusSignatureAge } 7 'le'
Add-Check 'SYS-03' 'System' 'User Account Control enabled' { Get-RegValue $polSys 'EnableLUA' } 1
Add-Check 'SYS-04' 'System' 'UAC prompts on the secure desktop' { Get-RegValue $polSys 'PromptOnSecureDesktop' } 1
Add-Check 'SYS-05' 'System' 'AutoRun disabled on all drives' {
    Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' } 255
Add-Check 'SYS-06' 'System' 'Inactivity lock within 15 minutes' {
    $v = Get-RegValue $polSys 'InactivityTimeoutSecs'; if (-not $v) { 99999 } else { $v } } 900 'le'
Add-Check 'SYS-07' 'System' 'Last signed-in user not displayed' { Get-RegValue $polSys 'DontDisplayLastUserName' } 1
Add-Check 'SYS-08' 'System' 'Secure Boot enabled' { Confirm-SecureBootUEFI } 'True'
Add-Check 'SYS-09' 'System' 'BitLocker protecting the OS drive' {
    (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus } 'On' 'eq' 'Workstation'
Add-Check 'SYS-10' 'System' 'Remote Registry service disabled' { (Get-Service -Name RemoteRegistry).StartType } 'Disabled'
Add-Check 'SYS-11' 'System' 'Print Spooler disabled (non-print servers)' { (Get-Service -Name Spooler).StartType } 'Disabled' 'eq' 'Server'
Add-Check 'SYS-12' 'System' 'WDigest cleartext credential caching off' {
    $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    if ($null -eq $v) { 0 } else { $v } } 0
Add-Check 'SYS-13' 'System' 'LSA protection (RunAsPPL) enabled' { Get-RegValue $lsa 'RunAsPPL' } 1 'ge'

# Logging and auditing
Add-Check 'LOG-01' 'Logging' 'PowerShell script block logging on' {
    Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' } 1
Add-Check 'LOG-02' 'Logging' 'Security log size at least 192 MB (KB shown)' {
    [math]::Round((Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1KB) } 196608 'ge'
Add-Check 'LOG-03' 'Logging' 'Audit: Credential Validation' { Get-AuditSetting 'Credential Validation' } 'Success and Failure' 'match'
Add-Check 'LOG-04' 'Logging' 'Audit: User Account Management' { Get-AuditSetting 'User Account Management' } 'Success and Failure' 'match'
Add-Check 'LOG-05' 'Logging' 'Audit: Security Group Management' { Get-AuditSetting 'Security Group Management' } 'Success' 'match'
Add-Check 'LOG-06' 'Logging' 'Audit: Logon' { Get-AuditSetting 'Logon' } 'Success and Failure' 'match'
Add-Check 'LOG-07' 'Logging' 'Audit: Account Lockout' { Get-AuditSetting 'Account Lockout' } 'Failure' 'match'
Add-Check 'LOG-08' 'Logging' 'Audit: Process Creation' { Get-AuditSetting 'Process Creation' } 'Success' 'match'
Add-Check 'LOG-09' 'Logging' 'Audit: Audit Policy Change' { Get-AuditSetting 'Audit Policy Change' } 'Success' 'match'

# ---------- run ----------
$results = foreach ($c in $checks) {
    if ($c.AppliesTo -ne 'All' -and $c.AppliesTo -ne $role) { continue }
    $actual = $null
    try { $actual = & $c.Get } catch { $actual = $null }
    $pass = Test-Result -Actual $actual -Op $c.Op -Expected $c.Expected
    $opText = switch ($c.Op) { 'ge' { '>= ' } 'le' { '<= ' } 'match' { 'contains ' } default { '' } }
    [pscustomobject]@{
        Id       = $c.Id
        Category = $c.Category
        Check    = $c.Title
        Expected = "$opText$($c.Expected)"
        Actual   = if ($null -eq $actual) { 'Not configured / unavailable' } else { "$actual" }
        Status   = if ($pass) { 'PASS' } else { 'FAIL' }
        Ref      = ''
    }
}

$total  = @($results).Count
$passed = @($results | Where-Object Status -eq 'PASS').Count
$score  = [math]::Round(($passed / $total) * 100, 1)

Write-Host ''
Write-Host ("{0} | {1} | role: {2}" -f $env:COMPUTERNAME, $os.Caption, $role) -ForegroundColor Cyan
Write-Host ''
foreach ($r in $results) {
    $color = if ($r.Status -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ("[{0}] {1,-10} {2}" -f $r.Status, $r.Id, $r.Check) -ForegroundColor $color
}
Write-Host ''
$results | Group-Object Category | ForEach-Object {
    $p = @($_.Group | Where-Object Status -eq 'PASS').Count
    Write-Host ("{0,-16} {1}/{2}" -f $_.Name, $p, $_.Count)
}
Write-Host ("`nOverall: {0}/{1} passed ({2}%)" -f $passed, $total, $score) -ForegroundColor Cyan

# ---------- reports ----------
$csvPath  = Join-Path $OutputDir "audit_$($env:COMPUTERNAME)_$stamp.csv"
$htmlPath = Join-Path $OutputDir "audit_$($env:COMPUTERNAME)_$stamp.html"
$results | Export-Csv -Path $csvPath -NoTypeInformation

function Enc { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
$rows = foreach ($r in $results) {
    '<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
        $r.Status.ToLower(), (Enc $r.Id), (Enc $r.Category), (Enc $r.Check), (Enc $r.Expected), (Enc $r.Actual), (Enc $r.Status)
}
$html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Hardening Audit - $($env:COMPUTERNAME)</title>
<style>
body { font-family: 'Times New Roman', serif; margin: 24px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #999; padding: 4px 8px; text-align: left; font-size: 13px; }
th { background: #1F3864; color: #fff; }
tr.pass td:last-child { color: #0a7a2f; font-weight: bold; }
tr.fail td:last-child { color: #b00020; font-weight: bold; }
</style></head><body>
<h2>Windows Hardening Audit</h2>
<p>$(Enc $env:COMPUTERNAME) &middot; $(Enc $os.Caption) &middot; $role &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
<p><b>Score: $passed / $total ($score%)</b></p>
<table><tr><th>ID</th><th>Category</th><th>Check</th><th>Expected</th><th>Actual</th><th>Status</th></tr>
$($rows -join "`n")
</table></body></html>
"@
Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Write-Host "`nReports saved:`n  $csvPath`n  $htmlPath"

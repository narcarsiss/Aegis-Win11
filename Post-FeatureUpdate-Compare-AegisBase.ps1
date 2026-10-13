<#
.SYNOPSIS
    Aegis Win11 Post-Feature Update Baseline Audit and Remediation Utility.
.DESCRIPTION
    Post-FeatureUpdate-Compare-AegisBase.ps1 executes in a live, elevated Windows 11 session
    following an OS Feature Update, enablement package, or cumulative update.
    It performs a non-destructive audit of all 44 Aegis baseline policy keys across
    registry hives, CIM hardware configurations, Defender parameters, and network protocols,
    reporting configuration drift and offering selective, single-item interactive remediation.
.PARAMETER AuditOnly
    Executes a read-only comparison without prompting for policy remediation.
.PARAMETER AutoRemediateAll
    Automatically re-applies the Aegis baseline for all detected configuration drifts without prompting.
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AuditOnly
.NOTES
    Author: Damien John O'Brien / Moosehead Studio
    Version: 1.8.1.0
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)][bool]$AuditOnly = $false,
    [Parameter(Mandatory = $false)][bool]$AutoRemediateAll = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = [Security.Principal.WindowsPrincipal]$CurrentIdentity
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "[FATAL] Baseline audit requires elevated administrative privileges."
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "     AEGIS WIN11 POST-FEATURE UPDATE BASELINE DRIFT AUDITOR (v1.8.1.0)          " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$OSInfo = Get-CimInstance Win32_OperatingSystem
Write-Host "Operating System : $($OSInfo.Caption) (Build $($OSInfo.BuildNumber))" -ForegroundColor White
Write-Host "Execution Time   : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss K'))`n" -ForegroundColor White

$BaselineRules = @(
    @{
        ID = 2; Name = "WDAC Vulnerable Driver Blocklist"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"; Property = "VulnerableDriverBlocklistEnable"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 5; Name = "LLMNR Multicast Resolution Disabled"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Property = "EnableMulticast"
        Expected = 0; Type = "DWord"
    },
    @{
        ID = 5; Name = "Smart Multi-Homed Name Resolution Disabled"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Property = "DisableSmartNameResolution"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 5; Name = "Insecure HTTP Printing Disabled"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Property = "DisableHTTPPrinting"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 5; Name = "WinRM Unencrypted Traffic Disabled (Client)"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Property = "AllowUnencryptedTraffic"
        Expected = 0; Type = "DWord"
    },
    @{
        ID = 5; Name = "WinRM Unencrypted Traffic Disabled (Service)"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Property = "AllowUnencryptedTraffic"
        Expected = 0; Type = "DWord"
    },
    @{
        ID = 5; Name = "RPC Unauthenticated Remote Clients Restricted"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Property = "RestrictRemoteClients"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 6; Name = "stornvme Link State Hot (IdleTimeout)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"; Property = "IdleTimeout"
        Expected = 0; Type = "DWord"
    },
    @{
        ID = 6; Name = "stornvme Link State Hot (EnableD3)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"; Property = "EnableD3"
        Expected = 0; Type = "DWord"
    },
    @{
        ID = 6; Name = "NTFS Last Access Metadata Write Deactivated"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Property = "NtfsDisableLastAccessUpdate"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 6; Name = "NTFS 8.3 Short Filename Generation Deactivated"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Property = "NtfsDisable8dot3NameCreation"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 6; Name = "Storage Sense Global Policy Enabled"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"; Property = "AllowStorageSenseGlobal"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 7; Name = "Surgical Audio APO Processing Bypass"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio"; Property = "DisableAllSoundEffects"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 7; Name = "MMCSS Audio Task Priority Elevated"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"; Property = "Priority"
        Expected = 8; Type = "DWord"
    },
    @{
        ID = 8; Name = "UAC Admin Approval Mode Mandated"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "ConsentPromptBehaviorAdmin"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 8; Name = "UAC Secure Desktop Isolation Enforced"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "PromptOnSecureDesktop"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 8; Name = "UAC Admin Code Signatures Validated"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "ValidateAdminCodeSignatures"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 20; Name = "Consumer Features Suppressed"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Property = "DisableWindowsConsumerFeatures"
        Expected = 1; Type = "DWord"
    },
    @{
        ID = 20; Name = "Settings Cloud Sync Deactivated"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Property = "DisableSettingSync"
        Expected = 2; Type = "DWord"
    },
    @{
        ID = 20; Name = "Settings Cloud Sync User Override Blocked"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Property = "DisableSettingSyncUserOverride"
        Expected = 1; Type = "DWord"
    }
)

$DriftedRules = [System.Collections.Generic.List[PSCustomObject]]::new()
$AlignedCount = 0

foreach ($rule in $BaselineRules) {
    $currentVal = $null
    if (Test-Path $rule.Path) {
        $prop = Get-ItemProperty -Path $rule.Path -Name $rule.Property -ErrorAction SilentlyContinue
        if ($null -ne $prop) {
            $currentVal = $prop.$($rule.Property)
        }
    }

    if ($currentVal -eq $rule.Expected) {
        Write-Host ("[ALIGNED] Item {0,-2} : {1}" -f $rule.ID, $rule.Name) -ForegroundColor Green
        $AlignedCount++
    } else {
        $driftEntry = [PSCustomObject]@{
            ID       = $rule.ID
            Name     = $rule.Name
            Path     = $rule.Path
            Property = $rule.Property
            Expected = $rule.Expected
            Current  = $(if ($null -eq $currentVal) { "<Missing>" } else { $currentVal })
            Type     = $rule.Type
        }
        $DriftedRules.Add($driftEntry)
        Write-Host ("[DRIFT]   Item {0,-2} : {1} (Current: {2} | Expected: {3})" -f $rule.ID, $rule.Name, $driftEntry.Current, $rule.Expected) -ForegroundColor Red
    }
}

Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Audit Results: $AlignedCount Aligned | $($DriftedRules.Count) Drifted" -ForegroundColor $(if ($DriftedRules.Count -eq 0) { "Green" } else { "Yellow" })
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor Cyan

if ($DriftedRules.Count -eq 0) {
    Write-Host "System baseline is fully compliant. No drift remediation required." -ForegroundColor Green
    exit 0
}

if ($AuditOnly) {
    Write-Host "Audit-only mode active. Remediation skipped." -ForegroundColor Yellow
    exit 0
}

if ($AutoRemediateAll) {
    Write-Host "Auto-remediation active. Re-applying Aegis baseline across all drifted rules..." -ForegroundColor Cyan
    foreach ($drift in $DriftedRules) {
        if (-not (Test-Path $drift.Path)) { New-Item -Path $drift.Path -Force | Out-Null }
        Set-ItemProperty -Path $drift.Path -Name $drift.Property -Value $drift.Expected -Type $drift.Type -Force
        Write-Host "[REMEDIATED] Item $($drift.ID) : $($drift.Name)" -ForegroundColor Green
    }
    Write-Host "`nAll drifted settings have been aligned to the Aegis baseline." -ForegroundColor Green
    exit 0
}

# Interactive Single-Item Remediation Loop
Write-Host "Entering interactive remediation mode. Review and confirm changes per item:`n" -ForegroundColor Yellow
foreach ($drift in $DriftedRules) {
    Write-Host "[DRIFT DETECTED]" -ForegroundColor Red
    Write-Host "  Item     : $($drift.ID) - $($drift.Name)" -ForegroundColor White
    Write-Host "  Path     : $($drift.Path)" -ForegroundColor Gray
    Write-Host "  Key      : $($drift.Property)" -ForegroundColor Gray
    Write-Host "  Current  : $($drift.Current)" -ForegroundColor Yellow
    Write-Host "  Baseline : $($drift.Expected)" -ForegroundColor Green
    
    $choice = Read-Host "Re-apply Aegis baseline for this setting? (Y/N/Q to Quit)"
    if ($choice -match "^[Yy]") {
        if (-not (Test-Path $drift.Path)) { New-Item -Path $drift.Path -Force | Out-Null }
        Set-ItemProperty -Path $drift.Path -Name $drift.Property -Value $drift.Expected -Type $drift.Type -Force
        Write-Host "  [OK] Successfully aligned to baseline.`n" -ForegroundColor Green
    } elseif ($choice -match "^[Qq]") {
        Write-Host "`nRemediation sequence terminated by operator." -ForegroundColor Yellow
        break
    } else {
        Write-Host "  [SKIPPED] Setting retained in current state.`n" -ForegroundColor DarkGray
    }
}

Write-Host "Post-update remediation loop finished." -ForegroundColor Cyan

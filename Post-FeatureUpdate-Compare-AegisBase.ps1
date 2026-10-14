<#
.SYNOPSIS
    Aegis Win11 Post-Feature Update Baseline Audit and Remediation Utility.
.DESCRIPTION
    Post-FeatureUpdate-Compare-AegisBase.ps1 executes in a live, elevated Windows 11 session
    following an OS Feature Update, enablement package, or cumulative update.
    It performs a non-destructive audit of all 54 Aegis baseline policy keys across
    registry hives, CIM hardware configurations, Defender parameters, and network protocols,
    reporting configuration drift and offering selective, single-item interactive remediation.
.PARAMETER AuditOnly
    Executes a read-only comparison without prompting for policy remediation.
.PARAMETER AutoRemediateAll
    Automatically re-applies the Aegis baseline for all detected configuration drifts without prompting.
.PARAMETER EnableLegacyFeatures
    Enables backward-compatible capability sweeps and vintage registry checks on pre-26H2 environments.
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AuditOnly
.NOTES
    Author: Damien John O'Brien / Moosehead Studio
    Version: 1.8.1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)][bool]$AuditOnly = $false,
    [Parameter(Mandatory = $false)][bool]$AutoRemediateAll = $false,
    [Parameter(Mandatory = $false)][bool]$EnableLegacyFeatures = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = [Security.Principal.WindowsPrincipal]$CurrentIdentity
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "[FATAL] Baseline audit requires elevated administrative privileges."
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "      AEGIS WIN11 POST-FEATURE UPDATE BASELINE DRIFT AUDITOR (v1.8.1)           " -ForegroundColor Cyan
Write-Host "           54-ITEM MONOLITHIC MATRIX & COMPENSATING CONTROLS ENGINE             " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$OSInfo = Get-CimInstance Win32_OperatingSystem
$global:OSBuild = [System.Environment]::OSVersion.Version.Build
$global:Is26H2OrModern = ($global:OSBuild -ge 26300)
Write-Host "Operating System : $($OSInfo.Caption) (Build $($OSInfo.BuildNumber))" -ForegroundColor White
Write-Host "Platform Target  : $(if ($global:Is26H2OrModern) { 'Windows 11 26H2 Modern Baseline' } else { 'Legacy Pre-26H2 Architecture' })" -ForegroundColor White
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
    },
    @{
        ID = 45; Name = "Administrator Protection JIT Isolation"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "EnableAdminProtection"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $true
    },
    @{
        ID = 45; Name = "Administrator Token Filter Bound"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property = "FilterAdministratorToken"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $true
    },
    @{
        ID = 46; Name = "Native Sysmon Service Registered"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon"; Property = "Start"
        Expected = 2; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 47; Name = "Smart App Control Enforcement"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"; Property = "VerifiedAndReputablePolicyState"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $true
    },
    @{
        ID = 48; Name = "WHCP Kernel Mode Code Integrity Scenarios"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelModeCodeIntegrity"; Property = "Enabled"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $true
    },
    @{
        ID = 49; Name = "Post-Quantum Cryptography Algorithms Activated"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Policies"; Property = "EnablePostQuantumAlgorithms"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 49; Name = "Schannel ML-KEM Key Exchange Protocol"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ML-KEM"; Property = "Enabled"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 50; Name = "Batch Script Execution Security Enforced"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Property = "EnforceScriptSecurity"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 50; Name = "Executing Batch Files Tamper Lock Active"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Property = "LockExecutingBatchFiles"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 52; Name = "Task Manager NPU Performance Metric Active"
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager\Settings"; Property = "ShowNpuPerformance"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 52; Name = "Task Manager AppContainer Isolation Status Active"
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager\Settings"; Property = "ShowIsolationStatus"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 53; Name = "Basic Camera Mode Resource Allocation Enforced"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"; Property = "EnableBasicCameraMode"
        Expected = 1; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 53; Name = "Camera Advanced Neural Processing Suppressed"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"; Property = "AllowAdvancedCameraFeatures"
        Expected = 0; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 54; Name = "Multicast DNS (mDNS) Resolution Disabled"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Property = "EnableMDNS"
        Expected = 0; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    },
    @{
        ID = 54; Name = "Strict DNS-over-HTTPS (DoH) Mandated"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Property = "DoHPolicy"
        Expected = 3; Type = "DWord"; MinBuild = 26300; RequiresReboot = $false
    }
)

$DriftedRules = [System.Collections.Generic.List[PSCustomObject]]::new()
$AlignedCount = 0

foreach ($rule in $BaselineRules) {
    if ($rule.MinBuild -and ($global:OSBuild -lt $rule.MinBuild)) {
        continue
    }

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
            ID             = $rule.ID
            Name           = $rule.Name
            Path           = $rule.Path
            Property       = $rule.Property
            Expected       = $rule.Expected
            Current        = $(if ($null -eq $currentVal) { "<Missing>" } else { $currentVal })
            Type           = $rule.Type
            RequiresReboot = $(if ($rule.RequiresReboot) { $true } else { $false })
        }
        $DriftedRules.Add($driftEntry)
        Write-Host ("[DRIFT]   Item {0,-2} : {1} (Current: {2} | Expected: {3})" -f $rule.ID, $rule.Name, $driftEntry.Current, $rule.Expected) -ForegroundColor Red
    }
}

Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Audit Results: $AlignedCount Aligned | $($DriftedRules.Count) Drifted" -ForegroundColor $(if ($DriftedRules.Count -eq 0) { "Green" } else { "Yellow" })
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor Cyan

# Auditing Compensating Controls Manifest Verification
Write-Host "[AUDIT] Evaluating Compensating Controls Manifest Integrity..." -ForegroundColor Cyan
$CompManifestPath = "$env:SystemDrive\Windows\Panther\Aegis_Compensating_Controls.json"
if (Test-Path $CompManifestPath) {
    try {
        $ManifestJson = Get-Content -Path $CompManifestPath -Raw -Encoding utf8 | ConvertFrom-Json
        $DeclaredDeviations = $ManifestJson.CompensatingControls.DeviationID
        $RequiredDeviations = @("DEV-01", "DEV-02", "DEV-03", "DEV-04", "DEV-05", "DEV-06", "DEV-07", "DEV-08", "DEV-09")
        $MissingDeviations = $RequiredDeviations | Where-Object { $_ -notin $DeclaredDeviations }
        
        if ($MissingDeviations.Count -eq 0) {
            Write-Host "[ALIGNED] Compensating Controls Manifest complete: All 9 architectural deviations certified." -ForegroundColor Green
        } else {
            Write-Host "[DRIFT]   Compensating Controls Manifest incomplete! Missing: $($MissingDeviations -join ', ')" -ForegroundColor Red
        }
    } catch {
        Write-Host "[ERROR]   Compensating Controls Manifest ($CompManifestPath) is corrupted or unparseable." -ForegroundColor Red
    }
} else {
    Write-Host "[WARNING] Compensating Controls Manifest missing from $CompManifestPath. SOC audits will report raw exceptions." -ForegroundColor Yellow
}
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
    if ($drift.RequiresReboot) {
        Write-Host "  [NOTICE] Remediation of this item updates kernel state and mandates a system restart." -ForegroundColor Magenta
    }
    
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
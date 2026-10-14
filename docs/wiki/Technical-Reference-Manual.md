# Technical Reference Manual

<!-- AEGIS-METADATA:START
Document-Version: 1.8.0
Document-Type: Technical Reference Documentation
Maintainer: Moosehead Studio
AEGIS-METADATA:END -->

<p align="center">
  <img src="../../assets/aegis-shield-base.png" alt="Aegis shield base" width="25%" />
</p>

**Document revision:** `1.8.0`  
**Maintained by:** Moosehead Studio  
**Target Operating System:** Windows 11 Ent / Edu / Pro / Home.
**Builds** 22H2, 23H2, 24H2, 26H2  

---

### Item 01: Strict Kernel-Mode App Control Policy

> [!CAUTION]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Critical. Strictly blocks kernel-level anti-cheat platforms for competitive gaming (Riot Vanguard, FaceIt, Easy Anti-Cheat) and proprietary ASIO audio interface drivers (Focusrite, Behringer, Universal Audio, RME).  

* **Policy Name:** Strict Kernel-Mode App Control Policy  
* **Target State:** Disabled (Omitted from Baseline)  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`  
* **Configuration Values:** `CodeIntegrityPolicy` = `0` (REG_DWORD)  
* **Technical Function:** Restricts loading of kernel-mode drivers and system binaries exclusively to a static cryptographic whitelist via Code Integrity policies.  
* **Beneficial Use Case:** Provides absolute enforcement against unauthorized kernel execution and unverified drivers.  
* **NOC / Performance Warnings:** Extreme administrative overhead for driver catalog maintenance; halts un-cataloged hardware initialization.  

* **PowerShell Deployment Orchestration:**
```powershell
# Strict Kernel-Mode App Control Policy (Omitted to preserve gaming and studio hardware)
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if (Test-Path $Path) {
    Remove-ItemProperty -Path $Path -Name "CodeIntegrityPolicy" -ErrorAction SilentlyContinue
}
```

---

### Item 02: WDAC App Control Policy (ISG & Driver Blocklists)

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Moderate. Full user-mode Intelligent Security Graph (ISG) enforcement blocks newly compiled developer scripts, local game mods, and niche CAD/DAW plugins lacking cloud prevalence.  

* **Policy Name:** WDAC App Control Policy (Kernel Driver Blocklist Enforced; User-Mode ISG in Audit Mode)  
* **Target State:** Modified Baseline (Kernel Driver Blocklist Active; User-Mode in Audit)  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`  
* **Configuration Values:** `VulnerableDriverBlocklistEnable` = `1` (REG_DWORD)  
* **Technical Function:** Enforces the Microsoft Kernel-Mode Vulnerable Driver Blocklist in silicon while keeping user-mode code integrity unconstrained.  
* **Beneficial Use Case:** Eliminates Bring Your Own Vulnerable Driver (BYOVD) exploitation without breaking local user scripts.  
* **NOC / Performance Warnings:** None for driver blocklist; eliminates ring-0 elevation vectors.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce Microsoft Vulnerable Driver Blocklist (BYOVD Mitigation)
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord -Force
```

---

### Item 03: Incorporate a Windows Defender Known Blocklist

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Safe for gaming, business suites, and creative workstations.  

* **Policy Name:** Incorporate a Windows Defender Known Blocklist  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`  
* **Configuration Values:** `VulnerableDriverBlocklistEnable` = `1` (REG_DWORD)  
* **Technical Function:** Synchronizes kernel blocking with Microsoft's cloud-sourced vulnerable application and driver database.  
* **Beneficial Use Case:** Prevents known malware staging tools from executing at the kernel boundary.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Synchronize Defender Driver Blocklist Parameter
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord -Force
```

---

### Item 04: Disable Data Usage Warning for All Networks

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Disable Data Usage Warning for All Networks (Except Tethering)  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local`  
* **Configuration Values:** `BlockDataUsageWarning` = `1` (REG_DWORD)  
* **Technical Function:** Adjusts Windows Connection Manager service parameters to suppress high data usage alarms across standard ethernet and Wi-Fi links.  
* **Beneficial Use Case:** Prevents the operating system from throttling background downloads or blocking large asset synchronization packages (Adobe Creative Cloud, CAD libraries, game installations).  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Suppress data usage alarms across standard network profiles
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "BlockDataUsageWarning" -Value 1 -Type DWord -Force
```

---

### Item 05: Clear DDF and CSP Data Script Feature / Schedule

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Minimal scheduled disk I/O during execution windows.  

* **Policy Name:** Clear DDF and CSP Data Script Feature / Schedule  
* **Target State:** Enabled  
* **Task Scheduler Name:** `Aegis_CacheCleanup`  
* **Configuration Values:** Weekly Schedule (Sundays at 03:00 AM)  
* **Technical Function:** Registers a routine maintenance task under `NT AUTHORITY\SYSTEM` to purge diagnostic data framework (DDF) caches and Configuration Service Provider (CSP) local transactional logs.  
* **Beneficial Use Case:** Sanitizes operational artifacts and prevents disk space bloat across long-term deployments.  
* **NOC / Performance Warnings:** Background execution consumes negligible CPU cycles for <2 seconds.  

* **PowerShell Deployment Orchestration:**
```powershell
# Register weekly DDF and CSP cache cleanup task
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "Get-ChildItem -Path ''C:\ProgramData\Microsoft\DiagnosticLogCSP\Variables'' -Recurse -Force | Remove-Item -Force -Recurse"'
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:00AM
Register-ScheduledTask -TaskName 'Aegis_CacheCleanup' -Action $Action -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force | Out-Null
```

---

### Item 06: CBOM Post-Quantum Awareness Feature

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk when executed as an offline audit. Excessive overhead if executed as a real-time system monitor.  

* **Policy Name:** Cryptography Bill of Materials (CBOM) Post-Quantum Audit  
* **Target State:** Disabled as a Background Monitor (Offline Assessment Script Only)  
* **Registry Hive:** N/A (Auditing Utility)  
* **Configuration Values:** `AuditMode` = `0`  
* **Technical Function:** Scans local certificate stores for legacy algorithms vulnerable to post-quantum decryption (MD5, SHA1, RSA keys <2048-bit).  
* **Beneficial Use Case:** Provides forward-looking cryptographic posture visibility for enterprise asset compliance.  
* **NOC / Performance Warnings:** None when executed as an on-demand audit.  

* **PowerShell Deployment Orchestration:**
```powershell
# On-demand CBOM cryptographic health query
Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { 
    $_.SignatureAlgorithm.FriendlyName -match 'MD5|SHA1' -or ($_.PublicKey.Key.KeySize -lt 2048 -and $_.PublicKey.Oid.FriendlyName -match 'RSA')
} | Select-Object Subject, Issuer, Thumbprint
```

---

### Item 07: Explorer Configurations, Privacy Controls, and Lock Screen Timers

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Explorer Configurations, Privacy Controls, and Lock Screen Timers  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`  
* **Configuration Values:** `DisableLockScreenAppNotifications` = `1`, `AllowClipboardHistory` = `0` (REG_DWORD)  
* **Technical Function:** Suppresses toast notifications over the lock screen, disables cloud clipboard history tracking, and mitigates local shoulder-surfing vectors.  
* **Beneficial Use Case:** Prevents sensitive data leakage when workstations are unattended in shared physical office spaces.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce lock screen privacy and disable global clipboard caching
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $Path -Name "AllowClipboardHistory" -Value 0 -Type DWord -Force
```

---

### Item 08: Auto-Update IANA IP Blocklist to Hosts File

> [!CAUTION]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Critical. Catastrophically degrades DNS Client service performance (`Dnscache`), spikes CPU utilization to 100%, and breaks legitimate CDN and game server lobby lookups.  

* **Policy Name:** Auto-Update IANA IP Blocklist to Hosts File  
* **Target State:** Disabled (Omitted from Baseline)  
* **File Target:** `%SystemRoot%\System32\drivers\etc\hosts`  
* **Configuration Values:** N/A  
* **Technical Function:** Injects tens of thousands of bogon IP addresses directly into the local Windows hosts file.  
* **Beneficial Use Case:** Legacy attempt at blocking malicious domains natively at the network resolution tier.  
* **NOC / Performance Warnings:** Severe DNS resolution latency. Storage of massive static host files causes local `Dnscache` memory leaks and web browsing timeouts.  

* **PowerShell Deployment Orchestration:**
```powershell
# Excluded from baseline: Route DNS filtering to dedicated upstream resolvers (Quad9/Cloudflare)
# No modifications committed to %SystemRoot%\System32\drivers\etc\hosts
```

---

### Item 09: Windows Update Enforcement and Metered Bypass

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Consumes background bandwidth on metered links.  

* **Policy Name:** Windows Update Enforcement and Metered Bypass  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`  
* **Configuration Values:** `AllowAutoWindowsUpdateDownloadOverMeteredNetwork` = `1` (REG_DWORD)  
* **Technical Function:** Bypasses metered connection blocks for critical security patches, preventing endpoints on mobile tethering from missing zero-day mitigation windows.  
* **Beneficial Use Case:** Ensures zero-day patches deploy automatically regardless of active network routing.  
* **NOC / Performance Warnings:** Cellular data usage on metered uplinks.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enable critical update delivery over metered interfaces
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Value 1 -Type DWord -Force
```

---

### Item 10: Enable ELAM (Early Launch Anti-Malware)

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Enable ELAM (Early Launch Anti-Malware) Native Initialization  
* **Target State:** Enabled via Platform Default (VBS/Secure Boot Enforced)  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch`  
* **Configuration Values:** `DriverLoadPolicy` = `1` (REG_DWORD)  
* **Technical Function:** Ensures antimalware kernel drivers initialize first during the boot sequence, preceding all third-party software drivers.  
* **Beneficial Use Case:** Prevents early-boot rootkits from blinding the security stack before Windows completes loading.  
* **NOC / Performance Warnings:** Handled natively by Windows Boot Manager under UEFI Secure Boot.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce DriverLoadPolicy for Early Launch Anti-Malware
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\EarlyLaunch"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DriverLoadPolicy" -Value 1 -Type DWord -Force
```

---

### Item 11: Disable Location Services System-Wide

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Regional mapping tools and weather widgets require manual postal code entry.  

* **Policy Name:** Disable Location Services System-Wide  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors`  
* **Configuration Values:** `DisableLocation` = `1`, `DisableWindowsLocationProvider` = `1` (REG_DWORD)  
* **Technical Function:** Deactivates the native Windows Location Provider, geofencing APIs, and location tracking sensors.  
* **Beneficial Use Case:** Prevents geographical location tracking and background sensor polling.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Deactivate Windows Location Provider system-wide
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableLocation" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $Path -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord -Force
```

---

### Item 12: SvcHost Process Isolation Preservation

> [!CAUTION]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Critical Risk if grouped. Manually grouping Service Host processes (`SvcHostSplitThresholdInKB`) undermines process isolation, increases crash blast radius, and violates Zero-Trust boundaries.  

* **Policy Name:** SvcHost Process Isolation Preservation  
* **Target State:** Preserved (Per-Service Isolation Enforced; Grouping Tweaks Banned)  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Control`  
* **Configuration Values:** Default Windows 11 Split Model Maintained  
* **Technical Function:** Retains per-service process isolation for every individual Windows service on systems with >3.5 GB RAM.  
* **Beneficial Use Case:** If a single service experiences a buffer overflow or crash, it isolates within its own PID without terminating co-hosted system services.  
* **NOC / Performance Warnings:** Eliminates the legacy memory optimization that pooled services to save 400MB RAM, prioritizing stability and security.  

* **PowerShell Deployment Orchestration:**
```powershell
# Remove legacy SvcHost grouping overrides to guarantee per-service process isolation
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SvcHostSplitThresholdInKB' -ErrorAction SilentlyContinue
```

---

### Item 13: Enhanced Mode Search for Windows Indexer

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Initial indexing introduces temporary background disk I/O; recommended for high-speed NVMe SSDs only.  

* **Policy Name:** Enhanced Mode Search for Windows Indexer  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search`  
* **Configuration Values:** `EnableEnhancedSearch` = `1` (REG_DWORD)  
* **Technical Function:** Extends the Windows Search crawler across all internal fixed drives and non-standard project directories.  
* **Beneficial Use Case:** Accelerates search retrieval for code repositories, CAD drawings, and media assets located outside standard library paths.  
* **NOC / Performance Warnings:** Initial disk indexing post-deployment consumes low-priority background I/O.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enable Enhanced Search Mode across all local volumes
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "EnableEnhancedSearch" -Value 1 -Type DWord -Force
```

---

### Item 14: Edge Browser Updates over Metered Networks

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Edge Browser Updates over Metered Networks  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate`  
* **Configuration Values:** `UpdateDefault` = `1` (REG_DWORD)  
* **Technical Function:** Configures the Microsoft Edge Enterprise Update engine to download security updates over metered connections.  
* **Beneficial Use Case:** Guarantees zero-day browser vulnerabilities are patched immediately regardless of connection type.  
* **NOC / Performance Warnings:** Minimal background network traffic.  

* **PowerShell Deployment Orchestration:**
```powershell
# Force immediate Edge browser security update downloads
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "UpdateDefault" -Value 1 -Type DWord -Force
```

---

### Item 15: Custom Visual Filters for Windows Event Viewer

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Custom Visual Filters for Windows Event Viewer  
* **Target State:** Disabled in Script Baseline (Retained in Security Audit Profiles)  
* **Registry Hive:** N/A (Event Viewer Console XML Views)  
* **Configuration Values:** None  
* **Technical Function:** Injects custom XML queries into Event Viewer targeting ASR blocks, driver load rejections, and authentication lockouts.  
* **Beneficial Use Case:** Streamlines local troubleshooting of security events for bench technicians.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Custom views omitted from automated baseline; queries surfaced via Show-DeploymentReport
```

---

### Item 16: Command-Line Process Creation Auditing (Event ID 4688)

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk in standard baseline; segregated behind `$EnableAntiForensicMode`.  

* **Policy Name:** Command-Line Process Creation Auditing  
* **Target State:** Enabled by Default (Disabled only if `-EnableAntiForensicMode` is explicitly `$true`)  
* **Registry Hive:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`  
* **Configuration Values:** `ProcessCreationIncludeCmdLine_Enabled` = `1` (REG_DWORD), Event Log Size = `65536` KB  
* **Technical Function:** Captures full command-line strings and parent-child execution trees inside security Event ID 4688.  
* **Beneficial Use Case:** Essential for EDR integration, forensic analysis, and auditing execution paths of system utilities.  
* **NOC / Performance Warnings:** Minor disk space consumption; event log allocated to 64MB buffer.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce 64MB logs and Event ID 4688 command-line parameter auditing
$AuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $AuditPath)) { New-Item -Path $AuditPath -Force | Out-Null }
Set-ItemProperty -Path $AuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
& auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
```

---

### Item 17: OpenSSH Cryptographic Cipher & MAC Hardening

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Rejects inbound/outbound SSH connections from obsolete legacy SSH servers.  

* **Policy Name:** Configure Windows OpenSSH to Secure MACs Only  
* **Target State:** Enabled  
* **Configuration File:** `%ProgramData%\ssh\sshd_config`  
* **Configuration Values:** `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com`  
* **Technical Function:** Restricts native Windows OpenSSH server and client components to Encrypt-then-Mac (ETM) algorithms.  
* **Beneficial Use Case:** Protects remote terminal administrative connections from cryptographic tampering and downgrade attacks.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce secure ETM MAC algorithms in OpenSSH
$SshPath = "$env:ProgramData\ssh\sshd_config"
if (Test-Path $SshPath) {
    Add-Content -Path $SshPath -Value "`nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    Restart-Service -Name "sshd" -ErrorAction SilentlyContinue
}
```

---

### Item 18: File System Long Path Support (`LongPathsEnabled`)

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Enable Support for Long Paths  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`  
* **Configuration Values:** `LongPathsEnabled` = `1` (REG_DWORD)  
* **Technical Function:** Removes the legacy 260-character `MAX_PATH` file system constraint across all Win32 file APIs.  
* **Beneficial Use Case:** Crucial for deep directory trees typical in complex audio sample libraries, CAD architectural packages, and Git code repositories.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Remove the legacy 260-character path limit
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1 -Type DWord -Force
```

---

### Item 19: Force Strong Key Protections for Computer-Stored User Keys

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Moderate. Interrupts developer CI/CD automation and silent build signing workflows by demanding interactive user approval.  

* **Policy Name:** Force Strong Key Protections for Computer-Stored User Keys  
* **Target State:** Disabled (Omitted from Baseline)  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Cryptography`  
* **Configuration Values:** `ForceKeyProtection` = `0` (REG_DWORD)  
* **Technical Function:** Requires an interactive user confirmation dialog every time an application attempts to access a stored private cryptographic key.  
* **Beneficial Use Case:** Prevents silent background credential exfiltration by malware.  
* **NOC / Performance Warnings:** Severe operational friction for automated developer tasks and local build pipelines.  

* **PowerShell Deployment Orchestration:**
```powershell
# Strong key protection omitted from baseline to preserve developer automation
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name "ForceKeyProtection" -ErrorAction SilentlyContinue
```

---

### Item 20: Privacy Toggles, Experience Control & Cloud Mitigation Matrix

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Privacy Toggles, Experience Control & Cloud Mitigation Matrix  
* **Target State:** Enabled  
* **Registry Hives:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`, `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`  
* **Configuration Values:** `DisableWindowsConsumerFeatures` = `1`, `AllowTelemetry` = `0` (REG_DWORD)  
* **Technical Function:** Deactivates automated speech analysis, cloud content suggestions, targeted advertising identifiers, and consumer feedback prompts.  
* **Beneficial Use Case:** Eliminates background operating system telemetry and advertising telemetry egress.  
* **NOC / Performance Warnings:** On Windows 11 Enterprise, IoT Enterprise, and Education editions, `AllowTelemetry = 0` restricts diagnostic emissions strictly to security-critical telemetry.

> [!NOTE]
> On Windows 11 Pro, the OS silently clamps `AllowTelemetry = 0` to `1` (Basic / Required diagnostic data) at the service layer without raising an error. Complete telemetry suppression (`0`) is architecturally unsupported by Microsoft on Pro and Home SKUs regardless of direct registry injection.  

* **PowerShell Deployment Orchestration:**
```powershell
# Neutralize consumer features and diagnostic data collection
$CloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $CloudPath)) { New-Item -Path $CloudPath -Force | Out-Null }
Set-ItemProperty -Path $CloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force

$DataPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (-not (Test-Path $DataPath)) { New-Item -Path $DataPath -Force | Out-Null }
Set-ItemProperty -Path $DataPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
```

---

### Item 21: Display Invisible Spoofed Extensions (`.url`, `.pif`, `.lnk`)

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Display Invisible Spoofed Extensions  
* **Target State:** Enabled across all profiles  
* **Registry Hive:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`  
* **Configuration Values:** `HideFileExt` = `0`, `ShowSuperHidden` = `1` (REG_DWORD)  
* **Technical Function:** Overrides default shell behavior to display all file extensions, including traditionally hidden system extensions.  
* **Beneficial Use Case:** Neutralizes double-extension social engineering attacks (e.g., `invoice.pdf.exe` or `document.url` masquerading as documents).  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce complete file extension visibility in File Explorer
$Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "HideFileExt" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $Path -Name "ShowSuperHidden" -Value 1 -Type DWord -Force
```

---

### Item 22: Anti-Malware Scan Interface (AMSI) Signature Validation

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Blocks unsigned internal debugging or legacy third-party monitoring agents lacking valid digital signatures.  

* **Policy Name:** AMSI Cryptographic Signing Enforcement for Security Providers  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\AMSI`  
* **Configuration Values:** `RequireSignatureValidation` = `1` (REG_DWORD)  
* **Technical Function:** Demands that all third-party security software hooking into the AMSI engine possess a valid, authentic digital code-signing certificate.  
* **Beneficial Use Case:** Prevents malicious binaries from mimicking legitimate antivirus software to disable or blind AMSI scanning.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce cryptographic code signing validation on AMSI providers
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\AMSI"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "RequireSignatureValidation" -Value 1 -Type DWord -Force
```

---

### Item 23: Disable the WebClient (WebDAV) Service

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Moderate. Blocks SharePoint document libraries mapped via legacy WebDAV web folders (native OneDrive sync client is completely unaffected).  

* **Policy Name:** Disable the WebClient Service  
* **Target State:** Enabled (Service Disabled & Stopped)  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Services\WebClient`  
* **Configuration Values:** `Start` = `4` (REG_DWORD)  
* **Technical Function:** Deactivates the legacy Windows WebDAV miniport client service.  
* **Beneficial Use Case:** Completely closes the attack vector used by remote attackers to harvest NetNTLM hashes via crafted `.search-ms` shortcuts or malicious UNC WebDAV links.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Disable and terminate the legacy WebClient (WebDAV) service
Set-Service -Name 'WebClient' -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name 'WebClient' -Force -ErrorAction SilentlyContinue
```

---

### Item 24: Disable Smart Multi-Homed Name Resolution

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Optimizes DNS query behavior across enterprise adapters.  

* **Policy Name:** Disable Smart Multi-Homed Name Resolution  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`  
* **Configuration Values:** `DisableSmartNameResolution` = `1` (REG_DWORD)  
* **Technical Function:** Prevents Windows from concurrently broadcasting DNS queries to all active network adapters (e.g., simultaneous ethernet, Wi-Fi, and VPN interfaces).  
* **Beneficial Use Case:** Eliminates serious DNS query leakage when routing sensitive traffic through corporate VPN tunnels.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Stop parallel multi-adapter DNS broadcasting
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
```

---

### Item 25: Protocol Hardening (NetBIOS, LMHOSTS, HTTP Printing, SMB3 Signing)

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Moderate. Disabling HTTP printing breaks older legacy network-attached office printers that lack raw TCP or IPP protocols.  

* **Policy Name:** Protocol Hardening & Network Transport Isolation  
* **Target State:** Enabled (100% Standalone Milestone)  
* **Registry Hives:** `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters`, `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers`  
* **Configuration Values:** `EnableLMHOSTS` = `0`, `NetbiosOptions` = `2`, `DisableHTTPPrinting` = `1`, `RequireSecuritySignature` = `$true`  
* **Technical Function:** Deactivates legacy name resolution protocols, removes SMBv1, disables insecure HTTP printing, and mandates SMB3 message signing.  
* **Beneficial Use Case:** Completely neutralizes local network broadcast poisoning (Responder) and man-in-the-middle SMB tampering.  
* **NOC / Performance Warnings:** Mandatory SMB3 payload encryption is intentionally omitted to avoid CPU saturation and preserve 10GbE network throughput during large file transfers.  

* **PowerShell Deployment Orchestration:**
```powershell
# Deactivate NetBIOS, LMHOSTS, HTTP printing, and mandate SMB3 signing
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'EnableLMHOSTS' -Value 0 -Type DWord -Force
Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*' -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 2 -Force
}
$PrinterPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $PrinterPath)) { New-Item -Path $PrinterPath -Force | Out-Null }
Set-ItemProperty -Path $PrinterPath -Name "DisableHTTPPrinting" -Value 1 -Type DWord -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
```

---

### Item 26: Legacy Component Evacuation (PowerShell v2, WordPad, VBScript, WMIC)

> [!CAUTION]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Critical. Breaks legacy enterprise batch scripts and older CAD/GIS automation macros that rely on VBScript or WMIC processes.  

* **Policy Name:** Legacy Component Evacuation  
* **Target State:** Enabled (Configurable via `-EvacuateLegacyCapabilities`)  
* **Capability Store:** Windows Online Capability and Feature Management  
* **Configuration Values:** WordPad, VBScript, WMIC capabilities uninstalled; PowerShell v2 feature disabled.  
* **Technical Function:** Removes outdated binaries officially marked for deprecation by Microsoft, establishing Windows Terminal and PowerShell 7 as defaults.  
* **Beneficial Use Case:** Eliminates historical attack surfaces used by malicious payloads to execute legacy macro evasion chains.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Remove deprecated capabilities and legacy PowerShell engine
Get-WindowsCapability -Online | Where-Object { $_.Name -like "*WordPad*" -or $_.Name -like "*VBScript*" -or $_.Name -like "*WMIC*" } | ForEach-Object {
    Remove-WindowsCapability -Online -Name $_.Name -ErrorAction SilentlyContinue | Out-Null
}
Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart -ErrorAction SilentlyContinue | Out-Null
```

---

### Item 27: Driver Store Non-Destructive Audit & IHV Protection

> [!CAUTION]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Critical Risk if swept destructively. Blanket `pnputil /delete-driver` sweeps delete third-party chipset controllers, Thunderbolt support, and external ASIO sound card drivers.  

* **Policy Name:** Driver Store Non-Destructive Audit  
* **Target State:** Non-Destructive Audit Only (Automatic Driver Deletion Banned)  
* **Execution Engine:** `pnputil.exe` / `Get-WindowsDriver`  
* **Configuration Values:** Destructive driver uninstallation disabled.  
* **Technical Function:** Retains third-party hardware abstractions while preventing unverified INF script execution.  
* **Beneficial Use Case:** Guarantees that specialized studio audio converters (Focusrite, Universal Audio) and gaming peripherals initialize properly upon reboot.  
* **NOC / Performance Warnings:** Retains standard driver store cache footprints on disk.  

* **PowerShell Deployment Orchestration:**
```powershell
# Destructive driver scrubbing omitted to preserve ASIO and Thunderbolt hardware initialization
```

---

### Item 28: Universal Firewall Profile Verification & Listener Alerts

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Surfaces interactive notification toasts when an application binds to a local listening port.  

* **Policy Name:** Universal Firewall Profile Verification & Listening Alerts  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile`  
* **Configuration Values:** `DisableNotifications` = `0` (REG_DWORD)  
* **Technical Function:** Enforces stateful firewall evaluation across Domain, Private, and Public profiles, displaying real-time alerts when a process binds to a listening socket.  
* **Beneficial Use Case:** Provides instant visibility when an application attempts unauthorized local socket listening.  
* **NOC / Performance Warnings:** Interactive notification toasts on network listener creation.  

* **PowerShell Deployment Orchestration:**
```powershell
# Surface firewall notification toasts for application listening sockets
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableNotifications" -Value 0 -Type DWord -Force
```

---

### Item 29: Secure Desktop Visual Isolation for UAC Elevation

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Preserves mandatory security isolation architecture.  

* **Policy Name:** Secure Desktop Visual Isolation for UAC Elevation  
* **Target State:** Enabled (Secure Desktop Retained)  
* **Registry Hive:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`  
* **Configuration Values:** `PromptOnSecureDesktop` = `1` (REG_DWORD)  
* **Technical Function:** Forces User Account Control authentication prompts to render on the isolated Secure Desktop (black screen layout).  
* **Beneficial Use Case:** Prevents screen-scraping malware from capturing credentials or injecting synthetic mouse clicks into the prompt window.  
* **NOC / Performance Warnings:** Slight screen transition dimming during elevation.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce Secure Desktop isolation for UAC credential prompts
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
```

---

### Item 30: Admin Approval Mode with Code Signature Validation

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** Admin Approval Mode with Code Signature Validation  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`  
* **Configuration Values:** `ConsentPromptBehaviorAdmin` = `1`, `ValidateAdminCodeSignatures` = `1` (REG_DWORD)  
* **Technical Function:** Restricts implicit administrative tokens, mandating credential verification and requiring authentic digital code signatures for elevated binaries.  
* **Beneficial Use Case:** Prevents malicious unsigned applications from piggybacking on pre-existing administrative permissions.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce Admin Approval Mode and strict administrative code signature validation
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $Path -Name "ValidateAdminCodeSignatures" -Value 1 -Type DWord -Force
```

---

### Item 31: Proximity Loss Remote Locking Matrix (Dynamic Lock)

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Negligible Bluetooth telemetry polling.  

* **Policy Name:** Proximity Loss Remote Locking Matrix (Dynamic Lock via Bluetooth)  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`  
* **Configuration Values:** `EnableDynamicLock` = `1` (REG_DWORD)  
* **Technical Function:** Enables Windows Dynamic Lock, utilizing paired Bluetooth hardware (such as a smartphone) to lock the session automatically when the user moves out of range.  
* **Beneficial Use Case:** Mitigates the risk of leaving workstations unlocked in shared environments.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enable Bluetooth proximity Dynamic Lock
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "EnableDynamicLock" -Value 1 -Type DWord -Force
```

---

### Item 32: Brute-Force Anti-Hammering & Lock Screen Scrubbing

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Account locks for 15 minutes after 5 consecutive incorrect passwords.  

* **Policy Name:** Brute-Force Anti-Hammering & Lock Screen Scrubbing  
* **Target State:** Enabled  
* **Configuration Subsystems:** Net Accounts & Local System Policies  
* **Configuration Values:** `lockoutthreshold` = `5`, `lockoutduration` = `15`, `DontDisplayLastUserName` = `1`  
* **Technical Function:** Enforces account lockout delays upon repeated failed attempts and hides previous usernames from the interactive logon interface.  
* **Beneficial Use Case:** Neutralizes automated physical brute-force attacks against workstation consoles.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce 5-attempt lockout threshold and hide previous user account identity
& net.exe accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 -Type DWord -Force
```

---

### Item 33: Legacy Cryptography Defund Matrix (TLS 1.0/1.1, MD5)

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Moderate. Rejects connections to obsolete database endpoints or internal web APIs that do not support modern TLS 1.2 or 1.3 ciphers.  

* **Policy Name:** Legacy Cryptography Defund Matrix  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`  
* **Configuration Values:** TLS 1.0/1.1 `Enabled` = `0`, MD5 Hash `Enabled` = `0` (REG_DWORD)  
* **Technical Function:** Deactivates insecure TLS 1.0 and 1.1 protocol handshakes and disables MD5 as an operating-system-level SCHANNEL cipher.  
* **Beneficial Use Case:** Protects network handshakes from cryptographic downgrade attacks.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Disable obsolete TLS 1.0/1.1 protocols and MD5 SCHANNEL hashing
$Schannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
foreach ($proto in @("TLS 1.0", "TLS 1.1")) {
    foreach ($side in @("Client", "Server")) {
        $p = "$Schannel\Protocols\$proto\$side"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "Enabled" -Value 0 -Type DWord -Force
    }
}
$Md5Path = "$Schannel\Hashes\MD5"
if (-not (Test-Path $Md5Path)) { New-Item -Path $Md5Path -Force | Out-Null }
Set-ItemProperty -Path $Md5Path -Name "Enabled" -Value 0 -Type DWord -Force
```

---

### Item 34: Platform Security Validation Prompt Engine & AMD Zen Silicon Alert

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. One-time hardware evaluation check during installation.  

* **Policy Name:** Platform Security Validation & AMD Zen Silicon Alert  
* **Target State:** Enabled  
* **Execution Engine:** CIM Query  
* **Configuration Values:** `ZenSiliconCheck` = Active  
* **Technical Function:** Evaluates processor architecture via WMI/CIM, alerting technicians if AMD Zen silicon is detected to ensure a 16-character BitLocker PIN is used.  
* **Beneficial Use Case:** Mitigates processor-level speculative execution vectors (such as Zenbleed) by prompting for strong encryption passphrases.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Evaluate processor architecture and log BitLocker PIN recommendations
$CpuData = Get-CimInstance Win32_Processor
$CpuNames = (($CpuData | ForEach-Object { $_.Name }) -join " ")
if ($CpuNames -match 'Ryzen|Threadripper|EPYC') {
    Write-Log "KernelTuning" "AMD Zen architecture detected. Verify that 16-character BitLocker PINs are enforced." "Warning"
}
```

---

### Item 35: Remote Desktop Clipboard & Drive Redirection Controls

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Disabling redirection blocks transferring local files or clipboard text through an active RDP session.  

* **Policy Name:** Remote Desktop Clipboard and Drive Redirection Controls  
* **Target State:** Configurable (Permitted in Standard Workstation Baseline; Disabled in Anti-Forensic Profile)  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`  
* **Configuration Values:** `fDisableCdm` = `0` (or `1` if Anti-Forensic), `fDisableClip` = `0` (or `1` if Anti-Forensic)  
* **Technical Function:** Controls whether client filesystems and clipboard buffers map into remote desktop sessions.  
* **Beneficial Use Case:** Permitted in standard baselines to allow developers and designers to transfer assets to remote render nodes; blocked in anti-forensic profiles to eliminate exfiltration.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# RDP redirection maintained for developer workflows; toggle to 1 for strict isolation
$RdpPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
if (-not (Test-Path $RdpPath)) { New-Item -Path $RdpPath -Force | Out-Null }
Set-ItemProperty -Path $RdpPath -Name 'fDisableCdm' -Value 0 -Type DWord -Force
Set-ItemProperty -Path $RdpPath -Name 'fDisableClip' -Value 0 -Type DWord -Force
```

---

### Item 36: Turn off Microsoft Consumer Experiences State Override

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** "Turn off Microsoft Consumer Experiences" State Override  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`  
* **Configuration Values:** `DisableWindowsConsumerFeatures` = `1` (REG_DWORD)  
* **Technical Function:** Explicitly enables the consumer experience suppression policy to strip third-party promotional apps.  
* **Beneficial Use Case:** Prevents Windows from automatically downloading and pinning pre-installed sponsored consumer games (Candy Crush, TikTok, etc.) on new user desktops.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce suppression of consumer application provisioning
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
```

---

### Item 37: Standard User Elevation Credential Prompting

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Standard administrative credential prompt friction.  

* **Policy Name:** Allow Elevation from Standard User Accounts  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`  
* **Configuration Values:** `ConsentPromptBehaviorUser` = `3` (REG_DWORD)  
* **Technical Function:** Configures UAC to prompt for administrator credentials when an unprivileged account requires administrative permission.  
* **Beneficial Use Case:** Essential for daily productivity; allows unprivileged daily accounts to elevate for installer execution by inputting credentials without needing a full user account logoff lifecycle.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Configure UAC credential prompt behavior for standard user accounts
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "ConsentPromptBehaviorUser" -Value 3 -Type DWord -Force
```

---

### Item 38: Comprehensive Microsoft Defender Hardening Matrix (14 ASR Rules & Sandbox)

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Controlled Folder Access is defaulted to `AuditMode` to prevent DAW/CAD save failures.  

* **Policy Name:** Comprehensive Microsoft Defender Hardening Matrix  
* **Target State:** Enabled  
* **Configuration Subsystems:** Microsoft Defender Engine (`Set-MpPreference`) & Environment  
* **Configuration Values:** `MP_FORCE_USE_SANDBOX` = `1`, `EnableNetworkProtection` = `Enabled`, `PUAProtection` = `Enabled`, 14 ASR Rules in `Block` Mode  
* **Technical Function:** Enforces Defender sandboxing, Intel TDT, Network Protection, and 14 enterprise ASR rules.  
* **Beneficial Use Case:** Radically hardens the endpoint against malicious macros, credential theft, and script injection while keeping Controlled Folder Access in `AuditMode` to protect audio recording and CAD rendering workflows.  
* **NOC / Performance Warnings:** None; optimized for production workstations.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce Defender compute sandboxing, Intel TDT, Network Protection, and 14 ASR rules
[System.Environment]::SetEnvironmentVariable('MP_FORCE_USE_SANDBOX', '1', 'Machine')
Set-MpPreference -EnableIntelTdt $true -EnableNetworkProtection Enabled -PUAProtection Enabled -ErrorAction SilentlyContinue
Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue

$AsrIds = @(
    'BE9BA2D9-53EA-4CDC-84e5-9b1eeee46550', '9e6c4e1f-7d60-472f-ba1a-a39af6b9414d',
    'D4E3A620-D21D-47D5-892B-37D128292256', 'D1E1244A-4A57-4D34-828B-2C679F530723',
    '56a863a9-1372-4db6-ac9a-8243d1281668', 'e6db77e5-3e12-422a-814c-814e2f9326b5',
    '01443614-cd74-433a-b99e-2ecdc07bfc25', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
    '3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
    '26190899-77ae-4889-ac9b-00b22a7f8d64', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
    'c1db55ab-c21a-4637-bb3f-a12568109d35', '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
)
$AsrActions = [string[]](@("Enabled") * $AsrIds.Count)
Set-MpPreference -AttackSurfaceReductionRules_Ids $AsrIds -AttackSurfaceReductionRules_Actions $AsrActions -ErrorAction SilentlyContinue
```

---

### Item 39: Enterprise Browser Policy Matrix (33 Discrete Edge/Brave GPOs)

> [!WARNING]  
> **Operational Impact:**  
> **System / Feature Break Risk:** Low Risk. Balanced Enhanced Security Mode prevents web rendering slowdowns in design tools like Figma.  

* **Policy Name:** Enterprise Browser Policy Matrix across Microsoft Edge and Brave  
* **Target State:** Enabled  
* **Registry Hives:** `HKLM\SOFTWARE\Policies\Microsoft\Edge`, `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`  
* **Configuration Values:** 33 discrete GPO directives including `EnhanceSecurityMode` = `1`, `EncryptedClientHelloEnabled` = `1`, `BlockThirdPartyCookies` = `1`, `BuiltInDnsClientEnabled` = `1`  
* **Technical Function:** Enforces Balanced Enhanced Security Mode, DNS-over-HTTPS, Encrypted Client Hello, and strict third-party tracking blocks while purging Copilot, shopping assistants, and sidebar widgets.  
* **Beneficial Use Case:** Balances strict browser isolation with public web compatibility, preserving GPU rendering in Figma and WebGL design apps.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce Enterprise Browser Security GPO across Edge and Brave
$EdgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $EdgePath)) { New-Item -Path $EdgePath -Force | Out-Null }
$EdgePolicies = @{
    "EnhanceSecurityMode"                   = 1
    "BuiltInDnsClientEnabled"               = 1
    "EncryptedClientHelloEnabled"           = 1
    "BlockThirdPartyCookies"                = 1
    "BackgroundModeEnabled"                 = 0
    "ParallelDownloadingEnabled"            = 1
    "GpuRasterizationEnabled"               = 1
    "Accelerated2dCanvasEnabled"            = 1
    "BackForwardCacheEnabled"               = 1
    "ShowRecommendationsEnabled"            = 0
    "SpotlightExperienceEnabled"            = 0
    "SleepingTabsEnabled"                   = 1
    "SleepingTabsTimeout"                   = 300
    "AutoDiscardSleepingTabsEnabled"        = 1
    "SmartScreenEnabled"                    = 1
    "PreventSmartScreenPromptOverride"      = 1
    "PreventSmartScreenPromptOverrideForFiles" = 1
    "PerformanceDetectorEnabled"            = 1
    "ExtensionsPerformanceDetectorEnabled"  = 1
    "RAMResourceControlsEnabled"            = 1
    "EfficiencyModeEnabled"                 = 1
    "AIGenThemesEnabled"                    = 0
    "EdgeThemeEnabled"                      = 0
    "AllowGamesMenu"                        = 0
    "AllowSurfGame"                         = 0
    "HubsSidebarEnabled"                    = 0
    "EdgeOpenInSidebarEnabled"              = 0
    "EdgeShoppingAssistantEnabled"          = 0
    "EdgeCopilotEnabled"                    = 0
    "DefaultSearchProviderEnabled"          = 1
}
foreach ($p in $EdgePolicies.Keys) { Set-ItemProperty -Path $EdgePath -Name $p -Value $EdgePolicies[$p] -Type DWord -Force }
Set-ItemProperty -Path $EdgePath -Name "DefaultSearchProviderName" -Value "DuckDuckGo" -Type String -Force
Set-ItemProperty -Path $EdgePath -Name "DefaultSearchProviderSearchURL" -Value "https://duckduckgo.com/?q={searchTerms}" -Type String -Force

$EdgeUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
if (-not (Test-Path $EdgeUpdatePath)) { New-Item -Path $EdgeUpdatePath -Force | Out-Null }
Set-ItemProperty -Path $EdgeUpdatePath -Name "UpdateDefault" -Value 1 -Type DWord -Force

$BravePath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
if (-not (Test-Path $BravePath)) { New-Item -Path $BravePath -Force | Out-Null }
Set-ItemProperty -Path $BravePath -Name "BraveWalletDisabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $BravePath -Name "BraveRewardsDisabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $BravePath -Name "BraveVpnDisabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $BravePath -Name "AIInteractionsEnabled" -Value 0 -Type DWord -Force
```

---

### Item 40: Unified 4096-Byte (4Kn) WinPE Partition Formatting & RMW Elimination

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Hardware-native storage optimization.  

* **Policy Name:** Unified 4096-Byte (4Kn) WinPE Partition Formatting & RMW Elimination  
* **Target State:** Enforced via `autounattend.xml` during WinPE Partitioning  
* **Configuration XML Element:** `<BlockAllocationSize>4096</BlockAllocationSize>`  
* **Technical Function:** Enforces a clean 4096-byte (4KB) allocation unit size on volume `C:` during the initial Windows Setup partitioning pass.  
* **Beneficial Use Case:** Matches the NTFS file system cluster size to the physical NAND flash page architecture of modern NVMe SSDs, completely eliminating Read-Modify-Write (RMW) write amplification and extending flash endurance.  
* **NOC / Performance Warnings:** Must be executed during clean WinPE installation.  

* **XML Schema Implementation:**
```xml
<!-- Injected in autounattend.xml under ModifyPartitions for Partition 4 -->
<ModifyPartition wcm:action="add">
    <Order>4</Order>
    <PartitionID>4</PartitionID>
    <Format>NTFS</Format>
    <Label>Aegis_OS</Label>
    <Letter>C</Letter>
    <BlockAllocationSize>4096</BlockAllocationSize>
</ModifyPartition>
```

---

### Item 41: Storage Controller D0 Latency Retention (`stornvme\Parameters\Device`)

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk on AC workstations; keeps NVMe links continuously hot.  

* **Policy Name:** Storage Controller D0 Latency Retention  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device`  
* **Configuration Values:** `IdleTimeout` = `0`, `EnableD3` = `0` (REG_DWORD)  
* **Technical Function:** Disables runtime D3 (RTD3) power management on the standard `stornvme.sys` driver, preventing the storage controller from cycling into low-power states.  
* **Beneficial Use Case:** Eliminates controller wake-up latency when real-time multi-track DAW recording sessions or heavy 3D CAD renders initiate sudden disk I/O bursts.  
* **NOC / Performance Warnings:** Preserves standard `stornvme.sys` stability while avoiding experimental `nvmedisk.sys` overrides.  

* **PowerShell Deployment Orchestration:**
```powershell
# Enforce stornvme controller power state D0 retention
$StornvmePath = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"
if (-not (Test-Path $StornvmePath)) { New-Item -Path $StornvmePath -Force | Out-Null }
Set-ItemProperty -Path $StornvmePath -Name "IdleTimeout" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $StornvmePath -Name "EnableD3" -Value 0 -Type DWord -Force
```

---

### Item 42: WinRE Push-Button Reset Bare-Metal 4KB Quick-Format Mirroring

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** WinRE Push-Button Reset Bare-Metal 4KB Quick-Format Mirroring  
* **Target State:** Staged in `C:\Recovery\OEM\`  
* **Configuration Files:** `ResetConfig.xml`, `ResetDiskLayout.txt`  
* **Configuration Values:** `format quick fs=ntfs unit=4096`  
* **Technical Function:** Stages a custom OEM Push-Button Reset diskpart script that Windows Recovery Environment (WinRE) calls during "Reset This PC" (Full Wipe).  
* **Beneficial Use Case:** Guarantees that factory resets maintain 300MB EFI partitions and 4096-byte cluster alignment across system lifecycles.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Stage WinRE bare-metal recovery engine ensuring 4KB quick format on factory resets
$RecoveryPath = "$env:SystemDrive\Recovery\OEM"
if (-not (Test-Path $RecoveryPath)) { New-Item -Path $RecoveryPath -ItemType Directory -Force | Out-Null }
@'
select disk 0
clean
convert gpt
create partition primary size=1000
format quick fs=ntfs label="WinRE"
set id="de94bba4-06d1-4d40-a16a-bfd50179d6ac"
create partition efi size=300
format quick fs=fat32 label="System"
create partition msr size=16
create partition primary
format quick fs=ntfs unit=4096 label="Aegis_OS"
assign letter="C"
'@ | Out-File -FilePath "$RecoveryPath\ResetDiskLayout.txt" -Encoding ascii -Force

@'
<?xml version="1.0" encoding="utf-8"?>
<Reset>
    <SystemDisk>
        <DiskpartScript Path="ResetDiskLayout.txt"/>
        <MinSize>64000</MinSize>
    </SystemDisk>
</Reset>
'@ | Out-File -FilePath "$RecoveryPath\ResetConfig.xml" -Encoding utf8 -Force
```

---

### Item 43: MMCSS Audio Engine Real-Time Scheduling Priority Elevation

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk.  

* **Policy Name:** MMCSS Audio Engine Real-Time Scheduling Priority Elevation  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio`  
* **Configuration Values:** `Priority` = `8`, `GPU Priority` = `8`, `Scheduling Category` = `High`, `SFIO Priority` = `High`  
* **Technical Function:** Injects high-priority scheduling parameters into the Windows Multimedia Class Scheduler Service (MMCSS) audio task pool.  
* **Beneficial Use Case:** Prioritizes digital audio threads over background system tasks, eliminating DPC latency spikes, clicks, and pops during heavy multi-track DAW recording.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Elevate MMCSS Audio task thread scheduling priority
$AudioPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"
if (-not (Test-Path $AudioPath)) { New-Item -Path $AudioPath -Force | Out-Null }
Set-ItemProperty -Path $AudioPath -Name "Priority" -Value 8 -Type DWord -Force
Set-ItemProperty -Path $AudioPath -Name "GPU Priority" -Value 8 -Type DWord -Force
Set-ItemProperty -Path $AudioPath -Name "Scheduling Category" -Value "High" -Type String -Force
Set-ItemProperty -Path $AudioPath -Name "SFIO Priority" -Value "High" -Type String -Force
```

---

### Item 44: Dynamic Hardware Identity Anchoring & SAM Token-Filter Gating

> [!IMPORTANT]  
> **Operational Impact:**  
> **System / Feature Break Risk:** No Risk. Replaces static template credentials with cryptographically bound local authority.  

* **Policy Name:** Dynamic Hardware Identity Anchoring & SAM Token-Filter Gating  
* **Target State:** Enabled  
* **Registry Hive:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`  
* **Configuration Values:** `LocalAccountTokenFilterPolicy` = `1` (Conditionally Gated on SAM Validation)  
* **Technical Function:** Generates a unique 6-character identifier from BIOS/UUID hardware telemetry, creates `MHS-$StickerID-Admin` with a 24-character cryptographic key, disables the built-in `Administrator` account, and only relaxes remote token filtering if the anchor user is verified in the local SAM.  
* **Beneficial Use Case:** Eliminates default credentials across deployed endpoints and prevents unauthenticated remote lateral movement across local networks.  
* **NOC / Performance Warnings:** None.  

* **PowerShell Deployment Orchestration:**
```powershell
# Validate dynamic administrative anchor before relaxing remote token filtering
if ($EnableLAPS_EntraIDSupport) {
    if (Get-LocalUser -Name $UniqueAdminName -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Force -ErrorAction SilentlyContinue
    } else {
        throw "Security Boundary Failure: Cannot relax token filters without a validated local administrative anchor."
    }
} else {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
<<<<<<< HEAD
}
<!-- AEGIS-REVISION-MATRIX:START -->
<!-- AEGIS-REVISION-MATRIX:END -->
=======
}
>>>>>>> 1c37ff213d024c2a271339d7524c1b5f4eaf778c

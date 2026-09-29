# Changelog

All notable changes to the Aegis Win11 Enterprise Deployment Toolkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.8.0] - 2026

### Added
* Formalized the Version 1.8.0 Production Architecture Milestone, freezing the core codebase for enterprise and high-performance production deployments.
* Synchronized the complete documentation suite: `README.md`, `Wiki.md`, `TechnicalGuide.md` (44-item policy card matrix), `AegisWin11SecurityArchitecture&ComplianceAuditReport.md`, and the vector infographic `AegisWin11_Architecture.svg`.
* Established the 100% Standalone Network and Protocol Fortress compliance milestone across CIS, NIST SP 800-53, and DISA STIG baselines.

### Security
* Validated complete separation of identity boundaries: dynamic administrator account (`MHS-$StickerID-Admin`) generated and verified before relaxing remote token policies (`LocalAccountTokenFilterPolicy = 1`).
* Enforced unconditional global deactivation of the built-in RID-500 `Administrator` account (`SID S-1-5-500`).
* Locked the kernel execution baseline: system-wide Exploit Guard (DEP, Bottom-Up ASLR, SEHOP), 14 Microsoft Defender ASR rules in Block mode, and the WDAC Vulnerable Driver Blocklist active natively without breaking ASIO drivers or competitive anti-cheat engines.

---

## [1.7.7] - 2026

### Added
* Injected Microsoft Abstract Syntax Tree (AST) Comment-Based Help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`) across all 18 parameters in `AegisWin11_Deploy.ps1` to support native `Get-Help` introspection.
* Added native Windows Storage Sense automated policies (`AllowStorageSenseGlobal = 1`, `ConfigStorageSenseCloudContentCleanThreshold = 30`) under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense` to purge unreferenced temporary files automatically.
* Elevated Multimedia Class Scheduler Service (MMCSS) audio thread scheduling priorities (`Priority = 8`, `GPU Priority = 8`, `Scheduling Category = High`, `SFIO Priority = High`) in `Invoke-CreativeKernelTuning` to prevent buffer underruns in studio DAWs.
* Added the optional parameter `-AICreativeKernelTuning` (default `$false`) to extend GPU Timeout Detection and Recovery (TDR) limits to 60 seconds (`TdrDelay = 60`, `TdrDdiDelay = 60`) for CAD, 3D rendering, and AI compute stability.
* Integrated a 60-second Network Location Awareness (NLA) internet pre-flight polling loop and a `DesktopAppInstaller` AppX family registration fallback into `Invoke-WingetDeployment`.

### Changed
* Isolated forensic modifications: event log capping (1024KB), command-line process auditing disablement, Prefetch deletion, and USN change journal destruction are strictly segregated behind `-EnableAntiForensicMode`. Preserved universal staging hygiene for clean baseline deployments.
* Implemented conditional BitLocker recovery key escrow: when `-EnableLAPS_EntraIDSupport` is enabled, local recovery document export is bypassed in favor of cloud tenant escrow; otherwise, keys are archived locally to `C:\Aegis_BitLocker_Recovery.txt` with locked ACLs.

---

## [1.7.6] - 2026

### Added
* Implemented targeted administrative desktop delivery: `Aegis_Deployment_Report.txt` and `Deployment_Logs.lnk` are staged in `C:\Windows\Panther\` and dispatched dynamically to the created administrator's desktop (`MHS-$StickerID-Admin`) upon first interactive login via `Aegis_PostLogon_Cleanup.ps1`.
* Enforced universal Desktop Recycle Bin icon placement (`{645FF040-5081-101B-9F08-00AA002F954E} = 0`) across `HKCU`, Default User (`NTUSER.DAT`), and all pre-existing user profile hives in `C:\Users\*`.
* Added terminal execution of `dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase` at the conclusion of `Invoke-PostDeploymentFinalization` to maximize reclaimed drive storage.
* Added the optional parameter `-ChangeDefaultWin11Name` (default `$true`) to stamp `Win11_Aegis_OS-$StickerID` into the Boot Configuration Data (BCD) description.

### Fixed
* Resolved administrative profile isolation fault where deployment reports placed on the disabled `Administrator` desktop were inaccessible to the active `MHS-$StickerID-Admin` user.

---

## [1.7.5] - 2026

### Added
* Re-introduced clean partitioning into `autounattend.xml` targeting Disk 0 with `<WillWipeDisk>true</WillWipeDisk>`, an expanded 300MB FAT32 EFI partition (supporting 4Kn native sector media), a 1000MB WinRE partition, and explicit `<BlockAllocationSize>4096</BlockAllocationSize>` formatting on volume C:.
* Enforced `NtfsDisableLastAccessUpdate = 1` and `NtfsDisable8dot3NameCreation = 1` during OOBE setup to eliminate Master File Table write amplification and 8.3 short filename generation overhead in high-density directories.
* Staged an OEM Push-Button Reset engine in `C:\Recovery\OEM\` (`ResetConfig.xml` and `ResetDiskLayout.txt`) to guarantee that native factory resets execute a 4096-byte quick format (`format quick fs=ntfs unit=4096`), maintaining physical NAND alignment across system lifecycles.
* Integrated Option A targeted AppX bloatware de-provisioning, preserving versioned XAML frameworks, the Windows Security Center interface (`SecHealthUI`), and Microsoft Store dependencies required for Winget package management.

### Removed
* Eradicated `NetworkThrottlingIndex = 0xFFFFFFFF` to prevent CPU cache saturation and high DPC latency across modern multi-gigabit network adapters, restoring default dynamic OS throttling.
* Formally rejected and banned experimental native NVMe registry overrides (`nvmedisk.sys` via Velocity IDs `1853569164`, `156965516`, etc.) to protect BitLocker platform configuration registers and preserve OEM diagnostic tool functionality.

---

## [1.7.4] - 2026

### Fixed
* Replaced localized English audit subcategory names with immutable system GUIDs (`{0CCE922B-69AE-11D9-BED3-505054503030}` and `{0CCE922C-69AE-11D9-BED3-505054503030}`) to prevent `0x00000057` execution errors on non-English Windows builds.
* Resolved non-interactive console deadlocks by guarding `[System.Console]::ReadLine()` calls with interactive environment checks in the reboot finalization sequence.
* Mitigated DAW (FL Studio, Ableton, Reaper) and CAD (AutoCAD, Revit) project save failures by transitioning Controlled Folder Access to `AuditMode` by default.
* Mitigated non-relocatable binary crashes in legacy ASIO audio drivers and specialized CAD plugins by removing system-wide `MandatoryASLR` while retaining `BottomUpASLR`.
* Hardened processor architecture queries under CIM to evaluate object arrays safely across multi-socket workstation motherboards (AMD Threadripper PRO, EPYC).
* Hardened `secedit.exe` execution to export current system policies before merging privilege deltas, preventing unintentional resets of unspecified local user rights.

---

## [1.7.3] - 2026

### Fixed
* Corrected PowerShell registry provider exceptions (`Registry::HKU`) by pre-mounting the `HKU` PSDrive alias to `HKEY_USERS`.
* Transitioned Default User hive modifications in `Invoke-DeepShellPurge` to native `reg.exe add` calls, eliminating file handle lock contention during hive unloads.
* Hardened `winget.exe` path discovery against PowerShell strict mode exceptions (`PropertyNotFoundException`) during early OOBE phases by adding system-wide AppX search fallbacks.

---

## [1.7.2] - 2026

### Added
* Expanded Microsoft Defender Attack Surface Reduction (ASR) enforcement from 4 to 14 enterprise rules in Block mode.
* Enforced Exploit Guard system-wide mitigations including Data Execution Prevention (DEP), Bottom-Up ASLR, and Structured Exception Handler Overwrite Protection (SEHOP).
* Enforced LM Compatibility Level 5 (Send NTLMv2 response only, refuse LM & NTLM).
* Enforced blank password usage restrictions across network interfaces (`LimitBlankPasswordUse = 1`).
* Cleared `NullSessionPipes` and `NullSessionShares` in Local Security Authority (LSA) parameters.
* Enabled Microsoft Defender Network Protection and Potentially Unwanted Application (PUA) blocking in Block mode.
* Hardened WinRM transport parameters to disallow basic authentication and prohibit unencrypted network traffic.
* Enforced unauthenticated remote client restrictions on the RPC subsystem (`RestrictRemoteClients = 1`).
* Restricted `SeNetworkLogonRight` to Administrators and Authenticated Users via security database modifications.
* Injected Microsoft Edge Update metered network bypass keys (`EdgeUpdate\UpdateDefault = 1`).
* Integrated automated evacuation of deprecated Windows capabilities (WMIC and VBScript).

---

## [1.7.1] - 2026

### Security
* Replaced static template deployment credentials with the Hardware Identity Engine, dynamically generating `MHS-$StickerID-Admin` anchors from BIOS serial numbers or SHA-256 hashes of system UUID/MAC data.
* Implemented cryptographic high-entropy password generation during setup via `System.Security.Cryptography.RandomNumberGenerator`.
* Enforced mandatory password change upon first interactive login (`net.exe user ... /logonpasswordchg:yes`).
* Added local SAM account verification checks before permitting `LocalAccountTokenFilterPolicy = 1` in hybrid Entra ID / LAPS configurations.

---

## [1.7.0] - 2026

### Changed
* Refactored monolithic procedural scripts into isolated functional blocks with structured try/catch logging and error handling.
* Added enterprise Entra ID and LAPS support flag (`-EnableLAPS_EntraIDSupport`) with automated `LocalAccountTokenFilterPolicy` configuration.
* Integrated unattended Winget package orchestration for baseline development, runtime libraries, and creative toolchains.
* Converted the temporary 7-day Bluetooth audio monitor into a persistent background task (`Aegis_BtMonitor`) to continuously enforce A2DP stereo mode.
* Decoupled GameBar protocol hijacking from `autounattend.xml` specialize passes and migrated staging paths to `C:\Aegis\AegisWin11_Deploy.ps1`.

---

## [1.6.0] - 2025

### Added
* Integrated unattended application provisioning via the Windows Package Manager (`winget.exe`).
* Added initial support for GPU Timeout Detection and Recovery (TDR) delay modifications.
* Added consumer OneDrive de-provisioning logic and File Explorer namespace stripping.

---

## [1.5.0] - 2024

### Changed
* Decomposed monolithic provisioning tasks into modular execution branches.
* Introduced preliminary execution parameter parsing (`param()`) to replace static code editing.
* Began architectural decoupling from offline image modification workflows in preparation for dynamic OOBE orchestration.

---

## Architectural Migration Boundary: Deprecation of Legacy Monolithic Baseline

> Notice: Version 1.4.2 marked the final release of the legacy monolithic `Hardening.ps1` deployment script and offline NTLite image modification workflows. The legacy repository (`Windows-11-Hardening-Isolation-Baseline-NTLite-`) was formally deprecated and transitioned to the modular, dynamic, and non-destructive Aegis Win11 architecture (`Aegis-Win11`).

---

## [1.4.2] - 2024

### Added
* Enforced the Microsoft Kernel-Mode Vulnerable Driver Blocklist via WDAC.
* Restricted OpenSSH client configurations to modern Encrypt-then-Mac (ETM) algorithms.
* Integrated AMD Zen architecture processor evaluation and strong BitLocker PIN advisory logic.
* Added `[GAME_ASSET_PROTECTION]` and `[CLIPBOARD_DATA_HARVESTING]` metadata definition blocks.

### Changed
* Replaced high-risk `DisableProtectedAudioProcessing` with `DisableAllSoundEffects` to eliminate DPC audio latency while preserving DRM media pipelines.
* Replaced aggressive WinPE auto-reboot triggers with standard enterprise local account lockout delay timers.
* Stabilized `HideFastUserSwitching` to remove the Switch User component from the interactive logon interface.

### Security
* Disabled NetBIOS over TCP/IP across all network adapters and disabled LMHOSTS resolution.

---

## [1.4.0] - 2024

### Added
* Scheduled Early Launch Anti-Malware (ELAM) post-OOBE driver initialization tasking.
* Configured weekly Diagnostic Data Framework (DDF) and CSP transactional cache cleanup tasks.
* Staged preliminary driver store auditing routines.

---

## [1.3.5] - 2023

### Added
* Injected 7-day self-destructing Bluetooth A2DP stereo monitor script.
* Enforced Ultimate Performance power scheme and locked display timeouts.
* Enabled LSASS Protected Process Light (`RunAsPPL = 1`).
* Enabled Virtualization-Based Security (VBS) and Hypervisor-Enforced Code Integrity (HVCI).
* Implemented baseline Defender Attack Surface Reduction (ASR) rules.

### Changed
* Mapped default user profile (`NTUSER.DAT`) registry overrides.
* Configured Microsoft Edge and Brave enterprise browser security parameters.
* Implemented account lockout brute-force thresholds (5 attempts / 15 minutes).

---

## [1.3.0] - 2023

### Added
* Enforced Hardware-Accelerated GPU Scheduling (HAGS) mode (`HwSchMode = 2`).
* Enabled NTFS Long Path support (`LongPathsEnabled = 1`).

### Changed
* Implemented dynamic Service Host process grouping calculations (`SvcHostSplitThresholdInKB`).
* Disabled Network Data Usage (NDU) driver to patch non-paged pool memory leaks.
* Locked kernel executive paging to physical storage (`DisablePagingExecutive = 1`).

---

## [1.2.2] - 2023

### Added
* Enabled TCP Receive Side Scaling (RSS) and TCP Window Auto-Tuning.
* Disabled Delivery Optimization peer-to-peer downloading.

### Removed
* Disabled legacy SMBv1 protocol.
* Disabled Link-Local Multicast Name Resolution (LLMNR).
* Disabled GameDVR, BcastDVRUserService, and GameBar presence writers.
* Disabled Fast Startup (`HiberbootEnabled = 0`) and SysMain (Superfetch) services.

---

## [1.2.0] - 2023

### Added
* Enforced SMB 3.1+ message encryption and packet signing.
* Disabled IPv6 network adapter bindings.
* Set `NetworkThrottlingIndex = 0xFFFFFFFF` to remove multimedia packet rate limiting.

---

## [1.1.2] - 2022

### Added
* Configured File Explorer to display hidden files and known file extensions.

### Removed
* Disabled Windows telemetry data collection (`AllowTelemetry = 0`) and advertising tracking.
* Disabled Microsoft consumer features and third-party promotional app pre-installations.
* Disabled Cortana and Windows Search web results.
* Disabled Windows Copilot and Recall data providers; uninstalled provisioned Copilot AppX packages.
* Disabled Windows Widgets and News and Interests feed overlays.
* Disabled Location Services system-wide.
* Disabled lock screen app notifications and cloud clipboard history.

---

## [1.1.0] - 2022

### Added
* Injected OEM branding parameters into System Properties (`sysdm.cpl`).
* Added interactive default credential warning triggers during first logon.
* Blocked automatic Microsoft Teams consumer installations.

---

## [1.0.0 - 1.0.2] - 2022

### Added
* Initialized unattended deployment automation via `autounattend.xml`.
* Established WinPE locale baselines: Australian regional configuration (`en-AU`) with US English input layout.
* Configured post-installation execution staging and Panther transcript logging.
```

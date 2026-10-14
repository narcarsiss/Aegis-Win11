<!-- AEGIS-METADATA:START
Document-Version: 1.8.0
Document-Type: changelog
Maintainer: Moosehead Studio
AEGIS-METADATA:END -->

<p align="center">
  <img src="assets/aegis-crystal-floor.png" alt="Aegis Win11 Logo" width="480" />
</p>

<h1 align="center">Aegis Windows 11 Deployment Toolkit</h1>

<p align="center"><b>Deterministic Low-Latency Systems Engineering &amp; Zero-Trust Device Foundation</b></p>

<p align="center">
  <a href="https://github.com/narcarsiss/Aegis-Win11/releases/tag/v1.8.1">
    <img src="https://img.shields.io/badge/Release-v1.8.1-334155?style=for-the-badge&labelColor=1E293B&logo=github&logoColor=white" alt="Release v1.8.1" /></a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-334155?style=for-the-badge&labelColor=1E293B" alt="License MIT" /></a>
  <a href="https://github.com/narcarsiss/Aegis-Win11/wiki">
    <img src="https://img.shields.io/badge/Wiki-Documentation-334155?style=for-the-badge&labelColor=1E293B&logo=gitbook&logoColor=white" alt="Wiki" /></a>
  <a href="https://www.microsoft.com/windows/">
    <img src="https://img.shields.io/badge/Platform-Windows%2011-334155?style=for-the-badge&labelColor=1E293B&logo=windows11&logoColor=white" alt="Platform Windows 11" /></a>
  <a href="https://learn.microsoft.com/powershell/">
    <img src="https://img.shields.io/badge/Runtime-PowerShell%205.1%2B-334155?style=for-the-badge&labelColor=1E293B&logo=powershell&logoColor=white" alt="PowerShell 5.1+" /></a>
  <a href="#4-cis-benchmark-nist-compliance-posture">
    <img src="https://img.shields.io/badge/Compliance-CIS,%20NIST-334155?style=for-the-badge&labelColor=1E293B" alt="CIS and NIST Compliance" /></a>
  <a href="autounattend.xml">
    <img src="https://img.shields.io/badge/Arch-x64%20%2F%20AMD64-334155?style=for-the-badge&labelColor=1E293B" alt="Architecture x64" /></a>
</p>

---

<details>
<summary><strong>Table of Contents (Click to Expand)</strong></summary>

- [1. Architectural Overview](#1-architectural-overview)
- [2. Systems Architecture Blueprint](#2-systems-architecture-blueprint)
- [3. Workload Compatibility & Boundary Matrix](#3-workload-compatibility-boundary-matrix)
- [4. CIS Benchmark & NIST Compliance Posture](#4-cis-benchmark-nist-compliance-posture)
- [5. Staging & Unattended Deployment Topology](#5-staging-unattended-deployment-topology)
- [6. Parameter Reference](#6-parameter-reference)
- [7. Subsystem Implementations](#7-subsystem-implementations)
- [8. Verification & Diagnostic Auditing](#8-verification-diagnostic-auditing)
- [9. Community & Technical Support](#9-community-technical-support)
- [10. License](#10-license)
</details>

---

## 1. Architectural Overview

Aegis Win11 is an automated, unattended provisioning pipeline engineered to replace arbitrary optimization and debloating scripts with verifiable systems engineering. It establishes a defense-in-depth posture while preventing runtime conflicts within high-performance workstations.

Standard OS stripping scripts regularly induce system failures by severing mandatory networking components (such as unbinding IPv6), degrading process boundaries (grouping svchost.exe instances to claim trivial memory reductions), disabling system memory paging mechanisms, or injecting unvalidated storage driver overrides. Aegis Win11 isolates telemetry, minimizes persistence vectors, and enforces Microsoft Defender Application Control (WDAC) driver blocklists while explicitly maintaining hardware abstraction layers, low-latency audio pipelines, and enterprise identity integration.

---

## 2. Systems Architecture Blueprint

<p align="center">
  <img src="assets/aegis-architecture-flow.png" alt="Aegis Win11 Systems Architecture" width="100%" />
</p>

---

<a id="3-workload-compatibility-boundary-matrix"></a>
## 3. Workload Compatibility & Boundary Matrix

Every policy within Aegis Win11 is evaluated against four non-negotiable operational workstation targets:

*   **Digital Audio Workstations (DAWs):** Preserves native ASIO hardware driver abstraction layers (Focusrite, Universal Audio, RME, Behringer, MOTU). Disables Audio Processing Objects (APOs) via `DisableAllSoundEffects` to eliminate DPC latency spikes while keeping DRM protected media pipelines (Widevine, PlayReady) operational. MMCSS Audio task thread priorities are locked to real-time (`Priority = 8`).
*   **Computer-Aided Design (CAD) & Rendering Suites:** Maintains nested directory depths via NTFS Long Paths (`LongPathsEnabled = 1`), disables NTFS timestamp write operations (`NtfsDisableLastAccessUpdate = 1`), disables 8.3 short filename generation (`NtfsDisable8dot3NameCreation = 1`), and enforces Hardware-Accelerated GPU Scheduling (HAGS) for applications including Autodesk Revit, AutoCAD, Blender, and Adobe Creative Cloud.
*   **Competitive Gaming & Anti-Cheat Runtimes:** Omits strict kernel-mode code integrity policies (`CodeIntegrityPolicy = 1`) and system-wide Mandatory ASLR, ensuring compatibility with kernel-level anti-cheat platforms (Riot Vanguard, Easy Anti-Cheat, BattlEye) and local gaming clients (Steam, Epic Games).
*   **Enterprise Suites & Identity Management:** Supports both standalone workstation topologies and enterprise domains via Microsoft Entra ID / Local Administrator Password Solution (LAPS) integration toggles, preserving Windows Remote Management (WinRM) and modern Kerberos/NTLMv2 authentication pathways. Dynamically anchors local administration under `Aegis$StickerID` to guarantee SAM and NetBIOS 20-character compliance.
*   **Windows 11 26H2 Ready (54-Item Monolithic Standard):** Natively enforces modern kernel isolation, Administrator Protection (just-in-time elevation), WHCP driver code integrity, Post-Quantum Cryptography (ML-KEM/ML-DSA), and strict DNS-over-HTTPS.

---

<a id="4-cis-benchmark-nist-compliance-posture"></a>
## 4. CIS Benchmark & NIST Compliance Posture

Aegis Win11 aligns with technical controls from the Center for Internet Security (CIS) Microsoft Windows 11 Enterprise Benchmark (v3.0.0), NIST SP 800-53 Rev 5 / NIST SP 800-171 Rev 2, DoD DISA STIG, and the ACSC Essential Eight framework across a 54-item monolithic matrix.

### Compliance Coverage Breakdown

*   **CIS Level 1 Profile (Enterprise Baseline):** ~24% direct synthetic implementation (~62 active configuration directives).
*   **CIS Level 2 Profile (High Security / Defense-in-Depth):** ~11% selective implementation.
*   **Standalone Implementation (Non-Domain Applicable):** 67.4% of CIS Level 1 and 82.8% of NIST SP 800-53 workstation controls.
*   **DoD DISA Windows 11 STIG Standalone:** 70.5% (74 / 105 applicable controls).
*   **Microsoft Defender Vulnerability Management (Devices):** 92.6% (63 / 68 controls).
*   **ACSC Essential Eight Workstation Baseline (ML1-ML3):** 88.5% (23 / 26 controls).
*   **Network & Protocol Fortress:** 100% compliance across all applicable standalone network boundaries.

### Documented Technical Deviations

To maintain credibility during external audits and peer review, the framework documents 9 intentional architectural deviations (`DEV-01` through `DEV-09`) formally registered during deployment in `C:\Windows\Panther\Aegis_Compensating_Controls.json`:

1.  **Administrative Identity Anchor (DEV-01 / CIS 2.3.1.1 & 2.3.1.4):** Built-in Administrator (`S-1-5-500`) is permanently disabled. A dynamic hardware-anchored account (`Aegis$StickerID`) is provisioned with 24-character CSPRNG entropy to eliminate RID 500 credential-stuffing targets.
2.  **Process Mitigation (DEV-02 / CIS 18.10.43.2.1):** Bottom-Up ASLR, DEP, and SEHOP are enforced system-wide. Mandatory ASLR (`MandatoryASLR`) is intentionally omitted; enforcing Mandatory ASLR globally causes immediate load termination for binaries and third-party audio/graphics DLLs not compiled with `/DYNAMICBASE`.
3.  **Kernel-Mode Code Integrity (DEV-03 / NIST SI-7):** Immutable WDAC application whitelisting is replaced by the Microsoft Recommended Vulnerable Driver Blocklist, WHCP signature verification, and Administrator Code Signing checks to preserve modular DAW audio interfaces and GPU compute runtimes.
4.  **Local Account Token Filter Policy (DEV-04 / CIS 2.3.10.2):** `LocalAccountTokenFilterPolicy` is conditionally relaxed only when `-EnableLAPS_EntraIDSupport` is active, enabling Windows LAPS and Entra ID remote management while restricting unauthenticated SAM enumeration via `RestrictAnonymousSAM`.
5.  **Power & Performance Throttling States (DEV-05 / DISA STIG WN11-CC-000050):** PCIe link power management and CPU core-parking throttles are deactivated (`stornvme` Link State D0, MMCSS Priority 8, EPP = 0 Race-to-Sleep) to eliminate real-time DPC latency spikes and audio buffer underruns in professional production environments.
6.  **Controlled Folder Access (DEV-06 / CIS 18.10.43.3.1):** Defaulted to `AuditMode`. Enforcing CFA in `Block` mode stops creative software (FL Studio, Ableton, Autodesk) and game runtimes from writing legitimate save states, scratch files, and presets to `%USERPROFILE%\Documents`.
7.  **Telemetry & Diagnostic Data Transmission (DEV-07 / CIS 18.9.30.2):** Diagnostic data is throttled to Security/0 and Settings Cloud Sync is suppressed (`DisableSettingSync = 2`) to maintain air-gapped data sovereignty and prevent cloud leakage of proprietary tokens.
8.  **DNS-over-HTTPS & Name Resolution (DEV-08 / CIS 18.8.14.1):** Strict DoH is mandated (`DoHPolicy = 3`) and unencrypted fallback is prohibited; mDNS and LLMNR are completely excised to eliminate local broadcast spoofing and poisoned credential relay vectors.
9.  **Interactive Logon Legal Notice (DEV-09 / CIS 2.3.7.3):** Interactive legal notice dialogs are suppressed on standalone creator endpoints to ensure unhindered single-user workstation workflows; delegated to enterprise domain group policies.

---

<a id="5-staging-unattended-deployment-topology"></a>
<details>
<summary><strong>5. Staging & Unattended Deployment Topology</strong></summary>

Deployment occurs across three discrete execution boundaries coordinated through `autounattend.xml` and staged PowerShell logic.

```
INSTALLER_USB:
└───autounattend.xml                           # Unattended answer file (4Kn, WinPE, specialize, OOBE)
├── Post-FeatureUpdate-Compare-AegisBase.ps1   # Post-upgrade drift audit & remediation utility
└───sources
    └───$OEM$
        └───$1
            └───Aegis
                └───AegisWin11_Deploy.ps1      # Post-OOBE orchestrator script
```
</details>  

---
> [!WARNING]  
> Deploying `autounattend.xml` with automated disk partitioning (`WipeDisk=true`) destroys all existing volume data on Disk 0. Ensure target machine data is backed up and BitLocker recovery keys are escrowed before boot media execution.
> Ensure the target installation drive enumerates as Disk 0 in the UEFI BIOS prior to boot.
> or disconnect/disable secondary SATA/AHCI drives upon initial staging.
  
---

<a id="6-parameter-reference"></a>
<details>
<summary><strong>6. Parameter Reference (`AegisWin11_Deploy.ps1`)</strong></summary>

| Parameter | Type | Default | Operational Impact |
| :--- | :--- | :--- | :--- |
| `-EnableAntiForensicMode` | Switch / Boolean | `$false` | When `$false`, configures 64MB event logs and enables Event ID 4688 command-line process auditing. When `$true`, caps logs at 1024KB, disables process auditing, purges Prefetch, and clears the USN journal. |
| `-EnforceDeviceEncryption` | Switch / Boolean | `$true` | When `$true`, verifies 4KB allocation unit size and provisions BitLocker XTS-AES-256 with TPM protection. |
| `-EnableLAPS_EntraIDSupport` | Switch / Boolean | `$false` | When `$true`, enables `LocalAccountTokenFilterPolicy` and drops `RestrictAnonymousSAM` once the dynamic anchor user is verified. Bypasses local plaintext key export in favor of cloud escrow. |
| `-ServiceTagIDEnableHardware` | Switch / Boolean | `$true` | Generates the administrative identity anchor from the BIOS serial number. Falls back to UUID/MAC SHA-256 hash if unavailable. |
| `-EnableEdgeTweaks` | Switch / Boolean | `$true` | Applies 33 enterprise security GPOs to Edge and Brave, including DNS-over-HTTPS, ECH, and tracking blocks. |
| `-EnableTelemetryPurge` | Switch / Boolean | `$true` | Strips consumer diagnostic tracking, Cortana, Windows Feeds, and advertising identifiers. |
| `-DeployWingetPackages` | Switch / Boolean | `$true` | Executes automated, unattended Winget package installations for baseline development and runtime tools. |
| `-EvacuateLegacyCapabilities` | Switch / Boolean | `$true` | Removes deprecated attack surfaces: WordPad, VBScript, WMIC, and PowerShell v2. |
| `-PurgeShellUI` | Switch / Boolean | `$true` | Executes Option A targeted bloatware removal and wipes pinned items via Policy Manager. |
| `-PurgeOneDrive` | Switch / Boolean | `$false` | When `$true`, uninstalls consumer OneDrive and removes explorer sidebar namespace CLSIDs. |
| `-AICreativeKernelTuning` | Switch / Boolean | `$false` | When `$true`, extends GPU Timeout Detection and Recovery (TDR) limits to 60 seconds. |
| `-ChangeDefaultWin11Name` | Switch / Boolean | `$true` | Updates the BCD bootloader description to `Win11_Aegis_OS-$StickerID`. |
| `-EnableVBS` | Switch / Boolean | `$true` | Enforces Virtualization-Based Security via group policy. |
| `-EnableHVCI` | Switch / Boolean | `$true` | Enforces Hypervisor-Enforced Code Integrity for kernel execution. |
| `-EnableLegacyFeatures` | Switch / Boolean | `$false` | When `$false` (default), skips redundant DISM capability checks for WordPad/WMIC on Build 26100+ and suppresses vintage registry hacks. When `$true`, executes legacy compatibility routines. |
| `-Unattended` | Switch / Boolean | `$true` | Suppresses interactive GUI modal dialogues, routing credentials to the transcript file. |
| `-AutoReboot` | Switch / Boolean | `$true` | Executes an automated reboot upon pipeline completion. If `$false`, pauses for operator interaction. |
| `-ControlledFolderAccessMode` | String (`Disabled`, `Enabled`, `AuditMode`) | `"AuditMode"` | Configures Microsoft Defender Controlled Folder Access. Defaulted to `AuditMode` to prevent DAW/CAD save failures. |
| `-DefaultSearchProvider` | String | `"duckduckgo"` | Sets the default search engine configuration across enterprise browsers. |
</details>
  
---

<a id="7-subsystem-implementations"></a>
<details>
<summary><strong>7. Subsystem Implementations</strong></summary>

### Hardware Identity Engine
The framework dynamically provisions a unique, hardware-bound administrative anchor during installation:
1.  Queries `Win32_Bios.SerialNumber`. If non-standard, queries `Win32_ComputerSystemProduct.UUID` and hashes the output via SHA-256 to create a 6-character identifier (`$StickerID`).
2.  Provisions `Aegis$StickerID` with a 24-character cryptographic password generated at runtime via `.NET` entropy (`RandomNumberGenerator`), strictly adhering to SAM 20-character boundaries.
3.  Enforces an immediate credential reset upon first interactive console login (`net user ... /logonpasswordchg:yes`).
4.  Exports the secret to `C:\Windows\Panther\Aegis_Bootstrap_Secret.txt` under strict ACL permissions restricted to `SYSTEM` and `Administrators`, then disables the built-in `Administrator` account (`SID S-1-5-500`).

### Storage Subsystem & Recovery Engine Architecture
1.  **Early FVE BitLocker Interception:** Injects `EncryptionMethodWithXtsOs = 7` during the `specialize` pass of `autounattend.xml`, pre-empting native Windows 11 automatic device encryption and enforcing XTS-AES-256 on the first pass to eliminate multi-hour 128-bit re-encryption cycles.
2.  **Unified 4096-Byte File Allocation:** The `autounattend.xml` schema forces `BlockAllocationSize = 4096` on volume `C:` during the clean WinPE format pass. Matching NTFS cluster sizes to physical 4KB NAND pages eliminates Read-Modify-Write (RMW) amplification loops, extending flash endurance and reducing I/O write latency.
3.  **Metadata & Index Suppression:** Sets `NtfsDisableLastAccessUpdate = 1` and `NtfsDisable8dot3NameCreation = 1` during OOBE setup. This stops Master File Table (MFT) write thrashing and eliminates 8.3 short filename generation overhead across directories containing massive file counts.
4.  **Continuous Controller Readiness:** Configures `IdleTimeout = 0` and `EnableD3 = 0` under `stornvme\Parameters\Device`, keeping NVMe links in active power state D0 and eliminating controller wake-up latency during real-time I/O processing.
5.  **Storage Sense Automation:** Injects native policies (`AllowStorageSenseGlobal = 1`, `ConfigStorageSenseCloudContentCleanThreshold = 30`) to purge unreferenced temporary files automatically.
6.  **Push-Button Reset (PBR) 4KB Mirroring:** Stages a bare-metal recovery engine via `C:\Recovery\OEM\ResetConfig.xml`. If a full wipe reset is executed, WinRE formats the system partition using an exact 4096-byte quick format (`format quick fs=ntfs unit=4096`), guaranteeing that factory recovery operations maintain physical NAND page alignment.
7.  **Silent Hardware BitLocker Pipeline:** Validates that TPM 2.0 is ready and that volume `C:` possesses an allocation unit size of exactly 4096 bytes before silently enabling XTS-AES-256 BitLocker encryption with a TPM protector. If `-EnableLAPS_EntraIDSupport` is false, it archives the recovery password to `C:\Aegis_BitLocker_Recovery.txt`; otherwise, local export is bypassed in favor of cloud escrow.

### Consumer Bloatware Sanitization
Aegis Win11 rejects blanket wildcard AppX removal scripts (`Get-AppxPackage | Remove-AppxPackage`). Indiscriminate package uninstallation destroys versioned Windows 11 system runtimes (`Microsoft.UI.Xaml.2.8`), the Windows Security Center interface (`Microsoft.SecHealthUI`), and Microsoft Store infrastructure required for Winget package management.

The framework enforces an explicit, non-destructive consumer blacklist targeting third-party and non-essential consumer stubs (BingNews, BingWeather, Clipchamp, Solitaire, Zune Video, Todos). Both installed instances and online provisioned stubs (`Get-AppxProvisionedPackage`) are uninstalled, preventing re-provisioning on secondary local user profiles while keeping system dependencies intact.

### Targeted Desktop Audit & Logs Delivery
1. `Aegis_Deployment_Report.txt`: Full text log detailing pass/fail posture across all baseline settings.
2. `Aegis_Deploy.json`: Machine-readable telemetry log serialized directly from pipeline execution memory.
3. `Deployment_Logs.lnk`: Desktop shortcut resolving directly to the local staging directory (`C:\Windows\Panther\`).
4. `Post-FeatureUpdate-Compare-AegisBase.ps1`: Companion drift auditing utility allowing administrators to detect and remediate policy reversion after major Windows updates.
A post-install first-logon dispatcher (`Aegis_PostLogon_Cleanup.ps1`) transfers these files directly onto the created administrator's desktop (`Aegis$StickerID`), ensuring full visibility while keeping public and unprivileged desktops clean.
</details>
  
---

<a id="8-verification-diagnostic-auditing"></a>
<details>
<summary><strong>8. Verification & Diagnostic Auditing</strong></summary>

### Companion Live-OS Drift Auditing Engine (`Post-FeatureUpdate-Compare-AegisBase.ps1`)

Major Windows Feature Updates (e.g., updating to 26H2) and cumulative servicing packages frequently overwrite local security policies and re-enable telemetry services. Aegis includes a standalone companion drift auditor designed to run on live, post-update systems:

* **Read-Only Non-Destructive Auditing:** Compares active registry keys, service startup configurations, and driver code integrity policies against the master 54-item baseline without modifying system state.
* **Compensating Controls Manifest Verification:** Ingests and parses `C:\Windows\Panther\Aegis_Compensating_Controls.json`, verifying that all 9 approved architectural exceptions (`DEV-01` through `DEV-09`) remain certified.
* **Single-Item Interactive Remediation:** Prompts operators individually (`[Y]es / [N]o / [Q]uit`) to restore drifted policies. Blanket overrides are prevented to ensure operational stability.
* **OS Build & Legacy Feature Gating:** Uses dynamic build detection (`MinBuild = 26300`) to suppress false-positive drift warnings on pre-26H2 images, and gates legacy checks behind `-EnableLegacyFeatures`.

```powershell
# 1. Execute non-destructive audit pass:
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AuditOnly

# 2. Execute interactive single-item remediation:
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1

# 3. Force automated mass remediation across all drifted policies:
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AutoRemediateAll
```

### Manual Diagnostic Commands

Post-installation validation can also be executed using elevated PowerShell diagnostic commands:

```powershell
# 1. Verify 4KB Allocation Unit Size
Get-Volume -DriveLetter C | Select-Object DriveLetter, AllocationUnitSize, FileSystemLabel

# 2. Verify BitLocker Encryption Status and Algorithm (XtsAes256)
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, ProtectionStatus, EncryptionMethod, VolumeType

# 3. Verify Attack Surface Reduction Rules (14 Rules in Block Mode)
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# 4. Verify Exploit Guard System Mitigations
Get-ProcessMitigation -System

# 5. Verify User Rights Assignment for Network Logons
secedit.exe /export /cfg "$env:TEMP\secpol_verify.inf" /areas USER_RIGHTS /quiet
Select-String -Path "$env:TEMP\secpol_verify.inf" -Pattern "SeNetworkLogonRight"
Remove-Item -Path "$env:TEMP\secpol_verify.inf" -Force

# 6. Verify Compensating Controls Manifest Schema & Integrity
Get-Content -Path "C:\Windows\Panther\Aegis_Compensating_Controls.json" | ConvertFrom-Json | Select-Object -ExpandProperty CompensatingControls | Format-Table DeviationID, Standard, Status
```
</details>
  
---

<a id="9-community-technical-support"></a>
## 9. Community & Technical Support

*   **Wiki Documentation:** [Aegis-Win11 Wiki](https://github.com/narcarsiss/Aegis-Win11/wiki)
*   **Technical Reference Manual:** [54-Item Policy Matrix](https://github.com/narcarsiss/Aegis-Win11/wiki/Technical-Reference-Manual)
*   **Security Architecture Report:** [Formal Compliance Audit](https://github.com/narcarsiss/Aegis-Win11/wiki/Security-Architecture-&-Compliance-Report)
*   **Community Discussions:** [GitHub Discussions](https://github.com/narcarsiss/Aegis-Win11/discussions)
     
---

<a id="10-license"></a>
## 10. License

<<<<<<< HEAD
Released by Moosehead Studio under the MIT License. See `LICENSE` for details.
<<<<<<< Updated upstream
=======
<!-- AEGIS-REVISION-MATRIX:START -->
<!-- AEGIS-REVISION-MATRIX:END -->
>>>>>>> Stashed changes
=======
Released by Moosehead Studio under the MIT License. See `LICENSE` for details.
>>>>>>> 1c37ff213d024c2a271339d7524c1b5f4eaf778c

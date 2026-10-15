<!-- [METADATA]
{
  "DocumentID": "AEGIS-WIKI-HOMEPAGE",
  "Title": "Aegis Win11 Enterprise Deployment Toolkit",
  "Version": "1.8.1",
  "ReleaseDate": "2026-10-14",
  "Classification": "Declassified Internal Engineering Documentation",
  "TargetOS": "Windows 11 Enterprise / Pro (24H2, 26H2)",
  "BaselineMatrix": "54-Item Monolithic Architecture",
  "CompensatingControls": "DEV-01 through DEV-09",
  "ComplianceStandards": [
    "CIS Windows 11 Enterprise Benchmark v3.0.0",
    "NIST SP 800-53 Rev 5",
    "DoD DISA Windows 11 STIG",
    "ACSC Essential Eight"
  ],
  "Maintainer": "Damien John O'Brien / Moosehead Studio"
}
-->

<!-- AEGIS-REVISION-MATRIX:START -->
<!-- AEGIS-REVISION-MATRIX:END -->

<p align="center">
  <img src="https://raw.githubusercontent.com/narcarsiss/Aegis-Win11/main/assets/aegis-shield-base.png" alt="Aegis shield base" width="25%" />
</p>

# Aegis Windows 11 Enterprise Infrastructure Wiki

Welcome to the technical reference wiki for the Aegis Windows 11 enterprise deployment ecosystem, maintained by Moosehead Studio.

Aegis-Win11 is an automated unattended provisioning pipeline and security hardening baseline engineered for physical Windows 11 workstations. It replaces brittle, unvalidated consumer debloating scripts with verifiable systems engineering. It establishes a defense-in-depth posture aligned with CIS Benchmarks, NIST SP 800-53 Rev 5, DoD DISA STIG, and ACSC Essential Eight controls while explicitly optimizing hardware pipelines for low-latency digital audio (ASIO/DAW), 3D engineering (CAD), and high-throughput execution runtimes without degrading gaming compatibility.

---

## Architectural Profiles

* **Digital Audio Workstations (DAWs):** Elevates Multimedia Class Scheduler Service (MMCSS) audio thread priorities to real-time (Priority 8), bypasses aggressive Bluetooth Hands-Free profile downsampling, suppresses Audio Processing Object (APO) pipeline overhead, and forces NVMe storage controller links into continuous low-latency state D0 (`IdleTimeout = 0`).
* **CAD and 3D Compute Stability:** Enforces Hardware-Accelerated GPU Scheduling (HAGS), removes `MAX_PATH` directory limits, suppresses NTFS metadata thrashing, and provides optional 60-second GPU Timeout Detection and Recovery (TDR) limits to prevent driver resets during heavy renders.
* **Competitive Gaming & Anti-Cheat Runtimes:** Omits strict kernel-mode code integrity policies (`CodeIntegrityPolicy = 1`) and system-wide Mandatory ASLR, ensuring compatibility with kernel-level anti-cheat platforms (Riot Vanguard, Easy Anti-Cheat, BattlEye) and local gaming clients (Steam, Epic Games).
* **Enterprise Suites & Identity Management:** Supports both standalone workstation topologies and enterprise domains via Microsoft Entra ID / Local Administrator Password Solution (LAPS) integration toggles, preserving Windows Remote Management (WinRM) and modern Kerberos/NTLMv2 authentication pathways. Dynamically anchors local administration under `Aegis$StickerID` to guarantee SAM and NetBIOS 20-character compliance.
* **Windows 11 26H2 Ready (54-Item Monolithic Standard):** Natively enforces modern kernel isolation, Administrator Protection (just-in-time elevation), WHCP driver code integrity, Post-Quantum Cryptography (ML-KEM/ML-DSA), and strict DNS-over-HTTPS.

---

## Ecosystem Scope Separation

The Aegis ecosystem maintains strict separation of concerns across three distinct repositories:

1. **Aegis-Win11 (This Repository):**
   * Core unattended installer schema (`autounattend.xml`).
   * Master post-OOBE deployment orchestrator (`AegisWin11_Deploy.ps1`).
   * Companion Live-OS Drift Auditing Engine (`Post-FeatureUpdate-Compare-AegisBase.ps1`).
   * Strictly code-only; zero binary image assets.

2. **Aegis-Haven:**
   * Standalone desktop application built on WinUI 3 / Windows App SDK (C# .NET).
   * Automates bootable USB media formatting, official ISO ingestion, driver slipstreaming, and bare-metal WinRE recovery image authoring.

3. **Aegis-Theme-Engine:**
   * Standalone companion package for visual asset delivery.
   * Houses custom 4K dark-mode wallpapers, multi-DPI user account picture tiles, cursor schemes, and Microsoft Edge enterprise theme policies.

---

## Technical Documentation Index

The technical reference documentation is organized into dedicated engineering manuals:

* **[Technical Reference Manual](Technical-Reference-Manual.md):** The complete 54-item granular policy matrix. Documents individual registry hives, target states, operational break risks, technical functions, beneficial use cases, NOC warnings, and standalone PowerShell orchestration blocks for every configuration.
* **[Security Architecture & Compliance Report](Security-Architecture-&-Compliance-Report.md):** The formal security evaluation report. Contains standalone benchmark scorecards across CIS Level 1/2, NIST SP 800-53, DISA STIG, Defender Vulnerability Management, and ACSC Essential Eight, alongside full technical justifications for all 9 approved architectural deviations (`DEV-01` through `DEV-09`).
* **[Community Discussions & Triage](https://github.com/narcarsiss/Aegis-Win11/discussions):** Architectural inquiries, support triage standards, and hardware compatibility forums explaining why legacy debloater tweaks (such as disabling IPv6 or disabling pagefiles) are strictly rejected.

---

## Rapid Deployment Workflow

```
TARGET_INSTALLER_USB:
├── autounattend.xml
└── sources/
    └── $OEM$/
        └── $1/
            └── Aegis/
                └── AegisWin11_Deploy.ps1
```

### 1. Staging Media Preparation
1. Format a target USB storage device with UEFI GPT FAT32.
2. Copy standard Windows 11 installation media assets to the USB root.
3. Place `autounattend.xml` in the root directory of the USB media.
4. Stage `AegisWin11_Deploy.ps1` at `USB:\sources\$OEM$\$1\Aegis\AegisWin11_Deploy.ps1`.

### 2. Workstation Execution Flow

<p align="center">
  <img src="https://raw.githubusercontent.com/narcarsiss/Aegis-Win11/main/assets/assets/aegis-workstation-execution-flow.png" alt="Aegis execution flow" width="100%" />
</p>

<details>
<summary>Expand for text version</summary>

1. Connect the deployment USB drive to the target physical workstation.
2. Boot into the UEFI USB installer environment.
3. Windows Setup parses `autounattend.xml`:
   * **WinPE Pass:** Formats Disk 0 with deterministic 4096-byte (4Kn) physical page allocation on volume `C:`, creating a 1000MB WinRE recovery partition and a 300MB EFI system partition.
   * **Specialize Pass:** Injects early BitLocker Full Volume Encryption (FVE) policies (`EncryptionMethodWithXtsOs = 7`), forcing XTS-AES-256 natively during initial OOBE hardware handoffs and eliminating 128-bit re-encryption cycles.
   * **Mirroring:** Windows Setup mirrors `sources\$OEM$\$1\` directly to `C:\Aegis\`.
   * **FirstLogonCommands:** Silently executes `C:\Aegis\AegisWin11_Deploy.ps1` non-interactively under elevated bypass context.
4. Following automated execution, review the verification audit artifacts delivered directly to the provisioned administrator desktop (`Aegis$StickerID`):
   * `Aegis_Deployment_Report.txt` (Human-readable baseline compliance summary).
   * `Aegis_Deploy.json` (Machine-readable pipeline telemetry log).
   * `Aegis_Compensating_Controls.json` (Formal auditor manifest certifying deviations `DEV-01` to `DEV-09`).
   * `Deployment_Logs.lnk` (Direct shortcut to the secure `C:\Windows\Panther\` directory).
   </details>

---

## Post-Update Lifecycle Maintenance

Major Windows Feature Updates (such as updating to version 26H2) and cumulative servicing updates regularly revert local security policies and re-enable background telemetry services. Aegis provides a standalone live-OS audit tool to maintain baseline compliance over the workstation lifecycle:

```powershell
# Execute non-destructive audit against the 54-item baseline:
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AuditOnly

# Execute interactive single-item policy remediation:
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1

# Force automated mass remediation across all drifted policies:
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AutoRemediateAll
```

---

## Architectural Hazard Exclusion Baseline

Under no circumstances will Aegis generate, incorporate, or support modifications matching the Architectural Hazard Exclusion Baseline:

* **Memory & Kernel Subsystem:** Reject `DisablePagingExecutive = 1`, pagefile deactivation, `LargeSystemCache = 1`, and Virtualization-Based Security (VBS) or Hypervisor-Enforced Code Integrity (HVCI) deactivation.
* **Network Stack:** Reject unbinding or disabling IPv6, setting `NetworkThrottlingIndex = 0xFFFFFFFF`, and globally disabling Nagle's algorithm (`TcpAckFrequency = 1` / `TCPNoDelay = 1`).
* **Storage Subsystem:** Reject disabling TRIM, experimental native NVMe velocity overrides (`nvmedisk.sys` via FeatureManagement Velocity IDs), and live-volume NTFS 8.3 or LastAccess registry injections.
* **Services & Shell:** Reject disabling `SysMain` on solid-state NVMe drives, unbinding the Windows Event Log service, and executing indiscriminate wildcard AppX package purges.

---

## License & Ownership

The Aegis Windows 11 Enterprise Deployment Toolkit is engineered and maintained by Damien John O'Brien / Moosehead Studio. Released under the MIT License. See `LICENSE` for details.
# Aegis Windows 11 Enterprise Infrastructure Wiki

<!-- AEGIS-METADATA:START
Document-Version: 1.8.0
Document-Type: Enterprise Infrastructure Documentation
Maintainer: Moosehead Studio
AEGIS-METADATA:END -->
<!-- AEGIS-REVISION-MATRIX:START -->
<!-- AEGIS-REVISION-MATRIX:END -->

<p align="center">
  <img src="https://raw.githubusercontent.com/narcarsiss/Aegis-Win11/main/assets/aegis-shield-base.png" alt="Aegis shield base" width="25%" />
</p>

**Document revision:** `1.8.0`  
**Maintained by:** Moosehead Studio  
**Target Operating System:** Windows 11 Ent / Edu / Pro / Home.  
**Builds** 22H2, 23H2, 24H2, 26H2  


The central technical reference for the Aegis Win11 Enterprise Deployment Toolkit, covering system architecture, security policies, compliance baselines, and deployment procedures.

---

## Architectural Philosophy

Aegis Win11 is engineered to replace subjective, community-sourced "debloating" scripts with deterministic systems engineering. It provides a hardened defense-in-depth posture while preserving execution boundaries required by specialized production environments:

* **Non-Destructive Baselines:** Core operating system dependencies are preserved. Mandatory services like IPv6 remain bound, `svchost.exe` process isolation is maintained, the virtual memory pagefile is retained, and experimental, unvalidated storage drivers (`nvmedisk.sys`) are strictly avoided.
* **Low-Latency Creative Audio Workstations:** Audio Processing Objects (APOs) are unhooked via `DisableAllSoundEffects = 1` and MMCSS audio scheduling thread priorities are locked to Priority 8, preventing DPC latency spikes and buffer underruns in professional studio DAWs while preserving DRM protected media pipelines.
* **CAD and 3D Compute Stability:** Enforces Hardware-Accelerated GPU Scheduling (HAGS), removes `MAX_PATH` directory limits, suppresses NTFS metadata thrashing, and provides optional 60-second GPU Timeout Detection and Recovery (TDR) limits to prevent driver resets during heavy renders.
* **Anti-Cheat and Gaming Compatibility:** Excludes global Mandatory ASLR and strict kernel driver code integrity whitelisting, ensuring unconstrained compatibility with competitive kernel-level anti-cheat platforms (Riot Vanguard, Easy Anti-Cheat, BattlEye) and gaming clients (Steam, Epic Games).
* **Enterprise Identity Ready:** Dynamically provisions hardware-anchored administrative accounts (`Aegis$StickerID`), disables the well-known built-in Administrator, and provides conditional UAC remote token relaxation for Microsoft Entra ID and Windows LAPS deployments.

---

## Systems Architecture Blueprint

<p align="center">
  <img src="https://raw.githubusercontent.com/narcarsiss/Aegis-Win11/main/assets/aegis-parameter-matrix.png" alt="Aegis Win11 parameter matrix" width="100%" />
</p>

---

## Documentation Navigation Map

The technical documentation is organized into dedicated reference manuals:

* **[Technical Reference Manual](Technical-Reference-Manual):** The complete 44-item granular policy matrix. Documents individual registry hives, target states, operational break risks, technical functions, beneficial use cases, NOC warnings, and standalone PowerShell orchestration blocks for every configuration.
* **[Security Architecture & Compliance Report](Security-Architecture-&-Compliance-Report):** The formal security evaluation report. Contains the standalone benchmark scorecard across the top 10 security auditing toolkits (63.0% CIS Level 1, 75.9% NIST SP 800-53, 89.7% MDE, and 100% Network Fortress) alongside documented technical justifications for intentional compliance deviations.
* **[Frequently Asked Questions & Community Triage](https://github.com/narcarsiss/Aegis-Win11/discussions):** Community discussion forums, triage standards, and architectural inquiries covering why legacy debloater tweaks are excluded from the baseline.

---

## 100% Standalone Network Fortress Milestone

Aegis Win11 achieves a complete 100% pass rate across all applicable standalone networking and protocol hardening controls defined in the CIS, NIST, and DISA STIG benchmarks:

* **Broadcast Resolution Poisoning Elimination:** Deactivates Link-Local Multicast Name Resolution (`EnableMulticast = 0`), NetBIOS over TCP/IP on all network adapters (`NetbiosOptions = 2`), and LMHOSTS lookup (`EnableLMHOSTS = 0`), neutralizing Responder-based spoofing attacks.
* **Remote Credential Redirection Severance:** Terminates and disables the legacy `WebClient` service (`Start = 4`) and disables insecure HTTP printing, eliminating remote WebDAV credential relay attacks.
* **SMB Transport Cryptography:** Removes the deprecated SMBv1 protocol feature and mandates cryptographic SMBv3 packet signing (`RequireSecuritySignature = $true`) across both client and server profiles.
* **Remote Management Isolation:** Restricts Windows Remote Management (WinRM) to encrypted transport only, disables basic authentication, and mandates authenticated RPC client bindings (`RestrictRemoteClients = 1`).

---

## Rapid Deployment Quickstart

### 1. Media Preparation
1. Format a USB flash drive as GPT with a FAT32 partition labeled `BOOT`.
2. Extract the standard Windows 11 Enterprise or Pro ISO contents onto the USB media.
3. Place `autounattend.xml` in the root directory of the USB drive (`USB:\autounattend.xml`).

### 2. Payload Staging
Stage the master orchestrator script within the distribution share structure:
```
USB_ROOT:\
├── autounattend.xml
└── sources\
    └── $OEM$\
        └── $1\
            └── Aegis\
                └── AegisWin11_Deploy.ps1
```

### 3. Execution
1. Connect the USB drive to the target physical workstation.
2. Boot into the UEFI USB installer.
3. Windows Setup parses `autounattend.xml`, intercepts BitLocker encryption via early FVE registry injection, executes 4096-byte page-aligned partitioning on Disk 0, mirrors `$OEM$\$1` to `C:\Aegis\`, and executes `AegisWin11_Deploy.ps1` non-interactively during `FirstLogonCommands`.

> [!TIP]
> Review the generated deployment audit documents (`Aegis_Deployment_Report.txt` and `Aegis_Deploy.json`) located at `C:\Windows\Panther\`.  
> These are delivered directly to the new administrator's desktop upon first logon.


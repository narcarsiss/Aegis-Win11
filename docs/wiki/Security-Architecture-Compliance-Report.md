# Security Architecture & Compliance Audit

<!-- AEGIS-METADATA:START
Document-Version: 1.8.0
Document-Type: Security Architecture & Compliance Documentation
Maintainer: Moosehead Studio
AEGIS-METADATA:END -->

<p align="center">
  <img src="../../assets/aegis-shield-base.png" alt="Aegis shield base" width="25%" />
</p>

**Document revision:** `1.8.0`  
**Maintained by:** Moosehead Studio  
**Target Operating System:** Windows 11 Ent / Edu / Pro / Home.
**Builds** 22H2, 23H2, 24H2, 26H2  
**Security Framework Alignment:** CIS Microsoft Windows 11 Enterprise Benchmark (v3.0.0), NIST SP 800-53 Rev 5, DoD DISA Windows 11 STIG  

---

## 1. Executive Summary

This document defines the security architecture, compliance posture, and deliberate engineering trade-offs of the Aegis Win11 deployment framework. Aegis Win11 is engineered for hybrid high-performance environments—specifically workstations running low-latency Digital Audio Workstations (DAWs), Computer-Aided Design (CAD) applications, competitive gaming engines with kernel-level anti-cheat platforms, and enterprise administrative suites.

Third-party endpoint baselines often chase superficial metrics, attempting to score 100% on automated compliance tools. In doing so, they enforce destructive configurations that disable core operating system networking, break professional hardware drivers, and halt development environments. Aegis Win11 rejects this approach. It enforces high-impact defense-in-depth controls while documenting explicit deviations required to maintain production stability across professional creative and operational workloads.

---

## 2. Benchmark Reality: The Fallacy of 100% Synthetic Compliance

When scanned with automated auditing engines (CIS-CAT Pro, DISA SCAP Compliance Checker, Tenable Nessus, Rapid7 InsightVM), an endpoint deployed via Aegis Win11 scores between 20% and 25% overall compliance against full enterprise benchmarks, while achieving an 89.7% standalone configuration score within Microsoft Defender Vulnerability Management.

Understanding this variance requires distinguishing between an unmanaged workstation deployment script and a domain-joined enterprise environment governed by Active Directory Domain Services (AD DS) or Microsoft Intune:

* **Centralized Directory Dependencies:** The CIS Windows 11 Enterprise Benchmark contains over 350 individual rules. More than 200 of these directives require an active Active Directory forest, Kerberos Key Distribution Center (KDC), or centralized Public Key Infrastructure (PKI). Enforcing these on an offline or standalone deployment causes immediate failure states.
* **Government-Specific Mandates:** DISA STIG benchmarks enforce requirements unique to federal networks, such as DoD legal logon banners, mandatory Common Access Card (CAC) smart-card infrastructure, and federal certificate trust chains. These controls provide no security value to commercial, creative, or private operational workstations.
* **Destructive Hardening Rules:** Level 2 benchmarks mandate configurations—including PowerShell Constrained Language Mode, global Mandatory ASLR, and complete NTLM denial—that directly terminate non-enterprise software suites.

Aegis Win11 focuses on the controls that represent real-world attack vectors: remote credential harvesting, unauthenticated network relays, kernel exploitation, and persistent host telemetry.

---

## 3. Hardness Scorecard Across Top 10 Security Benchmarks

The following assessment compares the raw compliance score across the entire benchmark versus the actual pass rate for discrete, standalone technical controls that do not require external directory infrastructure.

| # | Toolkit / Benchmark Name | Overall Score (Full Enterprise Benchmark) | Standalone Score (No AD / Entra ID / PKI Dependency) | Primary Implementation Focus |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **CIS Microsoft Windows 11 Enterprise (v3.0.0) - Level 1** | Implemented 58 of 241 = **24.1%** | Implemented 58 of 92 = **63.0%** | Baseline host protection, LSA PPL, Exploit Guard. |
| **2** | **CIS Microsoft Windows 11 Enterprise (v3.0.0) - Level 2** | Implemented 11 of 98 = **11.2%** | Implemented 11 of 32 = **34.4%** | Kernel isolation, hypervisor code integrity, ASR rules. |
| **3** | **DoD DISA Windows 11 STIG (v1/v2 Baseline)** | Implemented 69 of 280 = **24.6%** | Implemented 69 of 105 = **65.7%** | CAT I immediate exploit mitigation, legacy removal. |
| **4** | **NIST SP 800-53 Rev 5 (Workstation Technical Controls)** | Implemented 44 of 124 = **35.5%** | Implemented 44 of 58 = **75.9%** | Access control, host audit logs, memory virtualization. |
| **5** | **NIST SP 800-171 Rev 2/3 (CUI Protection - Endpoint)** | Implemented 22 of 48 = **45.8%** | Implemented 22 of 29 = **75.9%** | Data-at-rest encryption, malicious code isolation. |
| **6** | **Microsoft Defender Vulnerability Management (Secure Score)** | Implemented 61 of 85 = **71.8%** | Implemented 61 of 68 = **89.7%** | Device posture, ASR block rules, PUA/SmartScreen. |
| **7** | **Microsoft Security Compliance Toolkit (MS SCT GPO Baseline)** | Implemented 74 of 215 = **34.4%** | Implemented 74 of 96 = **77.1%** | Core Windows security templates, credential isolation. |
| **8** | **ACSC Essential Eight (Workstation Maturity Levels 1-3)** | Implemented 22 of 36 = **61.1%** | Implemented 22 of 26 = **84.6%** | Application control, macro execution, user restrictions. |
| **9** | **Tenable Nessus (CIS Windows 11 Enterprise Audit)** | Implemented 72 of 348 = **20.7%** | Implemented 72 of 104 = **69.2%** | Local registry audits, account policies, RPC security. |
| **10** | **Rapid7 InsightVM (Windows 11 Policy Manager Benchmark)** | Implemented 70 of 335 = **20.9%** | Implemented 70 of 101 = **69.3%** | Exploit mitigations, local boundary sanitization. |

---

## 4. Architectural Boundary: Endpoint Hardening vs. Identity Infrastructure

Security benchmarks evaluate an entire enterprise IT ecosystem, not merely the local operating system. Over 60% of benchmark rules require domain-level directory infrastructure to satisfy:

* **Active Directory (AD DS) & Kerberos (KDC):** Enforces ticket lifetimes, account lockouts across domain controllers, and centralized password age policies.
* **Public Key Infrastructure (PKI):** Distributes trusted enterprise root certificates and smart-card enrollment profiles.
* **Microsoft Entra ID (EID):** Governs Conditional Access policies, device compliance health attestation, and Multi-Factor Authentication (MFA).

An endpoint script cannot fabricate domain infrastructure. Attempting to force domain-dependent GPO settings onto an unmanaged or local client creates corrupted policies without improving security. Aegis strictly hardens the host execution boundaries, local memory layout, kernel drivers, and network protocols. When the system joins Active Directory or Entra ID, enterprise identity policies layer over this hardened foundation without conflict.

---

## 5. Intentional Technical Deviations and Operational Rationale

To maintain workload integrity across high-performance environments, Aegis Win11 explicitly deviates from the following benchmark recommendations:

### A. Exploit Guard: Mandatory ASLR (CIS 18.10.14.2.1)
* **Benchmark Directive:** Enforce Mandatory Address Space Layout Randomization (Force ASLR) system-wide.
* **Operational Conflict:** Mandatory ASLR strips base-relocation flexibility. Any third-party binary or dynamic link library (`.dll`) compiled without the `/DYNAMICBASE` flag fails to initialize, returning error code `0xC000007B`.
* **Workload Impact:** Crashes legacy and proprietary ASIO audio interface drivers (Focusrite, Universal Audio, RME, MOTU), older DAW VST2 audio plugins, and specialized CAD macros.
* **Aegis Baseline:** Enforces system-wide Data Execution Prevention (DEP), Structured Exception Handler Overwrite Protection (SEHOP), and Bottom-Up ASLR (`BottomUpASLR`), while explicitly keeping Mandatory ASLR disabled.

### B. PowerShell Constrained Language Mode (CIS 18.10.43.1 / NIST CM-7)
* **Benchmark Directive:** Enforce Constrained Language Mode (`__PSLockdownPolicy = 4`) globally.
* **Operational Conflict:** Constrained Language Mode restricts PowerShell to basic core cmdlets, blocking custom .NET type instantiation, COM object handling, and API interop calls.
* **Workload Impact:** Disables administrative orchestration scripts, CI/CD automated deployment runners, CAD build tasks, and software installation pipelines.
* **Aegis Baseline:** Retains Full Language Mode for administrative runtimes while implementing 14 Attack Surface Reduction (ASR) rules to prevent malicious scripts from making Win32 API calls or injecting code.

### C. Kernel-Mode Code Integrity Driver Whitelisting (CIS 18.10.43.1 / NIST SI-7)
* **Benchmark Directive:** Restrict kernel driver execution to a static, predefined cryptographic whitelist via strict WDAC.
* **Operational Conflict:** Halts initialization of any hardware driver not signed by Microsoft's WHQL root and cataloged in a static cryptographic XML policy.
* **Workload Impact:** Blocks proprietary digital audio hardware interfaces and competitive gaming anti-cheat kernel modules (Riot Vanguard, Easy Anti-Cheat, BattlEye).
* **Aegis Baseline:** Enforces the Microsoft Kernel-Mode Vulnerable Driver Blocklist (`VulnerableDriverBlocklistEnable = 1`). This mitigates Bring Your Own Vulnerable Driver (BYOVD) attack vectors while allowing legitimate, signed third-party drivers to initialize without manual catalog maintenance.

### D. Controlled Folder Access (CIS 18.10.43.4.2)
* **Benchmark Directive:** Enable Controlled Folder Access in `Block` mode.
* **Operational Conflict:** CFA locks all non-whitelisted process writes to standard user directories (`Documents`, `Desktop`, `Pictures`, `Music`).
* **Workload Impact:** DAWs (Ableton, FL Studio, Reaper, Pro Tools) cannot record audio tracks or save session presets to disk. CAD tools (AutoCAD, Revit) crash during auto-save routines. Game clients (Steam, Epic Games) fail to write local save files to `%USERPROFILE%\Documents\My Games`.
* **Aegis Baseline:** Deploys CFA in `AuditMode` by default, generating event logs for untrusted write operations without dropping user-mode file writes.

### E. Outbound NTLM Traffic Deny All (CIS 2.3.11.5)
* **Benchmark Directive:** Set "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" to `Deny All`.
* **Operational Conflict:** Completely halts NTLM authentication fallbacks across external network targets.
* **Workload Impact:** Eliminates connectivity to standalone local network-attached storage appliances (QNAP, Synology, TrueNAS) and office printers that cannot negotiate pure Kerberos tickets.
* **Aegis Baseline:** Configures LM Compatibility Level 5 (Send NTLMv2 responses only, refuse LM and NTLM). This blocks legacy hashing without breaking local SMB storage workflows.

### F. Mandatory SMB3 Payload Encryption (CIS 2.3.8.3)
* **Benchmark Directive:** Enforce encryption on all SMB communication (`EncryptData = 1`).
* **Operational Conflict:** Saturates workstation CPU cores with continuous cryptographic overhead during sustained local network transfers.
* **Workload Impact:** Severely throttles transfer speeds across 2.5 GbE and 10 GbE connections when moving 4K video scratch files, multi-gigabyte audio sample libraries, or engineering datasets.
* **Aegis Baseline:** Enforces SMB Message Signing (`RequireSecuritySignature = 1`) on both client and server configurations to eliminate NTLM relay and tampering attacks, while leaving payload encryption unconstrained for maximum local throughput.

---

## 6. The 100% Network & Protocol Fortress Milestone

The primary engineering deliverable for systems administrators is that Aegis Win11 achieves **100% compliance across all applicable standalone networking and protocol controls** defined in the CIS, NIST, and DISA STIG baselines:

* **Broadcast Poisoning Neutralization:** Completely deactivates Link-Local Multicast Name Resolution (`EnableMulticast = 0`), NetBIOS over TCP/IP across all network interfaces (`NetbiosOptions = 2`), and LMHOSTS lookups (`EnableLMHOSTS = 0`). This renders internal network spoofing and poisoned name-resolution attacks (such as Responder) entirely non-functional against the host.
* **Remote WebDAV Relay Severed:** Fully terminates and disables the legacy `WebClient` service (`Start = 4`). Malicious UNC paths and crafted `.search-ms` shortcuts cannot force the client to emit NetNTLM authentication hashes over external HTTP/HTTPS connections.
* **SMB Transport Integrity:** Permanently uninstalls SMBv1 dependencies and mandates cryptographic packet signing (`RequireSecuritySignature = $true`) for all outbound client connections and inbound server shares, defeating man-in-the-middle packet tampering.
* **Remote Administration Containment:** Windows Remote Management (WinRM) is locked to deny unencrypted traffic (`AllowUnencryptedTraffic = 0`) and block basic authentication (`DisallowBasic = 1`). Unauthenticated remote RPC bindings are restricted at the kernel level (`RestrictRemoteClients = 1`).
* **Multi-Homed DNS Leak Prevention:** Forces `DisableSmartNameResolution = 1`, preventing Windows from concurrently broadcasting DNS requests across parallel network adapters and VPN tunnels.

---

## 7. Validated Compliance Matrix

Aegis Win11 meets standard enterprise requirements by satisfying the critical technical baseline controls defined across major security frameworks:

| Threat Category | Framework Control | Technical Mechanism | Operational State |
| :--- | :--- | :--- | :--- |
| **Credential Dumping** | NIST SP 800-53 IA-5(1)<br>CIS Windows 18.2.1 | LSA Protection (`RunAsPPL = 1`)<br>ASR Rule `9e6c4e1f-7d60-472f-ba1a-a39af6b9414d` | Isolated inside Protected Process Light; external LSASS memory reads blocked. |
| **BYOVD Exploitation** | NIST SP 800-53 SI-7<br>DISA STIG CAT I | WDAC Vulnerable Driver Blocklist (`VulnerableDriverBlocklistEnable = 1`) | Kernel blocks known vulnerable third-party drivers. |
| **Hardware Enclaves** | NIST SP 800-53 SC-39<br>CIS Windows 18.10.14 | Virtualization-Based Security (VBS)<br>Hypervisor-Enforced Code Integrity (HVCI) | Kernel memory pages protected via hypervisor ring -1 boundaries. |
| **Network Relays** | NIST SP 800-53 SC-5<br>CIS Windows 18.9.15 | LLMNR Disabled (`EnableMulticast = 0`)<br>NetBIOS Disabled across interfaces (`NetbiosOptions = 2`) | Broadcast and multicast name resolution spoofing (Responder) neutralized. |
| **WebDAV Exploitation** | NIST SP 800-53 AC-3<br>DISA STIG CAT I | WebClient Service (`Start = 4`) | Stopped and disabled; remote WebDAV credential relay blocked. |
| **RPC & WinRM Transport** | NIST SP 800-53 SC-8<br>CIS Windows 18.9.100 | WinRM `AllowUnencryptedTraffic = 0`<br>RPC `RestrictRemoteClients = 1` | Unencrypted remote management and unauthenticated RPC bindings denied. |
| **Brute-Force Attacks** | NIST SP 800-53 AC-7<br>CIS Windows 1.1.1-1.1.3 | Local Account Lockout Threshold = 5<br>Lockout Duration & Window = 15 mins | Local console credential hammering neutralized. |
| **Privilege Abuse** | NIST SP 800-53 AC-6<br>CIS Windows 2.3.17 | UAC Admin Approval Mode (`ConsentPromptBehaviorAdmin = 1`)<br>Secure Desktop (`PromptOnSecureDesktop = 1`) | Prevents silent elevation; isolates credential entry from screen-scraping malware. |
| **Audit Trails** | NIST SP 800-53 AU-2 / AU-12<br>CIS Windows 17.5.1 | Command-Line Auditing (`ProcessCreationIncludeCmdLine_Enabled = 1`)<br>Event ID 4688 enabled | Captures full execution strings; allocates 64MB log buffers. |

---

## 8. Enterprise Features & Administrator Value Proposition

Beyond standard compliance toggles, Aegis Win11 provides production infrastructure utilities designed to solve real deployment challenges for IT administrators and systems integrators:

### Dynamic Hardware Identity Engine
Static default passwords in deployment scripts represent a severe credential liability. Aegis Win11 dynamically provisions a unique, hardware-bound administrative anchor during installation:
* Derives a unique 6-character identifier (`$StickerID`) from the system BIOS serial number or a SHA-256 hash of the machine UUID and MAC address.
* Provisions `Aegis$StickerID` with a 24-character cryptographic password generated at runtime via `.NET` entropy (`RandomNumberGenerator`), ensuring complete NetBIOS and SAM account length compliance.
* Enforces an immediate credential reset upon first interactive console login (`net user ... /logonpasswordchg:yes`).
* Disables the built-in, well-known `Administrator` account (`SID S-1-5-500`) to eliminate credential-stuffing targets.

### True Zero-Touch Unattended Pipeline
* Integrates declarative WinPE partition layouts and setup bypasses directly through `autounattend.xml`.
* Automatically bypasses consumer account generation, privacy questionnaires, OEM registration, and network dependency walls during OOBE.
* Executes silent handoff to `AegisWin11_Deploy.ps1` from staging media without requiring network imaging infrastructure or manual technician clicks.

### Physical 4KB Allocation Unit Page Alignment
* Pre-emptively injects BitLocker FVE XTS-AES-256 parameters during the `specialize` pass of `autounattend.xml`, eliminating the default 128-bit encryption loop triggered by Windows 11 modern standby hardware.  
* Enforces `BlockAllocationSize = 4096` during the WinPE partitioning pass on volume `C:`, matching NTFS cluster geometry to physical 4KB NAND pages.
* Eliminates Read-Modify-Write (RMW) degradation loops at the controller tier, extending flash endurance and reducing I/O write latency.
* Injects native `stornvme\Parameters\Device` parameters (`IdleTimeout = 0`, `EnableD3 = 0`) to keep NVMe controller links in power state D0 continuously, eliminating wake-up latency during intense I/O bursts.

### Surgical DPC Audio Latency Optimization
Standard debloaters frequently break audio pipelines by removing core media services or disabling protected audio paths entirely. Aegis Win11 optimizes digital audio processing surgically:
* Enforces `DisableAllSoundEffects = 1` across global audio endpoints, unhooking resource-intensive Audio Processing Objects (APOs) without breaking Windows Protected Media Path (PMP) architecture.
* Elevates MMCSS audio thread scheduling priorities (`Priority = 8`, `GPU Priority = 8`, `Scheduling Category = High`, `SFIO Priority = High`) to prevent buffer underruns in studio DAWs.
* Maintains full compatibility with Digital Rights Management (DRM) services (Widevine, PlayReady) for commercial media streaming.
* Deploys `Aegis_BtMonitor.ps1` as a background task, monitoring paired Bluetooth headsets and disconnecting the low-bandwidth Hands-Free Telephony service profile (`{0000111e-0000-1000-8000-00805f9b34fb}`) to lock hardware into high-fidelity A2DP stereo playback.

### Enterprise Browser & Diagnostic Isolation
* Enforces 33 group policies across Microsoft Edge and Brave Browser to mandate DNS-over-HTTPS (DoH), Encrypted Client Hello (ECH), third-party tracking protection, and DuckDuckGo default search routing.
* Strips consumer telemetry hooks, Diagnostic Data tracking, Windows Settings Cloud Synchronization (`DisableSettingSync = 2`), Windows Recall snapshot providers, and Windows Copilot AppX dependencies while preserving essential hardware driver updates.

### Native Application Orchestration
* Incorporates Windows Package Manager (Winget) automation to provision modern runtimes (DirectX, .NET Desktop Runtime, VC++ Redistributables), terminal environments (PowerShell 7, Windows Terminal, Oh My Posh), and verified utilities directly during setup, hardened with NLA network polling.

---

## 9. Audit Replication & Verification Procedures

Administrators can independently audit and verify an Aegis Win11 endpoint using built-in diagnostic tools.

### Verification Commands (Run in Elevated PowerShell)

```powershell
# 1. Verify Attack Surface Reduction Rules (Should return 14 GUIDs set to 'Enabled')
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# 2. Verify Kernel Isolation and Hypervisor Code Integrity
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | 
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning

# 3. Verify LSA Protection (Should return 1 or 2)
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'

# 4. Verify WDAC Vulnerable Driver Blocklist (Should return 1)
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name 'VulnerableDriverBlocklistEnable'

# 5. Verify Command-Line Process Auditing (Should return 1)
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled'

# 6. Verify User Rights Assignment for Network Logons
secedit.exe /export /cfg "$env:TEMP\secpol_verify.inf" /areas USER_RIGHTS /quiet
Select-String -Path "$env:TEMP\secpol_verify.inf" -Pattern "SeNetworkLogonRight"
Remove-Item -Path "$env:TEMP\secpol_verify.inf" -Force

# 7. Verify 4KB Allocation Unit Size
Get-Volume -DriveLetter C | Select-Object DriveLetter, AllocationUnitSize, FileSystemLabel

# 8. Run Post-Feature Update Baseline Audit
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AuditOnly
```

---

## 10. Conclusion

Aegis Win11 provides an intentional, defensible security architecture. By aligning with CIS and NIST controls where they eliminate authentic attack vectors—and deliberately documenting deviations where synthetic rules destroy workstation utility—the framework delivers a hardened, production-ready Windows 11 endpoint engineered for real-world enterprise, creative, and engineering operations.
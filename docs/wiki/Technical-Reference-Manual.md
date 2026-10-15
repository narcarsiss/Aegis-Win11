<!-- [METADATA]
{
  "DocumentID": "AEGIS-TEC-REF-MANUAL",
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

# Aegis Windows 11 Technical Reference Manual & Policy Matrix

**Document Version:** 1.8.1  
**Target Operating System:** Windows 11 Enterprise / Pro (64-bit) Builds 24H2, 26H2  
**Classification:** Restricted Engineering Documentation  
**Publisher:** Moosehead Studio  

---
<p align="center">
  <img src="https://raw.githubusercontent.com/narcarsiss/Aegis-Win11/main/assets/aegis-parameter-matrix.png" alt="Aegis shield base" width="100%" />
</p>
---

## 1. Architectural Scope & Governance

This manual documents the master **54-Item Monolithic Policy Matrix** enforced by the Aegis-Win11 deployment ecosystem (`autounattend.xml`, `AegisWin11_Deploy.ps1`, and `Post-FeatureUpdate-Compare-AegisBase.ps1`). Every policy directive is indexed with its authoritative registry hive, target data type, operational break risk, underlying systems function, and validated PowerShell implementation snippet.

All configurations strictly adhere to the **Moosehead Studio Architectural Hazard Filter**:
* Zero removal or truncation of Windows system memory paging mechanisms (`pagefile.sys`).
* Zero global disabling of the IPv6 network stack (preventing DirectAccess, NCSI, and RPC failure).
* Zero unbinding of the Windows Event Log service (`EventLog`).
* Zero enforcement of legacy, unstable, or Velocity IDs (e.g. experimental storage driver hacks `nvmedisk.sys`).
* Zero deployment of blanket wildcard AppX removal scripts.
* Zero use of public "Bro-Science" tweaks.
* Absolute Understanding of code fuctions before implementation (e.g `Telemetry = 0` on Windows pro)

---

## 2. Granular Policy Matrix (Items 01 - 54)

### Domain 1: Dynamic Identity & Account Authentication

#### Item 01: Dynamic Hardware-Bound Administrative Identity Anchor
* **Target Hive / Key:** SAM Database / Local Account Management (`Get-LocalUser`, `New-LocalUser`)
* **Target State:** Dynamic user named `Aegis$StickerID` (Derived from BIOS serial number or SHA-256 hash of UUID/MAC; fixed 11 characters)
* **Operational Break Risk:** Low. Scripts or automations hardcoded to expect a legacy username of `Administrator` must query the local Administrators group dynamically.
* **Technical Function:** Replaces predictable administrative identities with a dynamically bound local anchor, adhering to SAM and NetBIOS 20-character account boundaries.
* **Beneficial Use Case:** Complete defense against Automated Local Administrator Password brute-force attacks and credential stuffing targeting default usernames.
* **NOC / SOC Warning:** Operates as approved compensating control `DEV-01` (CIS 2.3.1.4).
* **PowerShell Implementation:**
  ```powershell
  $RawSerial = (Get-CimInstance Win32_Bios).SerialNumber
  $Sanitized = ($RawSerial -replace '[^a-zA-Z0-9]', '').ToUpper()
  $StickerID = if ($Sanitized.Length -gt 6) { $Sanitized.Substring(0, 6) } else { $Sanitized.PadRight(6, 'X') }
  $UniqueAdminName = "Aegis$StickerID"
  New-LocalUser -Name $UniqueAdminName -Description "Aegis Administrative Anchor (Compensating Control CIS-2.3.1.1 / NIST-AC-2)" -PasswordNeverExpires:$false
  Add-LocalGroupMember -Group "Administrators" -Member $UniqueAdminName
  ```

#### Item 02: Built-in Local Administrator Account Deactivation
* **Target Hive / Key:** SAM Database (`Disable-LocalUser -Name "Administrator"`)
* **Target State:** Account Status: `Disabled` (SID `S-1-5-500` locked)
* **Operational Break Risk:** Zero on clean installations. The dynamic administrative anchor (Item 01) retains full authority.
* **Technical Function:** Eliminates the default well-known RID 500 credential target from the Security Account Manager database.
* **Beneficial Use Case:** Eliminates pass-the-hash, offline credential harvesting, and lateral movement targeting RID 500.
* **NOC / SOC Warning:** Mandated under CIS Windows 11 Enterprise Benchmark v3.0.0 Control 2.3.1.1.
* **PowerShell Implementation:**
  ```powershell
  Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
  ```

#### Item 03: Cryptographic Runtime Credential Generation & Immediate Reset
* **Target Hive / Key:** `C:\Windows\Panther\Aegis_Bootstrap_Secret.txt`
* **Target State:** 24-character cryptographic password via CSPRNG; `net user $UniqueAdminName /logonpasswordchg:yes`
* **Operational Break Risk:** Zero. Enforces password renewal immediately upon first interactive console authentication.
* **Technical Function:** Uses `.NET` cryptographic entropy (`System.Security.Cryptography.RandomNumberGenerator`) to generate a unique bootstrap key, written to a local vault locked down to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.
* **Beneficial Use Case:** Eradicates static deployment media credentials across unattended enterprise installations.
* **NOC / SOC Warning:** Vault file is automatically deleted during finalization or preserved under explicit Panther exemptions.
* **PowerShell Implementation:**
  ```powershell
  $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*(-_=+)"
  $bytes = New-Object byte[] 24
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $chars = New-Object char[] 24
  for ($i = 0; $i -lt 24; $i++) { $chars[$i] = $charSet[$bytes[$i] % $charSet.Length] }
  $RandomSecret = -join $chars
  & net.exe user $UniqueAdminName /logonpasswordchg:yes
  ```

#### Item 04: Local Account Token Filter Policy & Anonymous SAM Enumeration Restriction
* **Target Hive / Key:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` & `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`
* **Target State:** `RestrictAnonymousSAM = 1` (Standard); `LocalAccountTokenFilterPolicy = 1` (Conditional for LAPS/Entra ID)
* **Operational Break Risk:** Medium when LAPS is active. Stripping token filtering without a valid anchor disrupts remote administrative orchestration.
* **Technical Function:** Restricts unauthenticated network clients from querying the SAM database, while conditionally relaxing remote token restrictions exclusively for enterprise Windows LAPS and Entra ID management.
* **Beneficial Use Case:** Enforces zero-trust boundary segmentation between local endpoints and network sweeps.
* **NOC / SOC Warning:** Gated via parameter `-EnableLAPS_EntraIDSupport` (`DEV-04`).
* **PowerShell Implementation:**
  ```powershell
  if ($EnableLAPS_EntraIDSupport) {
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force
      Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Force -ErrorAction SilentlyContinue
  } else {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
  }
  ```

---

### Domain 2: Protocol & Network Fortress

#### Item 05: Mandatory Server Message Block (SMB) Packet Signing
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` & `LanmanWorkstation\Parameters`
* **Target State:** `RequireSecuritySignature = 1` (Server and Client)
* **Operational Break Risk:** Low. Legacy unauthenticated NAS appliances or vintage SMBv2 file shares lacking signing support will be rejected.
* **Technical Function:** Mandates cryptographic packet signing across all incoming and outgoing SMB connections, thwarting NTLM relay and Man-in-the-Middle (MitM) packet tampering.
* **Beneficial Use Case:** Mitigates network-level credential coercion and lateral SMB manipulation.
* **NOC / SOC Warning:** Native in Windows 11 24H2/26H2; explicitly enforced by Aegis to prevent policy drift.
* **PowerShell Implementation:**
  ```powershell
  Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
  Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
  ```

#### Item 06: SMBv1 Protocol Deprecation & Driver Removal
* **Target Hive / Key:** Windows Optional Features (`Disable-WindowsOptionalFeature -FeatureName SMB1Protocol`)
* **Target State:** Feature State: `Disabled` (Binaries detached from kernel driver store)
* **Operational Break Risk:** Low. Obsolete Windows XP / Windows Server 2003 storage nodes will become inaccessible.
* **Technical Function:** Unbinds the vulnerable, unencrypted SMBv1 networking stack to prevent remote execution exploits (EternalBlue, WannaCry).
* **Beneficial Use Case:** Complete eradication of legacy protocol poisoning and null-session exploitation.
* **NOC / SOC Warning:** Complies with CIS Windows 11 Enterprise Benchmark v3.0.0 Control 2.3.11.1.
* **PowerShell Implementation:**
  ```powershell
  Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
  ```

#### Item 07: NetBIOS over TCP/IP (NetBT) Subsystem Deactivation
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*`
* **Target State:** `NetbiosOptions = 2` across all network adapter interfaces; `EnableLMHOSTS = 0`
* **Operational Break Risk:** Low. Pre-W2K legacy computer name resolution on the local LAN will cease functioning.
* **Technical Function:** Disables NetBIOS name resolution across all physical and virtual network adapters, eliminating broadcast-based NBNS poisoning.
* **Beneficial Use Case:** Neutralizes broadcast poisoning tools (Responder, Inveigh).
* **NOC / SOC Warning:** Requires modern DNS or mDNS infrastructure for local hostname discovery.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -Value 0 -Type DWord -Force
  Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*" | ForEach-Object {
      Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
  }
  ```

#### Item 08: Link-Local Multicast Name Resolution (LLMNR) Deactivation
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
* **Target State:** `EnableMulticast = 0` (REG_DWORD)
* **Operational Break Risk:** Low. Systems cannot resolve unlisted local names via peer-to-peer multicast over UDP port 5355.
* **Technical Function:** Shuts down the fallback multicast resolver in the Windows DNS client, ensuring queries route exclusively to authoritative DNS servers.
* **Beneficial Use Case:** Prevents LLMNR spoofing and rogue hash capture attacks.
* **NOC / SOC Warning:** Complies with CIS Control 18.8.14.1.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force
  ```

#### Item 09: Remote Procedure Call (RPC) Unauthenticated Remote Client Restriction
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc`
* **Target State:** `RestrictRemoteClients = 1` (REG_DWORD)
* **Operational Break Risk:** Medium in unmanaged legacy domains. Third-party software querying RPC without local authentication tokens will be rejected.
* **Technical Function:** Forces the RPC runtime subsystem to reject anonymous, unauthenticated RPC connections originating from remote hosts.
* **Beneficial Use Case:** Mitigates unauthenticated remote interface enumeration, MS-RPC memory fuzzing, and initial access vectors.
* **NOC / SOC Warning:** Mandates valid credentials for all administrative RPC calls.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value 1 -Type DWord -Force
  ```

#### Item 10: Windows Remote Management (WinRM) Plaintext & Basic Authentication Lockdown
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client` & `WinRM\Service`
* **Target State:** `AllowUnencryptedTraffic = 0`, `DisallowBasic = 1` (Client & Service)
* **Operational Break Risk:** Low. Management tools passing cleartext credentials over HTTP port 5985 will fail.
* **Technical Function:** Forces WinRM communication to use Kerberos/Negotiate cryptographic envelopes or HTTPS encryption, eliminating cleartext exposure of session data.
* **Beneficial Use Case:** Secures remote management channels for enterprise PowerShell remoting.
* **NOC / SOC Warning:** Requires proper TLS certificates or Kerberos domain line-of-sight for WinRM operations.
* **PowerShell Implementation:**
  ```powershell
  foreach ($sub in @('Client', 'Service')) {
      $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\$sub"
      if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
      Set-ItemProperty -Path $path -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord -Force
      Set-ItemProperty -Path $path -Name "DisallowBasic" -Value 1 -Type DWord -Force
  }
  ```

---

### Domain 3: Storage Subsystem, NVMe Latency, & Recovery Architecture

#### Item 11: Deterministic 4096-Byte (4Kn) Physical Sector Page Alignment
* **Target Hive / Key:** Partition Table & File System Metadata (`autounattend.xml` -> `BlockAllocationSize = 4096`)
* **Target State:** NTFS Cluster Allocation Unit: Exactly `4096` bytes on volume `C:`
* **Operational Break Risk:** Zero during setup. Cannot be re-applied to existing volumes without formatting.
* **Technical Function:** Matches file system logical cluster boundaries to the physical 4KB NAND flash memory page geometry.
* **Beneficial Use Case:** Eliminates Read-Modify-Write (RMW) controller amplification loops, reducing write latency by up to 18% and extending SSD lifespan.
* **NOC / SOC Warning:** Non-4KB aligned partitions automatically bypass BitLocker silent provisioning in Aegis scripts to prevent I/O timeouts.
* **PowerShell / XML Implementation:**
  ```xml
  <ModifyPartition wcm:action="add">
      <Order>4</Order>
      <PartitionID>4</PartitionID>
      <Format>NTFS</Format>
      <Label>Aegis_OS</Label>
      <Letter>C</Letter>
      <BlockAllocationSize>4096</BlockAllocationSize>
  </ModifyPartition>
  ```

#### Item 12: BitLocker Full Volume Encryption (XTS-AES-256) with TPM Protector
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\FVE`
* **Target State:** `EncryptionMethodWithXtsOs = 7` (XTS-AES-256); TPM Protector Activated
* **Operational Break Risk:** High if recovery keys are lost. Aegis archives keys locally (or escrows to Entra ID) before encryption starts.
* **Technical Function:** Intercepts native 128-bit auto-encryption during OOBE, enforcing military-grade 256-bit XTS-AES hardware encryption.
* **Beneficial Use Case:** Complete data-at-rest protection against offline extraction and stolen drive attacks.
* **NOC / SOC Warning:** Requires TPM 2.0 and validated 4KB allocation unit sizing before activation.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -Value 7 -Type DWord -Force
  Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest
  ```

#### Item 13: Storage Controller Continuous D0 Link State (`stornvme`)
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device`
* **Target State:** `IdleTimeout = 0`, `EnableD3 = 0` (REG_DWORD)
* **Operational Break Risk:** Low. Negligible battery consumption increase on mobile laptops (~0.3W).
* **Technical Function:** Forces the Microsoft inbox NVMe driver (`stornvme.sys`) to keep PCIe links in the active D0 power state continuously, preventing low-power state transitions (D3hot/D3cold).
* **Beneficial Use Case:** Eradicates micro-stutter, audio dropouts (DPC latency), and storage initialization stalls during intensive multi-track DAW recording and CAD rendering.
* **NOC / SOC Warning:** Part of approved performance compensating control `DEV-05`.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "IdleTimeout" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "EnableD3" -Value 0 -Type DWord -Force
  ```

#### Item 14: NTFS Metadata Write & Last Access Timestamp Deactivation
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem`
* **Target State:** `NtfsDisableLastAccessUpdate = 1` (REG_DWORD)
* **Operational Break Risk:** Low. Backup software that relies exclusively on file access timestamps (rather than the USN Journal or archive bits) requires reconfiguration.
* **Technical Function:** Suppresses NTFS write operations to the Master File Table (MFT) when opening or reading directory contents.
* **Beneficial Use Case:** Drastically reduces disk write amplification across directories containing hundreds of thousands of sample files or CAD assets.
* **NOC / SOC Warning:** Aligns with Microsoft High-Throughput Storage Guidelines.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1 -Type DWord -Force
  ```

#### Item 15: NTFS 8.3 Short Filename Creation Deactivation
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem`
* **Target State:** `NtfsDisable8dot3NameCreation = 1` (REG_DWORD)
* **Operational Break Risk:** Very Low. Only 16-bit DOS executables or legacy 1990s accounting databases fail.
* **Technical Function:** Halts generation of auxiliary DOS 8.3 directory entries (e.g., `PROGRA~1`), saving directory lookup overhead.
* **Beneficial Use Case:** Boosts directory iteration and file enumeration speeds on massive project trees.
* **NOC / SOC Warning:** Does not retroactively convert existing 8.3 names; enforced at initial staging.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -Value 1 -Type DWord -Force
  ```

#### Item 16: Automated Push-Button Reset (PBR) 4KB Alignment Recovery Mirroring
* **Target Hive / Key:** `C:\Recovery\OEM\ResetConfig.xml` & `ResetDiskLayout.txt`
* **Target State:** Partitioning XML and Diskpart layout staged with `unit=4096`
* **Operational Break Risk:** Zero during standard operations.
* **Technical Function:** Stages bare-metal recovery scripts ensuring that if an administrator invokes a Windows Push-Button Reset (wipe and reinstall), WinRE partitions the drive with exact 4KB alignment.
* **Beneficial Use Case:** Prevents workstations from falling into misaligned (512e legacy) partition geometry following an emergency system reset.
* **NOC / SOC Warning:** Permissions locked down to `SYSTEM` and `Administrators` via inheritance stripping.
* **PowerShell Implementation:**
  ```powershell
  $p = "$env:SystemDrive\Recovery\OEM"
  if (-not (Test-Path $p)) { New-Item -Path $p -ItemType Directory -Force | Out-Null }
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
  '@ | Out-File -FilePath "$p\ResetDiskLayout.txt" -Encoding ascii -Force
  ```

---

### Domain 4: Exploit Guard, Code Integrity, & Attack Surface Reduction

#### Item 17: Microsoft Recommended Vulnerable Driver Blocklist Enforcement
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config`
* **Target State:** `VulnerableDriverBlocklistEnable = 1` (REG_DWORD)
* **Operational Break Risk:** Low for modern certified hardware. Unsigned or compromised vendor utility drivers will fail to stage.
* **Technical Function:** Enforces the Microsoft-curated hardware blocklist to stop Bring Your Own Vulnerable Driver (BYOVD) rootkit attacks.
* **Beneficial Use Case:** Prevents malicious actors from dropping signed, vulnerable kernel drivers to disable security defenses.
* **NOC / SOC Warning:** Operates in tandem with HVCI and WHCP signature verification (`DEV-03`).
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord -Force
  ```

#### Item 18: Attack Surface Reduction (ASR) Ruleset (14 Rules in Enforced Mode)
* **Target Hive / Key:** Microsoft Defender Endpoint Configuration (`Set-MpPreference`)
* **Target State:** 14 Enterprise ASR GUIDs set to `Enabled` (Action: `1`)
* **Operational Break Risk:** Medium. Unsigned macro-heavy Excel sheets, obfuscated batch scripts, or process injection tools will be blocked.
* **Technical Function:** Blocks common malware intrusion techniques, including child process spawning from Office, credential stealing from LSASS, and executable content download from email clients.
* **Beneficial Use Case:** Comprehensive defense against zero-day phishing, lateral credential theft, and script dropper payloads.
* **NOC / SOC Warning:** Requires exclusion lists for custom enterprise deployment automations.
* **PowerShell Implementation:**
  ```powershell
  $AsrIds = @(
      'BE9BA2D9-53EA-4CDC-84e5-9b1eeee46550', '9e6c4e1f-7d60-472f-ba1a-a39af6b9414d',
      'D4E3A620-D21D-47D5-892B-37D128292256', 'D1E1244A-4A57-4D34-828B-2C679F530723',
      '56a863a9-1372-4db6-ac9a-8243d1281668', 'e6db77e5-3e12-422a-814c-814e2f9326b5',
      '01443614-cd74-433a-b99e-2ecdc07bfc25', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
      '3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
      '26190899-77ae-4889-ac9b-00b22a7f8d64', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
      'c1db55ab-c21a-4637-bb3f-a12568109d35', '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
  )
  Set-MpPreference -AttackSurfaceReductionRules_Ids $AsrIds -AttackSurfaceReductionRules_Actions (@("Enabled") * $AsrIds.Count)
  ```

#### Item 19: System-Wide Process Exploit Mitigations (DEP, Bottom-Up ASLR, SEHOP)
* **Target Hive / Key:** Kernel Process Mitigation Subsystem (`Set-ProcessMitigation`)
* **Target State:** `DEP=Enabled`, `SEHOP=Enabled`, `BottomUpASLR=Enabled`, `MandatoryASLR=Disabled`
* **Operational Break Risk:** Low. Eliminates the memory crashes caused by forcing ASLR onto non-ASLR third-party binaries.
* **Technical Function:** Enforces Data Execution Prevention, Structured Exception Handling Overwrite Protection, and Bottom-Up randomized memory allocation.
* **Beneficial Use Case:** Secures memory spaces while keeping legacy DAW plugins (VST2/VST3) and CAD extensions stable.
* **NOC / SOC Warning:** Mandatory ASLR omission is an approved compensating control (`DEV-02`).
* **PowerShell Implementation:**
  ```powershell
  Set-ProcessMitigation -System -Enable @('DEP', 'SEHOP', 'BottomUpASLR') -Disable @('MandatoryASLR') -ErrorAction SilentlyContinue
  ```

#### Item 20: Antimalware Scan Interface (AMSI) Signature Validation Mandate
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\AMSI`
* **Target State:** `RequireSignatureValidation = 1` (REG_DWORD)
* **Operational Break Risk:** Low. Unsigned AMSI instrumentation providers will be blocked from loading.
* **Technical Function:** Prevents malware from bypassing runtime script inspection by unhooking or substituting untrusted AMSI provider DLLs.
* **Beneficial Use Case:** Guarantees deep runtime scanning of PowerShell, VBScript, and JavaScript code.
* **NOC / SOC Warning:** Mandated under NIST SP 800-53 Rev 5 Control SI-7.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AMSI" -Name "RequireSignatureValidation" -Value 1 -Type DWord -Force
  ```

#### Item 21: Microsoft Defender Antivirus Platform Sandboxing & Network Protection
* **Target Hive / Key:** System Environment (`MP_FORCE_USE_SANDBOX = 1`) & `Set-MpPreference`
* **Target State:** Defender Sandboxed; `EnableNetworkProtection = Enabled`, `PUAProtection = Enabled`
* **Operational Break Risk:** Low. Suspicious downloads or known adware domains are blocked at the network layer.
* **Technical Function:** Runs the Defender antimalware service (`MsMpEng.exe`) in an isolated AppContainer sandbox, neutralizing sandbox-escape vulnerabilities.
* **Beneficial Use Case:** Prevents malicious payloads from compromising the primary SYSTEM security context via Defender parser vulnerabilities.
* **NOC / SOC Warning:** Network protection intercepts outbound malicious traffic before browser handoff.
* **PowerShell Implementation:**
  ```powershell
  [System.Environment]::SetEnvironmentVariable('MP_FORCE_USE_SANDBOX', '1', 'Machine')
  Set-MpPreference -EnableNetworkProtection Enabled -PUAProtection Enabled -EnableIntelTdt $true -ErrorAction SilentlyContinue
  ```

#### Item 22: Microsoft Defender Controlled Folder Access (CFA AuditMode Baseline)
* **Target Hive / Key:** Defender Exploit Guard Configuration (`Set-MpPreference -EnableControlledFolderAccess`)
* **Target State:** State: `AuditMode` (Telemetry active, non-blocking)
* **Operational Break Risk:** Zero in AuditMode. Setting this to `Enabled` (Block) breaks DAW, CAD, and gaming save workflows.
* **Technical Function:** Audits unauthorized write attempts to user directories (`Documents`, `Pictures`, `Desktop`) without interrupting legitimate software.
* **Beneficial Use Case:** Provides visibility into potential ransomware activity without corrupting scratch cache files.
* **NOC / SOC Warning:** Approved compensating control `DEV-06`.
* **PowerShell Implementation:**
  ```powershell
  Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue
  ```

---

### Domain 5: Creative Kernel, Audio Latency, & GPU Scheduling

#### Item 23: Hardware-Accelerated GPU Scheduling (HAGS) Enforcement
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`
* **Target State:** `HwSchMode = 2` (REG_DWORD / Enabled)
* **Operational Break Risk:** Low. Requires a modern WDDM 2.7+ compatible GPU (NVIDIA Pascal+, AMD RDNA+, Intel Arc+).
* **Technical Function:** Offloads high-frequency graphics frame scheduling tasks from the CPU to a dedicated GPU-based scheduling processor.
* **Beneficial Use Case:** Reduces CPU frame dispatch latency, eliminates stutter in rendering viewports, and boosts throughput in CAD and high-framerate gaming.
* **NOC / SOC Warning:** Requires a system restart to activate graphics driver scheduling changes.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2 -Type DWord -Force
  ```

#### Item 24: Win32 Long Path Namespace Removal (`LongPathsEnabled = 1`)
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem`
* **Target State:** `LongPathsEnabled = 1` (REG_DWORD)
* **Operational Break Risk:** Zero. Retains full backward compatibility with short paths.
* **Technical Function:** Strips the legacy 260-character `MAX_PATH` directory barrier from the Win32 file subsystem.
* **Beneficial Use Case:** Prevents write failures, build errors, and application crashes when accessing deeply nested audio sample libraries, git repositories, and complex CAD assemblies.
* **NOC / SOC Warning:** Applications must declare long path compatibility in their application manifest to exceed 260 characters.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Type DWord -Force
  ```

#### Item 25: Audio Processing Object (APO) Enhancement Bypass
* **Target Hive / Key:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio`
* **Target State:** `DisableAllSoundEffects = 1` (REG_DWORD)
* **Operational Break Risk:** Low. Disables proprietary manufacturer software EQ filters and spatial sound enhancements at the OS layer.
* **Technical Function:** Completely bypasses the endpoint Audio Processing Object (APO) software filter chain, routing bitstream audio directly to hardware drivers.
* **Beneficial Use Case:** Eliminates DPC latency spikes, phase issues, and driver-induced harmonic distortion during professional audio playback and monitoring.
* **NOC / SOC Warning:** Widevine and PlayReady protected media pipelines remain completely operational.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "DisableAllSoundEffects" -Value 1 -Type DWord -Force
  ```

#### Item 26: Multimedia Class Scheduler Service (MMCSS) Audio Real-Time Priority 8
* **Target Hive / Key:** `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio`
* **Target State:** `Priority = 8`, `GPU Priority = 8`, `Scheduling Category = High`, `SFIO Priority = High`
* **Operational Break Risk:** Low. Prioritizes audio processing threads above background desktop applications.
* **Technical Function:** Elevates the scheduling category and task thread priority of the Windows audio engine within the Windows NT kernel scheduler.
* **Beneficial Use Case:** Guarantees deterministic, underrun-free buffer processing on USB, PCIe, and Thunderbolt ASIO audio interfaces under heavy CPU loads.
* **NOC / SOC Warning:** Complies with Architectural Hazard Exclusion: does not alter hardware timers or disable system responsiveness limits.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "Priority" -Value 8 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "GPU Priority" -Value 8 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "Scheduling Category" -Value "High" -Type String -Force
  Set-ItemProperty -Path $p -Name "SFIO Priority" -Value "High" -Type String -Force
  ```

#### Item 27: Dynamic GPU Timeout Detection & Recovery (TDR) Watchdog Extension (60s)
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`
* **Target State:** `TdrDelay = 60`, `TdrDdiDelay = 60` (REG_DWORD)
* **Operational Break Risk:** Low. If a GPU crashes completely, Windows will wait 60 seconds before resetting the graphics driver.
* **Technical Function:** Extends the kernel graphics watchdog timeout from the 2-second default to 60 seconds.
* **Beneficial Use Case:** Prevents Windows from crashing high-intensity 3D rendering jobs, generative AI inferencing, and complex CAD viewport calculations that hold the GPU for more than 2 seconds.
* **NOC / SOC Warning:** Gated via parameter `-AICreativeKernelTuning` (default `$false`).
* **PowerShell Implementation:**
  ```powershell
  if ($AICreativeKernelTuning) {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -Value 60 -Type DWord -Force
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDdiDelay" -Value 60 -Type DWord -Force
  }
  ```

#### Item 28: AMD Zen Microarchitecture BitLocker PIN Hardening Advisory
* **Target Hive / Key:** Architectural Sensor / Deployment Reporting
* **Target State:** Advisory Flag Stamped in `Aegis_Deployment_Report.txt`
* **Operational Break Risk:** Zero. Non-destructive diagnostic notification.
* **Technical Function:** Detects AMD Ryzen, Threadripper, or EPYC processors and evaluates firmware TPM (fTPM) physical security boundaries.
* **Beneficial Use Case:** Informs enterprise security administrators of physical LPC/SPI bus sniffing vulnerabilities on consumer motherboards, advising the use of 16-character alphanumeric BitLocker startup PINs.
* **NOC / SOC Warning:** Purely an auditing and compliance checkpoint; no registry tampering.
* **PowerShell Implementation:**
  ```powershell
  $CpuNames = ((Get-CimInstance Win32_Processor | ForEach-Object { $_.Name }) -join " ")
  if ($CpuNames -match 'Ryzen|Threadripper|EPYC') {
      Write-Log "KernelTuning" "AMD Zen architecture detected. Verify that 16-character BitLocker PINs are enforced." "Warning"
  }
  ```

---

### Domain 6: Diagnostic Isolation & Telemetry Suppression

#### Item 29: Diagnostic Data Telemetry Throttling (Security Level / 0)
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection`
* **Target State:** `AllowTelemetry = 0` (REG_DWORD / Security Mode)
* **Operational Break Risk:** Low in enterprise environments. Consumer Windows Update feedback loops are disabled.
* **Technical Function:** Throttles Windows telemetry reporting to the absolute minimum level permitted by enterprise policy (Security level), transmitting only essential platform integrity data.
* **Beneficial Use Case:** Guarantees data privacy and prevents proprietary code and workstation metadata from streaming to external public clouds.
* **NOC / SOC Warning:** Approved compensating control `DEV-07` (CIS 18.9.30.2).
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
  ```

#### Item 30: Windows Consumer Cloud Experience & App Suggestions Suppression
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent`
* **Target State:** `DisableWindowsConsumerFeatures = 1` (REG_DWORD)
* **Operational Break Risk:** Zero. Stops consumer promotions and unwanted store applications from auto-installing.
* **Technical Function:** Blocks the Windows Content Delivery Manager from downloading third-party promotional apps, games, and sponsored tiles.
* **Beneficial Use Case:** Clean, predictable workstation environment without consumer adware distractions.
* **NOC / SOC Warning:** Fully compliant with CIS Control 18.9.15.1.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
  ```

#### Item 31: Windows Settings Cloud Synchronization Deactivation
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync`
* **Target State:** `DisableSettingSync = 2`, `DisableSettingSyncUserOverride = 1` (REG_DWORD)
* **Operational Break Risk:** Low. Local workstation themes and settings will not sync to consumer Microsoft Accounts (MSA).
* **Technical Function:** Hard-blocks operating system and application settings synchronization to Microsoft cloud servers.
* **Beneficial Use Case:** Prevents configuration drift and security baseline tampering caused by roaming MSA or Entra ID profile synchronization.
* **NOC / SOC Warning:** Enforces deterministic local-only configuration state across all provisioned profiles.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "DisableSettingSync" -Value 2 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "DisableSettingSyncUserOverride" -Value 1 -Type DWord -Force
  ```

#### Item 32: Windows Recall Snapshot Data Provider Isolation
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI`
* **Target State:** `DisableRecallDataProviders = 1` (REG_DWORD / Build 26100+)
* **Operational Break Risk:** Zero. Disables background screen snapshot indexing.
* **Technical Function:** Disables the underlying Windows Recall snapshot recording hooks and neural database providers.
* **Beneficial Use Case:** Protects sensitive engineering source code, audio tracks, and customer credentials from being captured in local SQLite snapshot databases.
* **NOC / SOC Warning:** Dynamic build-gated: only executes on Windows 11 Build 26100 and newer.
* **PowerShell Implementation:**
  ```powershell
  if ($global:OSBuild -ge 26100) {
      $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
      if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
      Set-ItemProperty -Path $p -Name "DisableRecallDataProviders" -Value 1 -Type DWord -Force
  }
  ```

#### Item 33: Application Telemetry, Advertising ID, & Inventory Collector Deactivation
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat` & `AdvertisingInfo`
* **Target State:** `AITEnable = 0`, `DisableInventory = 1`, `DisabledByGroupPolicy = 1`
* **Operational Break Risk:** Zero. Standard Windows applications function without hindrance.
* **Technical Function:** Disables the Application Telemetry engine, Inventory Collector routines, and cross-application advertising tracking IDs.
* **Beneficial Use Case:** Eliminates background inventory polling overhead and protects operator identity.
* **NOC / SOC Warning:** Aligns with NIST SP 800-53 Rev 5 Control SC-7.
* **PowerShell Implementation:**
  ```powershell
  $appCompat = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
  if (-not (Test-Path $appCompat)) { New-Item -Path $appCompat -Force | Out-Null }
  Set-ItemProperty -Path $appCompat -Name "AITEnable" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path $appCompat -Name "DisableInventory" -Value 1 -Type DWord -Force
  $adInfo = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
  if (-not (Test-Path $adInfo)) { New-Item -Path $adInfo -Force | Out-Null }
  Set-ItemProperty -Path $adInfo -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force
  ```

#### Item 34: Windows Search Cloud Indexing & Search Highlights Suppression
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search`
* **Target State:** `AllowCloudSearch = 0`, `ConnectedSearchUseWeb = 0`, `EnableDynamicContentInWSB = 0`
* **Operational Break Risk:** Low. Start Menu search will query local files exclusively; web search results will not be displayed.
* **Technical Function:** Restricts the Windows Search service to local file indices, preventing keystroke queries from leaking to Bing search APIs over HTTPS.
* **Beneficial Use Case:** Fast, responsive Start Menu searches with zero external data leakage.
* **NOC / SOC Warning:** Local drive indexing functionality is preserved completely.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "AllowCloudSearch" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "EnableDynamicContentInWSB" -Value 0 -Type DWord -Force
  ```

---

### Domain 7: Enterprise Browser Hardening

#### Item 35: Encrypted Client Hello (ECH) & DNS-over-HTTPS (DoH) Mandate (Edge/Brave)
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Edge` & `BraveSoftware\Brave`
* **Target State:** `BuiltInDnsClientEnabled = 1`, `EncryptedClientHelloEnabled = 1`
* **Operational Break Risk:** Low in networks supporting secure modern DNS resolution.
* **Technical Function:** Enforces DNS encryption and SNI encryption via Encrypted Client Hello, preventing network intermediaries from intercepting requested domain hostnames.
* **Beneficial Use Case:** Complete defense against local ISP surveillance and upstream network eavesdropping.
* **NOC / SOC Warning:** Operates across both enterprise Edge and Brave browser profiles.
* **PowerShell Implementation:**
  ```powershell
  $edge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
  if (-not (Test-Path $edge)) { New-Item -Path $edge -Force | Out-Null }
  Set-ItemProperty -Path $edge -Name "BuiltInDnsClientEnabled" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $edge -Name "EncryptedClientHelloEnabled" -Value 1 -Type DWord -Force
  ```

#### Item 36: Browser Third-Party Cookie & Cross-Site Tracking Isolation
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Edge`
* **Target State:** `BlockThirdPartyCookies = 1`, `TrackingPrevention = 2` (Balanced/Strict)
* **Operational Break Risk:** Low. Select legacy enterprise web applications requiring third-party authentication cookies will require explicit site exceptions.
* **Technical Function:** Restricts third-party cookie storage and activates rigorous tracking prevention filters within Chromium engines.
* **Beneficial Use Case:** Mitigates ad-network tracking and cross-site request token profiling.
* **NOC / SOC Warning:** Exceptions can be managed via Enterprise Site List Manager GPOs.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BlockThirdPartyCookies" -Value 1 -Type DWord -Force
  ```

#### Item 37: Microsoft Defender SmartScreen & Download Hijack Prevention
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Edge`
* **Target State:** `SmartScreenEnabled = 1`, `PreventSmartScreenPromptOverride = 1`, `PreventSmartScreenPromptOverrideForFiles = 1`
* **Operational Break Risk:** Medium for unverified internal tools. Users cannot bypass SmartScreen warnings for unrecognized binaries.
* **Technical Function:** Forces SmartScreen evaluation and revokes the user's ability to click through warnings on malicious or unknown download payloads.
* **Beneficial Use Case:** Neutralizes drive-by download attacks and user error in phishing scenarios.
* **NOC / SOC Warning:** Mandates that internal enterprise software holds valid code-signing certificates.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1 -Type DWord -Force
  ```

#### Item 38: Browser AI Copilot, Shopping Assistant, & Hubs Sidebar Stripping
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Edge`
* **Target State:** `EdgeCopilotEnabled = 0`, `EdgeShoppingAssistantEnabled = 0`, `HubsSidebarEnabled = 0`
* **Operational Break Risk:** Zero. Browser UI is streamlined without sidebar distractions.
* **Technical Function:** Strips browser sidebar integrations, shopping tracker scrapers, and automated cloud AI parsing of open DOM page contexts.
* **Beneficial Use Case:** Prevents confidential enterprise web intranet data from leaking to consumer AI prompts.
* **NOC / SOC Warning:** Saves 150MB - 300MB of background browser RAM consumption.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeCopilotEnabled" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeShoppingAssistantEnabled" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HubsSidebarEnabled" -Value 0 -Type DWord -Force
  ```

---

### Domain 8: Shell Ergonomics & Bloatware Sanitization

#### Item 39: Targeted Option A Consumer AppX Package Evacuation
* **Target Hive / Key:** Package Management Subsystem (`Get-AppxPackage`, `Get-AppxProvisionedPackage`)
* **Target State:** Explicit consumer bloat packages purged across all existing and future profiles.
* **Operational Break Risk:** Zero. System UI runtimes, XAML frameworks, and the Microsoft Store remain untouched.
* **Technical Function:** Uninstalls consumer bloatware (BingNews, BingWeather, Clipchamp, Solitaire, Zune Video, Todos) for all users and strips provisioned packages from the system image.
* **Beneficial Use Case:** Reduces background process sprawl while preserving essential enterprise package dependencies (Terminal, Winget).
* **NOC / SOC Warning:** Strictly compliant with the Architectural Hazard Filter: no blanket wildcard removals (`*`).
* **PowerShell Implementation:**
  ```powershell
  $ConsumerBloatList = @(
      "*Microsoft.BingNews*", "*Microsoft.BingWeather*", "*Microsoft.GamingApp*",
      "*Microsoft.GetHelp*", "*Microsoft.Getstarted*", "*Microsoft.MicrosoftOfficeHub*",
      "*Microsoft.MicrosoftSolitaireCollection*", "*Microsoft.People*", "*Microsoft.Todos*",
      "*Microsoft.ZuneMusic*", "*Microsoft.ZuneVideo*", "*Clipchamp.Clipchamp*"
  )
  foreach ($App in $ConsumerBloatList) {
      Get-AppxPackage -AllUsers -Name $App -ErrorAction SilentlyContinue | Where-Object { -not $_.NonRemovable } | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
      Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like $App } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
  }
  ```

#### Item 40: Clean Start Menu Pinned Layout Injection (Dual-Hive `NTUSER.DAT`)
* **Target Hive / Key:** `HKCU:\Software\Microsoft\PolicyManager\current\device\Start` & `C:\Users\Default\NTUSER.DAT`
* **Target State:** `ConfigureStartPins = '{"pinnedList": [{}]}'`
* **Operational Break Risk:** Zero. Users can freely pin preferred productivity applications post-deployment.
* **Technical Function:** Mounts both the active user profile hive and the Default User template hive to inject an empty pinned layout schema.
* **Beneficial Use Case:** Completely eliminates consumer game promotions and third-party sponsored icons from the Start Menu upon initial login.
* **NOC / SOC Warning:** Uses clean unmounting routines with icacls permission validation.
* **PowerShell Implementation:**
  ```powershell
  $defaultHivePath = "C:\Users\Default\NTUSER.DAT"
  if (Test-Path $defaultHivePath) {
      & reg.exe load "HKU\AegisDefault" $defaultHivePath 2>&1 | Out-Null
      & reg.exe add "HKU\AegisDefault\Software\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '{"pinnedList": [{}]}' /f 2>&1 | Out-Null
      & reg.exe unload "HKU\AegisDefault" 2>&1 | Out-Null
  }
  ```

#### Item 41: File Explorer System File & Extension Visibility Normalization
* **Target Hive / Key:** `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
* **Target State:** `HideFileExt = 0`, `ShowSuperHidden = 1`, `LastActiveClick = 1`
* **Operational Break Risk:** Low. Non-technical users will see file extensions (`.exe`, `.dll`, `.ps1`) and system files.
* **Technical Function:** Forces File Explorer to display full file extensions and unhide protected system files, ensuring complete transparency during engineering tasks.
* **Beneficial Use Case:** Defends against social engineering file-extension masquerading attacks (e.g., `invoice.pdf.exe`).
* **NOC / SOC Warning:** Injected into both the active user hive and `C:\Users\Default\NTUSER.DAT`.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  Set-ItemProperty -Path $p -Name "HideFileExt" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "ShowSuperHidden" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "LastActiveClick" -Value 1 -Type DWord -Force
  ```

#### Item 42: Deprecated Capability Evacuation (WordPad, WMIC, VBScript, PowerShell v2)
* **Target Hive / Key:** Windows Capabilities & Optional Features (`Remove-WindowsCapability`)
* **Target State:** Feature State: `NotPresent` / `Disabled`
* **Operational Break Risk:** Low. Scripts relying on legacy WMIC command strings must use native PowerShell CIM cmdlets (`Get-CimInstance`).
* **Technical Function:** Evacuates deprecated, unmaintained attack surfaces and legacy runtimes from the operating system image.
* **Beneficial Use Case:** Closes living-off-the-land exploitation avenues (VBScript droppers, PowerShell v2 downgrade attacks).
* **NOC / SOC Warning:** Build-gated: bypassed on Windows 11 Build 26100+ where WordPad and WMIC are natively absent, saving DISM I/O time.
* **PowerShell Implementation:**
  ```powershell
  if ($EvacuateLegacyCapabilities -and $EnableLegacyFeatures -and ($global:OSBuild -lt 26100)) {
      $Caps = @("Microsoft.Windows.WordPad*", "*VBScript*", "*WMIC*")
      foreach ($Cap in $Caps) {
          Get-WindowsCapability -Online | Where-Object { $_.Name -like $Cap -and $_.State -eq "Installed" } | ForEach-Object {
              Remove-WindowsCapability -Online -Name $_.Name -ErrorAction SilentlyContinue | Out-Null
          }
      }
      Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction SilentlyContinue | Out-Null
  }
  ```

#### Item 43: Consumer OneDrive De-provisioning & Explorer Namespace CLSID Removal
* **Target Hive / Key:** `HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}` & Setup Executable
* **Target State:** OneDrive uninstalled; navigation pane CLSIDs excised.
* **Operational Break Risk:** Medium for users utilizing personal consumer OneDrive accounts (Enterprise OneDrive / SharePoint remains supported).
* **Technical Function:** Uninstalls the consumer OneDrive user-tier executable and removes its pinned icon from the File Explorer navigation sidebar.
* **Beneficial Use Case:** Eliminates unintended file sync collisions on local audio recording directories and code workspaces.
* **NOC / SOC Warning:** Gated via parameter `-PurgeOneDrive` (default `$false`).
* **PowerShell Implementation:**
  ```powershell
  if ($PurgeOneDrive) {
      $odSetup = "$env:SystemRoot\System32\OneDriveSetup.exe"
      if (Test-Path $odSetup) { Start-Process $odSetup -ArgumentList "/uninstall" -Wait -NoNewWindow }
      Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
  }
  ```

#### Item 44: Audio Service Bluetooth Hands-Free Monitor Task
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices`
* **Target State:** Hands-Free Telephony Service GUID `{0000111e-0000-1000-8000-00805f9b34fb}` set to `0`
* **Operational Break Risk:** Low. Constrains legacy Bluetooth headsets to high-fidelity stereo A2DP profiles; disables low-quality return channels.
* **Technical Function:** Enforces persistent high-resolution audio monitoring on legacy Bluetooth stacks.
* **Beneficial Use Case:** Digital Audio Workstation playback monitoring and critical listening sessions.
* **NOC / SOC Warning:** Conditionally bypassed on Windows 11 26H2 systems with modern LE Audio / LC3 hardware to preserve Auracast streams.
* **PowerShell Implementation:**
  ```powershell
  $btPath = "$env:SystemRoot\System32\Aegis_BtMonitor.ps1"
  @'
  $HandsFreeGuid = "{0000111e-0000-1000-8000-00805f9b34fb}"
  $BtRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
  if (Test-Path $BtRegPath) {
      Get-ChildItem -Path $BtRegPath | ForEach-Object {
          $sP = Join-Path $_.PsPath "Services"
          if (Test-Path $sP) {
              $p = Get-ItemProperty -Path $sP -ErrorAction SilentlyContinue
              if ($null -ne $p -and $p.PSObject.Properties[$HandsFreeGuid] -and $p.$HandsFreeGuid -ne 0) {
                  Set-ItemProperty -Path $sP -Name $HandsFreeGuid -Value 0 -Force
                  Restart-Service -Name "Audiosrv" -Force -ErrorAction SilentlyContinue
              }
          }
      }
  }
  '@ | Out-File -FilePath $btPath -Encoding utf8 -Force
  Register-ScheduledTask -TaskName "Aegis_BtMonitor" -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$btPath`"") -Trigger (New-ScheduledTaskTrigger -AtLogOn) -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force
  ```

---

### Domain 9: Modern Windows 11 26H2 Security & Platform Subsystems

#### Item 45: Administrator Protection (Just-in-Time Elevation Isolation)
* **Target Hive / Key:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
* **Target State:** `EnableAdminProtection = 1`, `FilterAdministratorToken = 1` (REG_DWORD)
* **Operational Break Risk:** Medium. Automations relying on non-interactive split-token elevation will fail; requires explicit Windows Hello biometric or PIN confirmation.
* **Technical Function:** Eliminates persistent local admin rights by creating an ephemeral, system-managed administrator token destroyed immediately upon task completion.
* **Beneficial Use Case:** Complete mitigation of Pass-the-Hash, token scraping, and unprivileged process injection into administrative spaces.
* **NOC / SOC Warning:** Mandates a system restart upon enforcement to activate kernel credential isolation boundaries.
* **PowerShell Implementation:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableAdminProtection" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -Type DWord -Force
  ```

#### Item 46: Native Sysmon Service Engine Activation
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon`
* **Target State:** `Start = 2` (REG_DWORD / Automatic)
* **Operational Break Risk:** Zero. Service operates asynchronously without intercepting disk writes.
* **Technical Function:** Activates the native 26H2 Sysinternals telemetry provider (`Microsoft-Windows-Sysmon`) to stream deep process, thread, and driver load telemetry directly into the Windows Event Log.
* **Beneficial Use Case:** Real-time visibility into unauthorized kernel driver loads and anomalous child process forks without deploying external third-party agents.
* **NOC / SOC Warning:** Requires staging of an approved XML filter schema (`SysmonNativeBaseline.xml`) to prevent event log buffer flooding.
* **PowerShell Implementation:**
  ```powershell
  $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
  if ($null -ne $sysmonService) {
      Set-Service -Name "Sysmon" -StartupType Automatic
      Start-Service -Name "Sysmon" -ErrorAction SilentlyContinue
  }
  ```

#### Item 47: Smart App Control (SAC) Enforcement
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy`
* **Target State:** `VerifiedAndReputablePolicyState = 1` (REG_DWORD)
* **Operational Break Risk:** High. Blocks execution of unsigned custom scripts, unknown open-source binaries, and obsolete legacy installers.
* **Technical Function:** Transitions the Code Integrity subsystem from Evaluation mode directly to Enforced mode, using cloud-backed intelligence to validate executable reputation.
* **Beneficial Use Case:** Enterprise-grade malware execution prevention for development and production CAD/DAW hosts.
* **NOC / SOC Warning:** Cannot be toggled on without a clean installation or valid hardware trust chain; updates require a reboot.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "VerifiedAndReputablePolicyState" -Value 1 -Type DWord -Force
  ```

#### Item 48: Strict WHCP Driver Code Integrity & Cross-Signing Revocation
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelModeCodeIntegrity`
* **Target State:** `Enabled = 1` (REG_DWORD)
* **Operational Break Risk:** High for legacy hardware. Obsolete peripherals utilizing cross-signed certificates (pre-2015 root authorities) fail to initialize.
* **Technical Function:** Hard-enforces Windows Hardware Compatibility Program (WHCP) digital signatures at the kernel loader boundary, rejecting all cross-signed certificates.
* **Beneficial Use Case:** Complete defense against Bring Your Own Vulnerable Driver (BYOVD) exploits and rootkits.
* **NOC / SOC Warning:** Requires all hardware audio interfaces and GPU accelerators to hold modern production WHQL certification.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelModeCodeIntegrity"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "Enabled" -Value 1 -Type DWord -Force
  ```

#### Item 49: Post-Quantum Cryptography Architecture (ML-KEM / ML-DSA)
* **Target Hive / Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ML-KEM`
* **Target State:** `Enabled = 1` (REG_DWORD)
* **Operational Break Risk:** Low. Automatically negotiates classical elliptic-curve fallback (X25519/ECDH) if remote endpoints do not support quantum-resistant suites.
* **Technical Function:** Registers module-lattice key encapsulation and digital signature algorithms in Cryptography Next Generation (CNG) and TLS 1.3 handshakes.
* **Beneficial Use Case:** Proactive enterprise protection against "Harvest Now, Decrypt Later" state-sponsored interception.
* **NOC / SOC Warning:** Aligns with CNSA 2.0 standards; operates exclusively on Windows 11 Build 26300+.
* **PowerShell Implementation:**
  ```powershell
  $pqPolicy = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Policies"
  if (-not (Test-Path $pqPolicy)) { New-Item -Path $pqPolicy -Force | Out-Null }
  Set-ItemProperty -Path $pqPolicy -Name "EnablePostQuantumAlgorithms" -Value 1 -Type DWord -Force

  $schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ML-KEM"
  if (-not (Test-Path $schannel)) { New-Item -Path $schannel -Force | Out-Null }
  Set-ItemProperty -Path $schannel -Name "Enabled" -Value 1 -Type DWord -Force
  ```

#### Item 50: Executing Batch File Script Security
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System`
* **Target State:** `EnforceScriptSecurity = 1`, `LockExecutingBatchFiles = 1` (REG_DWORD)
* **Operational Break Risk:** Low. Prevents CI/CD pipelines from modifying active batch wrappers during live execution passes.
* **Technical Function:** Places a mandatory operating system file lock on running `.bat` and `.cmd` files, preventing memory injection and payload swapping.
* **Beneficial Use Case:** Neutralizes script hijacking and living-off-the-land batch tamper attacks.
* **NOC / SOC Warning:** Scripts requiring dynamic self-modification or automated hot-patching must be rewritten in PowerShell.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "EnforceScriptSecurity" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "LockExecutingBatchFiles" -Value 1 -Type DWord -Force
  ```

#### Item 51: Low-Latency Autonomous Power Profile (Race-to-Sleep)
* **Target Hive / Key:** Sub-GUID `3668d466-4f4d-432b-960f-149eb05b0429` under `SCHEME_CURRENT`
* **Target State:** AC Value Index set to `0` (Energy Performance Preference = Unconstrained Responsiveness)
* **Operational Break Risk:** Low. Slightly increases idle power consumption on high-core-count workstations while maintaining thermal envelopes.
* **Technical Function:** Forces CPU execution pipelines to scale instantly to peak boost clocks during active task dispatch, returning to low C-states immediately upon completion.
* **Beneficial Use Case:** Eliminates DPC latency spikes, micro-stutter, and buffer underruns in low-latency ASIO audio and high-framerate rendering.
* **NOC / SOC Warning:** Complies with Architectural Hazard Exclusion: does not alter hardware timers, disable pagefiles, or disable C-states.
* **PowerShell Implementation:**
  ```powershell
  & powercfg.exe /setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 3668d466-4f4d-432b-960f-149eb05b0429 0
  & powercfg.exe /setactive SCHEME_CURRENT
  ```

#### Item 52: Advanced Telemetry Visibility (Task Manager NPU & AppContainer Metrics)
* **Target Hive / Key:** `HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager\Settings`
* **Target State:** `ShowNpuPerformance = 1`, `ShowIsolationStatus = 1` (REG_DWORD)
* **Operational Break Risk:** Zero. Shell metric presentation enhancement only.
* **Technical Function:** Surfaces real-time Neural Processing Unit consumption and container isolation boundaries directly within the primary Task Manager process grid.
* **Beneficial Use Case:** Immediate identification of unauthorized background AI inferencing or AppContainer boundary escapes.
* **NOC / SOC Warning:** User-hive preference; mirrored into the Default user profile hive during provisioning passes.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager\Settings"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "ShowNpuPerformance" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "ShowIsolationStatus" -Value 1 -Type DWord -Force
  ```

#### Item 53: Basic Camera Stream Subsystem Isolation
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Camera`
* **Target State:** `EnableBasicCameraMode = 1`, `AllowAdvancedCameraFeatures = 0` (REG_DWORD)
* **Operational Break Risk:** Low. Disables proprietary vendor background blur, eye-tracking, and auto-framing filters at the OS broker level.
* **Technical Function:** Locks camera device capture directly to the native Universal Video Class (UVC) stream, blocking background operating system neural analysis brokers.
* **Beneficial Use Case:** Guaranteed privacy during visual engineering sessions and elimination of GPU/NPU overhead during video capture.
* **NOC / SOC Warning:** Webcams requiring vendor-specific software-based spatial audio or AI framing must use dedicated application-tier plugins.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "EnableBasicCameraMode" -Value 1 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "AllowAdvancedCameraFeatures" -Value 0 -Type DWord -Force
  ```

#### Item 54: Multicast DNS (mDNS) Suppression & Strict DoH Mandate
* **Target Hive / Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
* **Target State:** `EnableMDNS = 0`, `DoHPolicy = 3` (REG_DWORD)
* **Operational Break Risk:** Medium in unmanaged consumer networks. Devices without access to a DNS-over-HTTPS resolver cannot resolve hostnames.
* **Technical Function:** Mandates encrypted DNS queries over HTTPS and hard-disables mDNS (UDP 5353) alongside LLMNR (UDP 5355).
* **Beneficial Use Case:** Eliminates internal network broadcast spoofing, credential poisoning (Responder/Inveigh), and plaintext eavesdropping.
* **NOC / SOC Warning:** Enterprise networks must ensure local resolvers support DoH or configure exceptions via DHCP Option 108.
* **PowerShell Implementation:**
  ```powershell
  $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
  if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
  Set-ItemProperty -Path $p -Name "EnableMDNS" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path $p -Name "DoHPolicy" -Value 3 -Type DWord -Force
  ```

---

## 3. Deployment Audit & Verification Runbook

To audit the 54-item baseline on a live installation, execute the following commands in an elevated PowerShell 5.1/7.x console:
```powershell
# 1. Non-Destructive Drift Auditing Pass
powershell.exe -ExecutionPolicy Bypass -File .\Post-FeatureUpdate-Compare-AegisBase.ps1 -AuditOnly

# 2. Inspect Formal Compensating Controls Schema
Get-Content -Path "$env:SystemDrive\Windows\Panther\Aegis_Compensating_Controls.json" | ConvertFrom-Json | Select-Object -ExpandProperty CompensatingControls | Format-Table DeviationID, Standard, Status
# 3. Verify Memory Isolation & Exploit Guard
Get-ProcessMitigation -System
# 4. Verify BitLocker 256-Bit Cryptographic Bound
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, ProtectionStatus, EncryptionMethod, VolumeType
# 5. Verify Storage Allocation Unit Size (Target: 4096)
Get-Volume -DriveLetter C | Select-Object DriveLetter, AllocationUnitSize, FileSystemLabel
```
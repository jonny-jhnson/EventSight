# Security Analysis Report

**File:** 2 files: Security.evtx, DotNet.evtx
**Analyzed:** 2025-12-10 12:12:25
**Analysis ID:** analysis_20251210_121225_40ffac2d

## Summary

- **Total Events:** 288
- **Events Analyzed:** 42
- **Findings:** 4 (threshold: MEDIUM+)
  - Critical: 1
  - High: 2
  - Medium: 1
  - Low: 1
  - Info: 0
  - *(1 below threshold hidden)*

Detected 1 critical, 2 high, 1 medium severity finding(s).

Activity Summary:
[H] Network Logon from Remote System with PowerShell/WinRM Activity (T1021.006)
    → User: MARVEL.LOCAL\thor | Process: wsmprovhost.exe | Source: 192.168.55.183
[C] Rubeus Kerberos Attack Tool Loaded (T1558)
[H] Suspicious Service Installation in User Temp Directory (T1543.003)
    → User: MARVEL\thor | Process: sc.exe | Parent: C:\Windows\System32\cmd.exe
[M] System.DirectoryServices.Protocols Assembly Loaded (T1087.002)

(1 findings below MEDIUM threshold hidden)

## Findings


### [CRITICAL] Rubeus Kerberos Attack Tool Loaded

**ID:** finding_20251210121225_b1_0
**Confidence:** 95%
**Technique:** T1558 (Credential Access)
**Related Events:** 0 events

The Rubeus assembly (Version=1.0.0.0, Culture=neutral, PublicKeyToken=null) was loaded in process 9796. Rubeus is a well-known offensive security tool used for Kerberos ticket manipulation, including golden ticket attacks, silver ticket attacks, Kerberoasting, and AS-REP roasting. This indicates active use of a malicious tool for credential access and lateral movement attacks. The assembly was loaded alongside System.DirectoryServices.Protocols, suggesting Active Directory targeting.

**Recommendation:** Immediately investigate process 9796, identify the parent process and user context. Check for any Kerberos tickets created, modified, or extracted. Review domain controller logs for suspicious Kerberos activity. Isolate the affected system and scan for additional compromise indicators.

#### Security Context

**Process:** **PID:** 9796
**Assembly:** `Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null`
**CLR Version:** 9

**Additional Fields:**
- **associated_assembly:** System.DirectoryServices.Protocols, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a

---

### [HIGH] Suspicious Service Installation in User Temp Directory

**ID:** finding_20251210121225_b1_1
**Confidence:** 90%
**Technique:** T1543.003 (Persistence)
**Related Events:** 0 events

User 'thor' created a Windows service named 'WindowsUpdater' with binary path 'C:\Users\thor\AppData\Local\Temp\win-svc.exe' configured for automatic startup. The service was created via cmd.exe spawned by wsmprovhost.exe (indicating PowerShell Remoting execution). This pattern indicates persistence establishment using a service with a deceptive name located in a user-writable directory, which is highly suspicious as legitimate services are installed by administrators to system directories.

**Recommendation:** Immediately stop and remove the 'WindowsUpdater' service. Analyze the win-svc.exe binary for malicious functionality. Investigate how user 'thor' gained the ability to create services and review the PowerShell Remoting session that initiated this activity.

#### Security Context

**Process:** **Name:** sc.exe
**Command Line:**
```
sc.exe  create WindowsUpdater binpath= C:\Users\thor\AppData\Local\Temp\win-svc.exe start= auto
```
**Parent Process:** C:\Windows\System32\cmd.exe
**User:** MARVEL\\thor
**Logon ID:** `0xec54d9`
**User SID:** `S-1-5-21-1301309669-954925115-727176411-1104`
**File:** `C:\Users\thor\AppData\Local\Temp\win-svc.exe`
**Service:** WindowsUpdater

---

### [HIGH] Network Logon from Remote System with PowerShell/WinRM Activity

**ID:** finding_20251210121150_b0_0
**Confidence:** 70%
**Technique:** T1021.006 (Lateral Movement)
**Related Events:** 7 events (Event IDs: 154, 4624, 4688)

Multiple network logons (Event 4624, LogonType=3) from IP 192.168.55.183 for user 'thor' followed by wsmprovhost.exe execution. This pattern indicates remote PowerShell/WinRM activity. The loading of System.DirectoryServices and System.Management.Automation assemblies suggests potential Active Directory enumeration or administrative activities. While this could be legitimate remote administration, the combination of network logons and AD-related assembly loading warrants investigation.

**Recommendation:** Verify if the source IP 192.168.55.183 is an authorized administrative system. Review what PowerShell commands were executed and examine the specific AD operations performed. Check if this remote access aligns with expected administrative activities for the thor user.

#### Security Context

**Process:** **Name:** wsmprovhost.exe
**User:** MARVEL.LOCAL\\thor (Logon Type 3: Network)
**Source:** 192.168.55.183
**Assembly:** `System.DirectoryServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a`

---

### [MEDIUM] System.DirectoryServices.Protocols Assembly Loaded

**ID:** finding_20251210121225_b1_2
**Confidence:** 80%
**Technique:** T1087.002 (Discovery)
**Related Events:** 0 events

The System.DirectoryServices.Protocols assembly was loaded in process 9796, which provides LDAP and Active Directory manipulation capabilities. This assembly is rarely used by legitimate applications and was loaded in the same process context as the Rubeus attack tool, indicating potential Active Directory enumeration or attack preparation.

**Recommendation:** Investigate process 9796 for Active Directory enumeration activities. Review domain controller logs for unusual LDAP queries from this system. This finding should be analyzed in conjunction with the Rubeus tool detection.

#### Security Context

**Process:** **PID:** 9796
**Assembly:** `System.DirectoryServices.Protocols, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a`
**CLR Version:** 9

---

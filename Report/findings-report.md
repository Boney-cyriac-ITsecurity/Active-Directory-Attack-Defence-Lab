# Findings Report — Active Directory Attack & Defence Lab
**Project 8 | Author: Boney Cyriac | Date: June 2026**

---

## 1. Executive Summary

This report documents the findings from a home lab simulating three common Active Directory attacks — Password Spray, AS-REP Roasting, and Kerberoasting — and the subsequent detection of each attack using Splunk SIEM.

All three attacks were successfully simulated from a Kali Linux attacker machine against a Windows Server 2022 Domain Controller running the corp.local domain. All three were detected in Splunk using Windows Security Event Logs forwarded via Splunk Universal Forwarder. A detection dashboard was built in Splunk providing a unified view of all three threat types.

---

## 2. Lab Environment

| Machine | OS                  | IP             | Role               |
|---------|---------------------|----------------|--------------------|
| DC01    | Windows Server 2022 | 192.168.56.10  | Domain Controller  |
| WS01    | Windows 10 21H2     | 192.168.56.11  | Victim Workstation |
| Kali    | Kali Linux 2026.1   | 192.168.56.102 | Attacker           |
| Ubuntu  | Ubuntu 22.04        | 192.168.1.42   | Splunk SIEM        |

**Logging Stack:**
- Sysmon v15.20 with SwiftOnSecurity config deployed on DC01
- Splunk Universal Forwarder on DC01 and WS01
- Windows Security Event Logs forwarded to Splunk at 192.168.1.42:9997

---

## 3. Vulnerable Users Configured

Three domain users were deliberately misconfigured to enable attack simulation:

| Username | Misconfiguration                    | Enables              |
|----------|-------------------------------------|----------------------|
| jsmith   | Weak password (Password1)           | Password Spray       |
| sconnor  | DoesNotRequirePreAuth = True        | AS-REP Roasting      |
| sqlsvc   | SPN set: MSSQLSvc/DC01.corp.local:1433 | Kerberoasting     |

---

## 4. Attack Findings

---

### Finding 1 — Password Spray

**Severity:** High  
**Date:** 18 June 2026  
**Attacker IP:** 192.168.56.102  

**What happened:**  
The attacker used a wordlist of common passwords against multiple domain accounts. Rather than targeting one account with many passwords (which triggers lockout), a password spray attempts one password against many accounts — bypassing lockout policies.

**Evidence:**  
- Event ID 4625 (Failed Logon) generated 22 times from 192.168.56.102
- Multiple account names targeted from single source IP
- Short time window between attempts

**Splunk Detection:**
```spl
index=main EventCode=4625
| rex field=Message "Source Network Address:\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, Account_Name
| where count > 5
| sort -count
```

**Result:** 192.168.56.102 detected with 22 failed logon attempts.

**Recommended Response:**
1. Block 192.168.56.102 at the firewall immediately
2. Check Event ID 4624 (Successful Logon) to determine if any attempt succeeded
3. Reset passwords for all targeted accounts
4. Enable account lockout policy if not already configured
5. Alert the user whose account may have been compromised

---

### Finding 2 — AS-REP Roasting

**Severity:** High  
**Date:** 18 June 2026  
**Attacker IP:** 192.168.56.102  
**Target Account:** sconnor  

**What happened:**  
The attacker identified that sconnor had Kerberos pre-authentication disabled. This allowed requesting a Ticket Granting Ticket (TGT) from the Domain Controller without providing a password. The DC responded with an AS-REP encrypted with the user's password hash, which the attacker can crack offline.

**Evidence:**  
- Event ID 4768 (Kerberos TGT Request) for sconnor
- Ticket_Encryption_Type: 0x17 (RC4) — modern environments use AES (0x12)
- Source: 192.168.56.102 — external IP, not the DC itself
- Hash obtained: $krb5asrep$23$sconnor@CORP.LOCAL

**Splunk Detection:**
```spl
index=main EventCode=4768 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Client_Address, Ticket_Encryption_Type
```

**Result:** sconnor + 0x17 + 192.168.56.102 confirmed.

**Recommended Response:**
1. Enable Kerberos pre-authentication on sconnor immediately
2. Reset sconnor's password — assume the hash has been cracked
3. Audit all domain accounts for DoesNotRequirePreAuth = True
4. Run: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` to find all affected accounts
5. Investigate what sconnor has access to — assume account is compromised

---

### Finding 3 — Kerberoasting

**Severity:** High  
**Date:** 18 June 2026  
**Attacker IP:** 192.168.56.102  
**Target Service Account:** sqlsvc (SPN: MSSQLSvc/DC01.corp.local:1433)  

**What happened:**  
The attacker authenticated as Administrator and requested a Kerberos service ticket for sqlsvc. Because sqlsvc had an SPN registered, any authenticated domain user can request its service ticket. The ticket is encrypted with sqlsvc's password hash and can be cracked offline without triggering any lockout.

**Evidence:**  
- Event ID 4769 (Kerberos Service Ticket Request) for sqlsvc
- Ticket_Encryption_Type: 0x17 (RC4) — confirms weak encryption
- Requesting account: Administrator@CORP.LOCAL from 192.168.56.102
- Hash obtained: $krb5tgs$23$*sqlsvc$CORP.LOCAL*

**Splunk Detection:**
```spl
index=main EventCode=4769 Service_Name=sqlsvc
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
```

**Result:** sqlsvc + 0x17 + 192.168.56.102 confirmed.

**Recommended Response:**
1. Reset sqlsvc password immediately with a long, complex password (25+ characters)
2. Configure sqlsvc to use AES encryption — removes the RC4 0x17 signature
3. Audit all service accounts with SPNs: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"}`
4. Apply principle of least privilege — sqlsvc should only have access it needs
5. Consider using Group Managed Service Accounts (gMSA) — passwords auto-rotate

---

## 5. Summary of Detections

| Attack          | Event ID | Key Indicator          | Detected |
|-----------------|----------|------------------------|----------|
| Password Spray  | 4625     | 22 failures, 1 IP      | ✅ Yes   |
| AS-REP Roasting | 4768     | RC4 (0x17), sconnor    | ✅ Yes   |
| Kerberoasting   | 4769     | RC4 (0x17), sqlsvc     | ✅ Yes   |

---

## 6. Key Takeaways

1. **RC4 is the universal red flag** — both AS-REP Roasting and Kerberoasting produce Event IDs with Ticket_Encryption_Type 0x17. Any modern AD environment should be using AES. RC4 from an external IP is always suspicious.

2. **Windows Security Event Logs require manual field extraction in Splunk** — fields like source IP are embedded in the raw Message field and must be parsed using `rex`. This is a real-world SPL skill, not a workaround.

3. **Kerberos attacks leave minimal noise** — unlike brute force, AS-REP Roasting and Kerberoasting each generate only 1-2 events. Detection depends on knowing exactly which event and field to watch, not on volume thresholds.

4. **Sysmon enhances visibility significantly** — standard Windows Security logs alone miss process creation, network connections, and lateral movement. Sysmon with the SwiftOnSecurity config provides the additional context needed for thorough investigation.

---

## 7. Tools Used

| Tool | Purpose |
|------|---------|
| Impacket GetNPUsers.py | AS-REP Roasting |
| Impacket GetUserSPNs.py | Kerberoasting |
| Kali Linux | Attack platform |
| Splunk Enterprise 9.2.1 | SIEM detection |
| Splunk Universal Forwarder | Log forwarding |
| Sysmon v15.20 | Enhanced endpoint logging |
| VirtualBox | Lab virtualisation |

---

*Report prepared by Boney Cyriac — linkedin.com/in/boney-cyriac*
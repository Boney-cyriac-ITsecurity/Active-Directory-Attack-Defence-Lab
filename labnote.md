# Project 8 — Active Directory Attack & Defence Lab

## Lab Architecture
| Machine | OS                  | IP             | Role                |
|---------|---------------------|----------------|---------------------|
| DC01    | Windows Server 2022 | 192.168.56.10  | Domain Controller   |
| WS01    | Windows 10 21H2     | 192.168.56.11  | Victim Workstation  |
| Kali    | Kali Linux 2026.1   | 192.168.56.102 | Attacker            |
| Ubuntu  | Ubuntu 22.04        | 192.168.1.42   | Splunk SIEM         |

## Domain
- Domain Name: corp.local
- NetBIOS: CORP
- DC Hostname: DC01

## Vulnerable Users Created
| Username | Vulnerability                  | Attack Target     |
|----------|-------------------------------|-------------------|
| jsmith   | Weak password (Password1)      | Password Spray    |
| sconnor  | DoesNotRequirePreAuth = True   | AS-REP Roasting   |
| sqlsvc   | SPN set (MSSQLSvc/DC01:1433)   | Kerberoasting     |

---

## Phase Progress

- [x] Phase 1 — DC Setup
- [x] Phase 2 — User Config + Sysmon + Log Forwarding
- [x] Phase 3 — Attacks from Kali
- [x] Phase 4 — Splunk Detection + Dashboard
- [ ] Phase 5 — Investigation Runbook
- [ ] Phase 6 — Report + GitHub

---

## Phase 1 — DC Setup (Completed: 15-June-2026)
- DC01 promoted to Domain Controller
- Domain: corp.local
- DNS verified: corp.local → 192.168.56.10

---

## Phase 2 — User Config + Sysmon + Log Forwarding (Completed: 17-June-2026)
- [x] Vulnerable users created: jsmith, sconnor, sqlsvc
- [x] Sysmon v15.20 installed on DC01 with SwiftOnSecurity config
- [x] Splunk Universal Forwarder installed on DC01 → forwarding to 192.168.1.42:9997
- [x] WS01 joined to corp.local domain
- [x] WS01 logs confirmed in Splunk — 28 events
- [x] Both DC01 and WS01 feeding WinEventLog:Security to Splunk

---

## Phase 3 — Attacks from Kali (Completed: 18-June-2026)

### Attack 1 — Password Spray
- Tool: CrackMapExec / custom spray
- Target user: jsmith
- Attempts: 22 failed logons from 192.168.56.102
- Event generated: 4625 (Failed Logon)
- Screenshot: Screenshots/phase3-attack1-password-spray.png

### Attack 2 — AS-REP Roasting
- Tool: Impacket GetNPUsers.py
- Command: `python3 GetNPUsers.py corp.local/sconnor -no-pass -dc-ip 192.168.56.10`
- Target user: sconnor (DoesNotRequirePreAuth = True)
- Result: $krb5asrep$23$ hash obtained
- Event generated: 4768 (Kerberos TGT Request) with Ticket_Encryption_Type 0x17
- Screenshot: Screenshots/phase3-attack2-asreproast-hash-kali.png

### Attack 3 — Kerberoasting
- Tool: Impacket GetUserSPNs.py
- Command: `python3 GetUserSPNs.py corp.local/Administrator:pass@123 -dc-ip 192.168.56.10 -request`
- Target: sqlsvc (SPN: MSSQLSvc/DC01.corp.local:1433)
- Result: $krb5tgs$23$ hash obtained
- Event generated: 4769 (Kerberos Service Ticket Request) with Ticket_Encryption_Type 0x17
- Screenshot: Screenshots/phase3-attack3-kerberoast-hash-kali.png

---

## Phase 4 — Splunk Detection + Dashboard (Completed: 18-June-2026)

### Detection 1 — Password Spray
- Event ID: 4625
- SPL Query:
```
index=main EventCode=4625
| rex field=Message "Source Network Address:\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, Account_Name
| where count > 5
| sort -count
```
- Result: 192.168.56.102 with count 22 detected
- Screenshot: Screenshots/phase3-detection1-password-spray-splunk.png

### Detection 2 — AS-REP Roasting
- Event ID: 4768
- SPL Query:
```
index=main EventCode=4768 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Client_Address, Ticket_Encryption_Type
```
- Result: sconnor, 192.168.56.102, 0x17 confirmed
- Screenshot: Screenshots/phase3-detection2-asreproast-splunk.png

### Detection 3 — Kerberoasting
- Event ID: 4769
- SPL Query:
```
index=main EventCode=4769 Service_Name=sqlsvc
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
```
- Result: sqlsvc, Administrator@CORP.LOCAL, 192.168.56.102, 0x17 confirmed
- Screenshot: Screenshots/phase3-detection3-kerberoast-splunk.png

### Dashboard
- Name: AD Attack Detection - Home Lab
- Panels: Password Spray (bar chart) + AS-REP Roasting (table) + Kerberoasting (table)
- Screenshot: Screenshots/phase3-dashboard-full-1.png
- Screenshot: Screenshots/phase3-dashboard-full-2.png

---

## Key Event IDs Reference
| Event ID | Meaning                         | Attack                |
|----------|---------------------------------|-----------------------|
| 4625     | Failed logon                    | Password Spray        |
| 4624     | Successful logon                | Lateral Movement      |
| 4648     | Logon with explicit credentials | Pass-the-Hash         |
| 4768     | Kerberos TGT request            | AS-REP Roasting       |
| 4769     | Kerberos service ticket request | Kerberoasting         |
| 4672     | Special privileges assigned     | Privilege Escalation  |
| 4728     | User added to security group    | DA Escalation         |
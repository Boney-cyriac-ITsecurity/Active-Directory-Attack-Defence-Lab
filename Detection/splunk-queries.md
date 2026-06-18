# Splunk Detection Queries — Project 8
## Active Directory Attack & Defence Lab

---

## Query 1 — Password Spray Detection

**Trigger:** Multiple failed logons from a single IP in a short window  
**Event ID:** 4625 — Failed Logon  
**Red Flag:** Same source IP targeting multiple accounts

```spl
index=main EventCode=4625
| rex field=Message "Source Network Address:\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, Account_Name
| where count > 5
| sort -count
```

**Why rex is needed:** Windows Security Event logs do not auto-extract all fields in Splunk. The source IP lives inside the raw Message field and must be parsed manually using rex.

**Result in lab:** 192.168.56.102 with count 22 across multiple accounts — confirmed password spray.

---

## Query 2 — AS-REP Roasting Detection

**Trigger:** Kerberos TGT requested using RC4 encryption instead of AES  
**Event ID:** 4768 — Kerberos Authentication Service Request  
**Red Flag:** Ticket_Encryption_Type = 0x17 (RC4) from an external IP

```spl
index=main EventCode=4768 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Client_Address, Ticket_Encryption_Type
```

**Why 0x17 matters:** Modern Windows environments use AES (0x12/0x11) for Kerberos. RC4 (0x17) only appears when an account has pre-authentication disabled — a deliberate misconfiguration attackers look for. Any 0x17 from an external IP is high-confidence suspicious.

**Result in lab:** sconnor + 192.168.56.102 + 0x17 — confirmed AS-REP Roasting.

---

## Query 3 — Kerberoasting Detection

**Trigger:** Service ticket requested for a service account using RC4 encryption  
**Event ID:** 4769 — Kerberos Service Ticket Request  
**Red Flag:** Ticket_Encryption_Type = 0x17 for a service account SPN from an external IP

```spl
index=main EventCode=4769 Service_Name=sqlsvc
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
```

**Why this works:** Attackers request service tickets for accounts with SPNs to crack offline. The RC4 flag (0x17) identifies the attack because modern Kerberos uses AES. Filtering by Service_Name isolates the specific service account targeted.

**Result in lab:** Administrator@CORP.LOCAL requested sqlsvc ticket, 0x17, from 192.168.56.102 — confirmed Kerberoasting.

---

## Notes

- All queries written and tested in Splunk Enterprise 9.2.1
- Logs sourced from Windows Security Event Log via Splunk Universal Forwarder
- Sysmon v15.20 with SwiftOnSecurity config used for enhanced endpoint visibility
- Time range: All Time (lab environment — no rolling window needed)
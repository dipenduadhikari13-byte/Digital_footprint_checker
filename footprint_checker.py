#!/usr/bin/env python3
"""
Digital Footprint Checker v3.1
================================
Breach APIs (all free):
  • EmailRep.io     — reputation + breach flag, no key needed
  • HudsonRock      — infostealer / combolist intelligence, no key needed
  • LeakCheck.io    — 50 free checks/day (optional key from leakcheck.io)
  • Holehe          — probes 120+ sites via forgot-password (uses httpx+trio)
"""

import os, sys, time, requests, phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
from dotenv import load_dotenv
from datetime import datetime

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"; C="\033[96m"
DIM="\033[2m"; BOLD="\033[1m"; RESET="\033[0m"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Accept": "application/json",
}

def banner():
    print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════╗
║          DIGITAL FOOTPRINT CHECKER  v3.1                 ║
║  Checks where YOUR emails & phone numbers are registered ║
╚══════════════════════════════════════════════════════════╝{RESET}
{DIM}  Loaded from .env  |  Run only on your own data{RESET}
""")

def section(title):
    bar = "─" * 58
    print(f"\n{B}{BOLD}┌{bar}┐\n│  {title:<56}│\n└{bar}┘{RESET}")

def found(site, detail=""):
    print(f"  {G}[✔ FOUND]{RESET}  {BOLD}{site}{RESET}  {DIM}{detail}{RESET}")

def info(msg):  print(f"  {C}[i]  {msg}{RESET}")
def warn(msg):  print(f"  {Y}[!]  {msg}{RESET}")
def err(msg):   print(f"  {R}[ERR] {msg}{RESET}")

# ── Load .env ─────────────────────────────────────────────────────────────────
def load_config():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        err(f".env not found at: {env_path}")
        err("Copy .env.example → .env and fill in your details.")
        sys.exit(1)
    load_dotenv(env_path)
    emails = [e.strip() for e in os.getenv("EMAILS","").split(",") if e.strip()]
    phones = [p.strip() for p in os.getenv("PHONES","").split(",") if p.strip()]
    lc_key = os.getenv("LEAKCHECK_API_KEY","").strip() or None
    if not emails and not phones:
        err("No emails or phones in .env.")
        sys.exit(1)
    return emails, phones, lc_key

# ── 1. EmailRep.io ────────────────────────────────────────────────────────────
def check_emailrep(email):
    url = f"https://emailrep.io/{requests.utils.quote(email)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            data     = r.json()
            rep      = data.get("reputation", "unknown")
            details  = data.get("details", {})
            print(f"  {'─'*50}")
            print(f"  Reputation     : {BOLD}{rep.upper()}{RESET}")
            print(f"  Suspicious     : {R+'YES'+RESET if data.get('suspicious') else G+'NO'+RESET}")
            print(f"  Credentials    : {R+'LEAKED'+RESET if details.get('credentials_leaked') else G+'Not in known leaks'+RESET}")
            print(f"  Data breach    : {R+'YES'+RESET if details.get('data_breach') else G+'NO'+RESET}")
            print(f"  Malicious act  : {R+'YES'+RESET if details.get('malicious_activity') else G+'NO'+RESET}")
            print(f"  Spam flag      : {Y+'YES'+RESET if details.get('spam') else G+'NO'+RESET}")
            profiles = details.get("profiles", [])
            if profiles:
                print(f"\n  {BOLD}Known site registrations (via emailrep.io){RESET}")
                for site in sorted(profiles):
                    found(site)
        elif r.status_code == 429:
            warn("EmailRep.io: rate limited (5 req/hr). Wait 1 hour or get a free key at emailrep.io")
        else:
            warn(f"EmailRep.io returned HTTP {r.status_code}")
    except requests.RequestException as e:
        err(f"EmailRep.io failed: {e}")

# ── 2. HudsonRock Cavalier ────────────────────────────────────────────────────
def check_hudsonrock(email):
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={requests.utils.quote(email)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            stealers = r.json().get("stealers", [])
            if stealers:
                print(f"  {R}{BOLD}Found in {len(stealers)} infostealer log(s)!{RESET}")
                for s in stealers:
                    found("HudsonRock (infostealer)",
                          f"date: {s.get('date_compromised','?')}  malware: {s.get('malware_path','?')}")
            else:
                info("HudsonRock: not found in any infostealer logs.")
        elif r.status_code == 429:
            warn("HudsonRock: rate limited — try again in a few minutes.")
        else:
            warn(f"HudsonRock returned HTTP {r.status_code}")
    except requests.RequestException as e:
        err(f"HudsonRock failed: {e}")

# ── 3. LeakCheck.io ───────────────────────────────────────────────────────────
def check_leakcheck(email, api_key):
    url = f"https://leakcheck.io/api/public?key={api_key}&check={requests.utils.quote(email)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("sources"):
                for src in data["sources"]:
                    found("LeakCheck.io", f"(source: {src})")
            else:
                info("LeakCheck.io: no records found.")
        elif r.status_code == 401:
            warn("LeakCheck.io: invalid API key.")
        elif r.status_code == 429:
            warn("LeakCheck.io: daily quota exceeded (50/day on free plan).")
        else:
            warn(f"LeakCheck.io returned HTTP {r.status_code}")
    except requests.RequestException as e:
        err(f"LeakCheck.io failed: {e}")

# ── 4. Holehe — correct API for v1.61 (httpx + trio) ─────────────────────────
def check_holehe(email):
    try:
        import trio
        import httpx
        from holehe.core import import_submodules, get_functions, launch_module
    except ImportError as e:
        err(f"holehe import failed: {e}")
        return []

    out = []

    async def _run():
        modules  = import_submodules("holehe.modules")
        websites = get_functions(modules)          # no args → all sites
        client   = httpx.AsyncClient(timeout=10)
        async with trio.open_nursery() as nursery:
            for website in websites:
                nursery.start_soon(launch_module, website, email, client, out)
        await client.aclose()

    try:
        trio.run(_run)
    except Exception as e:
        err(f"Holehe runtime error: {e}")
        return []

    registered   = [r for r in out if r.get("exists")]
    inconclusive = [r for r in out if r.get("rateLimit") and not r.get("exists")]
    return registered, inconclusive

# ── Phone check ───────────────────────────────────────────────────────────────
def check_phone(raw_phone):
    section(f"PHONE: {raw_phone}")
    try:
        parsed = phonenumbers.parse(raw_phone, None)
    except Exception as e:
        err(f"Could not parse '{raw_phone}': {e}"); return
    if not phonenumbers.is_valid_number(parsed):
        warn("Phone number appears invalid."); return

    fmt      = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)\
                           .replace(" ","").replace("-","")
    type_map = {
        PhoneNumberType.MOBILE: "Mobile", PhoneNumberType.FIXED_LINE: "Fixed Line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
        PhoneNumberType.TOLL_FREE: "Toll-Free", PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.UNKNOWN: "Unknown",
    }
    print(f"\n  {BOLD}Basic Info{RESET}")
    print(f"  ├─ Formatted  : {fmt}")
    print(f"  ├─ Country    : {geocoder.description_for_number(parsed, 'en')}")
    print(f"  ├─ Carrier    : {carrier.name_for_number(parsed, 'en') or 'Unknown'}")
    print(f"  └─ Line Type  : {type_map.get(number_type(parsed),'Unknown')}")

    print(f"\n  {BOLD}Infostealer Check (HudsonRock){RESET}")
    try:
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-phone?phone={requests.utils.quote(national)}"
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code == 200:
            stealers = r.json().get("stealers", [])
            if stealers:
                for s in stealers:
                    found("HudsonRock", f"date: {s.get('date_compromised','?')}")
            else:
                info("Not found in infostealer logs.")
        else:
            warn(f"HudsonRock phone check: HTTP {r.status_code}")
    except requests.RequestException as e:
        err(f"HudsonRock phone check failed: {e}")

    print(f"\n  {BOLD}Public Lookup Links{RESET}  {DIM}(open in browser){RESET}")
    for name, url in [
        ("Truecaller",     f"https://www.truecaller.com/search/in/{national}"),
        ("NumLookup",      f"https://www.numlookup.com/results?phone={fmt.replace(' ','')}"),
        ("Sync.me",        f"https://sync.me/search/?phone={fmt.replace(' ','')}"),
        ("SpamCalls.net",  f"https://spamcalls.net/en/search/{national}"),
        ("Epieos (phone)", f"https://epieos.com/?q={fmt.replace(' ','')}&t=phone"),
    ]:
        print(f"  {G}>{RESET}  {name:<16}  {DIM}{url}{RESET}")
    print(f"\n  {DIM}Tip: WhatsApp > New Chat > type number to check if registered.{RESET}")

# ── Email check ───────────────────────────────────────────────────────────────
def check_email(email, lc_key):
    section(f"EMAIL: {email}")

    print(f"\n  {BOLD}[1/3]  EmailRep.io{RESET}  {DIM}(reputation + breach flag, no key){RESET}\n")
    check_emailrep(email)
    time.sleep(1.5)

    print(f"\n  {BOLD}[2/3]  HudsonRock Cavalier{RESET}  {DIM}(infostealer / combolist, no key){RESET}\n")
    check_hudsonrock(email)
    time.sleep(1.2)

    if lc_key:
        print(f"\n  {BOLD}[+]  LeakCheck.io{RESET}  {DIM}(50 free/day){RESET}\n")
        check_leakcheck(email, lc_key)
        time.sleep(1.2)
    else:
        print()
        warn("LeakCheck.io skipped — add LEAKCHECK_API_KEY to .env (50 free/day, no CC).")
        info("Get key: https://leakcheck.io → Sign up → API Keys")

    print(f"\n  {BOLD}[3/3]  Holehe{RESET}  {DIM}(probing 120+ sites via forgot-password...){RESET}\n")
    result = check_holehe(email)
    if result:
        registered, inconclusive = result
        if registered:
            print(f"  {G}{BOLD}Registered on {len(registered)} site(s):{RESET}")
            for r in sorted(registered, key=lambda x: x["name"]):
                found(r["name"], f"({r.get('domain','')})")
        else:
            info("Not detected on any of the probed sites.")
        if inconclusive:
            print(f"\n  {Y}Rate-limited / inconclusive on {len(inconclusive)} site(s):{RESET}")
            for r in inconclusive:
                warn(f"{r['name']} ({r.get('domain','')})")

    print(f"\n  {BOLD}OSINT Links{RESET}  {DIM}(open in browser){RESET}")
    enc = requests.utils.quote(f'"{email}"')
    for name, url in [
        ("Google dork",   f"https://www.google.com/search?q={enc}"),
        ("Pastebin dork", f"https://www.google.com/search?q=site:pastebin.com+{enc}"),
        ("Dehashed",      f"https://www.dehashed.com/search?query={requests.utils.quote(email)}"),
        ("Epieos",        f"https://epieos.com/?q={requests.utils.quote(email)}&t=email"),
        ("IntelX",        f"https://intelx.io/?s={requests.utils.quote(email)}"),
        ("LeakCheck web", f"https://leakcheck.io/search?query={requests.utils.quote(email)}"),
    ]:
        print(f"  {G}>{RESET}  {name:<18}  {DIM}{url}{RESET}")

# ── Summary ───────────────────────────────────────────────────────────────────
def print_summary(emails, phones):
    section("SUMMARY")
    print(f"\n  Emails checked : {BOLD}{len(emails)}{RESET}")
    for e in emails: print(f"    • {e}")
    print(f"  Phones checked : {BOLD}{len(phones)}{RESET}")
    for p in phones: print(f"    • {p}")
    print(f"\n  {DIM}Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    emails, phones, lc_key = load_config()
    info(f"Loaded {len(emails)} email(s) and {len(phones)} phone(s) from .env\n")
    for email in emails:
        check_email(email, lc_key)
        time.sleep(1)
    for phone in phones:
        check_phone(phone)
    print_summary(emails, phones)

if __name__ == "__main__":
    main()
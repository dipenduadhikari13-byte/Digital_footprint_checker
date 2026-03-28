# Digital Footprint Checker

Check where **your own** email addresses and phone numbers are registered across the internet.

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create your .env file from the example
cp .env.example .env

# 3. Edit .env and add YOUR emails and phone numbers
nano .env

# 4. Run it
python3 footprint_checker.py
```

---

## What gets checked

### Email addresses
| Method | What it does |
|--------|-------------|
| **Holehe** | Probes 120+ websites (Google, Twitter, Instagram, GitHub, PayPal…) via their "Forgot Password" endpoints — no login or scraping needed |
| **Leak Check** | Checks if your email appeared in known data breaches or paste dumps (free API key needed) |
| **Search links** | Generates ready-to-open URLs for Dehashed, Epieos, Pastebin, etc. |

### Phone numbers
| Method | What it does |
|--------|-------------|
| **phonenumbers library** | Country, carrier, line type (mobile/VoIP/fixed) |
| **Lookup links** | Generates links for Truecaller, NumLookup, Sync.me, SpamCalls |

---

## .env format

```env
EMAILS=you@gmail.com,you@outlook.com,work@company.com
PHONES=+911234567890,+919876543210
LEAKCHECK_API_KEY=your_key_here
```

- Phone numbers **must include country code**
- LEAKCHECK_API_KEY is **optional but recommended**
- Multiple values separated by commas

---

## Notes

- **Holehe** works by sending a "forgot password" request and checking if the site says "email not found" vs "email sent". No passwords are involved.
- Some sites may **rate-limit** Holehe if run frequently — wait a few minutes and retry.
- This tool is intended for **checking your own data only**.
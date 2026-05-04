---
name: dedup-check
description: Before submitting a finding, compare it against the program's publicly disclosed reports to estimate duplicate probability. Combines endpoint/parameter fingerprinting, vulnerability class matching, and title similarity scoring. Run this after /triager and before any submission. Trigger on phrases like "check for duplicates", "is this already reported", "dedup check", "similarity check", "will this be a dup", or automatically before any report submission.
---

# Dedup Check Skill

A duplicate is the most demoralizing outcome in bug bounty. The bug is real, the PoC is solid, and the program closes it as N/A or Duplicate with no reward. This skill runs a structured similarity check against the program's public disclosed reports before you submit — so you know the duplicate risk going in.

Run this after `/triager` returns "Submit" and before you actually submit. It takes under 5 minutes.

---

## Input

This skill requires a finding summary. Before running, have these ready:

```
Target program: [HackerOne/Bugcrowd program name]
Vulnerability class: [e.g. IDOR, SSRF, OAuth redirect_uri bypass, Race condition]
Endpoint/parameter: [Exact URL and parameter affected]
One-line description: [What the bug does — be precise]
```

---

## Step 1 — Pull Disclosed Reports from Program

### HackerOne

```bash
# Pull public disclosed reports via HackerOne Hacktivity
# Replace PROGRAM_HANDLE with the program's HackerOne handle
curl -s "https://hackerone.com/programs/PROGRAM_HANDLE/hacktivity?limit=100&disclosed=true" \
  -H "Accept: application/json" 2>/dev/null | \
  python3 -c "
import sys, json
try:
  data = json.load(sys.stdin)
  reports = data.get('reports', data.get('data', []))
  for r in reports:
    title = r.get('title', r.get('attributes', {}).get('title', ''))
    severity = r.get('severity_rating', r.get('attributes', {}).get('severity_rating', ''))
    vuln_type = r.get('weakness', {}).get('name', '') if isinstance(r.get('weakness'), dict) else ''
    print(f'{severity} | {vuln_type} | {title}')
except: print('Parse error — check program handle')
" 2>/dev/null | head -100
```

### Bugcrowd

```bash
# Pull from Bugcrowd Hall of Fame / public disclosures
# Replace PROGRAM_HANDLE with the Bugcrowd program handle
curl -s "https://bugcrowd.com/PROGRAM_HANDLE/hall-of-fame" \
  -H "Accept: application/json" 2>/dev/null | head -200
```

If API pulls return nothing (many programs restrict this), fall back to manual browsing:
- **HackerOne:** `https://hackerone.com/PROGRAM_HANDLE?type=team` → Activity tab → filter "Disclosed"
- **Bugcrowd:** `https://bugcrowd.com/PROGRAM_HANDLE` → Hall of Fame
- **Intigriti:** `https://app.intigriti.com/programs/COMPANY/PROGRAM/submissions`

Copy the last 50–100 disclosed report titles into a file:

```bash
ssh user@$KALI_IP "cat > ~/bugbounty/$TARGET/intel/disclosed-reports.txt" << 'EOF'
[paste titles here, one per line]
EOF
```

---

## Step 2 — Fingerprint Your Finding

Extract the key matching signals from your finding:

```bash
ssh user@$KALI_IP 'python3 -s' << 'ENDSSH'
import re, os

# Fill these in before running
MY_FINDING = """
vuln_class: IDOR
endpoint: /api/v2/users/{id}/profile
parameter: id
description: Authenticated user can access any other user profile by incrementing the id parameter
"""

# Extract tokens for matching
lines = MY_FINDING.strip().split("\n")
for line in lines:
    key, _, val = line.partition(":")
    print(f"  {key.strip():15} → {val.strip()}")

print()
print("Matching signals extracted. Compare against Step 3 output.")
ENDSSH
```

---

## Step 3 — Similarity Score Against Disclosed Reports

Run a token-overlap similarity check between your finding and each disclosed report title:

```bash
ssh user@$KALI_IP 'python3 -s' << 'ENDSSH'
import re, pathlib, os

TARGET_DIR = os.path.expanduser(f"~/bugbounty/{os.environ.get('TARGET', 'TARGET')}/intel")
DISCLOSED = pathlib.Path(TARGET_DIR) / "disclosed-reports.txt"

MY_CLASS   = "IDOR"     # <-- change to your vuln class
MY_ENDPOINT = "/api/v2/users/{id}/profile"  # <-- change to your endpoint
MY_TITLE    = "IDOR on user profile endpoint allows accessing other users data"  # <-- your draft title

CLASS_SYNONYMS = {
    "IDOR": ["idor", "insecure direct object", "object reference", "broken object", "bola"],
    "SSRF": ["ssrf", "server-side request", "internal request"],
    "CSRF": ["csrf", "cross-site request", "state parameter"],
    "XSS":  ["xss", "cross-site scripting", "reflected", "stored", "dom-based"],
    "SQLi": ["sql injection", "sqli", "sql", "injection"],
    "RCE":  ["rce", "remote code", "code execution", "command injection"],
    "OAuth": ["oauth", "redirect_uri", "authorization code", "token", "oidc", "sso"],
    "Race": ["race condition", "toctou", "double-spend", "concurrent"],
}

synonyms = CLASS_SYNONYMS.get(MY_CLASS, [MY_CLASS.lower()])

def token_overlap(a: str, b: str) -> float:
    ta = set(re.findall(r"\w+", a.lower()))
    tb = set(re.findall(r"\w+", b.lower()))
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)

def class_match(title: str) -> bool:
    tl = title.lower()
    return any(s in tl for s in synonyms)

def endpoint_match(title: str) -> bool:
    parts = [p for p in re.split(r"[/{}?=&.]", MY_ENDPOINT) if p and len(p) > 2]
    return any(p.lower() in title.lower() for p in parts)

if not DISCLOSED.exists():
    print(f"[WARN] {DISCLOSED} not found.")
    print("Paste disclosed report titles into intel/disclosed-reports.txt and re-run.")
else:
    print(f"Checking against {DISCLOSED}")
    print()
    print(f"{'SCORE':>6}  {'CLASS?':>6}  {'ENDPOINT?':>9}  TITLE")
    print("-" * 80)
    results = []
    with open(DISCLOSED) as f:
        for line in f:
            title = line.strip()
            if not title:
                continue
            score   = token_overlap(MY_TITLE, title)
            c_match = class_match(title)
            e_match = endpoint_match(title)
            risk    = score + (0.3 if c_match else 0) + (0.2 if e_match else 0)
            results.append((risk, score, c_match, e_match, title))
    results.sort(reverse=True)
    for risk, score, c_match, e_match, title in results[:20]:
        flag = "⚠️ " if risk > 0.5 else "   "
        print(f"{score:>6.2f}  {str(c_match):>6}  {str(e_match):>9}  {flag}{title[:70]}")
    print()
    top_risk = results[0][0] if results else 0
    if top_risk > 0.7:
        print("❌ HIGH duplicate risk — strong match on class + endpoint + title tokens")
    elif top_risk > 0.4:
        print("⚠️  MEDIUM duplicate risk — similar reports exist; review top matches manually")
    else:
        print("✅ LOW duplicate risk — no strong overlap with disclosed reports")

ENDSSH
```

---

## Step 4 — Vulnerability Class Frequency Check

How saturated is this vuln class on this program? A program that has disclosed 40 IDORs has triagers trained to recognize and quickly duplicate IDOR submissions:

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
TARGET_DIR=~/bugbounty/$TARGET/intel
DISCLOSED="$TARGET_DIR/disclosed-reports.txt"

if [ ! -f "$DISCLOSED" ]; then
  echo "[SKIP] disclosed-reports.txt not found"
  exit 0
fi

echo "=== Vuln Class Distribution in Disclosed Reports ==="
for class in idor ssrf xss sqli csrf rce oauth race graphql; do
  count=$(grep -ic "$class" "$DISCLOSED" 2>/dev/null || echo 0)
  printf "  %-12s %d disclosed\n" "$class" "$count"
done
ENDSSH
```

A class with >10 disclosed reports means heavy competition — your variant must be meaningfully different to avoid a duplicate.

---

## Step 5 — Save Dedup Assessment

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p "$TARGET_DIR/findings"

cat >> "$TARGET_DIR/findings/dedup-assessment.md" << 'EOF'

---
## Dedup Assessment: [FINDING TITLE]
Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Vuln class: [CLASS]
Endpoint: [ENDPOINT]

Top similarity matches from disclosed reports:
- [title] | score: [X] | class match: yes/no
- [title] | score: [X] | class match: yes/no

Duplicate risk: LOW / MEDIUM / HIGH
Decision: [Submit / Needs differentiation / Do not submit]

Differentiating factors (if medium/high risk):
- [What makes your variant different from disclosed reports]
- [Why the impact chain is distinct]
EOF

echo "[*] Dedup assessment appended to $TARGET_DIR/findings/dedup-assessment.md"
ENDSSH
```

---

## Dedup Risk Decision Matrix

| Risk Level | Score | Action |
|---|---|---|
| LOW | < 0.4 | Submit — low overlap with disclosed reports |
| MEDIUM | 0.4 – 0.7 | Review top matches manually; articulate what makes your variant distinct in the report |
| HIGH | > 0.7 | Strong overlap — either don't submit, or reframe around a genuinely distinct impact chain |
| Class saturated | >10 disclosures | Add a "Why this wasn't caught" section to your report; differentiation is critical |

---

## Guiding Principles

- **A duplicate risk score is not a submission veto.** HIGH risk means "review carefully" — not "don't submit." Your variant may have a different root cause, scope, or impact chain.
- **Similarity is about tokens, not intent.** Two IDOR reports on the same endpoint with different parameters can both be valid.
- **If you can't articulate what's different, that's the finding — it's probably a dup.** Spend the 5 minutes before you spend the 2 hours writing the report.
- **Program activity matters.** A program that disclosed 3 reports in 2 years has a very different duplicate landscape than one disclosing 20 per month.
- **Run this after `/triager`, not before.** Triager filters invalid bugs. Dedup filters valid bugs that are already known. Different gates.

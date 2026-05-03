---
name: subdomain-takeover
description: Systematically detect, verify, and document subdomain takeover vulnerabilities by identifying dangling DNS records pointing to unclaimed third-party services. Use this skill whenever subdomain recon is complete or when a CNAME points to an external provider that may have lapsed registrations. Trigger on phrases like "check for subdomain takeover", "dangling DNS", "subdomain takeover candidates", "verify takeovers", or when subdomain-enum has flagged CNAME records pointing to cloud providers, SaaS platforms, or CDN services.
---

# Subdomain Takeover Skill

You are verifying subdomain takeover candidates. A subdomain takeover occurs when a CNAME or other DNS record points to an external service that is no longer registered or provisioned — an attacker who claims the service can serve content from the victim's subdomain, enabling phishing, cookie theft, and CSP bypass. This is one of the most consistently reportable findings across all bug bounty programs.

This skill begins after `/recon/subdomain-enum` has run. The takeover candidates file from that workflow is the input.

---

## Phase 1 — Candidate Collection

### Step 1.1 — Load Takeover Candidates from Recon

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/takeover

# Primary source: subdomain-enum takeover candidates
if [ -f $TARGET_DIR/recon/subdomains/takeover-candidates.txt ]; then
  cp $TARGET_DIR/recon/subdomains/takeover-candidates.txt \
     $TARGET_DIR/recon/takeover/candidates.txt
  echo "[*] Loaded $(wc -l < $TARGET_DIR/recon/takeover/candidates.txt) candidates from subdomain-enum"
else
  echo "[-] No takeover-candidates.txt found — running CNAME analysis now"
fi
```

### Step 1.2 — Fresh CNAME Extraction (if candidates file missing)

```bash
# Extract all CNAME records from subdomain list
while read SUB; do
  CNAME=$(dig +short CNAME "$SUB" 2>/dev/null)
  if [ -n "$CNAME" ]; then
    # Check if CNAME target resolves
    RESOLVES=$(dig +short "$CNAME" 2>/dev/null | head -1)
    if [ -z "$RESOLVES" ]; then
      echo "[DANGLING] $SUB -> $CNAME (CNAME target does not resolve)"
    else
      echo "[RESOLVES] $SUB -> $CNAME -> $RESOLVES"
    fi
  fi
done < $TARGET_DIR/recon/subdomains/all-subdomains.txt | \
  tee $TARGET_DIR/recon/takeover/cname-analysis.txt

# Extract dangling ones
grep '^\[DANGLING\]' $TARGET_DIR/recon/takeover/cname-analysis.txt | \
  awk '{print $2, $4}' > $TARGET_DIR/recon/takeover/candidates.txt

echo "[*] Dangling CNAMEs found: $(wc -l < $TARGET_DIR/recon/takeover/candidates.txt)"
```

---

## Phase 2 — Provider Fingerprinting

For each candidate, identify the target service from the CNAME and match it to a known takeover method:

```bash
while IFS=' ' read -r SUBDOMAIN CNAME_TARGET; do
  echo "=== $SUBDOMAIN ==="
  echo "CNAME: $CNAME_TARGET"

  # Fetch the HTTP response to get the service's "not found" fingerprint
  BODY=$(curl -sk --max-time 8 -L "https://$SUBDOMAIN" 2>/dev/null || \
         curl -sk --max-time 8 -L "http://$SUBDOMAIN" 2>/dev/null)
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "https://$SUBDOMAIN" 2>/dev/null)

  echo "HTTP: $HTTP_CODE"
  echo "Body snippet: $(echo $BODY | head -c 300)"
  echo ""
done < $TARGET_DIR/recon/takeover/candidates.txt | \
  tee $TARGET_DIR/recon/takeover/fingerprints.txt
```

### Takeover Fingerprint Reference

Match the HTTP response body against these known signatures:

| Provider | CNAME pattern | Takeover fingerprint | Claim method |
|---|---|---|---|
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here` | Create repo with matching name |
| **Heroku** | `*.herokuapp.com` | `No such app` | `heroku create [app-name]` |
| **Netlify** | `*.netlify.app` / `*.netlify.com` | `Not Found - Request ID` | Claim site in Netlify dashboard |
| **Vercel** | `*.vercel.app` | `The deployment could not be found` | Deploy to matching project |
| **AWS S3** | `*.s3.amazonaws.com` / `s3-website-*` | `NoSuchBucket` | Create S3 bucket with matching name in same region |
| **AWS CloudFront** | `*.cloudfront.net` | `ERROR: The request could not be satisfied` | Requires CF distribution pointing to claimable origin |
| **Azure** | `*.azurewebsites.net` / `*.blob.core.windows.net` | `404 Web Site not found` | Create App Service / Storage with matching name |
| **Fastly** | `*.fastly.net` | `Fastly error: unknown domain` | Add domain in Fastly dashboard |
| **Pantheon** | `*.pantheonsite.io` | `404 error unknown site` | Claim via Pantheon dashboard |
| **Ghost** | `*.ghost.io` | `The thing you were looking for is no longer here` | Register Ghost Pro account |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | Register Shopify store with matching subdomain |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` | Create Zendesk account with matching subdomain |
| **Tumblr** | `*.tumblr.com` | `There's nothing here` | Claim Tumblr blog |
| **Surge.sh** | `*.surge.sh` | `project not found` | `surge --domain [subdomain]` |
| **HubSpot** | `*.hs-sites.com` | `Domain not found` | Claim in HubSpot CMS |
| **Read the Docs** | `*.readthedocs.io` | `Unknown Host` | Create RTD project |

---

## Phase 3 — Verification

### Step 3.1 — Confirm Takeover Conditions

Before claiming anything, verify all three conditions are met:

```bash
SUBDOMAIN="[candidate]"
CNAME_TARGET="[cname target]"

# Condition 1: CNAME still points to external service (DNS not fixed)
dig +short CNAME "$SUBDOMAIN"

# Condition 2: CNAME target does not resolve to a claimed resource
dig +short "$CNAME_TARGET"

# Condition 3: HTTP response matches known takeover fingerprint
curl -sk -L "https://$SUBDOMAIN" | head -c 500
```

**All three must be true:**
1. CNAME record exists and points to the external service
2. The CNAME target is unclaimed / returns a "not found" response
3. The HTTP body matches a known takeover fingerprint for that provider

If any condition fails — do not attempt to claim and do not submit.

### Step 3.2 — Scope and Authorization Check

Before claiming, run `/scope-checker` on the subdomain:
- The subdomain must be in scope
- Confirm program policy allows subdomain takeover testing
- Some programs explicitly disallow claiming external services even to demonstrate the vulnerability

```bash
echo "[MANUAL CHECK] Verify program policy allows subdomain takeover PoC"
echo "If policy is unclear — document the finding without claiming the service"
```

---

## Phase 4 — PoC Documentation

Document the finding regardless of whether you claim the service:

```bash
cat > $TARGET_DIR/findings/takeover-$SUBDOMAIN.md << 'EOF'
# Subdomain Takeover: [subdomain]

## Summary
[subdomain] has a dangling CNAME record pointing to [service] which is no longer provisioned.
An attacker can claim this [service] account/resource and serve arbitrary content from [subdomain].

## DNS Evidence
```
Dig output showing: [subdomain] CNAME [cname-target]
Dig output showing: [cname-target] does not resolve
```

## HTTP Response (confirming unclaimed state)
```
GET https://[subdomain]
HTTP 404
[takeover fingerprint string from response body]
```

## Provider
[Service name] — Takeover possible by: [claim method]

## Impact
An attacker can:
- Serve arbitrary content from a trusted [program] subdomain
- Set cookies on the [parent domain] domain (if applicable)
- Bypass Content-Security-Policy rules that trust [subdomain]
- Use the subdomain for phishing with a [program]-branded URL

## Severity
High — Content can be served from a trusted program subdomain without authentication
EOF
```

**For PoC:** Take a screenshot of the takeover fingerprint response from the subdomain. This is sufficient — you do not need to claim the service to submit the finding.

---

## Phase 5 — Cookie Scope Impact Assessment

If the taken-over subdomain is on the same domain as the main application, assess cookie theft potential:

```bash
# Check if main application sets cookies scoped to parent domain
curl -sk -I "https://$TARGET_DOMAIN" | grep -i 'set-cookie' | \
  grep -iE '(domain=\.?[^;]+)'

# If cookie has Domain=.target.com — it is accessible from ALL subdomains
# including the taken-over one
# This escalates severity from High to Critical (session hijacking possible)
```

**If parent-domain cookies are present:** The finding escalates — a taken-over subdomain can receive cookies set by the main application on any cross-subdomain navigation. Document this escalation path explicitly in the finding.

---

## Output Summary

| File | Contents |
|---|---|
| `candidates.txt` | All subdomain takeover candidates (subdomain + CNAME target) |
| `cname-analysis.txt` | Full CNAME resolution analysis for all subdomains |
| `fingerprints.txt` | HTTP response fingerprints for each candidate |

---

## Severity Reference

| Condition | Severity |
|---|---|
| Takeover possible + parent-domain cookie in scope | Critical |
| Takeover possible on auth/API subdomain | High |
| Takeover possible on standard marketing/static subdomain | High |
| Dangling CNAME confirmed but provider not claimable | Medium |
| Dangling CNAME on out-of-scope subdomain | Informational |

---

## Guiding Principles

- **Never claim a service without confirming all three verification conditions.** A false-positive takeover claim wastes program trust and may be considered abuse.
- **Screenshot the fingerprint — DNS records change.** CNAME records can be fixed before the program verifies your report. The screenshot is your timestamp.
- **Cookie scope is the severity multiplier.** Always check parent-domain cookie scope. A takeover on a subdomain that receives session cookies is Critical, not High.
- **Do not serve any content from a claimed subdomain.** If you claim the service to confirm exploitability, serve a static HTML file with your handle and a timestamp only. Do not serve phishing content, malware, or anything beyond proof of claim.
- **Some providers fix the race condition before you can claim.** If the CNAME is removed before you can verify, document the evidence you captured and submit anyway — the DNS history is the finding.

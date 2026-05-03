---
name: dotnet-hunter
description: Comprehensive .NET and ASP.NET bug bounty skill covering fingerprinting, framework detection, and systematic testing of .NET-specific vulnerability classes. Use this skill whenever a target is identified as running .NET, ASP.NET, ASP.NET Core, or IIS. Trigger on phrases like "test this .NET app", "ASP.NET target", "hunt .NET bugs", "ViewState testing", ".NET recon", or when recon reveals .aspx/.ashx extensions, X-Powered-By: ASP.NET headers, or IIS server banners.
---

# .NET Hunter Skill

You are hunting a .NET or ASP.NET application. .NET targets have a distinct attack surface that generic web app workflows miss entirely — ViewState deserialization, padding oracles, IIS-specific path traversal, route handler abuse, and framework version CVEs are all .NET-specific classes that other hunters frequently overlook.

This skill runs in three phases: **Fingerprint** the stack, **Map** the attack surface, then **Hunt** the .NET-specific bug classes systematically.

---

## Phase 1 — Fingerprinting and Stack Detection

### Step 1.1 — HTTP Header Analysis

Collect headers from the target and extract .NET indicators:

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/dotnet

# Grab headers from all live Tier 1 hosts
while read host; do
  echo "=== $host ==="
  curl -sk -I "$host" | grep -iE \
    '(x-powered-by|x-aspnet|x-aspnetmvc|server|x-frame|x-runtime|set-cookie|x-requestid)'
  echo ""
done < $TARGET_DIR/recon/subdomains/live-hostnames.txt \
  > $TARGET_DIR/recon/dotnet/headers.txt 2>/dev/null

cat $TARGET_DIR/recon/dotnet/headers.txt
```

**.NET indicator headers to flag:**

| Header | What it reveals |
|---|---|
| `X-Powered-By: ASP.NET` | Classic ASP.NET (WebForms or MVC) |
| `X-AspNet-Version: 4.0.x` | Exact .NET CLR version |
| `X-AspNetMvc-Version: 5.x` | ASP.NET MVC version |
| `Server: Microsoft-IIS/10.0` | IIS version — maps to Windows Server release |
| `Set-Cookie: ASP.NET_SessionId=` | Session cookie — WebForms confirmed |
| `Set-Cookie: .ASPXAUTH=` | Forms authentication token |
| `Set-Cookie: __RequestVerificationToken=` | MVC anti-CSRF token present |

### Step 1.2 — Extension and Route Fingerprinting

```bash
# Check for .NET-specific file extensions in URL recon
grep -iE '\.(aspx|ashx|asmx|axd|svc|cshtml|vbhtml|aspx\.cs|dll)' \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/js/endpoints.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/dotnet/dotnet-endpoints.txt

echo "[*] .NET-specific endpoints found:"
cat $TARGET_DIR/recon/dotnet/dotnet-endpoints.txt
```

### Step 1.3 — Error Page Fingerprinting

Force error responses to extract version and stack information:

```bash
# Send malformed requests to trigger verbose error pages
for host in $(cat $TARGET_DIR/recon/subdomains/live-hostnames.txt | head -10); do
  echo "=== $host ==="
  # Invalid route
  curl -sk "$host/this-path-does-not-exist-$(date +%s)" | \
    grep -iE '(asp\.net|version|stack trace|system\.web|microsoft\.net|runtime|iis|at [A-Z][a-z]+\.)' | \
    head -20
  # Malformed request
  curl -sk "$host/%3fid=1'" | \
    grep -iE '(sql|exception|error|stack|version)' | head -10
  echo ""
done > $TARGET_DIR/recon/dotnet/error-pages.txt 2>/dev/null

cat $TARGET_DIR/recon/dotnet/error-pages.txt
```

**If a verbose stack trace is returned:** This is itself a reportable finding (information disclosure). Document it immediately as a Lead with the full stack trace.

### Step 1.4 — Framework Classification

Based on Phases 1.1–1.3, classify the target:

| Framework | Key Indicators | Attack Priority |
|---|---|---|
| **ASP.NET WebForms** | `.aspx` extensions, `__VIEWSTATE` param, `ASP.NET_SessionId` cookie | ViewState deserialization, padding oracle, event validation bypass |
| **ASP.NET MVC (4/5)** | `X-AspNetMvc-Version`, `/Home/Index` routes, `__RequestVerificationToken` | Route enumeration, AntiForgery bypass, parameter tampering |
| **ASP.NET Core** | No `X-AspNet-Version`, `Set-Cookie: .AspNetCore.`, Kestrel or IIS headers | JWT/cookie forgery, endpoint routing quirks, middleware bypass |
| **WCF / ASMX** | `.svc` or `.asmx` extensions, SOAP responses | XXE in SOAP, insecure deserialization, unauthenticated WSDL |
| **IIS + Classic ASP** | `.asp` extensions, `Server: Microsoft-IIS` without ASP.NET header | Path traversal, short filename disclosure, PUT method enabled |

Save classification:
```bash
echo "Framework: [CLASSIFICATION]" > $TARGET_DIR/recon/dotnet/classification.txt
echo "IIS Version: [VERSION]" >> $TARGET_DIR/recon/dotnet/classification.txt
echo ".NET Version: [VERSION]" >> $TARGET_DIR/recon/dotnet/classification.txt
```

---

## Phase 2 — .NET Attack Surface Mapping

### Step 2.1 — ViewState Discovery (WebForms only)

```bash
# Find all pages with __VIEWSTATE parameters
while read url; do
  response=$(curl -sk "$url")
  if echo "$response" | grep -q '__VIEWSTATE'; then
    echo "[VIEWSTATE] $url"
    # Extract ViewState value
    echo "$response" | grep -oP '(?<=__VIEWSTATE" value=")[^"]+' | head -1
  fi
done < $TARGET_DIR/recon/dotnet/dotnet-endpoints.txt \
  > $TARGET_DIR/recon/dotnet/viewstate-pages.txt

echo "[*] Pages with ViewState:"
cat $TARGET_DIR/recon/dotnet/viewstate-pages.txt
```

### Step 2.2 — Handler and Service Endpoint Discovery

```bash
mkdir -p $TARGET_DIR/recon/dotnet

# Common .NET handler and service paths
HANDLERS=(
  "/elmah.axd" "/trace.axd" "/scriptresource.axd" "/webresource.axd"
  "/api/values" "/api/health" "/api/swagger" "/swagger/ui"
  "/_blazor" "/signalr" "/signalr/negotiate" "/hubs"
  "/Service.svc" "/Service.asmx" "/api.asmx"
  "/admin" "/umbraco" "/sitefinity" "/sitecore"
  "/Telerik.Web.UI.WebResource.axd"
)

for host in $(head -5 $TARGET_DIR/recon/subdomains/live-hostnames.txt); do
  for path in "${HANDLERS[@]}"; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$host$path")
    if [[ "$status" =~ ^(200|301|302|401|403)$ ]]; then
      echo "[$status] https://$host$path"
    fi
  done
done > $TARGET_DIR/recon/dotnet/handlers.txt

echo "[*] Live .NET handlers/services:"
cat $TARGET_DIR/recon/dotnet/handlers.txt
```

**High-priority finds:**
- `/elmah.axd` — Error logging handler. If accessible without auth: critical information disclosure (stack traces, SQL queries, internal paths)
- `/trace.axd` — ASP.NET trace viewer. Full request/response history. Critical if accessible
- `/Telerik.Web.UI.WebResource.axd` — Known vulnerable Telerik UI handler (CVE-2017-9248, CVE-2019-18935 — RCE)
- `/signalr` or `/hubs` — WebSocket endpoints, potential for auth bypass

### Step 2.3 — IIS-Specific Path Checks

```bash
for host in $(head -5 $TARGET_DIR/recon/subdomains/live-hostnames.txt); do
  echo "=== $host ==="

  # IIS short filename disclosure (8.3 filenames)
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$host/*~1*/a.aspx" --max-time 5)
  echo "Short filename probe: $status"

  # IIS tilde enumeration indicator
  valid=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$host/a*~1*/.aspx" --max-time 5)
  invalid=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$host/zzzzzz~1*/.aspx" --max-time 5)
  echo "Tilde enum (valid/invalid): $valid / $invalid"
  if [ "$valid" != "$invalid" ]; then
    echo "[!] TILDE ENUMERATION LIKELY POSSIBLE on $host"
  fi

  # HTTP methods allowed
  echo "Allowed methods:"
  curl -sk -X OPTIONS "https://$host/" -I | grep -i allow

done > $TARGET_DIR/recon/dotnet/iis-checks.txt

cat $TARGET_DIR/recon/dotnet/iis-checks.txt
```

---

## Phase 3 — .NET Vulnerability Hunting

### Step 3.1 — ViewState MAC Disabled Check

If ViewState pages were found in Step 2.1, test for MAC validation disabled:

```bash
# Get a page with ViewState
PAGE_URL="[URL from viewstate-pages.txt]"

# Capture baseline ViewState
curl -sk "$PAGE_URL" -c $TARGET_DIR/recon/dotnet/cookies.txt \
  -o $TARGET_DIR/recon/dotnet/baseline.html

# Extract ViewState
VIEWSTATE=$(grep -oP '(?<=__VIEWSTATE" value=")[^"]+' \
  $TARGET_DIR/recon/dotnet/baseline.html | head -1)

echo "ViewState (first 100 chars): ${VIEWSTATE:0:100}"
echo "ViewState length: ${#VIEWSTATE}"

# Decode and inspect structure
echo "$VIEWSTATE" | base64 -d 2>/dev/null | xxd | head -20
```

**Analysis:**
- If ViewState decodes to readable serialized data without a trailing HMAC signature → **MAC validation disabled** → ViewState deserialization attack possible
- If the last ~20 bytes appear to be a hash (non-printable binary) → MAC enabled → requires machine key leak to exploit
- Use [ysoserial.net](https://github.com/pwntester/ysoserial.net) to generate payloads if MAC is disabled or key is known

**If MAC disabled, document as Finding immediately.** Deserialization RCE potential on unpatched .NET versions.

### Step 3.2 — ViewState Generator / Machine Key Exposure

```bash
# Check for web.config exposure (common misconfig on IIS)
for host in $(head -5 $TARGET_DIR/recon/subdomains/live-hostnames.txt); do
  for path in "/web.config" "/Web.config" "/app.config" "/appsettings.json" \
               "/appsettings.Development.json" "/appsettings.Production.json" \
               "/.env" "/global.asax" "/packages.config"; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$host$path" --max-time 5)
    if [ "$status" = "200" ]; then
      echo "[!] EXPOSED: https://$host$path"
      curl -sk "https://$host$path" | head -50
    fi
  done
done
```

**If `web.config` is accessible:** Extract `machineKey` (validationKey + decryptionKey). These keys enable ViewState forgery and .ASPXAUTH cookie forgery. Critical severity — document as Finding immediately with the keys redacted in notes.

### Step 3.3 — Padding Oracle Detection

ASP.NET WebForms apps on older .NET versions may be vulnerable to POET (Padding Oracle Exploit Tool):

```bash
# Check for Oracle-triggerable encrypted parameters
# Look for encrypted params in URLs and cookies
curl -sk "$PAGE_URL" -v 2>&1 | grep -iE '(set-cookie|location)' | \
  grep -iE '([A-Za-z0-9+/]{20,}={0,2})'

# Tamper with .ASPXAUTH cookie to check for padding oracle response differences
# Replace last byte of cookie and observe 500 vs 200/redirect behavior
ORIG_COOKIE=$(curl -sk -I "$PAGE_URL" | grep -oP '(?<=\.ASPXAUTH=)[^;]+')
if [ -n "$ORIG_COOKIE" ]; then
  echo "[*] .ASPXAUTH cookie found: ${ORIG_COOKIE:0:20}..."
  echo "[*] Manual test: tamper last byte and observe response code difference"
  echo "    500 on tamper = padding oracle likely present"
fi
```

### Step 3.4 — Telerik UI Vulnerability Check

If `/Telerik.Web.UI.WebResource.axd` was found in Step 2.2:

```bash
TELERIK_URL="https://$TARGET_DOMAIN/Telerik.Web.UI.WebResource.axd"

# CVE-2017-9248: Cryptographic weakness in Telerik.Web.UI.DialogHandler
status=$(curl -sk -o /dev/null -w "%{http_code}" \
  "$TELERIK_URL?type=rau" --max-time 10)
echo "RAU endpoint status: $status"

# Check for DialogHandler
status2=$(curl -sk -o /dev/null -w "%{http_code}" \
  "${TELERIK_URL}?type=rau&rauPostData=AAAABQAAABBq" --max-time 10)
echo "DialogHandler probe: $status2"

if [[ "$status" = "200" || "$status2" != "404" ]]; then
  echo "[!] Telerik handler accessible — test for CVE-2017-9248 and CVE-2019-18935"
  echo "[!] If exploitable: unauthenticated file upload / RCE possible"
fi
```

### Step 3.5 — ELMAH and Trace Handler Exploitation

If `/elmah.axd` or `/trace.axd` were found accessible in Step 2.2:

```bash
# Pull ELMAH error log — may contain SQL queries, stack traces, internal paths, credentials
curl -sk "https://$TARGET_DOMAIN/elmah.axd" | \
  grep -iE '(password|pwd|secret|token|connectionstring|sql|select|insert|exception|stack)' | \
  head -50 > $TARGET_DIR/recon/dotnet/elmah-output.txt

if [ -s $TARGET_DIR/recon/dotnet/elmah-output.txt ]; then
  echo "[!] ELMAH data extracted — reviewing for sensitive content:"
  cat $TARGET_DIR/recon/dotnet/elmah-output.txt
fi

# Pull trace.axd — full request/response history
curl -sk "https://$TARGET_DOMAIN/trace.axd" | \
  grep -iE '(authorization|cookie|password|token|session)' | head -30
```

### Step 3.6 — ASP.NET Core Endpoint Routing Bypass

For ASP.NET Core targets:

```bash
# Test for route normalization bypass (uppercase/lowercase inconsistency)
for path in $(grep -iE '/(api|v[0-9]+)/' $TARGET_DIR/recon/api/all-endpoints.txt | head -20); do
  clean_path=$(echo "$path" | sed 's|https://[^/]*||')
  upper_path=$(echo "$clean_path" | tr '[:lower:]' '[:upper:]')

  orig=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$TARGET_DOMAIN$clean_path" --max-time 5)
  upper=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$TARGET_DOMAIN$upper_path" --max-time 5)

  if [ "$orig" != "$upper" ] && [ "$upper" != "404" ]; then
    echo "[!] Route normalization discrepancy: $clean_path ($orig) vs uppercase ($upper)"
  fi
done

# Test for middleware bypass via double-encoding or path traversal
for path in $(head -10 $TARGET_DIR/recon/dotnet/dotnet-endpoints.txt); do
  clean=$(echo "$path" | sed 's|https://[^/]*||')
  encoded=$(echo "$clean" | sed 's|/|%2F|g')
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$TARGET_DOMAIN$encoded" --max-time 5)
  echo "$clean → encoded: $status"
done
```

### Step 3.7 — .ASPXAUTH Cookie Forgery (if machineKey known)

If `web.config` was found and contains machineKey values:

```
Do not attempt automated forgery during recon. Document the key exposure as a Finding.
Provide the following manual verification steps in the PoC:

1. Confirm machineKey values (validationKey + decryptionKey + algorithms)
2. Use Katana/Burp with the .NET MachineKey plugin to forge a .ASPXAUTH cookie
   for a known admin username (e.g. "administrator" or "admin")
3. Replace the .ASPXAUTH cookie in a browser session
4. Confirm authentication as the forged user
5. Screenshot the admin panel or privileged functionality

Impact: Authentication bypass / account takeover for any user including admins.
Severity: Critical
```

---

## Phase 4 — .NET Hypothesis Generation

After completing Phases 1–3, generate .NET-specific hypotheses based on findings. Apply the same 4-question filter from `/hypothesis-agent`:

**High-value .NET hypothesis classes to consider:**

1. **ViewState deserialization chain** — MAC disabled or key known + unpatched .NET version = RCE via ysoserial.net payloads targeting ObjectStateFormatter
2. **Telerik file upload without auth** — RAU endpoint accessible + vulnerable version = unauthenticated file write to web root
3. **ELMAH credential harvesting** — connection strings in error logs = direct database access
4. **machineKey-based .ASPXAUTH forgery** — key in web.config + known admin username = authentication bypass
5. **IIS short filename enumeration** — tilde vulnerability present = enumerate hidden files and directories, potentially exposing backup files, config files
6. **SOAP/WCF XXE** — ASMX or SVC endpoint accepts XML input without XXE protection = out-of-band data exfiltration
7. **Route constraint bypass** — ASP.NET Core route normalization inconsistency = WAF or auth middleware bypass on protected endpoints
8. **Insecure deserialization via JSON.NET** — TypeNameHandling enabled in JSON API = RCE via gadget chains

---

## Output Summary

All output files written to `$TARGET_DIR/recon/dotnet/`:

| File | Contents |
|---|---|
| `headers.txt` | HTTP headers from all live hosts, .NET indicators highlighted |
| `dotnet-endpoints.txt` | .NET-specific endpoints (.aspx, .ashx, .asmx, .svc, .axd) |
| `error-pages.txt` | Error page responses, stack traces if verbose mode enabled |
| `classification.txt` | Framework, IIS, and .NET version classification |
| `viewstate-pages.txt` | Pages with `__VIEWSTATE` parameters and raw values |
| `handlers.txt` | Live .NET handler endpoints with status codes |
| `iis-checks.txt` | IIS tilde enumeration, short filename, HTTP method results |
| `elmah-output.txt` | ELMAH error log contents if accessible |

---

## Severity Reference

| Finding | Severity |
|---|---|
| ViewState MAC disabled (unpatched .NET) | Critical |
| machineKey exposed in web.config | Critical |
| Telerik CVE-2019-18935 RCE | Critical |
| ELMAH accessible with connection strings / credentials | Critical |
| .ASPXAUTH forgery via known machineKey | Critical |
| trace.axd accessible (full request history) | High |
| ELMAH accessible (stack traces, paths only) | Medium |
| Verbose error pages with stack traces | Low–Medium |
| IIS tilde enumeration enabled | Low |
| HTTP methods (PUT/DELETE) enabled unnecessarily | Low |

---

## Guiding Principles

- **Version matters more in .NET than in most stacks.** ViewState deserialization, Telerik RCE, and padding oracles are all version-gated. Always establish the .NET and IIS version before testing.
- **A visible ViewState is not automatically a finding.** MAC enabled + no key leak = not exploitable. Confirm MAC status before logging as a lead.
- **ELMAH and trace.axd are instant High/Critical if accessible.** They exist to log everything including credentials. If you find them open, document and stop — don't spend time enumerating further before logging.
- **machineKey exposure is Critical regardless of whether you exploit it.** The key is the vulnerability. Document it, redact it in notes, do not use it beyond confirming it decrypts a cookie.
- **Never attempt actual deserialization RCE payloads against production.** Generate the PoC payload structure in notes and describe what it would do. Actual execution is destructive and out of scope.
- **Run /triager before submitting any .NET finding.** Telerik and ViewState findings are high-noise — confirm exploitability before claiming impact.

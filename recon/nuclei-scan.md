---
name: nuclei-scan
description: Run targeted nuclei scans against the live host inventory and API surface produced by earlier recon steps. Covers CVE detection, technology fingerprinting, exposure/misconfiguration discovery, and secret scanning. Run after api-surface and before hypothesis-agent so findings enrich the hypothesis pool. Trigger on phrases like "run nuclei", "nuclei scan", "CVE scan", "scan for known vulnerabilities", or automatically as Step 4 in the recon pipeline.
---

# Nuclei Scan Workflow

Nuclei bridges automated CVE/exposure detection and manual hypothesis-driven testing. It runs against the live host list and API surface map already produced by earlier recon steps — giving hypothesis-agent a pre-populated set of confirmed or likely findings before any manual testing begins.

**Prerequisites:** `subdomain-enum` and `api-surface` must have been run. This workflow consumes their output directly.

---

## Step 1 — Verify Prerequisites and Setup

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/nuclei

# Verify nuclei is available
which nuclei || { echo "[!] nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"; exit 1; }
nuclei -version

# Verify input files exist
[ -f $TARGET_DIR/recon/live-hosts.txt ] || { echo "[!] live-hosts.txt missing — run subdomain-enum first"; exit 1; }
[ -f $TARGET_DIR/recon/api/all-endpoints.txt ] && echo "[*] API surface map found" || echo "[*] API surface map not found — nuclei will scan hosts only"

# Update nuclei templates
nuclei -update-templates -silent
echo "[*] Templates updated: $(nuclei -tl 2>/dev/null | wc -l) total"
```

---

## Step 2 — Technology Fingerprinting (Always Run First)

Tech detection runs before vulnerability scanning so the results inform which CVE/exploit templates to prioritize.

```bash
echo "[*] Phase 1: Technology fingerprinting"

nuclei \
  -l $TARGET_DIR/recon/live-hosts.txt \
  -t technologies/ \
  -severity info \
  -c 25 \
  -timeout 10 \
  -silent \
  -json \
  -o $TARGET_DIR/recon/nuclei/tech-fingerprint.json 2>/dev/null

# Human-readable summary
cat $TARGET_DIR/recon/nuclei/tech-fingerprint.json 2>/dev/null | \
  python3 -c "
import sys, json
techs = {}
for line in sys.stdin:
    try:
        r = json.loads(line.strip())
        name = r.get('info',{}).get('name','?')
        host = r.get('host','?')
        techs.setdefault(name, []).append(host)
    except: pass
for tech, hosts in sorted(techs.items()):
    print(f'  {tech}: {len(hosts)} host(s)')
" | tee $TARGET_DIR/recon/nuclei/tech-summary.txt

echo "[*] Unique technologies detected: $(wc -l < $TARGET_DIR/recon/nuclei/tech-summary.txt)"
```

**After this step:** Review `tech-summary.txt`. This directly feeds CVE template selection in Step 3. Note any of:
- WordPress, Drupal, Joomla (CMS vulns)
- Apache, Nginx, IIS (web server CVEs)
- Spring, Rails, Laravel, Django (framework-specific bugs)
- Elasticsearch, Redis, Memcached (exposed services)
- Jenkins, Grafana, Kibana, GitLab (admin panels)
- .NET / ASP.NET (use `/dotnet-hunter` after scan)

---

## Step 3 — CVE Template Scan (Targeted by Tech Stack)

Run CVE templates scoped to the detected tech stack. Do not blast all CVE templates blindly — it wastes time and increases noise.

```bash
echo "[*] Phase 2: CVE scanning (tech-targeted)"

# Read detected tech stack from summary
TECH_STACK=$(cat $TARGET_DIR/recon/nuclei/tech-summary.txt | awk '{print $1}' | tr '[:upper:]' '[:lower:]' | tr '\n' ',' | sed 's/,$//')
echo "[*] Detected stack: $TECH_STACK"

# Run CVE templates — nuclei auto-filters by what's relevant when tags are specified
nuclei \
  -l $TARGET_DIR/recon/live-hosts.txt \
  -t cves/ \
  -severity critical,high,medium \
  -c 20 \
  -timeout 15 \
  -rate-limit 50 \
  -silent \
  -json \
  -o $TARGET_DIR/recon/nuclei/cves.json 2>/dev/null

# Count and display
CVE_COUNT=$(wc -l < $TARGET_DIR/recon/nuclei/cves.json 2>/dev/null || echo 0)
echo "[*] CVE matches: $CVE_COUNT"

if [ "$CVE_COUNT" -gt 0 ]; then
  echo "[!] CVE FINDINGS:"
  cat $TARGET_DIR/recon/nuclei/cves.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line.strip())
        sev  = r.get('info',{}).get('severity','?').upper()
        name = r.get('info',{}).get('name','?')
        host = r.get('host','?')
        cve  = r.get('info',{}).get('classification',{}).get('cve-id',[''])[0]
        print(f'  [{sev}] {cve} — {name} @ {host}')
    except: pass
" | sort
fi
```

**CVE finding escalation rule:** A nuclei CVE match is a **Lead**, not a Finding. Verify the vulnerable version is actually running before escalating to a Finding. Use `/cve-vuln-check` for version confirmation and PoC.

---

## Step 4 — Exposure and Misconfiguration Scan

Catches exposed admin panels, debug endpoints, cloud metadata, default credentials, and sensitive file exposure.

```bash
echo "[*] Phase 3: Exposures and misconfigurations"

nuclei \
  -l $TARGET_DIR/recon/live-hosts.txt \
  -t exposures/ \
  -t misconfiguration/ \
  -t default-logins/ \
  -t exposed-panels/ \
  -severity critical,high,medium,low \
  -c 20 \
  -timeout 10 \
  -rate-limit 60 \
  -silent \
  -json \
  -o $TARGET_DIR/recon/nuclei/exposures.json 2>/dev/null

EXPO_COUNT=$(wc -l < $TARGET_DIR/recon/nuclei/exposures.json 2>/dev/null || echo 0)
echo "[*] Exposure/misconfig matches: $EXPO_COUNT"

if [ "$EXPO_COUNT" -gt 0 ]; then
  echo "[!] EXPOSURE FINDINGS:"
  cat $TARGET_DIR/recon/nuclei/exposures.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line.strip())
        sev  = r.get('info',{}).get('severity','?').upper()
        name = r.get('info',{}).get('name','?')
        host = r.get('host','?')
        url  = r.get('matched-at', host)
        print(f'  [{sev}] {name} @ {url}')
    except: pass
" | sort
fi
```

**High-value exposure signals to escalate immediately:**
- Exposed `.git` directory → source code disclosure, secret extraction
- `.env` file accessible → credentials, API keys, DB strings
- AWS metadata endpoint reachable (`169.254.169.254`) → cloud SSRF
- Admin panels with default credentials → full compromise
- Kibana/Elasticsearch open → `/elasticsearch-findings` workflow
- Jenkins open → RCE surface → `/cve-vuln-check`

---

## Step 5 — Secret and Token Scanning (API Surface Endpoints)

Run secret-detection templates against the API surface — catches API keys, tokens, and credentials leaked in HTTP responses.

```bash
echo "[*] Phase 4: Secret scanning against API surface"

if [ -f $TARGET_DIR/recon/api/all-endpoints.txt ]; then
  # Build full URLs from endpoints (prepend base domain)
  cat $TARGET_DIR/recon/api/all-endpoints.txt | \
    grep -E '^/' | \
    sed "s|^|https://$TARGET_DOMAIN|" | \
    head -500 \
    > $TARGET_DIR/recon/nuclei/api-urls-for-scan.txt

  nuclei \
    -l $TARGET_DIR/recon/nuclei/api-urls-for-scan.txt \
    -t exposures/tokens/ \
    -t exposures/keys/ \
    -severity critical,high,medium \
    -c 15 \
    -timeout 10 \
    -rate-limit 30 \
    -silent \
    -json \
    -o $TARGET_DIR/recon/nuclei/secrets.json 2>/dev/null

  SECRET_COUNT=$(wc -l < $TARGET_DIR/recon/nuclei/secrets.json 2>/dev/null || echo 0)
  echo "[*] Secret/token matches: $SECRET_COUNT"

  if [ "$SECRET_COUNT" -gt 0 ]; then
    echo "[!] SECRETS FOUND:"
    cat $TARGET_DIR/recon/nuclei/secrets.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line.strip())
        name = r.get('info',{}).get('name','?')
        url  = r.get('matched-at','?')
        print(f'  [SECRET] {name} @ {url}')
    except: pass
"
  fi
else
  echo "[*] No API surface map found — skipping secret scan against endpoints"
fi
```

---

## Step 6 — Subdomain Takeover Templates

Nuclei has dedicated takeover detection templates that complement the manual `/subdomain-takeover` workflow.

```bash
echo "[*] Phase 5: Subdomain takeover templates"

nuclei \
  -l $TARGET_DIR/recon/live-hosts.txt \
  -t takeovers/ \
  -severity critical,high \
  -c 30 \
  -timeout 10 \
  -silent \
  -json \
  -o $TARGET_DIR/recon/nuclei/takeovers.json 2>/dev/null

TAKE_COUNT=$(wc -l < $TARGET_DIR/recon/nuclei/takeovers.json 2>/dev/null || echo 0)
echo "[*] Potential takeovers: $TAKE_COUNT"

if [ "$TAKE_COUNT" -gt 0 ]; then
  echo "[!] TAKEOVER CANDIDATES — verify with /subdomain-takeover:"
  cat $TARGET_DIR/recon/nuclei/takeovers.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line.strip())
        name = r.get('info',{}).get('name','?')
        host = r.get('host','?')
        print(f'  [TAKEOVER] {name} @ {host}')
    except: pass
"
fi
```

---

## Step 7 — Consolidate and Score

```bash
echo "[*] Consolidating nuclei output"

# Merge all JSON output
cat \
  $TARGET_DIR/recon/nuclei/cves.json \
  $TARGET_DIR/recon/nuclei/exposures.json \
  $TARGET_DIR/recon/nuclei/secrets.json \
  $TARGET_DIR/recon/nuclei/takeovers.json \
  2>/dev/null > $TARGET_DIR/recon/nuclei/all-findings.json

TOTAL=$(wc -l < $TARGET_DIR/recon/nuclei/all-findings.json 2>/dev/null || echo 0)
echo ""
echo "========================================="
echo "  NUCLEI SCAN SUMMARY"
echo "========================================="
echo "  CVE matches:          $(wc -l < $TARGET_DIR/recon/nuclei/cves.json 2>/dev/null || echo 0)"
echo "  Exposures/miscfgs:    $(wc -l < $TARGET_DIR/recon/nuclei/exposures.json 2>/dev/null || echo 0)"
echo "  Secrets/tokens:       $(wc -l < $TARGET_DIR/recon/nuclei/secrets.json 2>/dev/null || echo 0)"
echo "  Takeover candidates:  $(wc -l < $TARGET_DIR/recon/nuclei/takeovers.json 2>/dev/null || echo 0)"
echo "  TOTAL:                $TOTAL"
echo "========================================="
echo ""

# Extract critical/high items as prioritized leads
cat $TARGET_DIR/recon/nuclei/all-findings.json | python3 -c "
import sys, json
findings = []
for line in sys.stdin:
    try:
        r = json.loads(line.strip())
        sev = r.get('info',{}).get('severity','')
        if sev in ('critical','high'):
            findings.append(r)
    except: pass

print(f'[!] Critical/High priority leads: {len(findings)}')
for r in findings:
    sev  = r.get('info',{}).get('severity','?').upper()
    name = r.get('info',{}).get('name','?')
    url  = r.get('matched-at', r.get('host','?'))
    print(f'  [{sev}] {name} @ {url}')
" | tee $TARGET_DIR/recon/nuclei/priority-leads.txt
```

---

## Step 8 — Feed Into hypothesis-agent

With nuclei output complete, run hypothesis generation with the enriched context:

```
/hypothesis-agent $TARGET_DIR
```

The hypothesis agent should treat nuclei findings as:
- **Critical/High CVE matches** → immediate `/cve-vuln-check` to confirm version and PoC
- **Exposed admin panels** → manual auth testing, default credentials, IDOR surface
- **Misconfiguration findings** → verify exploitability, build impact chain before reporting
- **Secrets in responses** → extract, test for scope of access, escalate if valid
- **Takeover candidates** → hand off to `/subdomain-takeover` for verification

---

## Rate Limiting and Scope Discipline

- **Always use `-rate-limit`** — default nuclei rate is aggressive and will trigger WAF blocks or program violations.
- **Stick to in-scope hosts only** — feed only the `live-hosts.txt` produced by subdomain-enum, which has already been filtered through `/scope-checker`.
- **Do not run fuzzing templates** (`-t fuzzing/`) without explicit instruction — these are active exploitation attempts, not passive detection.
- **Do not run `network/` templates** against cloud-hosted targets — port scanning outside a browser is out of scope on most programs.
- If a WAF starts blocking (429/403 flood), stop the scan, reduce `-rate-limit` to 10, and resume.

---

## Output Files

| File | Contents |
|---|---|
| `tech-fingerprint.json` | Full technology detection results (raw JSON) |
| `tech-summary.txt` | Human-readable tech stack per host |
| `cves.json` | CVE template matches |
| `exposures.json` | Exposure and misconfiguration findings |
| `secrets.json` | Secret/token findings from API surface |
| `takeovers.json` | Subdomain takeover candidates |
| `all-findings.json` | Merged output of all phases |
| `priority-leads.txt` | Critical/High items extracted for immediate action |

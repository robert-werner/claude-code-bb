---
name: subdomain-enum
description: Execute a comprehensive subdomain enumeration workflow combining passive and active discovery, DNS resolution, and HTTP probing to build a prioritized list of live in-scope subdomains. Run this at the start of any engagement with a wildcard or multi-domain scope. Trigger on phrases like "enumerate subdomains", "subdomain recon", "find subdomains", "map the attack surface".
---

# Subdomain Enumeration Workflow

Subdomain enumeration is the foundation of every engagement. A missed subdomain is a missed finding. This workflow runs multiple tools in parallel, deduplicates results, resolves live hosts, and produces a prioritized hit list for further recon.

---

## Prerequisites

Verify tools are available:
```bash
which /home/kali/go/bin/subfinder && echo "subfinder OK"
which /home/kali/go/bin/amass && echo "amass OK" || echo "amass not found — skip"
which /home/kali/go/bin/dnsx && echo "dnsx OK"
which /home/kali/go/bin/httpx && echo "httpx OK"
which /home/kali/go/bin/waybackurls && echo "waybackurls OK"
```

---

## Step 1 — Passive Discovery (run in parallel)

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/subdomains

# subfinder — certificate transparency + passive sources
/home/kali/go/bin/subfinder -d $TARGET_DOMAIN -silent \
  -o $TARGET_DIR/recon/subdomains/subfinder.txt 2>/dev/null &

# waybackurls — extract subdomains from Wayback Machine
/home/kali/go/bin/waybackurls $TARGET_DOMAIN 2>/dev/null | \
  grep -oE '[a-zA-Z0-9._-]+\.'$TARGET_DOMAIN | \
  sort -u > $TARGET_DIR/recon/subdomains/wayback-subs.txt &

# Certificate transparency via crt.sh (passive, no active requests to target)
curl -sk "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" 2>/dev/null | \
  python3 -c "import sys,json; \
    [print(e.get('name_value','').replace('*.','')) \
    for e in json.load(sys.stdin) if e.get('name_value')]" | \
  grep -E '^[a-zA-Z0-9._-]+$' | sort -u \
  > $TARGET_DIR/recon/subdomains/crtsh.txt &

wait
echo "[*] Passive discovery complete"
```

---

## Step 2 — Merge and Deduplicate

```bash
cat $TARGET_DIR/recon/subdomains/*.txt | \
  grep -E "\.$TARGET_DOMAIN$|^$TARGET_DOMAIN$" | \
  sort -u > $TARGET_DIR/recon/subdomains/all-subs-raw.txt

echo "[*] Total unique subdomains (pre-resolution): $(wc -l < $TARGET_DIR/recon/subdomains/all-subs-raw.txt)"
```

---

## Step 3 — DNS Resolution

```bash
# Resolve only subdomains that have valid DNS records
/home/kali/go/bin/dnsx -l $TARGET_DIR/recon/subdomains/all-subs-raw.txt \
  -silent -a -resp \
  -o $TARGET_DIR/recon/subdomains/resolved.txt 2>/dev/null

echo "[*] Resolved: $(wc -l < $TARGET_DIR/recon/subdomains/resolved.txt) subdomains"

# Extract just the hostnames
awk '{print $1}' $TARGET_DIR/recon/subdomains/resolved.txt | sort -u \
  > $TARGET_DIR/recon/subdomains/resolved-hosts.txt
```

---

## Step 4 — HTTP Probing

```bash
# Probe for live HTTP/HTTPS services
/home/kali/go/bin/httpx -l $TARGET_DIR/recon/subdomains/resolved-hosts.txt \
  -silent -status-code -title -tech-detect -follow-redirects \
  -timeout 10 \
  -o $TARGET_DIR/recon/subdomains/live-hosts.txt 2>/dev/null

echo "[*] Live HTTP hosts: $(wc -l < $TARGET_DIR/recon/subdomains/live-hosts.txt)"
```

---

## Step 5 — Scope Filter

```bash
# Run scope-checker on all discovered subdomains
# Flag any that are out-of-scope before proceeding
echo "[*] Filtering against program scope..."

# Extract hostnames only from live hosts output
awk '{print $1}' $TARGET_DIR/recon/subdomains/live-hosts.txt | \
  sed 's|https\?://||' | cut -d'/' -f1 \
  > $TARGET_DIR/recon/subdomains/live-hostnames.txt
```

Run `/scope-checker` on any subdomains that don't obviously match the primary target domain before active testing.

---

## Step 6 — Priority Scoring

After probing, prioritize live hosts for further recon based on these signals:

**Tier 1 — Test immediately:**
- Login pages, admin panels, API gateways (`api.`, `admin.`, `internal.`, `staging.`, `dev.`)
- Subdomains with non-standard ports
- Subdomains returning 401/403 (auth exists, worth probing)
- Subdomains with unique tech stacks (not the same as the main app)

**Tier 2 — Test after Tier 1:**
- Standard subdomains with web apps
- Redirect chains leading to interesting destinations

**Tier 3 — Note but deprioritize:**
- Static asset CDNs, marketing pages, documentation
- Subdomains returning generic 404s with no application logic

```bash
# Quick filter for high-priority subdomains
grep -iE '(admin|internal|staging|dev|api|auth|login|portal|dashboard|corp|vpn|mail|jenkins|jira|confluence|gitlab|grafana|kibana)' \
  $TARGET_DIR/recon/subdomains/live-hosts.txt \
  > $TARGET_DIR/recon/subdomains/priority-tier1.txt

echo "[!] Tier 1 priority targets:"
cat $TARGET_DIR/recon/subdomains/priority-tier1.txt
```

---

## Step 7 — Subdomain Takeover Check

```bash
# Check for dangling DNS records (subdomain takeover candidates)
# Look for CNAMEs pointing to unclaimed third-party services
/home/kali/go/bin/dnsx -l $TARGET_DIR/recon/subdomains/resolved-hosts.txt \
  -silent -cname -resp 2>/dev/null | \
  grep -iE '(github\.io|s3\.amazonaws|cloudfront|azurewebsites|herokuapp|fastly|pantheonsite|ghost\.io|helpscoutdocs|cargo\.site|tumblr)' \
  > $TARGET_DIR/recon/subdomains/takeover-candidates.txt

if [ -s $TARGET_DIR/recon/subdomains/takeover-candidates.txt ]; then
  echo "[!] POTENTIAL SUBDOMAIN TAKEOVER CANDIDATES:"
  cat $TARGET_DIR/recon/subdomains/takeover-candidates.txt
  echo "[*] Saved to takeover-candidates.txt — verify manually before reporting"
fi
```

---

## Output Summary

| File | Contents |
|---|---|
| `all-subs-raw.txt` | All discovered subdomains, unresolved |
| `resolved.txt` | DNS-resolved subdomains with IPs |
| `live-hosts.txt` | HTTP-probed live hosts with status/title/tech |
| `priority-tier1.txt` | High-value subdomains for immediate attention |
| `takeover-candidates.txt` | Potential subdomain takeover targets |

---
name: js-analysis
description: Extract intelligence from JavaScript bundles — endpoints, API keys, secrets, internal routes, auth tokens, and hidden functionality. Run this workflow after initial subdomain/URL recon to mine JS files for targets that other hunters miss. Trigger when URL recon is complete and JS files are available, or on phrases like "analyze JS", "mine JS files", "extract endpoints from JS", "check JS bundles".
---

# JS Analysis Recon Workflow

JavaScript bundles are one of the highest-yield recon surfaces and one of the most underworked. Minified production bundles contain endpoints, auth logic, feature flags, internal API routes, and occasionally credentials — all shipped directly to the attacker's browser.

---

## Step 1 — Collect JS Files

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/js

# Pull all JS URLs from existing URL recon
grep -E '\.js(\?|$)' $TARGET_DIR/recon/urls.txt | sort -u > $TARGET_DIR/recon/js/js-urls.txt

echo "[*] Found $(wc -l < $TARGET_DIR/recon/js/js-urls.txt) JS files"
```

If URL recon hasn't been run yet, run katana first:
```bash
/home/kali/go/bin/katana -u https://$TARGET_DOMAIN -d 3 -jc -ef css,png,jpg,svg \
  -o $TARGET_DIR/recon/js/katana-js.txt 2>/dev/null
grep '\.js' $TARGET_DIR/recon/js/katana-js.txt | sort -u >> $TARGET_DIR/recon/js/js-urls.txt
```

---

## Step 2 — Download JS Files

```bash
mkdir -p $TARGET_DIR/recon/js/files

while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sk "$url" -o "$TARGET_DIR/recon/js/files/$filename"
  echo "$url -> $filename" >> $TARGET_DIR/recon/js/url-map.txt
done < $TARGET_DIR/recon/js/js-urls.txt

echo "[*] Downloaded $(ls $TARGET_DIR/recon/js/files/ | wc -l) JS files"
```

---

## Step 3 — Extract Endpoints

```bash
# Extract URL patterns from JS files
grep -hroE '("|\/)(api|v[0-9]+|graphql|rest|internal|admin|auth|oauth|user|account|payment|webhook)[^"\s,;)]*' \
  $TARGET_DIR/recon/js/files/ | \
  sort -u > $TARGET_DIR/recon/js/endpoints-raw.txt

# Also extract relative paths
grep -hroE '"/[a-zA-Z0-9_/-]{3,50}"' \
  $TARGET_DIR/recon/js/files/ | \
  tr -d '"' | sort -u >> $TARGET_DIR/recon/js/endpoints-raw.txt

# Deduplicate
sort -u $TARGET_DIR/recon/js/endpoints-raw.txt > $TARGET_DIR/recon/js/endpoints.txt
echo "[*] Extracted $(wc -l < $TARGET_DIR/recon/js/endpoints.txt) unique endpoint patterns"
```

---

## Step 4 — Secret Scanning

```bash
# Scan for exposed credentials and keys
grep -hroiE \
  '(api[_-]?key|apikey|secret|token|password|passwd|credential|auth)[[:space:]]*[:=][[:space:]]*["\x27][^"\x27]{8,}["\x27]' \
  $TARGET_DIR/recon/js/files/ | \
  sort -u > $TARGET_DIR/recon/js/secrets-raw.txt

# Scan for common key formats
grep -hroE \
  '(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|Bearer [a-zA-Z0-9._-]{20,}|[0-9a-f]{32})' \
  $TARGET_DIR/recon/js/files/ | \
  sort -u >> $TARGET_DIR/recon/js/secrets-raw.txt

echo "[*] Potential secrets found: $(wc -l < $TARGET_DIR/recon/js/secrets-raw.txt)"
cat $TARGET_DIR/recon/js/secrets-raw.txt
```

**IMPORTANT:** For each potential secret found, verify before reporting:
- Does this key grant access to sensitive operations, or is it a public rate-limit key?
- Is this a public API key for a public-facing service (maps, analytics, CDN)? If yes, likely intentional — do not report as exposed credential without proving unauthorized access
- Test the key's actual capabilities before making any impact claims

---

## Step 5 — Feature Flag and Hidden Functionality Detection

```bash
# Look for feature flags, admin routes, debug endpoints
grep -hroiE \
  '(feature[_-]?flag|beta|internal|debug|admin|staging|canary|rollout)["\x27\s]*[:=]["\x27\s]*[a-zA-Z0-9_-]+' \
  $TARGET_DIR/recon/js/files/ | \
  sort -u > $TARGET_DIR/recon/js/feature-flags.txt

# Look for environment variables leaked into bundles
grep -hroE 'process\.env\.[A-Z_]+' \
  $TARGET_DIR/recon/js/files/ | \
  sort -u > $TARGET_DIR/recon/js/env-vars.txt

echo "[*] Feature flags/env vars:"
cat $TARGET_DIR/recon/js/feature-flags.txt
cat $TARGET_DIR/recon/js/env-vars.txt
```

---

## Step 6 — GraphQL Detection

```bash
# Check for GraphQL queries/mutations/subscriptions in JS
grep -hroiE '(query|mutation|subscription)[[:space:]]+[A-Z][a-zA-Z]+[[:space:]]*[({]' \
  $TARGET_DIR/recon/js/files/ | \
  sort -u > $TARGET_DIR/recon/js/graphql-ops.txt

if [ -s $TARGET_DIR/recon/js/graphql-ops.txt ]; then
  echo "[!] GraphQL operations found — check for introspection and IDOR via node IDs"
  cat $TARGET_DIR/recon/js/graphql-ops.txt
fi
```

---

## Step 7 — Feed Into hypothesis-agent

After completing JS analysis, run `/hypothesis-agent $TARGET_DIR` to generate attack hypotheses based on the extracted endpoints, secrets, and flags. The JS analysis output is often the highest-signal input the hypothesis agent receives.

---

## Output Summary

All output files written to `$TARGET_DIR/recon/js/`:

| File | Contents |
|---|---|
| `js-urls.txt` | All JS file URLs discovered |
| `url-map.txt` | URL-to-filename mapping |
| `endpoints.txt` | Extracted API endpoints and routes |
| `secrets-raw.txt` | Potential credentials and keys |
| `feature-flags.txt` | Feature flags and debug variables |
| `env-vars.txt` | process.env references |
| `graphql-ops.txt` | GraphQL operation names |

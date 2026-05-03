---
name: idor-hunter
description: Systematically hunt for Insecure Direct Object Reference (IDOR) vulnerabilities across an application's API and web surfaces. Use this skill when you have authenticated access to an application and want to map object references, test cross-account access, and validate actual data exposure. Trigger on phrases like "hunt for IDOR", "test object references", "check access controls", "test IDOR", or when recon reveals endpoints with IDs, GUIDs, or user-controlled object references.
---

# IDOR Hunter Skill

You are executing a systematic IDOR hunt. IDOR vulnerabilities are high-yield on Bugcrowd and HackerOne — but only when you can demonstrate actual cross-account data access with a complete PoC. Theoretical access control weaknesses without demonstrated data exposure do not meet the bar.

**Prime directive:** You need two accounts. Account A (attacker) accesses resources belonging to Account B (victim). If you don't have two accounts, stop and flag this to the hunter before proceeding.

---

## Step 1 — Map Object References

From existing recon and traffic analysis, identify all endpoints that contain object identifiers:

```bash
# Pull all URLs with numeric or GUID-style IDs from recon
grep -hE '(/[0-9]+|/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})' \
  ~/bugbounty/$TARGET/recon/urls.txt | sort -u
```

For each endpoint, classify the ID type:

| ID Type | Example | Exploitability |
|---|---|---|
| Sequential integer | `/users/1234` | High — predictable, easy to enumerate |
| Short alphanumeric | `/order/ABC123` | Medium — may be guessable |
| UUID v4 | `/doc/550e8400-...` | Low — unpredictable, but test anyway with known victim UUID |
| Hashed/encoded | `/file/aGVsbG8=` | Decode first, then treat as above |

---

## Step 2 — Account Setup Verification

Before testing, verify two-account setup:

```bash
cat ~/bugbounty/$TARGET/notes/accounts.md
```

Required:
- **Account A (attacker):** active session token / cookie
- **Account B (victim):** account with objects to target (orders, files, messages, profile data)
- **Known victim object IDs:** at least one real ID belonging to Account B

If accounts.md doesn't exist or is incomplete, stop and ask the hunter to set up a second test account.

---

## Step 3 — Baseline Requests

For each target endpoint:

1. Make the request as Account B — capture the full response, note all returned fields
2. Make the same request as Account A with Account B's object ID — compare responses
3. Make the same request unauthenticated — note if auth is enforced at all

Document exact HTTP requests including all headers. Store in:
```bash
mkdir -p ~/bugbounty/$TARGET/recon/idor
cat > ~/bugbounty/$TARGET/recon/idor/[endpoint-name]-baseline.txt
```

---

## Step 4 — Attack Vectors

For each endpoint with an object reference, test these vectors in order:

**Vector 1 — Direct ID substitution**
Replace Account A's ID with Account B's ID. Use Account A's session.

**Vector 2 — HTTP method substitution**
If GET is blocked, try POST, PUT, PATCH with the same ID. Some authorization checks are method-specific.

**Vector 3 — Parameter pollution**
Add a second `id=` or `user_id=` parameter alongside the legitimate one.
`/api/profile?id=[A_id]&id=[B_id]`

**Vector 4 — Nested resource access**
If `/api/users/[B_id]/orders` is protected, try `/api/users/[A_id]/orders?user_id=[B_id]` or `/api/orders?owner=[B_id]`.

**Vector 5 — Indirect reference via related object**
If direct object access is protected, can you reach B's data through a related endpoint? (e.g., access B's invoice via a shared order reference)

**Vector 6 — Batch / bulk endpoints**
Look for `/api/users/bulk`, `/api/export`, or `/api/admin` endpoints that may process multiple IDs with weaker per-object authorization.

**Vector 7 — GraphQL (if applicable)**
Test introspection, then try accessing other users' nodes directly by ID in queries and mutations.

---

## Step 5 — Validate Impact

An IDOR finding is only reportable if you can demonstrate:

1. **Data you should not see is returned** — not a 200 status, but actual B's data in the response
2. **The data is sensitive** — PII, financial data, private messages, authentication tokens, health data
3. **The access is unauthorized** — Account A has no legitimate reason to access B's resource
4. **The chain is reproducible** — exact request, exact response, works independently

If you get a 200 but the response contains only A's data (re-keyed to B's ID), it's not a valid IDOR — it's broken behavior but not exploitable.

---

## Step 6 — Severity Calibration

| Scenario | Severity |
|---|---|
| Read access to another user's PII, financial data, or health data | High |
| Write/delete access to another user's objects | High |
| Read access to non-sensitive profile data (name, public info) | Low / N/A |
| Read access to internal metadata without PII | Informational |
| Unauthenticated access to any sensitive data | Critical (add auth bypass) |

---

## Output Format

For each confirmed IDOR:

### IDOR: [Endpoint]
**Severity:** [Critical / High / Medium / Low]
**Data Exposed:** [Exact fields returned — be specific]
**Attack Vector Used:** [Which of the 7 vectors worked]

**Proof of Concept:**
```
Account A session: [token]
Request: [full HTTP request]
Response: [relevant excerpt showing B's data]
Account B verification: [same request with B's session showing same data]
```

**Impact Statement:**
Complete the sentence: "An attacker can use this to [specific action] against [specific victim] resulting in [specific harm], as demonstrated by [specific evidence]."

Save to:
```bash
cat > ~/bugbounty/$TARGET/findings/idor-[endpoint].md
```

---

## Guiding Principles

- **No PoC = no finding.** A 200 response code is not proof of IDOR. Actual victim data in the response is proof.
- **Sensitive data or it doesn't count.** IDOR on non-sensitive data is almost always Informational or N/A on Bugcrowd.
- **Two accounts are non-negotiable.** Self-referential testing (A accessing A's own resources) is not IDOR testing.
- **Document the exact HTTP exchange.** Triagers will try to reproduce this independently. Give them everything they need.
- **Write and delete IDORs are higher severity than read.** If you find a write vector, confirm it, escalate severity, and stop — don't actually modify victim data.

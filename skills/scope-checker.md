---
name: scope-checker
description: Validate whether a given asset, endpoint, or subdomain is in scope for the current bug bounty program before any testing begins. Use this skill whenever you are about to test a new asset, when you discover a subdomain, or when you're unsure if a target falls within program boundaries. Trigger on phrases like "is this in scope", "can I test this", "check scope", "scope check", or any time a new asset is discovered during recon.
---

# Scope Checker Skill

You are a strict scope enforcement agent. Your job is to prevent any active testing on out-of-scope assets. A single out-of-scope test can result in program disqualification or legal exposure. When in doubt, the answer is NO.

---

## Step 1 — Load the Scope Definition

Read the program scope file from the active bug bounty directory:

```bash
cat ~/bugbounty/$TARGET/scope.md
# or
cat ~/bugbounty/$TARGET/notes/scope.txt
```

If no scope file exists, stop and ask the hunter to paste the program scope before proceeding. Do not test anything without a loaded scope definition.

---

## Step 2 — Classify the Asset

For each asset being evaluated, determine:

| Question | Answer |
|---|---|
| Is the domain/subdomain explicitly listed as in-scope? | Yes / No / Wildcard match |
| Is the domain/subdomain explicitly listed as out-of-scope? | Yes / No |
| Does a wildcard rule (e.g. `*.example.com`) cover this asset? | Yes / No |
| Is the asset a third-party service (CDN, SaaS, cloud provider)? | Yes / No |
| Does the program scope say "all assets owned by [company]"? | Yes / No |

**Decision logic:**
- Explicitly in scope → **PROCEED**
- Explicitly out of scope → **STOP — passive recon only**
- Covered by wildcard → **PROCEED with caution, note it**
- Third-party / shared infrastructure → **STOP — do not test**
- Ambiguous / not mentioned → **PASSIVE RECON ONLY — flag for hunter review**

---

## Step 3 — Passive-Only Protocol

For out-of-scope or ambiguous assets, you may ONLY:
- Note the asset exists
- Document any in-scope implications (e.g. shared auth, data flows)
- Record it in `~/bugbounty/$TARGET/notes/oos-assets.md`

You may NOT:
- Send any active requests to the asset
- Run any scanners, fuzzers, or probes
- Follow redirects that land on out-of-scope domains

---

## Step 4 — Output Format

### Scope Verdict: [ASSET]
**Status:** IN SCOPE / OUT OF SCOPE / PASSIVE ONLY / AMBIGUOUS

**Reason:** One sentence explaining the classification — which rule matched, or why it's ambiguous.

**Matched Rule:** Quote the exact scope line from the program definition.

**Action:** What Claude will do next (proceed with active testing / passive mapping only / flag for hunter / stop).

**Notes:** Any relevant context — shared infrastructure, subdomain of an in-scope wildcard, known third-party ownership, etc.

---

## Guiding Principles

- **When in doubt, do not test.** Ambiguity is not permission.
- **Third-party infrastructure is never in scope** unless the program explicitly says so.
- **Wildcard scope does not mean unlimited scope.** Some programs exclude specific subdomains under a wildcard — check the exclusions list before assuming a wildcard match is safe.
- **Document everything.** Even out-of-scope assets should be noted — they may have in-scope implications later.
- **Never trust a scope assumption from a previous session.** Programs update scope. Re-check before a new hunt session.

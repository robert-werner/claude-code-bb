---
name: new-engagement
description: Orchestrate the full new-target onboarding sequence automatically: preflight check, program intelligence research, scope definition, and subdomain enumeration. Use this skill at the start of any brand new bug bounty engagement. Trigger on phrases like "start a new engagement", "new target", "begin hunting", "kick off this program", "start fresh on", or any time a target name or program URL is provided with no existing session checkpoint. Runs all four phases in order, stops at any blocking failure, and hands off to hypothesis-agent when recon is complete.
---

# New Engagement Skill

You are starting a brand new bug bounty engagement from zero. Your job is to run the full onboarding sequence without the hunter having to manually trigger each phase. Execute each stage in order. Do not skip ahead. If any stage produces a NO-GO or a blocking failure, stop, report the exact issue, and wait for hunter input before proceeding.

This skill completes when subdomain enumeration is done and a hypothesis session is ready to begin.

---

## Stage 1 — Preflight Check

Run `/preflight-check` before anything else.

**If verdict is NO-GO:**
Stop immediately. Output:
```
[BLOCKED] New engagement halted at Stage 1 — Preflight.
Required fixes before proceeding:
[list from preflight output]

Re-run /new-engagement after fixes are applied.
```
Do not proceed to Stage 2.

**If verdict is GO WITH WARNINGS:**
Note which optional tools are missing and which recon steps will be affected. Continue to Stage 2. Carry the warnings forward and surface them before the affected recon step.

**If verdict is GO:**
Continue to Stage 2 immediately.

---

## Stage 2 — Target Initialization

Set up the target directory and scope file if they don't exist.

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH

TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/{notes,recon,recon/subdomains,recon/js,recon/api,leads,findings,reports,intel}

# Initialize scope file if missing
if [ ! -f $TARGET_DIR/scope.md ]; then
  cat > $TARGET_DIR/scope.md << 'EOF'
# Scope — $TARGET
## In Scope
<!-- Add in-scope domains, wildcards, and IP ranges here -->

## Out of Scope
<!-- Add explicitly excluded assets here -->

## Notes
<!-- Program-specific rules, bounty ranges, special instructions -->
EOF
  echo "[CREATED] $TARGET_DIR/scope.md — fill in before Stage 3"
else
  echo "[OK] Scope file exists"
  cat $TARGET_DIR/scope.md
fi

# Initialize session start marker for file change tracking
touch $TARGET_DIR/session-start.txt

ENDSSH
```

**If scope.md was just created:**
Pause and output:
```
[INPUT REQUIRED] scope.md was created but is empty.

Paste the program's scope definition now, or edit ~/bugbounty/$TARGET/scope.md on Kali
before continuing.

When scope is filled in, say "continue" to resume Stage 3.
```
Wait for hunter confirmation before proceeding. Do not run program intelligence or recon against an undefined scope.

**If scope.md already exists and has content:**
Continue to Stage 3 immediately.

---

## Stage 3 — Program Intelligence

Run `/program-intelligence` for this target.

This produces:
- A list of already-found vulnerability classes to avoid duplicating
- A list of gap surfaces with no prior disclosures (highest opportunity)
- A triager behavior profile
- A tiered hunt priority map

Save the output:
```bash
ssh user@$KALI_IP "mkdir -p ~/bugbounty/$TARGET/intel"
# program-intelligence saves to ~/bugbounty/$TARGET/intel/program-intel.md automatically
```

**If no disclosed reports are available** (new program, private program, or no data):
Note it, skip the gap analysis, and continue. Absence of intel is not a blocker — it just means the priority map will be based on scope alone rather than historical data.

**After Stage 3 completes:**
Surface the Tier 1 priority list from the intelligence report. This is what subdomain enumeration will focus on first.

---

## Stage 4 — Subdomain Enumeration

Run `/recon/subdomain-enum` against the primary in-scope domain(s).

**Before starting**, confirm in-scope domains from the scope file:
```bash
ssh user@$KALI_IP "grep -A20 'In Scope' ~/bugbounty/$TARGET/scope.md"
```

Run enumeration against each in-scope root domain. If multiple root domains are in scope, run them sequentially, not in parallel (to avoid rate-limit issues on passive sources).

**If a preflight warning indicated subfinder or waybackurls is missing:**
Note which passive sources will be skipped. Continue with available tools — partial subdomain coverage is better than no coverage.

**After enumeration completes**, run scope-checker on any discovered subdomains that don't obviously match the primary domain:
```bash
# Review and flag ambiguous subdomains
ssh user@$KALI_IP "cat ~/bugbounty/$TARGET/recon/subdomains/live-hosts.txt"
```

Run `/scope-checker` on any subdomain that:
- Uses a different registrable domain than the target
- Appears to be third-party infrastructure (CDN, SaaS, cloud provider)
- Is not covered by an explicit wildcard in scope.md

---

## Stage 5 — Handoff Briefing

Once all four stages complete, produce a structured handoff before starting any active testing:

---

### New Engagement Ready: $TARGET

**Preflight:** [GO / GO WITH WARNINGS — list any active warnings]

**Program Intelligence Summary:**
- Disclosed findings to avoid: [count and classes]
- Gap surfaces (highest opportunity): [bullet list from intel report]
- Triager profile: [one sentence]
- Tier 1 hunt priority: [list]

**Subdomain Recon Summary:**
- Total subdomains discovered: [count]
- Live HTTP hosts: [count]
- Tier 1 priority targets: [list from priority-tier1.txt]
- Subdomain takeover candidates: [count, or "none detected"]
- Out-of-scope assets noted: [count]

**Recommended Next Steps (in order):**
1. Run `/recon/js-analysis` against Tier 1 subdomains
2. Run `/recon/api-surface` against Tier 1 subdomains
3. Run `/hypothesis-agent ~/bugbounty/$TARGET` after js-analysis and api-surface complete
4. Begin manual testing on highest-scored hypotheses

**Blocking Items (require hunter input before proceeding):**
[List anything that needs a human decision, or "None — ready to proceed autonomously"]

---

After producing the handoff briefing, write a session checkpoint via `/session-resume` (WRITE mode) to capture the engagement start state.

Then proceed to Step 1 of Recommended Next Steps unless the hunter says otherwise.

---

## Stage Failure Reference

| Stage | Blocking failure | Non-blocking warning |
|---|---|---|
| Preflight | SSH down, required tool missing | Optional tool missing |
| Target Init | Cannot create directories on Kali | Scope file was empty (pause for input) |
| Program Intel | n/a — always continues | No disclosed reports available |
| Subdomain Enum | No in-scope domains defined in scope.md | Some passive sources unavailable |

---

## Guiding Principles

- **Never start recon without a defined scope.** If scope.md is empty, pause and wait. An undefined scope is not permission to test everything.
- **Each stage's output feeds the next.** Don't skip stages to save time — program intelligence shapes subdomain prioritization, and subdomain results shape hypothesis generation.
- **Carry warnings forward, don't bury them.** If preflight warned that a tool is missing, surface that warning again before the stage that depends on it.
- **One blocking failure stops the chain.** Do not attempt workarounds for NO-GO conditions. Report and wait.
- **The handoff briefing is mandatory.** The hunter needs to see the full picture before autonomous hunting begins. Do not skip straight to js-analysis without producing it.
- **Write a checkpoint after Stage 5.** The engagement start state — scope, intel summary, subdomain count, Tier 1 targets — must survive context compaction.

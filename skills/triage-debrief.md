---
name: triage-debrief
description: Analyze a closed bug bounty report (N/A, Informational, or Duplicate) and extract structured lessons learned. Use this skill after any report is closed without a bounty to understand exactly what failed, what would have made it reportable, and what patterns to avoid in future submissions. Trigger on phrases like "analyze this closure", "why was this N/A", "debrief this report", "lessons from this rejection", or when the hunter pastes a closed report or triage decision.
---

# Triage Debrief Skill

You are a post-mortem analyst. A report was closed. Your job is to extract maximum signal from that failure — not to relitigate it, not to find excuses, but to understand exactly what went wrong and encode that into rules that prevent the same mistake from happening again.

This hunter has a Bugcrowd suspension history. Every N/A is not just a missed bounty — it is account damage. Treat every closure as a learning event that must produce concrete, actionable rules.

---

## Step 1 — Load the Closed Report

Read the closed report from the notes directory:

```bash
cat ~/bugbounty/$TARGET/reports/[report-name].md
```

Also read any triage response or closure comment the hunter has saved.

---

## Step 2 — Classify the Closure Type

| Closure Type | Definition |
|---|---|
| **N/A** | Finding not valid, not a vulnerability, or not meeting program bar |
| **Informational** | Valid observation but below bounty threshold |
| **Duplicate** | Valid finding but already reported |
| **Out of Scope** | Asset or vulnerability class not covered by program |
| **Not Reproducible** | Triager could not reproduce with provided steps |
| **Spam / Low Quality** | Submission quality too poor to evaluate |

---

## Step 3 — Root Cause Analysis

For every closed report, identify the **primary failure point** from this list:

**Evidence failures:**
- No PoC or incomplete PoC
- Screenshots outdated or not matching claims
- Steps to reproduce could not be followed independently
- Missing HTTP request/response captures

**Impact failures:**
- Impact stated theoretically, not demonstrated
- Impact chain had an unvalidated step
- Sensitivity of data not established (internal ≠ sensitive)
- Data was already publicly available elsewhere
- PII claimed but data didn't meet legal definition

**Scope failures:**
- Asset not in scope
- Vulnerability class excluded by program
- Third-party infrastructure tested

**Duplicate failures:**
- Common/high-traffic surface, didn't check disclosed reports first
- Known pattern for this tech stack
- Endpoint too obvious — certainty of prior hunter testing was high

**Quality failures:**
- Title overclaimed severity
- Severity inflated beyond demonstrated impact
- Best-practice suggestion framed as a vulnerability
- Report too vague for independent reproduction

---

## Step 4 — Extract Actionable Rules

For each root cause identified, generate a concrete rule in this format:

> **Rule:** [One-sentence rule that would have prevented this closure]
> **Applies to:** [Finding type / surface / platform]
> **Check before submitting:** [Specific verification step]

These rules should be specific to this failure — not generic security advice.

---

## Step 5 — Pattern Detection

Compare this closure against the hunter's closure history (if available in notes):

```bash
ls ~/bugbounty/*/reports/closed/
cat ~/bugbounty/*/reports/closed/*.md
```

Answer:
- Is this the same root cause as a previous closure?
- Is this the same finding type as a previous closure?
- Is there an emerging pattern that suggests a systemic gap in the hunter's methodology?

If a pattern exists, flag it explicitly. A repeated mistake is a methodology problem, not a one-off.

---

## Step 6 — Duplicate Risk Retrospective

If the closure was Duplicate:
- What signals were present in recon that should have indicated high duplicate risk?
- Was the endpoint high-traffic / obvious?
- Was this a known pattern for the target's tech stack?
- What pre-submission check would have caught this?

Generate a rule for avoiding this duplicate class in future hunts on similar targets.

---

## Step 7 — Lesson Material: Forward Deployment

This step runs after every closure — positive (resolved) or negative (N/A, dup, informational). A lesson is worthless if it only points backward.

For every finding that closes, answer these three questions and write the answers to notes:

**1. What did this finding confirm about how this target was built?**
Every bug is evidence of a developer assumption, a framework default, an architectural shortcut, or a trust boundary that was never enforced. Name it explicitly.

> Example: "This IDOR confirms the API does not re-validate ownership after the initial auth check — the pattern is likely present on any endpoint that accepts an object ID parameter."

**2. What other surfaces on this target make the same assumption?**
Do not stop at the endpoint you found. Look left and right: what other flows, endpoints, or services were built by the same team with the same logic?

```bash
# Search recon for endpoints with the same structural pattern
grep -r "/api/v[0-9]/" ~/bugbounty/$TARGET/recon/ | grep -v "$(echo $FOUND_ENDPOINT)"
```

List every candidate. They go into Leads, not Findings.

**3. What would a developer who wrote this bug also have gotten wrong elsewhere?**
Think about the developer's mental model. If they didn't validate ownership on object reads, did they validate it on object writes? On bulk endpoints? On export/download endpoints? On admin actions?

Produce 2–3 new hypotheses from this reasoning and add them to the hypothesis queue:

```bash
cat >> ~/bugbounty/$TARGET/leads.md << EOF

## Leads from [FINDING TITLE] lesson material — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- [Hypothesis 1 derived from confirmed bug logic]
- [Hypothesis 2 — same developer assumption, different surface]
- [Hypothesis 3 — related trust boundary, adjacent endpoint]
EOF
```

**For negative closures (N/A, Duplicate, Informational):**
The same three questions apply — just directed at what was *missing* rather than what was confirmed. A duplicate closure tells you the endpoint is high-traffic and heavily hunted. That means adjacent, less-obvious endpoints on the same feature are *less* likely to be duplicates. Pivot there.

**Do not dwell.** Once the lesson is extracted and leads are written, the closed report is closed. Don't re-read it. Don't relitigate it. The lesson is now in the queue as forward motion — that is its only value going forward.

---

## Output Format

### Debrief: [Report Title]
**Closure Type:** N/A / Informational / Duplicate / OOS / Not Reproducible

**Primary Failure:** One sentence — the single most important thing that caused this closure.

**Root Cause Breakdown:**
Bullet list of every failure point identified, categorized.

**Rules Extracted:**
Numbered list of actionable rules generated from this closure. These must be specific, not generic.

**Pattern Flag:**
Is this a recurring pattern? If yes, describe the systemic gap and what methodology change would fix it.

**What Would Have Made This Reportable:**
Concrete steps — not vague improvements. If it was fundamentally not a vulnerability, say so directly.

**Duplicate Risk Score (if applicable): [X/10]**
How predictable was this duplicate in hindsight? What should have been checked?

**Lesson Material — Forward Deployment:**
- Developer assumption confirmed/disproved: [one sentence]
- Other surfaces with same assumption: [list as leads]
- New hypotheses queued: [2–3 bullet points]
- Primitives extracted (if any): [reusable gadgets or behavioral signals]

---

## Guiding Principles

- **No excuses. No triager-blaming.** If the report was closed, assume the hunter's submission was the variable that could have been different.
- **One closure = one set of rules.** Every debrief must produce at least one new actionable rule.
- **Patterns are more valuable than individual lessons.** If the same root cause appears three times, it's a methodology gap — fix the methodology.
- **A Duplicate closure is not a failure of skill — it's a failure of intelligence gathering.** Treat it as a recon gap, not bad luck.
- **A confirmed finding is not a destination — it is a compass bearing.** Use what it revealed about the target to generate the next angle of attack. Then move.
- **Lessons are fuel, not weight.** Extract them quickly, deploy them forward, and don't carry the closed report as baggage into the next hypothesis.
- **Save all extracted rules to the global lessons file:**

```bash
echo "[DATE] [RULE]" >> ~/bugbounty/lessons-learned.md
```

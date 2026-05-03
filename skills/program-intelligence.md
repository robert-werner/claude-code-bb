---
name: program-intelligence
description: Research a bug bounty program's history, disclosed reports, known triager behavior, and scope patterns to build a pre-hunt intelligence profile. Use this skill at the start of a new program engagement to understand what's already been found, what the triagers accept, and where the best opportunities are. Trigger on phrases like "research this program", "what's been reported here", "program intel", "pre-hunt research", or at the start of any new engagement.
---

# Program Intelligence Skill

You are an intelligence analyst. Before touching a target, you study it. Your job is to build a complete picture of the program's history, triager behavior, and opportunity landscape — so hunting time is spent on high-value surfaces, not re-running what others have already found.

---

## Step 1 — Load Program Details

Read the program scope and any existing notes:

```bash
cat ~/bugbounty/$TARGET/scope.md
ls ~/bugbounty/$TARGET/
```

Identify:
- Platform (HackerOne / Bugcrowd / Intigriti / other)
- Program name / handle
- Scope boundaries
- Any VDP (Vulnerability Disclosure Policy) vs. paid bounty program

---

## Step 2 — Disclosed Report Analysis

If the program has public disclosures, analyze them. Save output:

```bash
cat ~/bugbounty/$TARGET/intel/disclosed-reports.md
```

For each disclosed report, extract:
- Vulnerability class
- Affected endpoint or surface
- Severity awarded
- Time-to-triage (signal for program responsiveness)
- Any notable triager comments

Build two lists:

**Already Found (avoid duplicating):**
Endpoints, parameters, and vulnerability classes that appear in disclosed reports. These are high-traffic surfaces — other hunters are still testing them.

**Gaps (high opportunity):**
Vulnerability classes or surfaces that are in scope but have NO disclosed reports. Absence of disclosures on a surface = either nobody looked, or it's well-defended. Either is worth investigating.

---

## Step 3 — Triager Behavior Profile

From disclosed reports and any available triage comments, characterize the program's triagers:

| Signal | Observation |
|---|---|
| Average time to first response | |
| Acceptance rate (estimated from disclosure ratio) | |
| Severity calibration (do they downgrade?) | |
| Evidence standards (what PoC level do they require?) | |
| Known N/A patterns for this program | |
| Preferred report format signals | |

Note: if no disclosure data is available, skip this step and flag the gap.

---

## Step 4 — Technology Stack Intelligence

From disclosed reports, public recon, and any available job postings:

- Identify the tech stack (frameworks, cloud provider, CDN, auth provider)
- Note any stack-specific vulnerability classes that are historically rewarded here
- Flag any known CVEs or public exploits relevant to their stack versions

---

## Step 5 — Hunt Priority Map

Generate a prioritized surface map based on all intelligence gathered:

**Tier 1 — Highest opportunity (test first):**
In-scope surfaces with no disclosed reports + complex functionality (auth, payments, file upload, API, admin).

**Tier 2 — Standard opportunity:**
In-scope surfaces with some disclosures but vulnerability classes not exhausted.

**Tier 3 — Low opportunity (skip unless nothing else remains):**
High-traffic surfaces with many disclosures. Likely well-hunted. Only worth testing with a novel angle.

**Do Not Test:**
Anything out of scope, third-party, or explicitly excluded.

---

## Output Format

### Program Intelligence Report: [Program Name]
**Platform:** HackerOne / Bugcrowd / Other
**Scope summary:** [One sentence]
**Disclosed reports analyzed:** [Count]

**Already Found — Avoid Duplicating:**
[Bullet list of vulnerability classes and surfaces with known disclosures]

**Gap Surfaces — High Opportunity:**
[Bullet list of in-scope surfaces with no disclosed findings]

**Triager Profile:**
[2-3 sentences on triager behavior, evidence bar, known N/A patterns]

**Tech Stack:**
[Identified stack components and any relevant vulnerability history]

**Hunt Priority Map:**
[Tier 1 / Tier 2 / Tier 3 / Do Not Test — with specific surfaces]

**First Recon Target:**
[Single most valuable surface to start recon on, with reasoning]

---

## Save Output

```bash
# Save to target intel directory
mkdir -p ~/bugbounty/$TARGET/intel
# Write the intelligence report
cat > ~/bugbounty/$TARGET/intel/program-intel.md << 'EOF'
[output here]
EOF
```

---

## Guiding Principles

- **Intelligence before recon. Recon before testing.** Don't touch the target until you know what others have already found.
- **Absence of disclosures is signal, not silence.** A surface with no disclosures either hasn't been hunted seriously or is very well defended. Determine which before investing time.
- **Triager behavior is learnable.** Programs have patterns. A triager who consistently downgrades severity or uses specific N/A boilerplate is predictable — adapt submissions accordingly.
- **The hunt priority map is a living document.** Update it as new disclosures appear or new surfaces are discovered during recon.

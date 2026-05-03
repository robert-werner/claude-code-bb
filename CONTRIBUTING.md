# Contributing

This repo is a living toolkit. If you've developed a skill or recon workflow that's improved your hunting, it belongs here.

Before writing anything new, read two or three existing skills end-to-end. The format is deliberate — consistency matters because Claude Code reads these files as instructions, not documentation.

---

## Skill vs. Recon Workflow — Which Are You Writing?

**Skill** (`skills/`) — An analytical or decision-making capability. Skills tell Claude *how to think* about something: how to evaluate a report, how to generate hypotheses, how to classify an asset. Skills are triggered by conversation or context, not necessarily by running shell commands.

**Recon Workflow** (`recon/`) — A procedural, tool-driven pipeline. Recon workflows are sequences of shell commands that produce output files. They tell Claude *how to execute* a specific recon phase against a target.

When in doubt: if your contribution is mostly bash, it's a recon workflow. If it's mostly reasoning/evaluation logic, it's a skill.

---

## Skill Format

Every skill file must start with a YAML frontmatter block, followed by the skill body.

### Frontmatter (required)

```yaml
---
name: your-skill-name
description: [One paragraph. Must cover three things: (1) what the skill does, (2) when to use it, (3) exact trigger phrases Claude should recognize to invoke it automatically.]
---
```

**Rules for the `description` field:**
- Include explicit trigger phrases: `"Trigger on phrases like 'X', 'Y', or 'Z'"`
- Describe the input Claude expects and the output it produces
- Be specific enough that Claude auto-invokes the skill correctly without the hunter typing the exact skill name
- Keep it to one paragraph — this is a routing label, not documentation

**Example (from `triager.md`):**
```yaml
---
name: triager
description: Evaluate a bug bounty report before submission by critiquing it from the
  perspective of a real triager. Use this skill whenever a user wants to assess a report's
  quality, validate impact chains, check if findings are reportable, or avoid submitting
  weak/incomplete reports. Trigger on phrases like "critique my report", "is this reportable",
  "review this finding", "should I submit this", "rate my report", or when a user pastes
  a bug bounty report draft.
---
```

---

### Skill Body Structure

After the frontmatter, follow this structure:

```markdown
# Skill Name

One-paragraph role statement. Tell Claude exactly what persona or function it is
performing. Be direct — "You are X. Your job is Y. Your prime directive is Z."
If there are critical constraints (e.g. account suspension risk, no destructive actions),
state them here before any steps.

---

## Step 1 — [Step Name]

[Instructions for this step. If shell commands are needed, include them as bash blocks
with the exact paths established in CLAUDE.md.]

---

## Step 2 — [Step Name]

...

---

## Output Format

[Define the exact output structure Claude must produce. Use headers, tables, and
labeled sections. Do not leave output format ambiguous — Claude will improvise
if you don't specify, and improvised output is inconsistent output.]

---

## Guiding Principles

[3–7 bullet points. These are the prime directives that override edge cases.
Write them as rules Claude must never violate, not suggestions.]
```

---

### Skill Writing Rules

**Be imperative, not descriptive.**
Write instructions as commands: "Read the file", "Run this command", "Flag this pattern".
Do not describe what Claude will do — tell it what to do.

> ✅ `Run /scope-checker on every new asset before active testing.`
> ❌ `The scope-checker skill can be used to verify assets are in scope.`

**Specify output format exactly.**
Every skill must define a concrete output structure. Use section headers with fixed labels (e.g. `### Verdict`, `### Critical Weaknesses`). If output is unspecified, Claude will format it differently every time.

**Hard rules go in Guiding Principles.**
Anything Claude must never do regardless of context belongs in Guiding Principles as a bolded, direct statement. These are circuit breakers, not guidelines.

> ✅ `**Never call a report ready if you wouldn't accept it as a triager.**`
> ❌ `Try to be conservative when evaluating reports.`

**No hedging language.**
Avoid "may", "might", "could", "consider", "perhaps". Claude reads these as optional. If something is required, say it is required.

**Reference other skills explicitly.**
If your skill should hand off to another skill after completing, say so directly:
> `After completing this workflow, run /hypothesis-agent $TARGET_DIR.`

**Account for failure states.**
Every skill should specify what Claude does when inputs are missing, tools fail, or conditions aren't met. "Stop and notify the hunter" is a valid and required answer for blocking failures.

---

## Recon Workflow Format

Recon workflows follow the same frontmatter convention but are structured around shell command sequences.

### Frontmatter

```yaml
---
name: your-workflow-name
description: [What recon phase this covers, when to run it, what tools it requires,
  what output files it produces. Trigger phrases for conversational invocation.]
---
```

### Body Structure

```markdown
# Workflow Name

One-paragraph context: what surface this covers, why it matters, what hunters miss
if they skip it.

---

## Prerequisites

[Tool availability checks. Always verify tools exist before running — silent failures
waste sessions. Use the exact paths from CLAUDE.md.]

---

## Step 1 — [Phase Name]

[Bash block. Always use $TARGET_DIR and $TARGET_DOMAIN variables — never hardcode
target names. Output files go to $TARGET_DIR/recon/[workflow-name]/.]

---

## Output Summary

| File | Contents |
|---|---|
| `filename.txt` | What's in it |
```

### Recon Workflow Rules

**Always use variables, never hardcoded targets.**
Every path and domain reference must use `$TARGET`, `$TARGET_DIR`, or `$TARGET_DOMAIN`. Hardcoded values break the workflow for every other target.

**Create output directories explicitly.**
Do not assume directories exist. Every workflow must run `mkdir -p $TARGET_DIR/recon/[name]/` before writing any output files.

**Every workflow ends with an Output Summary table.**
List every file written, with a one-line description of its contents. This is how other workflows (and hypothesis-agent) know what data is available.

**Note rate-limit and detection risks.**
If a step sends active requests to the target, note it. Distinguish passive recon (safe to run freely) from active probing (rate limits apply).

**Chain to the next workflow.**
If your workflow produces output that feeds a downstream workflow or skill, say so at the end:
> `After this workflow completes, run /recon/api-surface or pass output to /hypothesis-agent.`

---

## Adding to CLAUDE.md and README.md

When adding a new skill or recon workflow:

1. **CLAUDE.md** — Add your skill to the Skills Index table. If it fits into the Session Lifecycle order, add it to the numbered steps. Keep the lifecycle linear.
2. **README.md** — Add a row to the Skills or Recon Workflows table with a one-paragraph description.

Do not leave a skill undocumented in CLAUDE.md. Claude will not use skills it doesn't know exist.

---

## What Makes a Good Skill

A skill is worth adding if it encodes knowledge that would otherwise require the hunter to intervene. Ask:

- Does this skill make a decision Claude would otherwise get wrong?
- Does it enforce a standard that matters for account health or report quality?
- Does it produce output that feeds another skill or workflow?
- Would a new hunter using this repo benefit from it on day one?

If the answer to at least two of these is yes, the skill belongs here.

**Do not add skills that are just checklists.** If the skill doesn't require Claude to reason, evaluate, or make decisions — it's a note, not a skill.

---

## Style

- Headings: `##` for major sections, `###` for subsections and output sections
- Bash blocks: always fenced with ` ```bash ` and a closing ` ``` `
- Tables: use for structured comparisons, output summaries, and decision matrices
- Horizontal rules (`---`): between every major section
- Tone: direct, imperative, no fluff. Write for Claude, not for a human reader skimming docs.

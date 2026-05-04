---
name: skill-writer
description: Author and commit a new skill or recon workflow file when Claude discovers a novel technique, attack class, behavioral pattern, or recon method that is not covered by any existing skill. Use this whenever a hunt produces a repeatable method worth encoding, a technique is used successfully that has no corresponding skill file, or the hunter says something belongs in the skill library. Trigger on phrases like "add this to skills", "write a skill for this", "save this technique", "this should be a skill", "document this method", "add to skill library", or automatically when a validated finding uses a technique not covered by any existing skill.
---

# Skill Writer

You are a skill author. A technique, attack class, or recon method was used successfully or discovered during a hunt, and it has no corresponding skill file. Your job is to encode it into a permanent, reusable skill or recon workflow that meets the same quality bar as the existing library — so the next time this surface appears on any target, the full methodology is already written.

Do not write thin skills. A skill must encode *how to think* or *how to execute* — not just note that something exists. If you can't fill out all sections below with real, specific content, the technique is not ready to be a skill yet. Write it as a Primitive in notes instead and return when more is known.

---

## Step 1 — Qualify the Skill

Before writing anything, answer all four questions. If any answer is "no" or "unknown", stop and note the technique as a Primitive instead.

| Question | Answer |
|---|---|
| Is this technique repeatable on other targets? | yes / no |
| Does it require Claude to reason or make decisions (not just run commands)? | yes / no |
| Does it encode something a hunter would get wrong without explicit guidance? | yes / no |
| Can you define a concrete trigger condition for when to use it? | yes / no |

If all four are yes: proceed to Step 2.

If this is purely a sequence of shell commands with no reasoning required: write it as a recon workflow in `recon/` instead of `skills/`.

---

## Step 2 — Define the Skill Metadata

Before writing the file, nail down:

```
Skill name (slug, kebab-case):     [e.g. host-header-injection]
Skill type:                        [skill / recon-workflow]
Discovery context:                 [What hunt/target/finding produced this]
Technique summary (1 sentence):    [What this technique does]
Trigger condition:                 [When should Claude auto-invoke this]
Existing skill most similar to it: [Which existing skill is the closest cousin]
What makes this different:         [Why a new file is needed vs. extending an existing one]
```

If this is too close to an existing skill (same class, same surface, overlapping steps): extend the existing skill with a new section instead of creating a new file. Document the extension in the output.

---

## Step 3 — Write the Skill File

Follow the format from `CONTRIBUTING.md` exactly. Every section is required.

### Required sections (in order):
1. YAML frontmatter (`name`, `description` with trigger phrases)
2. Role statement paragraph (what Claude is, what its job is, any hard constraints)
3. Prerequisites (tools, prior recon required, scope requirements)
4. Numbered steps with bash blocks where applicable
5. Validation Standard (what constitutes a confirmed finding for this technique — not just a signal)
6. Output Format (exact structure Claude must produce at the end)
7. Guiding Principles (3–7 hard rules, bolded, imperative)

### Writing rules (non-negotiable):
- Every bash block uses `$TARGET`, `$TARGET_DIR` — never hardcoded values
- Output files go to `$TARGET_DIR/recon/[skill-name]/` or `$TARGET_DIR/leads/` — never ad-hoc paths
- Every step has a failure state: what to do when the step fails or produces no output
- No hedging language: "may", "might", "consider" are forbidden — if it's required, say so
- Validation Standard must be stricter than "got a 200"
- Guiding Principles must include one rule about not over-escalating findings from this surface

---

## Step 4 — Self-Review Before Committing

Before writing to disk, run this checklist:

```
[ ] Frontmatter has name + description with explicit trigger phrases
[ ] Role statement tells Claude exactly what it is and what its constraints are
[ ] Every step is imperative (not descriptive)
[ ] Bash blocks use $TARGET and $TARGET_DIR — no hardcoded values
[ ] Output format is defined with exact section headers
[ ] Validation Standard is defined (not just "check for interesting response")
[ ] Guiding Principles include a false-positive / over-escalation guard
[ ] New file does NOT duplicate an existing skill (checked against skills index)
[ ] File is named in kebab-case and placed in the correct directory
```

If any checkbox fails: fix it before proceeding. Do not commit a skill that fails this checklist.

---

## Step 5 — Write the File to Kali

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
# Write skill file to the claude-code-bb directory
# Adjust path to wherever the hunter keeps the repo on Kali
REPO_DIR=~/claude-code-bb
SKILL_FILE="$REPO_DIR/skills/[SKILL-NAME].md"

cat > "$SKILL_FILE" << 'SKILL_EOF'
[FULL SKILL CONTENT HERE]
SKILL_EOF

echo "[*] Written: $SKILL_FILE"
wc -l "$SKILL_FILE"
ENDSSH
```

---

## Step 6 — Update the Skill Index

After writing the file, immediately run `/skill-index-updater` to:
- Add the new skill to the Skills Index table in `CLAUDE.md`
- Add a row to the Skills table in `README.md`

Do not skip this step. A skill that is not in `CLAUDE.md` does not exist — Claude will never invoke it.

---

## Step 7 — Commit to Git

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH
REPO_DIR=~/claude-code-bb
SKILL_NAME="[SKILL-NAME]"
DISCOVERY="[ONE-LINE CONTEXT: what hunt/target produced this]"

cd "$REPO_DIR"
git add skills/${SKILL_NAME}.md CLAUDE.md README.md
git commit -m "feat(skill): add ${SKILL_NAME} — ${DISCOVERY}"
git push origin main

echo "[*] Skill committed and pushed."
ENDSSH
```

If the repo is not on Kali (hunter uses a different workflow), write the file to disk and notify the hunter to commit manually.

---

## Output Format

After completing all steps, produce:

```
=== New Skill Written ===

File:              skills/[skill-name].md
Type:              skill / recon-workflow
Discovery source:  [hunt context that produced this]
Trigger phrases:   [the phrases that will auto-invoke this skill]
Extends existing:  [skill name] / none

Skill summary:
[2-3 sentences: what it does, when to use it, what the validation standard is]

CLAUDE.md updated: yes
README.md updated:  yes
Committed to git:   yes / pending hunter action

Next action: [The skill is now active. If this technique is relevant to the current
hunt, invoke it now on the current target.]
```

---

## Guiding Principles

- **Quality over speed.** A thin skill is worse than no skill — it gives false confidence and produces inconsistent output. If the technique isn't understood well enough to fill all sections, write it as a Primitive and return later.
- **One skill per technique class.** Do not create a new skill for every variant. An SSRF via PDF renderer and an SSRF via webhook URL are both SSRF — they belong in one skill with variant-specific sections.
- **Never commit a skill that fails the Step 4 checklist.** The checklist exists because missing sections cause silent failures in autonomous operation.
- **Discovery context must be recorded.** Every skill must carry the hunt context that produced it — in the frontmatter description or a `## Origin` section. Context is what makes a skill useful to audit later.
- **Skills are for Claude, not for documentation.** Write for the model that will execute these instructions, not for a human reader. Imperative, specific, unambiguous.
- **If a skill already covers this technique at 80%, extend it.** New files fragment the skill index. Extensions keep related logic co-located and reduce the chance of conflicting guidance.

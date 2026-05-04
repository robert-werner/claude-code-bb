---
name: skill-index-updater
description: Update CLAUDE.md and README.md after a new skill or recon workflow is added to the library. Keeps the Skills Index in CLAUDE.md and the Skills table in README.md in sync with the actual contents of the skills/ and recon/ directories. Trigger on phrases like "update the skill index", "add to CLAUDE.md", "update README", "index new skill", or automatically after /skill-writer completes.
---

# Skill Index Updater

A skill that isn't indexed in `CLAUDE.md` doesn't exist. This skill reads the current state of the `skills/` and `recon/` directories, diffs it against the current `CLAUDE.md` Skills Index and `README.md` Skills table, and writes the missing entries. It runs after every `/skill-writer` invocation and any time the index and the file system are out of sync.

---

## Step 1 — Read the Current Skill Directory

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
REPO_DIR=~/claude-code-bb

echo "=== skills/ directory ==="
ls "$REPO_DIR/skills/"

echo ""
echo "=== recon/ directory ==="
ls "$REPO_DIR/recon/"
ENDSSH
```

---

## Step 2 — Read the Current Index

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
REPO_DIR=~/claude-code-bb

echo "=== Skills Index in CLAUDE.md ==="
grep -A 200 "## Skills Index" "$REPO_DIR/CLAUDE.md" | head -60

echo ""
echo "=== Skills table in README.md ==="
grep -A 100 "## Skills" "$REPO_DIR/README.md" | head -60
ENDSSH
```

---

## Step 3 — Extract Metadata from New Skill File

For the newly written skill file, read its frontmatter to extract the name, description, and trigger condition:

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH
REPO_DIR=~/claude-code-bb
SKILL_FILE="$REPO_DIR/skills/[SKILL-NAME].md"

echo "=== Frontmatter ==="
head -10 "$SKILL_FILE"

echo ""
echo "=== First non-frontmatter paragraph ==="
awk '/^---$/{p++} p==2{print; exit} p==2' "$SKILL_FILE" | head -5
ENDSSH
```

From the frontmatter and first paragraph, derive:
- **Skill name** (the `name:` field, formatted as `/skill-name`)
- **When to use** (condensed from the `description:` field to one clause)
- **What it does** (the first sentence of the skill body)

---

## Step 4 — Write Missing Entries

### CLAUDE.md — Skills Index table

Add a new row to the Skills Index table in `CLAUDE.md`:
```
| `/[skill-name]` | [When to use — one clause] |
```

Position: insert after the skill it is most related to. If unrelated to any existing skill, append at the end of the table before the closing line.

### README.md — Skills table

Add a new row to the Skills table in `README.md`:
```
| `skills/[skill-name].md` | [What it does — one sentence matching the frontmatter description, condensed] |
```

### Session Lifecycle (CLAUDE.md) — only if applicable

If the new skill fits into a specific lifecycle step (e.g., a new hunter type that belongs in Step 5 Hunt, or a new validation skill), add it to the relevant numbered step. Do not add every new skill to the lifecycle — only skills that change the hunt flow.

---

## Step 5 — Write Updates to Disk

```bash
# Read current CLAUDE.md and README.md, insert new rows, write back
# Use Python for safe in-place table editing
ssh user@$KALI_IP 'python3 -s' << 'ENDSSH'
import pathlib, re

REPO = pathlib.Path.home() / "claude-code-bb"

# --- CLAUDE.md ---
claude = (REPO / "CLAUDE.md").read_text()

new_row_claude = "| `/[SKILL-NAME]` | [WHEN TO USE] |\n"
anchor = "| `/triage-debrief`"  # insert before this row as default; adjust as needed

if new_row_claude.split('`')[1] not in claude:
    claude = claude.replace(anchor, new_row_claude + anchor)
    (REPO / "CLAUDE.md").write_text(claude)
    print("[+] CLAUDE.md updated")
else:
    print("[=] CLAUDE.md already contains this skill")

# --- README.md ---
readme = (REPO / "README.md").read_text()

new_row_readme = "| `skills/[SKILL-NAME].md` | [WHAT IT DOES] |\n"
anchor_readme = "| `skills/triage-debrief.md`"  # insert before; adjust as needed

if "skills/[SKILL-NAME].md" not in readme:
    readme = readme.replace(anchor_readme, new_row_readme + anchor_readme)
    (REPO / "README.md").write_text(readme)
    print("[+] README.md updated")
else:
    print("[=] README.md already contains this skill")

ENDSSH
```

Fill in `[SKILL-NAME]`, `[WHEN TO USE]`, and `[WHAT IT DOES]` with actual values derived from Step 3 before running.

---

## Step 6 — Verify

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH
REPO_DIR=~/claude-code-bb
SKILL_NAME="[SKILL-NAME]"

echo "CLAUDE.md entry:"
grep "$SKILL_NAME" "$REPO_DIR/CLAUDE.md"

echo ""
echo "README.md entry:"
grep "$SKILL_NAME" "$REPO_DIR/README.md"
ENDSSH
```

Both lines must be present and contain the correct skill name. If either is missing, re-run Step 4.

---

## Output Format

```
=== Skill Index Updated ===

CLAUDE.md — Skills Index: [added / already present]
README.md — Skills table:  [added / already present]
Lifecycle step updated:    [yes — step N / no]

New entries written:
  CLAUDE.md: | /[skill-name] | [when to use] |
  README.md: | skills/[skill-name].md | [what it does] |
```

---

## Guiding Principles

- **Never remove existing rows.** This skill only adds. If a row needs to be removed or renamed, that requires explicit hunter instruction.
- **Descriptions in the index must be shorter than the skill frontmatter.** CLAUDE.md rows are routing labels — one clause maximum. Full descriptions live in the skill file itself.
- **Do not add a skill to the Session Lifecycle unless it changes the hunt flow.** Support skills (like this one) don't belong in the numbered lifecycle steps.
- **Run verification before reporting success.** Do not report "CLAUDE.md updated" without confirming the grep in Step 6 returns a result.

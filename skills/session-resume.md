---
name: session-resume
description: Generate or consume a structured session handoff document so Claude can resume a bug bounty hunt after context compaction, a sleep break, or a new session. Use this skill at the end of a long session to write a resume checkpoint, or at the start of a new session to re-orient and pick up exactly where work stopped. Trigger on phrases like "write a checkpoint", "save session state", "resume hunt", "where did we leave off", "context dump", or automatically before context compaction is likely.
---

# Session Resume Skill

Context compaction kills hunts. This skill exists to make Claude stateless-safe — able to pick up any bug bounty session from a clean checkpoint without losing track of what was tested, what was found, and what was next.

**Two modes:**
- **WRITE** — end of session, generate a checkpoint
- **READ** — start of session, consume a checkpoint and resume

---

## WRITE Mode — Generating a Checkpoint

Run at the end of a session, before going to bed, or when context is getting long.

### Step 1 — Gather State

Run on Kali via SSH:

```bash
# List all recon files and their modification times
find ~/bugbounty/$TARGET -type f -newer ~/bugbounty/$TARGET/session-start.txt 2>/dev/null | sort

# Show current leads
cat ~/bugbounty/$TARGET/leads.md

# Show current findings
cat ~/bugbounty/$TARGET/findings.md

# Show last 50 lines of notes
tail -50 ~/bugbounty/$TARGET/notes/notes.md
```

### Step 2 — Write Checkpoint File

Write to `~/bugbounty/$TARGET/session-checkpoint.md`:

```markdown
# Session Checkpoint — [DATE TIME]

## Target
[Program name, target domain, scope summary]

## Session Summary
[2-3 sentences: what was the focus of this session, what approach was taken]

## Recon Completed
- [Tool]: [what was run, against what, output file location]
- [Tool]: ...

## Recon Still Needed
- [ ] [Specific recon task not yet completed]
- [ ] ...

## Leads (open)
[Copy current leads.md content — every open lead with its status]

## Leads (closed this session)
- [Lead]: [outcome — why closed, what was found or ruled out]

## Findings This Session
[Copy findings.md — every validated finding with status]

## Hypotheses Generated
[Any hypotheses from hypothesis-agent not yet tested]

## Exact Stopping Point
[One paragraph: what was the last thing tested, what was the result, what was the intended next step]

## Next Session Priority
1. [Highest priority task — be specific: endpoint, tool, hypothesis]
2. [Second priority]
3. [Third priority]

## Blocked Items
[Anything that requires hunter input, additional access, or external information before proceeding]

## Tools Running / Background Processes
[Any tools left running in background — command, PID if known, expected runtime]
```

---

## READ Mode — Resuming from Checkpoint

Run at the start of a new session.

### Step 1 — Load Checkpoint

```bash
cat ~/bugbounty/$TARGET/session-checkpoint.md
```

If no checkpoint exists:
```bash
ls ~/bugbounty/
# List available targets and ask hunter which to resume
```

### Step 2 — Verify State

Before assuming the checkpoint is current, verify:

```bash
# Check if any recon files were modified since the checkpoint was written
find ~/bugbounty/$TARGET -type f -newer ~/bugbounty/$TARGET/session-checkpoint.md

# Check if background tools finished
cat ~/bugbounty/$TARGET/notes/notes.md | tail -20
```

### Step 3 — Produce a Resume Briefing

Output this before starting any work:

---

**Session Resume Briefing**

**Target:** [Target name and domain]
**Last session:** [Date/time of checkpoint]
**Checkpoint age:** [How long ago was this written]

**Picking up at:** [Exact stopping point from checkpoint]

**First action this session:** [Single, specific next step — no ambiguity]

**Open leads:** [Count and one-line summary of each]
**Validated findings:** [Count and severity summary]
**Recon gaps remaining:** [Bullet list]

**Blocked items requiring hunter input:**
[List anything that needs a human decision before proceeding]

---

After producing the briefing, execute the First Action immediately without waiting for hunter confirmation, unless there are blocked items that require input.

---

## Auto-Checkpoint Trigger

Write a checkpoint automatically whenever:
- The hunter says they are stepping away or going to sleep
- A finding is validated (always checkpoint after a Finding is confirmed)
- A major recon phase completes
- Before switching from one target surface to another
- Every 2 hours of autonomous operation

Do not ask permission to write a checkpoint. Just write it.

---

## Guiding Principles

- **The checkpoint is the single source of truth for session state.** Notes files are raw data — the checkpoint is the curated map.
- **Be surgical about the stopping point.** "Testing auth flows" is not a stopping point. "Sent modified request to /api/v2/users/[id] with role=admin, received 403, was about to test with X-Forwarded-For header" is a stopping point.
- **Next session priorities must be actionable immediately.** If a priority requires 10 minutes of setup before any testing can happen, break that setup into its own first step.
- **Findings never leave the checkpoint.** Every validated finding must survive context compaction. If it's not in the checkpoint, it doesn't exist.

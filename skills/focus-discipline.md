---
name: focus-discipline
description: Recalibrate hunt focus when the session has stalled, is looping on a single surface, or has drifted from the hypothesis queue. Converts confirmed findings and recent failures into forward momentum by extracting lesson material and redeploying it as new hypotheses. Trigger on phrases like "I'm stuck", "what should I focus on", "recalibrate", "focus discipline", "I keep testing the same thing", "what's next", or when autonomous operation shows signs of fixation.
---

# Focus Discipline Skill

Fixation is the hunter's most expensive failure mode. It doesn't look like giving up — it looks like diligence. You're still working, still sending requests, still reading responses. But you're orbiting a surface that has already given you everything it's going to give, and the rest of the target is going untested.

This skill breaks the loop. It reads current session state, diagnoses what's happening, and produces a concrete next action that is not the thing you've been doing.

---

## Step 1 — Read Current State

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH
TARGET_DIR=~/bugbounty/$TARGET

echo "=== Open Leads ==="
cat "$TARGET_DIR/leads.md" 2>/dev/null | tail -60

echo ""
echo "=== Validated Findings ==="
cat "$TARGET_DIR/findings.md" 2>/dev/null

echo ""
echo "=== Recent Notes (last 40 lines) ==="
tail -40 "$TARGET_DIR/notes/notes.md" 2>/dev/null

echo ""
echo "=== Last Checkpoint ==="
head -30 "$TARGET_DIR/session-checkpoint.md" 2>/dev/null
ENDSSH
```

Read all output before continuing.

---

## Step 2 — Fixation Diagnosis

After reading state, answer these questions internally:

| Signal | Present? |
|---|---|
| Same endpoint retried >5 times with minor variations | yes / no |
| No new lead opened in the last 45 minutes | yes / no |
| Notes reference the same URL >10 times in recent entries | yes / no |
| Hypothesis queue has untested items that have been skipped | yes / no |
| A confirmed finding is being re-examined instead of closed | yes / no |
| The session has been on one attack class for >90 minutes with no progress | yes / no |

If 2 or more signals are present: **fixation confirmed**. Proceed to Step 3.

If 0–1 signals are present: state the current focus is healthy. Identify the next hypothesis from the queue and resume.

---

## Step 3 — Inventory What Has Been Confirmed

List every confirmed finding and every ruled-out lead from this session:

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH
TARGET_DIR=~/bugbounty/$TARGET

echo "=== Confirmed Findings ==="
grep -h "^##\|^- \[FINDING\]\|Finding:" "$TARGET_DIR/findings.md" 2>/dev/null

echo ""
echo "=== Ruled Out Leads ==="
grep -h "ruled out\|not vulnerable\|false positive\|N/A\|no issue" \
  "$TARGET_DIR/leads.md" "$TARGET_DIR/notes/notes.md" 2>/dev/null | tail -20
ENDSSH
```

For each confirmed finding, ask:
- What developer assumption did this confirm?
- What other endpoints share that assumption?

For each ruled-out lead, ask:
- Why was it not vulnerable?
- What does that tell me about how this application validates or trusts input?

Write the answers as notes — they are the raw material for Step 4.

---

## Step 4 — Extract Lesson Material and Convert to Leads

Lesson material is any confirmed signal about *how this application works* — its trust model, its validation logic, its developer habits. Every confirmed finding and every negative result carries it.

**Conversion process:**

For each piece of lesson material:
1. State the confirmed behavior in one sentence (not the bug — the underlying assumption or pattern)
2. List 2–3 other surfaces that plausibly share the same behavior
3. State what a test would look like on each of those surfaces

Write every output of this process as a Lead:

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
TARGET_DIR=~/bugbounty/$TARGET

cat >> "$TARGET_DIR/leads.md" << 'EOF'

## Leads from Focus Discipline recalibration — DATE_PLACEHOLDER
### Lesson: [ONE-SENTENCE BEHAVIOR CONFIRMED]
- [ ] [Surface 1] — [what to test and why the same pattern may apply]
- [ ] [Surface 2] — [what to test and why]
- [ ] [Surface 3] — [what to test and why]
EOF

echo "[*] New leads written. Proceed with the first unchecked item."
ENDSSH
```

Replace `DATE_PLACEHOLDER` and the lead content with actual values before writing.

---

## Step 5 — Hard Stop on the Current Surface

Whatever surface triggered the fixation diagnosis: **stop testing it now**.

- Add a note: `[PAUSED — focus-discipline recalibration — $(date)] Retesting this surface later with fresh recon is allowed. Not before.`
- Do not return to this surface in the current session unless new recon (a new endpoint, a new parameter, a new behavioral signal) provides a genuinely different angle.

This is not giving up. A surface that has been tested systematically and yielded nothing is a closed surface. Closed surfaces are not failures — they are completed work. The hypothesis queue is what matters.

---

## Step 6 — Pick the Next Action and Execute

From the current open leads (including any just created in Step 4), select the highest-priority untested item:

**Priority order:**
1. Any lead generated from lesson material in this session (freshest signal)
2. Any hypothesis from `/hypothesis-agent` that hasn't been touched
3. Any recon gap (a workflow that wasn't completed — js-analysis, api-surface, etc.)
4. A new surface in scope that hasn't been looked at at all

State the chosen next action explicitly:

```
Next action: [Exact description — endpoint, tool, test technique]
Reason: [Why this is the highest-priority item right now]
Expected output: [What a positive result looks like — what response, behavior, or state change would constitute a signal]
Time box: 45 minutes
```

Execute immediately after stating this. Do not re-read old notes first. Do not re-verify old findings. Start the next action.

---

## The Core Principle

A confirmed finding is not a finish line. It is a flashlight — it illuminates the developer's thinking, the application's trust model, the team's habits. Point the flashlight at the next dark corner and keep moving.

A ruled-out lead is not a failure. It is a data point. It tells you what this application *does* validate, which tells you where to look for what it *doesn't*.

The only real failure mode is staying in one place. Stay mobile.

---

## Guiding Principles

- **Lesson material is the most valuable recon you have.** It comes from the target itself, not from passive tools. Use it aggressively.
- **A finding that is documented and queued for reporting is done.** Your job at that moment is to move to the next hypothesis — not to polish, re-verify, or celebrate.
- **Negative results are forward motion in disguise.** A surface that doesn't yield a bug tells you what the application gets right — and that tells you where it probably gets something wrong.
- **The hypothesis queue is the heartbeat of the hunt.** If the queue is empty, you are not recalibrating — you need to run `/hypothesis-agent` again with updated recon.
- **Time-box everything.** 45 minutes on a hypothesis. If it yields nothing testable, it gets paused and replaced. Not abandoned — paused. You can return with new recon. Not the same requests.

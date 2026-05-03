---
name: preflight-check
description: Verify that all required tools, directories, and configurations are in place before starting a bug bounty session. Run this at the start of every new session or when switching targets. Trigger on phrases like "preflight", "check tools", "am I ready to hunt", "setup check", "verify environment", or automatically at the start of any new engagement before any recon or testing begins.
---

# Preflight Check Skill

A session that starts with missing tools fails silently. A scan that runs but produces no output because a binary isn't found wastes hours. This skill verifies the full environment before any recon or testing begins and produces a clear GO / NO-GO decision.

Run this before every session. It takes under 30 seconds.

---

## Step 1 — Verify SSH Connectivity

All commands run on Kali over SSH. Verify the connection is alive first:

```bash
ssh -o ConnectTimeout=5 user@$KALI_IP 'echo "SSH OK: $(hostname)"'
```

If this fails: stop. Everything else depends on SSH. Do not proceed until connectivity is restored. Notify the hunter.

---

## Step 2 — Tool Inventory Check

Run on Kali via SSH. Check every tool used across all skills and recon workflows:

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'

PASS=""
FAIL=""
WARN=""

check_tool() {
  local name=$1
  local path=$2
  local required=$3  # "required" or "optional"
  if [ -x "$path" ]; then
    PASS="$PASS\n  [OK] $name ($path)"
  elif command -v $name &>/dev/null; then
    PASS="$PASS\n  [OK] $name ($(which $name))"
  else
    if [ "$required" = "required" ]; then
      FAIL="$FAIL\n  [MISSING] $name — expected at $path"
    else
      WARN="$WARN\n  [WARN] $name not found — optional but recommended"
    fi
  fi
}

echo "=== Recon Tools ==="
check_tool "subfinder"    "/home/kali/go/bin/subfinder"    required
check_tool "waybackurls"  "/home/kali/go/bin/waybackurls"  required
check_tool "katana"       "/home/kali/go/bin/katana"        required
check_tool "dnsx"         "/home/kali/go/bin/dnsx"          required
check_tool "httpx"        "/home/kali/go/bin/httpx"         required
check_tool "getallurls"   "/usr/bin/getallurls"             optional
check_tool "amass"        "/home/kali/go/bin/amass"         optional

echo "=== HTTP / Exploitation Tools ==="
check_tool "curl"         "/usr/bin/curl"                   required
check_tool "python3"      "/usr/bin/python3"                required
check_tool "jq"           "/usr/bin/jq"                     required
check_tool "ffuf"         "/home/kali/go/bin/ffuf"          optional
check_tool "nuclei"       "/home/kali/go/bin/nuclei"        optional
check_tool "nikto"        "/usr/bin/nikto"                  optional

echo "=== System Utilities ==="
check_tool "wget"         "/usr/bin/wget"                   required
check_tool "git"          "/usr/bin/git"                    required
check_tool "grep"         "/usr/bin/grep"                   required
check_tool "sed"          "/usr/bin/sed"                    required
check_tool "awk"          "/usr/bin/awk"                    required
check_tool "md5sum"       "/usr/bin/md5sum"                 required

echo ""
if [ -n "$PASS" ]; then
  echo "INSTALLED:"
  echo -e "$PASS"
fi
if [ -n "$WARN" ]; then
  echo ""
  echo "OPTIONAL (missing):"
  echo -e "$WARN"
fi
if [ -n "$FAIL" ]; then
  echo ""
  echo "MISSING (required):"
  echo -e "$FAIL"
fi

ENDSSH
```

---

## Step 3 — Directory Structure Check

Verify the bug bounty working directory exists and has the expected layout for the current target:

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH

TARGET_DIR=~/bugbounty/$TARGET

echo "=== Directory Structure ==="

check_dir() {
  if [ -d "$1" ]; then
    echo "  [OK] $1"
  else
    echo "  [CREATE] $1"
    mkdir -p "$1"
  fi
}

check_file() {
  local path=$1
  local label=$2
  if [ -f "$path" ]; then
    echo "  [OK] $path ($label)"
  else
    echo "  [MISSING] $path — $label"
  fi
}

check_dir ~/bugbounty
check_dir $TARGET_DIR
check_dir $TARGET_DIR/notes
check_dir $TARGET_DIR/recon
check_dir $TARGET_DIR/recon/subdomains
check_dir $TARGET_DIR/recon/js
check_dir $TARGET_DIR/recon/api
check_dir $TARGET_DIR/leads
check_dir $TARGET_DIR/findings
check_dir $TARGET_DIR/reports
check_dir $TARGET_DIR/intel

echo ""
echo "=== Required Config Files ==="
check_file $TARGET_DIR/scope.md "program scope definition"
check_file ~/bugbounty/lessons-learned.md "global lessons log"

# Create lessons-learned.md if it doesn't exist
if [ ! -f ~/bugbounty/lessons-learned.md ]; then
  echo "# Lessons Learned" > ~/bugbounty/lessons-learned.md
  echo "Created ~/bugbounty/lessons-learned.md"
fi

ENDSSH
```

---

## Step 4 — Session Checkpoint Check

Check whether a prior session checkpoint exists for this target:

```bash
ssh user@$KALI_IP "ls -la ~/bugbounty/$TARGET/session-checkpoint.md 2>/dev/null && \
  echo '' && \
  echo 'Last checkpoint:' && \
  head -5 ~/bugbounty/$TARGET/session-checkpoint.md || \
  echo '[NEW] No session checkpoint found — this is a fresh engagement'"
```

If a checkpoint exists: offer to run `/session-resume` before proceeding with any new work.

---

## Step 5 — Network Sanity Check

Verify Kali has outbound internet access (required for passive recon tools):

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'

echo "=== Network Checks ==="

# DNS resolution
if host google.com &>/dev/null; then
  echo "  [OK] DNS resolution working"
else
  echo "  [FAIL] DNS resolution broken — passive recon tools will fail"
fi

# HTTPS outbound
if curl -sk --max-time 5 https://crt.sh -o /dev/null; then
  echo "  [OK] HTTPS outbound (crt.sh reachable)"
else
  echo "  [WARN] crt.sh unreachable — subdomain enum via certificate transparency will fail"
fi

# Wayback Machine
if curl -sk --max-time 5 https://web.archive.org -o /dev/null; then
  echo "  [OK] Wayback Machine reachable"
else
  echo "  [WARN] Wayback Machine unreachable — waybackurls output will be empty"
fi

ENDSSH
```

---

## Step 6 — GO / NO-GO Decision

After all checks complete, produce a single verdict:

---

### Preflight Result

**Verdict:** GO / NO-GO / GO WITH WARNINGS

**GO** — All required tools present, directories created, SSH live, network healthy.

**NO-GO** — One or more required tools missing or SSH unreachable. List exactly what must be fixed:
```
Required actions before hunting:
1. [Specific fix]
2. [Specific fix]
```

**GO WITH WARNINGS** — All required tools present but optional tools missing or network warnings exist. List warnings and note which recon workflows will be affected:
```
Warnings (non-blocking):
- [tool] missing — [which workflow is affected]
- [network issue] — [which step will fail]
```

**Prior session detected:** [Yes — run /session-resume to continue / No — fresh engagement]

**Scope file:** [Loaded / MISSING — paste program scope before hunting]

**First recommended action:** [Single next step: run /session-resume, define scope, or begin /subdomain-enum]

---

## Install Snippets for Missing Tools

If required Go-based tools are missing, provide the install command immediately:

```bash
# Install all Go-based recon tools at once
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

```bash
# Install system tools
sudo apt-get install -y curl wget jq python3 git nikto
```

---

## Guiding Principles

- **Never start a session without running preflight.** A missing tool that fails silently wastes the entire overnight run.
- **Create missing directories automatically.** Don't ask — just create them and note it in the output.
- **A missing scope file is a NO-GO.** Testing without a loaded scope is the fastest path to an out-of-scope submission or program violation.
- **If a prior checkpoint exists, always offer /session-resume.** Starting fresh when half a hunt is already documented wastes all prior recon.
- **Provide fix commands immediately.** Don't just report missing tools — give the exact install command so the hunter can fix and re-run in one step.

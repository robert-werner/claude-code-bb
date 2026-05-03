# claude-code-bb

CLAUDE.md configurations, custom skills, and recon workflows for bug bounty hunting with Claude Code.  
Built and documented as part of the LoganSec bug bounty journey.

## How to use

Drop `CLAUDE.md` into the root of whatever directory you're running Claude Code from.  
Skills go in a `/skills` folder. Recon workflows go in a `/recon` folder in the same directory.

For a brand new target, just say **"start a new engagement on [target]"** — `/new-engagement` handles the rest.

Adapt everything. These are my configs — your hunting style will be different.

---

## Session Flow

CLAUDE.md enforces this order every session:

```
preflight-check
  → new-engagement (first time) or session-resume (returning)
      → [new-engagement runs internally:]
          program-intelligence → scope-checker → subdomain-enum
      → js-analysis → api-surface
          → hypothesis-agent
              → idor-hunter / dotnet-hunter / manual testing
                  → report-draft → triager → submit
                      → triage-debrief (after every closure)
```

---

## Skills

| Skill | What it does |
|---|---|
| `skills/preflight-check.md` | Verifies SSH connectivity, all required tools, directory structure, and network health before any session starts. Produces a GO / NO-GO verdict with install commands for anything missing |
| `skills/new-engagement.md` | One-command onboarding for a new target — chains preflight, program intelligence, scope initialization, and subdomain enumeration in sequence. Pauses at blocking failures and requires scope confirmation before recon begins |
| `skills/program-intelligence.md` | Pre-hunt research — analyzes disclosed reports, builds a triager behavior profile, maps gap surfaces with no prior disclosures, and generates a tiered hunt priority map |
| `skills/scope-checker.md` | Loads the program scope and classifies any asset as IN SCOPE / OUT OF SCOPE / PASSIVE ONLY before active testing. Hard stops on third-party infrastructure and ambiguous assets |
| `skills/hypothesis-agent.md` | Reads all recon files for a target and generates 5–10 specific, non-obvious attack hypotheses with test steps, uniqueness scores, and a duplicate-risk adversarial review |
| `skills/idor-hunter.md` | Systematic IDOR workflow covering 7 attack vectors. Enforces two-account setup, validates actual victim data exposure (not just a 200), and produces a submission-ready PoC |
| `skills/dotnet-hunter.md` | Comprehensive .NET/ASP.NET skill — fingerprints the stack (WebForms, MVC, Core, WCF, IIS), maps .NET-specific attack surface, and systematically tests ViewState MAC, Telerik CVEs, ELMAH/trace exposure, machineKey leaks, IIS tilde enumeration, and ASP.NET Core routing bypasses |
| `skills/triager.md` | Pre-submission critique — simulates a real Bugcrowd triager, runs N/A pattern detection, validates the impact chain, calibrates severity, and produces a Submit / Fix / Do Not Submit verdict |
| `skills/report-draft.md` | Formats a validated finding into a clean, submission-ready report |
| `skills/session-resume.md` | Two-mode skill: WRITE generates a full session checkpoint (recon status, open leads, findings, exact stopping point), READ consumes it and resumes immediately. Auto-writes every 2 hours and after every validated finding |
| `skills/triage-debrief.md` | Post-mortem for closed reports — extracts root cause, generates actionable rules, detects recurring failure patterns, and appends lessons to `~/bugbounty/lessons-learned.md` |

---

## Recon Workflows

Run in this order for a new target. Each workflow feeds into the next.

| Workflow | What it does |
|---|---|
| `recon/subdomain-enum.md` | Multi-source passive subdomain discovery (subfinder + waybackurls + crt.sh in parallel), DNS resolution with dnsx, HTTP probing with httpx, tier-1 priority scoring, and subdomain takeover candidate detection via CNAME analysis |
| `recon/js-analysis.md` | Downloads all JS bundles for a target, extracts API endpoints and routes, scans for exposed secrets and API keys, detects feature flags and `process.env` leaks, and identifies GraphQL operations |
| `recon/api-surface.md` | Discovers Swagger/OpenAPI spec files, mines Wayback Machine for historical API endpoints, crawls with katana, classifies endpoints by interest level, detects versioned routes, and tests GraphQL introspection |

After all three complete, run `/hypothesis-agent ~/bugbounty/$TARGET` to generate attack hypotheses from the combined output.

---

## File Tree

```
claude-code-bb/
├── CLAUDE.md                      # Master config — session lifecycle, rules, skill index
├── CONTRIBUTING.md                # How to write new skills and recon workflows
├── skills/
│   ├── preflight-check.md         # Environment and tool verification
│   ├── new-engagement.md          # Full onboarding chain for a new target
│   ├── program-intelligence.md    # Pre-hunt program research
│   ├── scope-checker.md           # In-scope / out-of-scope classification
│   ├── hypothesis-agent.md        # Attack hypothesis generation from recon
│   ├── idor-hunter.md             # Systematic IDOR testing workflow
│   ├── dotnet-hunter.md           # .NET/ASP.NET/IIS fingerprinting and vulnerability hunting
│   ├── triager.md                 # Pre-submission report critique
│   ├── report-draft.md            # Finding → submission-ready report
│   ├── session-resume.md          # Session checkpoint write/read
│   └── triage-debrief.md          # Post-closure lessons extraction
└── recon/
    ├── subdomain-enum.md          # Subdomain discovery and prioritization
    ├── js-analysis.md             # JavaScript bundle mining
    └── api-surface.md             # API endpoint discovery and classification
```

---

## More

📺 [LoganSec](https://www.youtube.com/@Logan-sec)  
𝕏 [@LoganOpSec](https://x.com/LoganOpSec)  
🐛 One hunter's bug bounty journey; documented as it happens.

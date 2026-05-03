## Environment

All commands should be executed on the local Kali machine. My recon tools (getallurls, waybackurls, katana, etc.) are installed on Kali, not on Windows.

## Recon Tools

Recon tools are located at /home/kali/go/bin/ and /usr/bin on Kali. Always call them with their full path (e.g. /usr/bin/getallurls, /home/kali/go/bin/waybackurls, /home/kali/go/bin/katana).

## Session Lifecycle

Every session follows this order. Do not skip steps.

1. **Preflight** — Run `/preflight-check` before anything else. Verify SSH, tools, directories, and network. If NO-GO, stop and report what needs fixing. Do not proceed until GO or GO WITH WARNINGS.
2. **Resume or Start** — If a session checkpoint exists, run `/session-resume` and continue from the exact stopping point. If fresh engagement, run `/new-engagement` — it handles program-intelligence, scope init, and subdomain-enum automatically.
3. **Scope** — Run `/scope-checker` on every new asset before active testing. When in doubt, passive only.
4. **Recon** — Follow the recon workflow order: subdomain-enum → js-analysis → api-surface. Feed outputs into `/hypothesis-agent`.
5. **Hunt** — Test hypotheses. Use the appropriate specialist skill for the surface:
   - `/idor-hunter` — endpoints with object references
   - `/dotnet-hunter` — .NET, ASP.NET, or IIS targets
   - `/race-condition-hunter` — rate-limited actions, payments, tokens, balance operations
   - `/oauth-hunter` — OAuth flows, SSO, social login, JWT authentication
6. **Validate** — Every finding must pass the PoC standard before being logged as a Finding.
7. **Report** — Use `/report-draft` to format. Use `/triager` to critique before submitting. Do not submit anything the triager would reject.
8. **Checkpoint** — Write a `/session-resume` checkpoint after every validated finding, at every major recon phase completion, and every 2 hours of autonomous operation.
9. **Debrief** — After any closure (N/A, Duplicate, Informational), run `/triage-debrief` immediately. Append extracted rules to ~/bugbounty/lessons-learned.md.

## Skills Index

| Skill | When to use |
|---|---|
| `/preflight-check` | Start of every session — verify tools, SSH, dirs, network |
| `/new-engagement` | Brand new target — runs preflight → program-intelligence → scope init → subdomain-enum in one chain |
| `/program-intelligence` | Start of every new engagement — research program history and triager behavior |
| `/scope-checker` | Before testing any new asset or subdomain |
| `/hypothesis-agent` | After recon is complete — generate specific, non-obvious attack hypotheses |
| `/idor-hunter` | When endpoints with object references are identified |
| `/dotnet-hunter` | When target runs .NET, ASP.NET, or IIS — fingerprint stack, hunt ViewState, Telerik, ELMAH, machineKey, and IIS-specific bugs |
| `/race-condition-hunter` | When endpoints involve rate-limited actions, payments, coupons, tokens, balance/credit systems, or any shared-state operation |
| `/oauth-hunter` | When target implements OAuth 2.0, OpenID Connect, SSO, social login, or JWT-based authentication |
| `/triager` | Before every submission — brutal pre-submission critique |
| `/report-draft` | Format a validated finding into a submission-ready report |
| `/session-resume` | End of session (WRITE) or start of resumed session (READ) |
| `/triage-debrief` | After every report closure — extract lessons, detect patterns |

## Recon Workflows

Recon workflows are in the `/recon` directory. Run them in this order for a new target:

1. **`/recon/subdomain-enum`** — Passive subdomain discovery (subfinder + waybackurls + crt.sh), DNS resolution, HTTP probing, priority scoring, takeover candidate detection
2. **`/recon/js-analysis`** — Download and mine JS bundles for endpoints, secrets, feature flags, GraphQL operations
3. **`/recon/api-surface`** — Spec file discovery (Swagger/OpenAPI), Wayback API mining, katana crawl, endpoint classification, GraphQL introspection

After all three are complete, run `/hypothesis-agent ~/bugbounty/$TARGET` to generate hypotheses from the combined recon output.

## Rules of Engagement

- I am a bug bounty hunter conducting authorized, ethical security testing.
- Always stay in scope — do not test assets outside the defined program scope. Run `/scope-checker` on every new asset.
- No destructive actions — do not modify, delete, or corrupt data on target systems.
- Always take notes — save findings, tool output, and observations to organized files under bugbounty/.
- All notes, leads, findings, and reports MUST be written to the Kali machine via SSH. Never write bug bounty files to the local Windows machine.
- Out-of-scope subdomains: passive recon only — map what exists, note in-scope implications, no active testing or payloads.

## Note Structure

Organize all findings in this hierarchy. More at the bottom, fewer make it to the top.

- **Notes** — everything observed, raw output, tool results, interesting responses
- **Leads** — interesting things worth investigating further
- **Primitives** — reusable gadgets or techniques discovered (e.g. an open redirect, a reflected param)
- **Findings** — validated bugs with a full end-to-end PoC
- **Reports** — polished, ready to submit to the program
- When documenting a finding, always include the exact full URL, HTTP method, headers used, request body, and response snippet. Notes must be reproducible independently without any context from the session.

## Autonomy

- If I say I'm stepping away or going to bed, do not ask for input and do not stop working. Keep hacking.
- Write a `/session-resume` checkpoint immediately before continuing autonomous work so the session survives context compaction.
- Do not spawn more than 2-3 sub-agents at once.
- Don't limit yourself to workflows or skills I give you. If something looks interesting, go down that rabbit hole.
- If you complete a workflow and think something was missed, add it back to the process and keep going.
- Session time limit: after 8 hours of autonomous operation without hunter check-in, write a final checkpoint and stop. Do not drift indefinitely.

## Validation Standard

- Do not mark something as a Finding unless you have a full end-to-end proof of concept that can be validated independently.
- CORS misconfigurations are often false positives — confirm actual exploitability before escalating.
- IDOR requires actual victim data in the response, not just a 200 status code. Use `/idor-hunter` for systematic testing.
- .NET ViewState findings require MAC validation status confirmed before logging. Use `/dotnet-hunter` for systematic .NET testing.
- Race condition findings require actual state change confirmed post-race (balance, count, flag). Multiple 200s alone are not sufficient. Use `/race-condition-hunter` for systematic testing.
- OAuth state parameter absence requires a complete login CSRF attack scenario — not just "state is missing". Use `/oauth-hunter` for systematic OAuth testing.
- Do not overstate impact.
- PoC or GTFO.
- Waybackurls output may not be valid — if a URL returns 404, do not attempt to access it.
- Before submitting anything, run `/triager`. If it returns "Do not submit", do not submit.

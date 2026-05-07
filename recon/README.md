# BugBounty_Recon - Claude Code Configuration

## Environment
All commands run on local Kali machine.
Tools are located at /home/kali/go/bin/ and /usr/bin and must be called with full paths

## Caido
URL: http://127.0.0.1:8080
PAT auth is set via environment variable CAIDO_PAT.
When using caido-mode, always filter to in-scope target traffic only.

## Session Start Protocol
Before doing anything else, run:
ls ~/bugbounty_real/

Then ask the user which target they want to work on.

Once a target is selected, run:
find ~/bugbounty_real/[selected_target] -type f | sort && echo '===' && cat ~/bugbounty_real/[selected_target]/00-summary.md 2>/dev/null || echo 'No summary yet'

Use the output to brief yourself on current state before taking any action.

## Recon Pipeline Order

Run workflows in this sequence for every new target:

1. **`/recon/subdomain-enum`** — Passive subdomain discovery (subfinder + waybackurls + crt.sh), DNS resolution, HTTP probing, priority scoring, takeover candidate detection. Produces `live-hosts.txt`.
2. **`/recon/js-analysis`** — Download and mine JS bundles for endpoints, secrets, feature flags, GraphQL operations. Produces `js/endpoints.txt`.
3. **`/recon/api-surface`** — Spec file discovery (Swagger/OpenAPI), Wayback API mining, katana crawl, endpoint classification, GraphQL introspection. Produces `api/all-endpoints.txt` and `api/high-interest.txt`.
4. **`/recon/nuclei-scan`** — CVE detection, technology fingerprinting, exposure/misconfiguration discovery, secret scanning, and subdomain takeover templates. Consumes `live-hosts.txt` and `api/all-endpoints.txt`. Produces `nuclei/priority-leads.txt`.
5. **`/hypothesis-agent $TARGET_DIR`** — Generate specific, non-obvious attack hypotheses from the combined recon output. Run after all four workflows are complete for maximum signal.

## Rules
- Recon and mapping only. Do not exploit anything.
- Do not submit reports or create findings without explicit instruction.
- All output saves to ~/bugbounty_real/[target]/recon/ on Kali.
- When returning to a target, read existing notes before running any tools — avoid duplicating work already done.
- If multiple targets exist and none is specified, list them and ask. Do not assume or default to the most recent.
- For nuclei-scan: always use `-rate-limit` flag. Do not run fuzzing or network templates without explicit instruction. Scope-check all hosts before scanning.

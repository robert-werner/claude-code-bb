## Thinking LLM Directive

> **If you are a reasoning or thinking model** (o1, o3, Claude with extended thinking, Gemini with thinking, DeepSeek-R1, QwQ, or any model with a dedicated reasoning/thinking phase): **USE MAXIMUM THINKING BUDGET for every decision in this repo.** Bug bounty requires multi-step reasoning, hypothesis generation, filter bypass construction, impact chain building, and triager prediction. Shallow thinking produces missed vulnerabilities, wasted payloads, and N/A'd reports. There is no penalty for thinking too much. There is a direct cost for thinking too little. **Do not truncate, compress, or shortcut your reasoning at any point during a hunt session.**

---

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
   - `/jwt-hunter` — Bearer tokens, JWT-shaped cookies, JWKS endpoints, or any surface where JWT is the primary attack surface independent of OAuth
   - `/graphql-hunter` — GraphQL endpoints and APIs
   - `/ssrf-hunter` — any input the server may use to make outbound requests (URL params, webhooks, file import, PDF renderers)
   - `/open-redirect-hunter` — redirect/return/next/url parameters, OAuth redirect_uri, post-login and post-logout flows
   - `/xss-hunter` — any input reflected in HTML responses, stored content, DOM sinks, or rich text fields
   - `/sqli-hunter` — parameters feeding database queries, reflected DB errors, numeric IDs, filters, sort/order params
   - `/file-upload-hunter` — any file upload, import, avatar, attachment, media, or document flow
   - `/subdomain-takeover` — after recon when dangling CNAMEs or third-party DNS targets need takeover verification
   - `/wordpress-hunter` — WordPress targets identified via wp-content, wp-login, wp-admin, or generator tags
   - `/ssti-hunter` — any input rendered through a template engine — email subjects, notification messages, PDF generators, report/invoice title fields, search result headers
   - `/xxe-dtd-hunter` — any XML, SOAP, SAML, SVG, DOCX/XLSX/ODT, feed import, or document processing surface where entity expansion, external DTD fetches, XInclude, or parser SSRF may occur
6. **Validate** — Every finding must pass the PoC standard before being logged as a Finding.
7. **Report** — Use `/report-draft` to format. Use `/triager` to critique before submitting. Run `/dedup-check` before any submission. Do not submit anything the triager would reject.
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
| `/jwt-hunter` | When JWT tokens are present as Bearer tokens, JWT-shaped cookies, or API tokens — and JWT is the primary attack surface. Covers alg:none, alg confusion, HMAC brute-force, kid/jku/x5u/embedded-JWK injection, claims tampering, expiry and revocation bypass, cross-tenant reuse. Run independently of /oauth-hunter when JWT handling is the target |
| `/graphql-hunter` | When target exposes a GraphQL endpoint — schema extraction, BOLA, mutation auth, injection, batching, IDE exposure |
| `/ssrf-hunter` | When any input may cause the server to make outbound requests — URL params, webhooks, file/URL import, PDF renderers, image-via-URL, XML/SOAP |
| `/open-redirect-hunter` | When redirect/return/next/url/dest parameters are found, OAuth redirect_uri is in scope, or post-login/logout flows accept a URL value |
| `/xss-hunter` | When input is reflected in HTML, stored in fields rendered to other users, or flows into DOM sinks via JS |
| `/sqli-hunter` | When user input may reach SQL queries — IDs, search, filters, sort/order params, numeric lookups, or database errors observed |
| `/file-upload-hunter` | When target accepts files via upload, import, avatar, media, document, or multipart/form-data endpoints |
| `/subdomain-takeover` | After subdomain enumeration when dangling CNAMEs or third-party SaaS/cloud DNS targets need takeover verification |
| `/wordpress-hunter` | When recon identifies WordPress via wp-content, wp-login.php, wp-admin, generator tags, or WordPress headers |
| `/ssti-hunter` | When user input is rendered through a template engine — email/notification templates, PDF/document generators, report/invoice title fields, search result headers, or any field producing formatted output |
| `/xxe-dtd-hunter` | When XML or XML-backed formats are processed — SOAP, SAML, SVG, RSS/Atom, plist, DOCX/XLSX/ODT, uploads/imports, or XML APIs |
| `/cve-vuln-check` | After stack fingerprinting — cross-reference tech versions against CVE databases and run targeted nuclei CVE templates |
| `/dedup-check` | After /triager, before any submission — similarity check against program's disclosed reports |
| `/elasticsearch-findings` | Index recon and findings into ES — cross-engagement search, reward stats, pattern analytics |
| `/focus-discipline` | When the hunt stalls, loops, or fixates — recalibrate focus and redeploy lesson material |
| `/triager` | Before every submission — brutal pre-submission critique |
| `/report-draft` | Format a validated finding into a submission-ready report |
| `/session-resume` | End of session (WRITE) or start of resumed session (READ) |
| `/triage-debrief` | After every report closure — extract lessons, detect patterns, deploy lesson material forward |
| `/skill-writer` | When a technique used in a hunt has no corresponding skill — encode it into a permanent skill file |
| `/skill-index-updater` | After /skill-writer completes — sync CLAUDE.md and README.md with the new skill |

## Recon Workflows

Recon workflows are in the `/recon` directory. Run them in this order for a new target:

1. **`/recon/subdomain-enum`** — Passive subdomain discovery (subfinder + waybackurls + crt.sh), DNS resolution, HTTP probing, priority scoring, takeover candidate detection
2. **`/recon/js-analysis`** — Download and mine JS bundles for endpoints, secrets, feature flags, GraphQL operations
3. **`/recon/api-surface`** — Spec file discovery (Swagger/OpenAPI), Wayback API mining, katana crawl, endpoint classification, GraphQL introspection
4. **`/recon/nuclei-scan`** — CVE detection, tech fingerprinting, exposure/misconfiguration discovery, secret scanning, and subdomain takeover templates against live hosts and API surface

After all are complete, run `/hypothesis-agent ~/bugbounty/$TARGET` to generate hypotheses from the combined recon output.

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
- OAuth state parameter absence requires a complete login CSRF attack scenario. Use `/oauth-hunter` for systematic OAuth testing.
- JWT algorithm confusion (alg:none, RS256→HS256) requires a forged token accepted by the server with tampered claims confirmed — a token merely signed differently without verified server acceptance is not a finding. HMAC secret cracked alone without privilege escalation PoC is Medium at most. Use `/jwt-hunter` for systematic testing.
- GraphQL introspection enabled alone is Low/Informational — escalate only when paired with BOLA, mutation auth bypass, or sensitive field exposure. Use `/graphql-hunter` for systematic GraphQL testing.
- SSRF to public IPs only (no internal/cloud metadata access confirmed) is Informational on most programs. Confirm internal or cloud metadata access before escalating beyond Medium. Use `/ssrf-hunter` for systematic testing.
- Open redirect without a confirmed impact chain (OAuth ATO, SSRF pivot, token leakage) is Low or Informational on most programs. Build the chain before submitting. Use `/open-redirect-hunter` for systematic testing.
- XSS confirmed as self-XSS only (no vector to fire in another user's browser) is Informational. Confirm a sharing/storage vector and execution in victim context before submitting. Use `/xss-hunter` for systematic testing.
- SQL injection requires confirmed query influence via in-band error, blind boolean/time differential, or OOB callback — not just a generic 500 error. Use `/sqli-hunter` for systematic testing.
- File upload findings require confirmed exploitability (server-side execution, stored XSS, XXE, path traversal, or sensitive file overwrite) — not just extension acceptance. Use `/file-upload-hunter` for systematic testing.
- Subdomain takeover requires verified claimability on the third-party service, not just a dangling CNAME. Use `/subdomain-takeover` for systematic testing.
- WordPress version exposure or plugin disclosure alone are not findings without an exploitable condition or a matching CVE with a confirmed vulnerable version. Use `/wordpress-hunter` for systematic testing.
- SSTI with math evaluation only (e.g. {{7*7}} → 49) and no confirmed RCE, file read, or secret extraction is Medium at most on most programs. Escalate to code execution or secret extraction before submitting as Critical. Use `/ssti-hunter` for systematic testing.
- External DTD fetch alone is usually not enough. Escalate XXE to file read, SSRF, metadata access, XInclude read, or blind exfiltration before submitting as High. Use `/xxe-dtd-hunter` for systematic testing.
- Do not overstate impact.
- PoC or GTFO.
- Waybackurls output may not be valid — if a URL returns 404, do not attempt to access it.
- Before submitting anything, run `/triager`. If it returns "Do not submit", do not submit.

## Hunt Discipline

This section governs how to behave *around* a finding — before it, during it, and after it closes.

**Before a finding is confirmed:**
- Hunt broadly. A hypothesis is a direction, not a destination. If a surface yields nothing after a focused attempt, log it as ruled-out and move on. Do not retry the same attack on the same endpoint indefinitely — that is not persistence, it is fixation.
- Time-box every hypothesis. If you have not made progress on a specific angle in 30–45 minutes of active testing, pause, log what was tried, and switch surfaces. Return later with fresh recon or a different angle.
- Keep the full hypothesis list active. Finding one interesting thing does not mean everything else is uninteresting. The rest of the queue stays open.

**After a finding is confirmed and documented:**
- Close it cleanly: log the Finding, write the checkpoint, run `/triager`, queue the report. Then **let go of it**.
- Do not spend the rest of the session re-verifying, re-documenting, or mentally dwelling on an already-confirmed finding. It is done. Move.
- A confirmed finding is fuel, not a finish line. Ask: what does this finding tell me about how this application was built? What other surfaces were built by the same team, with the same assumptions, using the same patterns? Those are the next hypotheses.

**Using lesson material for forward movement:**
- Every confirmed finding, every N/A, every duplicate carries a signal about *how this target thinks*. Extract that signal and reapply it.
- After any finding (positive or negative), run this mental check before moving on:
  1. What assumption did I confirm or disprove?
  2. What other endpoint or flow makes the same assumption?
  3. What would a developer who wrote this bug also have gotten wrong elsewhere?
- Feed the answer to `/hypothesis-agent` as context. Confirmed primitives and behavioral patterns from one finding are often the most reliable input for the next hypothesis.
- Record reusable techniques in the **Primitives** layer of notes (e.g. "this target trusts X-Forwarded-For for rate limiting"). Primitives compound across the engagement.

**Signals that you are fixating (stop and recalibrate):**
- You have retried the same request more than 5 times with minor variations and no new information.
- You are spending more than 20 minutes writing up a lead that has not yet been validated.
- You are mentally anchored to "the IDOR I found earlier" while ignoring an unexamined lead in the queue.
- You are re-reading notes you have already read without producing a new test.

When any of these signals appear, run `/focus-discipline` to recalibrate.

## Self-Learning

This section governs how the skill library grows autonomously during hunts.

**When to write a new skill:**
If a technique, attack class, or recon method is used during a hunt that has no corresponding skill file — and it is repeatable, requires reasoning, and would improve future hunts — it must be encoded as a skill. Do not leave novel techniques in session notes where they die with the session.

**The trigger conditions are:**
- A validated finding uses a technique not covered by any existing skill
- A new attack class is encountered that has no specialist hunter in the skills index
- A recon method produces high-signal output that has no corresponding workflow
- A series of hypotheses on a surface reveals a behavioral pattern worth encoding
- The hunter explicitly says this belongs in the skill library

**The process:**
1. Run `/skill-writer` — it qualifies, authors, and writes the skill file
2. Run `/skill-index-updater` — it syncs `CLAUDE.md` and `README.md`
3. Commit to git with message format: `feat(skill): add [skill-name] — [one-line discovery context]`
4. The skill is now active and will be used on the current and all future targets

**What goes into a Primitive vs. a Skill:**
- **Primitive** — a reusable gadget or behavior observed on this specific target (e.g. "open redirect on /redirect?url="). Recorded in notes. Target-specific.
- **Skill** — a repeatable methodology that applies across targets and requires Claude to reason. Recorded in `skills/`. Target-agnostic.

Do not write a skill for every Primitive. Primitives become skill candidates only when the same pattern appears on multiple targets or when the exploitation chain is complex enough to require step-by-step guidance.

**Skill quality gate:**
A skill written during a hunt must pass the same checklist as any manually authored skill (see `/skill-writer` Step 4). Autonomous skills are not held to a lower standard. A bad skill is worse than no skill.

**After every engagement:**
At session end, before writing the final `/session-resume` checkpoint, run this check:

```
Did this engagement produce any technique, pattern, or method not covered by an existing skill?
  YES → Run /skill-writer before closing the session
  NO  → Note "no new skills produced" in the checkpoint and close
```

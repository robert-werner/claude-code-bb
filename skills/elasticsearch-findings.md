---
name: elasticsearch-findings
description: Index recon output, findings, and nuclei results into Elasticsearch for persistent storage, cross-engagement search, and pattern analytics. Use this to query findings across multiple targets, detect recurring vulnerability patterns, and build Kibana dashboards. Trigger on phrases like "index findings", "search findings in ES", "elasticsearch", "query across targets", "show findings dashboard", or "track findings".
---

# Elasticsearch Findings Skill

Flat text files lose context. You can't query "show me all IDOR findings across every target I've hunted," or "which programs have the most live subdomains," or "what's my hit rate on OAuth bugs." This skill indexes all recon output and findings into Elasticsearch so you can query, filter, and analyze across your entire bug bounty history.

Requires the ES stack from `docker/docker-compose.yml` to be running (`docker compose up -d elasticsearch kibana`).

---

## ES Index Schema

Three indices, each with a `target` field for cross-engagement filtering:

| Index | Contents | Key Fields |
|---|---|---|
| `bb-subdomains` | All discovered subdomains and live hosts | `subdomain`, `target`, `indexed_at` |
| `bb-endpoints` | Crawled URLs, API endpoints, JS-extracted routes | `url`, `target`, `source_file`, `indexed_at` |
| `bb-vulns` | nuclei findings, CVE matches, manual findings | `template-id`, `info.severity`, `host`, `target`, `matched-at` |

A fourth index `bb-findings` is created manually for validated bugs (see Step 4).

---

## Step 1 — Start the ES Stack

```bash
# Start Elasticsearch and Kibana
docker compose -f docker/docker-compose.yml up -d elasticsearch kibana

# Wait for ES to be ready
until curl -sf http://localhost:9200/_cluster/health &>/dev/null; do
  echo "Waiting for Elasticsearch..."
  sleep 5
done
echo "[OK] Elasticsearch is up at http://localhost:9200"
echo "[OK] Kibana is up at http://localhost:5601"
```

If running on Kali (not Docker), install and start ES manually:
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update && sudo apt-get install -y elasticsearch kibana
sudo systemctl start elasticsearch kibana
```

---

## Step 2 — Index Recon Data for Current Target

### Option A: Docker (recommended)

```bash
export TARGET=example.com
TARGET=$TARGET docker compose -f docker/docker-compose.yml \
  --profile load run --rm es-loader
```

### Option B: Direct via SSH to Kali

```bash
ssh user@$KALI_IP 'bash -s' << ENDSSH
TARGET_DIR=~/bugbounty/$TARGET
ES=http://localhost:9200

bulk_index() {
  local index=$1
  local file=$2
  local field=$3

  if [ ! -f "$file" ]; then return; fi

  BULK=""
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    BULK+="{ \"index\": {} }\n"
    BULK+="{ \"$field\": \"$line\", \"target\": \"$TARGET\", \"indexed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" }\n"
  done < "$file"

  echo -e "$BULK" | curl -s -X POST "$ES/$index/_bulk" \
    -H "Content-Type: application/x-ndjson" \
    --data-binary @- | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Indexed: errors={d[\"errors\"]}')"
}

bulk_index "bb-subdomains" "$TARGET_DIR/recon/subdomains/live-hosts.txt" "subdomain"
bulk_index "bb-endpoints"  "$TARGET_DIR/recon/api/katana-crawl.txt"       "url"
bulk_index "bb-endpoints"  "$TARGET_DIR/recon/js/endpoints-extracted.txt" "url"
ENDSSH
```

---

## Step 3 — Index a Validated Finding Manually

Every time a finding is validated, index it into `bb-findings`:

```bash
ssh user@$KALI_IP 'bash -s' << 'ENDSSH'
ES=http://localhost:9200

# Fill these in for each finding
FINDING_JSON=$(cat << 'EOF'
{
  "target":       "$TARGET",
  "program":      "program-name-on-h1-or-bc",
  "vuln_class":   "IDOR",
  "severity":     "high",
  "endpoint":     "/api/v2/users/{id}/profile",
  "parameter":    "id",
  "title":        "IDOR allows accessing any user profile",
  "status":       "draft",
  "duplicate_risk": "low",
  "found_at":     "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "submitted_at": null,
  "outcome":      null,
  "reward":       null,
  "notes":        "Two-account PoC confirmed. User B's data returned with User A's token."
}
EOF
)

curl -s -X POST "$ES/bb-findings/_doc" \
  -H "Content-Type: application/json" \
  -d "$FINDING_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'[+] Indexed finding: id={d[\"_id\"]}')
"
ENDSSH
```

Update the `outcome`, `reward`, and `status` fields after program response:

```bash
# Update outcome after triage (replace DOC_ID with the _id from above)
curl -s -X POST "http://localhost:9200/bb-findings/_update/DOC_ID" \
  -H "Content-Type: application/json" \
  -d '{"doc": {"outcome": "resolved", "reward": 500, "status": "closed"}}'
```

---

## Step 4 — Query Across Engagements

### Find all critical/high nuclei findings across all targets
```bash
curl -s "http://localhost:9200/bb-vulns/_search" -H "Content-Type: application/json" -d '{
  "query": {
    "terms": {"info.severity": ["critical", "high"]}
  },
  "_source": ["target", "host", "template-id", "info.name", "info.severity"],
  "size": 50
}' | python3 -c "import sys,json; [print(h['_source']) for h in json.load(sys.stdin)['hits']['hits']]"
```

### Count findings by vuln class
```bash
curl -s "http://localhost:9200/bb-findings/_search" -H "Content-Type: application/json" -d '{
  "aggs": {
    "by_class": {
      "terms": {"field": "vuln_class.keyword", "size": 20}
    }
  },
  "size": 0
}' | python3 -c "
import sys, json
d = json.load(sys.stdin)
for b in d['aggregations']['by_class']['buckets']:
    print(f"  {b['key']:20} {b['doc_count']} findings")
"
```

### Find all endpoints containing a keyword (e.g. "/admin", "/api/v1")
```bash
KEYWORD="/admin"
curl -s "http://localhost:9200/bb-endpoints/_search" -H "Content-Type: application/json" -d "{
  \"query\": {\"wildcard\": {\"url\": {\"value\": \"*$KEYWORD*\"}}},
  \"_source\": [\"url\", \"target\"],
  \"size\": 100
}" | python3 -c "import sys,json; [print(h['_source']['target']+'\t'+h['_source']['url']) for h in json.load(sys.stdin)['hits']['hits']]"
```

### Show reward and outcome stats
```bash
curl -s "http://localhost:9200/bb-findings/_search" -H "Content-Type: application/json" -d '{
  "aggs": {
    "total_reward":  {"sum":   {"field": "reward"}},
    "avg_reward":   {"avg":   {"field": "reward"}},
    "by_outcome":   {"terms": {"field": "outcome.keyword", "size": 10}},
    "by_severity":  {"terms": {"field": "severity.keyword", "size": 10}}
  },
  "size": 0
}' | python3 -c "
import sys, json
d = json.load(sys.stdin)['aggregations']
print(f'  Total rewards:  ${d[\"total_reward\"][\"value\"] or 0:.0f}')
print(f'  Average reward: ${d[\"avg_reward\"][\"value\"] or 0:.0f}')
print()
print('  Outcomes:')
for b in d['by_outcome']['buckets']: print(f'    {b[\"key\"]:15} {b[\"doc_count\"]}')
print()
print('  By severity:')
for b in d['by_severity']['buckets']: print(f'    {b[\"key\"]:15} {b[\"doc_count\"]}')
"
```

---

## Step 5 — Kibana Dashboard Setup

After data is indexed, import this saved search config into Kibana:

1. Open `http://localhost:5601`
2. Go to **Stack Management → Index Patterns** → create patterns for `bb-*`, `bb-subdomains`, `bb-endpoints`, `bb-findings`, `bb-vulns`
3. Go to **Discover** → select `bb-findings` → add columns: `target`, `vuln_class`, `severity`, `outcome`, `reward`
4. Go to **Dashboard** → **Create** → add these panels:
   - **Pie chart** — `bb-findings` by `vuln_class.keyword`
   - **Bar chart** — `bb-findings` by `outcome.keyword`
   - **Data table** — `bb-vulns` filtered to `critical`/`high`, columns: target, host, template-id, severity
   - **Metric** — `bb-findings` sum of `reward` field
   - **Bar chart** — `bb-subdomains` count by `target.keyword` (how many live hosts per program)

Save the dashboard as **Bug Bounty Overview**.

---

## Step 6 — Cross-Engagement Pattern Detection

After 3+ engagements, run this to detect recurring successful patterns:

```bash
curl -s "http://localhost:9200/bb-findings/_search" -H "Content-Type: application/json" -d '{
  "query": {
    "term": {"outcome.keyword": "resolved"}
  },
  "aggs": {
    "winning_classes": {
      "terms": {"field": "vuln_class.keyword", "size": 10}
    },
    "winning_endpoints": {
      "terms": {"field": "endpoint.keyword", "size": 20}
    }
  },
  "size": 0
}' | python3 -c "
import sys, json
d = json.load(sys.stdin)['aggregations']
print('=== Your Winning Vuln Classes ===')
for b in d['winning_classes']['buckets']:
    print(f'  {b[\"key\"]:20} {b[\"doc_count\"]} resolved findings')
print()
print('=== Your Most Productive Endpoint Patterns ===')
for b in d['winning_endpoints']['buckets']:
    print(f'  {b[\"key\"]:40} {b[\"doc_count\"]} resolved')
"
```

Feed this output to `/hypothesis-agent` as context: "My historically successful patterns are X — generate hypotheses for $TARGET that exploit similar surfaces."

---

## Guiding Principles

- **ES is persistence, not a crutch.** Run `session-resume` checkpoints as usual — ES supplements, doesn't replace, file-based notes.
- **Index after validation, not before.** Raw recon data goes in automatically. Manual findings go in only after PoC is confirmed — you don't want half-formed leads polluting your analytics.
- **One ES instance, all targets.** The `target` field on every document is how you scope queries per program. Don't run separate ES clusters per engagement.
- **Kibana dashboards are optional.** The `curl` queries in Step 4 give you everything without a browser. Kibana is a nice-to-have, not a blocker.
- **Back up the ES volume before wiping containers.** `docker volume ls` → `docker run --rm -v es-data:/data -v $(pwd):/backup alpine tar czf /backup/es-backup.tar.gz /data`

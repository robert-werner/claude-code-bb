---
name: containerized-recon
description: Run the full recon pipeline (subfinder, dnsx, httpx, katana, nuclei) inside Docker containers without modifying the host system. Use when Kali SSH is unavailable, on a fresh machine, or when you want isolated, reproducible recon runs. Trigger on phrases like "containerized recon", "docker recon", "run recon in docker", "no kali available", or "isolated recon".
---

# Containerized Recon Skill

Sometimes there's no Kali box. Sometimes you want recon that runs identically on any machine without installing a single Go binary. This skill runs the complete recon pipeline — subdomain discovery, DNS resolution, HTTP probing, crawling, and CVE scanning — inside Docker containers, writing all output to `./recon-data/` on the host.

All tool images are official ProjectDiscovery images. No custom image builds required.

---

## Prerequisites

```bash
# Verify Docker and Compose are available
docker --version        # requires 24.x or later
docker compose version  # requires Compose v2
```

If Docker is missing, install it:
```bash
curl -fsSL https://get.docker.com | sh
```

All recon output lands in `./recon-data/` relative to where you run the commands. Create it first:

```bash
mkdir -p ./recon-data/subdomains ./recon-data/api ./recon-data/js ./recon-data/vulns
export TARGET=example.com
```

---

## Step 1 — Subdomain Discovery

```bash
# Passive subdomain enumeration
docker compose -f docker/docker-compose.yml run --rm subfinder \
  -d $TARGET \
  -o /recon/subdomains/subdomains-raw.txt \
  -all -silent

echo "[*] Found $(wc -l < ./recon-data/subdomains/subdomains-raw.txt) subdomains"
```

---

## Step 2 — DNS Resolution

```bash
docker compose -f docker/docker-compose.yml run --rm dnsx \
  -l /recon/subdomains/subdomains-raw.txt \
  -o /recon/subdomains/subdomains-resolved.txt \
  -silent

echo "[*] Resolved $(wc -l < ./recon-data/subdomains/subdomains-resolved.txt) live subdomains"
```

---

## Step 3 — HTTP Probing

```bash
docker compose -f docker/docker-compose.yml run --rm httpx \
  -l /recon/subdomains/subdomains-resolved.txt \
  -o /recon/subdomains/live-hosts.txt \
  -title -tech-detect -status-code \
  -silent

echo "[*] HTTP-alive hosts: $(wc -l < ./recon-data/subdomains/live-hosts.txt)"
```

---

## Step 4 — Endpoint Crawl

```bash
docker compose -f docker/docker-compose.yml run --rm katana \
  -list /recon/subdomains/live-hosts.txt \
  -o /recon/api/katana-crawl.txt \
  -d 3 -jc -silent

echo "[*] Endpoints discovered: $(wc -l < ./recon-data/api/katana-crawl.txt)"
```

---

## Step 5 — CVE / Nuclei Scan

```bash
# Update templates first (runs inside container, persisted in named volume)
docker compose -f docker/docker-compose.yml run --rm nuclei -update-templates -silent

# Scan against live hosts
docker compose -f docker/docker-compose.yml run --rm nuclei \
  -l /recon/subdomains/live-hosts.txt \
  -tags cve \
  -severity critical,high,medium \
  -c 10 \
  -o /recon/vulns/nuclei-cve-raw.txt \
  -json-export /recon/vulns/nuclei-cve.json \
  -silent

echo "[*] Nuclei findings: $(wc -l < ./recon-data/vulns/nuclei-cve-raw.txt 2>/dev/null || echo 0)"
```

---

## Step 6 — Index Results into Elasticsearch (Optional)

Spin up Elasticsearch + Kibana, then run the loader:

```bash
# Start ES + Kibana
docker compose -f docker/docker-compose.yml up -d elasticsearch kibana

# Wait for ES to be healthy (~30s), then load all recon data
TARGET=$TARGET docker compose -f docker/docker-compose.yml \
  --profile load run --rm es-loader

echo "[*] Kibana: http://localhost:5601"
echo "[*] Elasticsearch: http://localhost:9200"
```

See `/elasticsearch-findings` skill for querying and dashboarding.

---

## Recon Output Structure

```
./recon-data/
├── subdomains/
│   ├── subdomains-raw.txt       # raw subfinder output
│   ├── subdomains-resolved.txt  # DNS-validated subdomains
│   └── live-hosts.txt           # HTTP-probed live hosts with tech fingerprints
├── api/
│   └── katana-crawl.txt         # crawled endpoints
├── js/
└── vulns/
    ├── nuclei-cve-raw.txt       # plain-text nuclei output
    └── nuclei-cve.json          # structured JSON for ES ingestion
```

---

## Guiding Principles

- **All output is on the host at `./recon-data/`.** Nothing is lost when containers stop.
- **Scope check before every active step.** Run `/scope-checker` before httpx, katana, or nuclei runs. Subfinder and dnsx are passive — they're always safe.
- **`network_mode: host` gives containers real internet access** on Linux. On macOS/Windows Docker Desktop, remove it and expose ports explicitly if needed.
- **nuclei template volume is persistent.** Templates are not re-downloaded on every run — just updated. First run may take a few minutes.
- **For multi-target engagements**, set `TARGET` before each run and keep separate `./recon-data/` directories per target.

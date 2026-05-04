#!/usr/bin/env python3
"""Load recon output files into Elasticsearch for the current TARGET."""
import os, json, pathlib, datetime
from urllib import request, error

ES_HOST = os.environ.get("ES_HOST", "http://localhost:9200")
TARGET  = os.environ.get("TARGET", "unknown")
RECON   = pathlib.Path("/recon")


def es_put(index: str, doc_id: str, body: dict) -> None:
    url = f"{ES_HOST}/{index}/_doc/{doc_id}"
    data = json.dumps(body).encode()
    req = request.Request(url, data=data, method="PUT",
                          headers={"Content-Type": "application/json"})
    try:
        with request.urlopen(req) as r:
            r.read()
    except error.URLError as e:
        print(f"  [WARN] ES write failed: {e}")


def ensure_index(index: str, mappings: dict) -> None:
    url = f"{ES_HOST}/{index}"
    req = request.Request(url, method="HEAD")
    try:
        request.urlopen(req)
        return  # already exists
    except error.HTTPError as e:
        if e.code != 404:
            raise
    # create
    body = json.dumps({"mappings": mappings}).encode()
    req2 = request.Request(url, data=body, method="PUT",
                           headers={"Content-Type": "application/json"})
    with request.urlopen(req2) as r:
        r.read()
    print(f"  [+] Index created: {index}")


def load_txt(filepath: pathlib.Path, index: str, field: str) -> int:
    if not filepath.exists():
        return 0
    count = 0
    with open(filepath) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            doc = {
                field: line,
                "target": TARGET,
                "source_file": str(filepath.name),
                "indexed_at": datetime.datetime.utcnow().isoformat()
            }
            es_put(index, f"{TARGET}-{filepath.stem}-{i}", doc)
            count += 1
    return count


def load_nuclei_json(filepath: pathlib.Path, index: str) -> int:
    if not filepath.exists():
        return 0
    count = 0
    with open(filepath) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
                doc["target"] = TARGET
                doc["indexed_at"] = datetime.datetime.utcnow().isoformat()
                template_id = doc.get("template-id", str(i))
                host = doc.get("host", "unknown").replace("https://", "").replace("http://", "").replace("/", "_")
                es_put(index, f"{TARGET}-{template_id}-{host}-{i}", doc)
                count += 1
            except json.JSONDecodeError:
                continue
    return count


def main():
    print(f"[*] Indexing recon data for target: {TARGET}")
    print(f"[*] Elasticsearch: {ES_HOST}")
    print()

    ensure_index("bb-subdomains", {"properties": {
        "subdomain": {"type": "keyword"},
        "target": {"type": "keyword"},
        "source_file": {"type": "keyword"},
        "indexed_at": {"type": "date"}
    }})

    ensure_index("bb-endpoints", {"properties": {
        "url": {"type": "keyword"},
        "target": {"type": "keyword"},
        "source_file": {"type": "keyword"},
        "indexed_at": {"type": "date"}
    }})

    ensure_index("bb-vulns", {"properties": {
        "target": {"type": "keyword"},
        "host": {"type": "keyword"},
        "template-id": {"type": "keyword"},
        "info": {"properties": {
            "name": {"type": "text"},
            "severity": {"type": "keyword"}
        }},
        "matched-at": {"type": "keyword"},
        "indexed_at": {"type": "date"}
    }})

    # Load subdomains
    sub_files = [
        RECON / "subdomains" / "subdomains-resolved.txt",
        RECON / "subdomains" / "live-hosts.txt",
    ]
    for f in sub_files:
        n = load_txt(f, "bb-subdomains", "subdomain")
        print(f"  [+] Loaded {n} records from {f.name} → bb-subdomains")

    # Load endpoints
    ep_files = [
        RECON / "api" / "endpoints-classified.txt",
        RECON / "api" / "katana-crawl.txt",
        RECON / "js" / "endpoints-extracted.txt",
    ]
    for f in ep_files:
        n = load_txt(f, "bb-endpoints", "url")
        print(f"  [+] Loaded {n} records from {f.name} → bb-endpoints")

    # Load nuclei findings
    vuln_files = list((RECON / "vulns").glob("*.json")) if (RECON / "vulns").exists() else []
    for f in vuln_files:
        n = load_nuclei_json(f, "bb-vulns")
        print(f"  [+] Loaded {n} nuclei findings from {f.name} → bb-vulns")

    print()
    print("[*] Done. Browse findings at http://localhost:5601")


if __name__ == "__main__":
    main()

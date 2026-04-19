#!/usr/bin/env python3
# Vespera — AI-powered SOC alert pipeline
# Copyright (c) 2026 Latens.SyN — https://github.com/LatensSyN/vespera
# License: MIT
#
# MISP enrichment integration — looks up IPs and hashes from Wazuh alerts
# against a MISP threat intelligence instance. Generates a JSON enrichment file
# that ollama-alert.py reads to inject MISP context into the LLM prompt.
#
# Integrates with Wazuh (https://wazuh.com) — copyright Wazuh Inc., GPLv2
# Integrates with MISP (https://www.misp-project.org/) — AGPL-3.0
# This project is not affiliated with or endorsed by Wazuh Inc. or MISP Project.

import sys
import json
import os
import sqlite3
import importlib.util
from datetime import datetime

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    # requests is shipped with Wazuh's framework python3
    sys.exit(0)


def _load_config():
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (
        "/var/ossec/integrations/config.py",
        os.path.join(here, "config.py"),
        os.path.normpath(os.path.join(here, "..", "config", "config.py")),
    ):
        p = os.path.abspath(p)
        if os.path.isfile(p):
            spec = importlib.util.spec_from_file_location("vespera_config", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            return m
    return None


_cfg = _load_config()
MISP_URL = getattr(_cfg, "MISP_URL", "") if _cfg else ""
MISP_KEY = getattr(_cfg, "MISP_KEY", "") if _cfg else ""
MISP_VERIFY_SSL = bool(getattr(_cfg, "MISP_VERIFY_SSL", False)) if _cfg else False
MISP_TIMEOUT = int(getattr(_cfg, "MISP_TIMEOUT", 10)) if _cfg else 10
MISP_CACHE_TTL_HOURS = int(getattr(_cfg, "MISP_CACHE_TTL_HOURS", 24)) if _cfg else 24
MIN_ALERT_LEVEL = int(getattr(_cfg, "MIN_ALERT_LEVEL", 7)) if _cfg else 7

CACHE_DB = "/var/ossec/var/misp-cache.db"
LOG_FILE = "/var/ossec/logs/misp-enrich.log"
OUTPUT_DIR = "/var/ossec/var"

PRIVATE_RANGES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                  "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                  "127.", "::1", "0.0.0.0", "169.254.")


def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.utcnow().isoformat()} {msg}\n")
    except Exception:
        pass


def init_cache():
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS lookups (
            ioc TEXT PRIMARY KEY,
            result TEXT,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def is_private_ip(ip):
    return any(ip.startswith(p) for p in PRIVATE_RANGES)


def query_misp(ioc):
    """Query MISP REST API for an IOC. Returns dict with match status."""
    if not MISP_URL or not MISP_KEY:
        return {"match": False, "error": "MISP not configured"}

    conn = init_cache()
    cur = conn.execute(
        f"SELECT result FROM lookups WHERE ioc=? AND cached_at > datetime('now','-{MISP_CACHE_TTL_HOURS} hours')",
        (ioc,)
    )
    row = cur.fetchone()
    if row:
        return json.loads(row[0])

    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {"value": ioc, "limit": 5}
    try:
        r = requests.post(
            f"{MISP_URL.rstrip('/')}/attributes/restSearch",
            headers=headers,
            json=payload,
            verify=MISP_VERIFY_SSL,
            timeout=MISP_TIMEOUT
        )
        data = r.json()
        attrs = data.get("response", {}).get("Attribute", [])
        result = {
            "match": len(attrs) > 0,
            "count": len(attrs),
            "events": [
                {
                    "event_id": a.get("event_id"),
                    "category": a.get("category"),
                    "type": a.get("type"),
                    "comment": a.get("comment", ""),
                    "event_info": a.get("Event", {}).get("info", ""),
                    "threat_level": a.get("Event", {}).get("threat_level_id", "")
                }
                for a in attrs
            ]
        }
        conn.execute(
            "INSERT OR REPLACE INTO lookups (ioc, result) VALUES (?, ?)",
            (ioc, json.dumps(result))
        )
        conn.commit()
        return result
    except Exception as e:
        log(f"Error querying MISP for {ioc}: {e}")
        return {"match": False, "error": str(e)}


def extract_iocs(alert):
    """Extract IPs, hashes from alert for MISP lookup."""
    iocs = []
    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})

    # IPs — try common field names
    seen_ips = set()
    for key in ("srcip", "src_ip", "dstip", "dest_ip"):
        ip = data.get(key) or alert.get(key, "")
        if ip and ip not in seen_ips and not is_private_ip(ip):
            iocs.append(("ip", ip))
            seen_ips.add(ip)

    # Hashes from FIM
    for hash_field, hash_type in (
        ("sha256_after", "sha256"),
        ("sha256", "sha256"),
        ("md5_after", "md5"),
        ("md5", "md5"),
        ("sha1_after", "sha1"),
        ("sha1", "sha1"),
    ):
        h = syscheck.get(hash_field, "")
        if h and len(h) > 10:
            iocs.append((hash_type, h))

    return iocs


def main():
    # Wazuh integratord passes alert file path as argv[1]; fallback to stdin
    alert_str = ""
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], encoding="utf-8") as f:
            alert_str = f.read().strip()
    else:
        alert_str = sys.stdin.read().strip()

    if not alert_str:
        sys.exit(0)

    try:
        alert = json.loads(alert_str)
    except Exception as e:
        log(f"JSON parse error: {e}")
        sys.exit(0)

    level = alert.get("rule", {}).get("level", 0)
    if level < MIN_ALERT_LEVEL:
        sys.exit(0)

    iocs = extract_iocs(alert)
    if not iocs:
        sys.exit(0)

    enrichments = []
    for ioc_type, ioc_val in iocs:
        result = query_misp(ioc_val)
        if result.get("match"):
            enrichments.append({
                "ioc": ioc_val,
                "type": ioc_type,
                "misp_match": True,
                "details": result
            })
            log(f"MISP MATCH: {ioc_type}={ioc_val} found in {result['count']} events")

    if enrichments:
        alert_id = alert.get("id", "unknown")
        output_file = os.path.join(OUTPUT_DIR, f"misp-enrich-{alert_id}.json")
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(enrichments, f, indent=2)
            log(f"Enrichment written: {output_file}")
        except Exception as e:
            log(f"Failed to write {output_file}: {e}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# Vespera — AI-powered SOC alert pipeline
# Copyright (c) 2026 Latens.SyN — https://github.com/LatensSyN/vespera
# License: MIT
#
# Integrates with Wazuh (https://wazuh.com) — copyright Wazuh Inc., GPLv2
# This project is not affiliated with or endorsed by Wazuh Inc.

import sys, os, requests, json, time, urllib3, re, hashlib
from datetime import datetime, timezone, timedelta
urllib3.disable_warnings()

# ─── Config — lit config/config.py (même dépôt) avec fallback sur les défauts ─
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_repo_root, "config"))
try:
    import config as _cfg
    OPENSEARCH_URL   = getattr(_cfg, "OPENSEARCH_URL",   "https://localhost:9200")
    OPENSEARCH_USER  = getattr(_cfg, "OPENSEARCH_USER",  "admin")
    OPENSEARCH_PASS  = getattr(_cfg, "OPENSEARCH_PASS",  "changeme")
    OPENCTI_URL      = getattr(_cfg, "OPENCTI_URL",      "http://localhost:8080")
    OPENCTI_TOKEN    = getattr(_cfg, "OPENCTI_TOKEN",    "")
    MIN_LEVEL        = getattr(_cfg, "MIN_ALERT_LEVEL",  10)
except ImportError:
    print("[warn] config/config.py introuvable — copier config/config.example.py vers config/config.py",
          file=sys.stderr)
    OPENSEARCH_URL  = "https://localhost:9200"
    OPENSEARCH_USER = "admin"
    OPENSEARCH_PASS = "changeme"
    OPENCTI_URL     = "http://localhost:8080"
    OPENCTI_TOKEN   = ""
    MIN_LEVEL       = 10

CHECK_INTERVAL = int(os.environ.get("VESPERA_BRIDGE_INTERVAL", "60"))
STATE_FILE = os.environ.get(
    "VESPERA_BRIDGE_STATE",
    os.path.join(_repo_root, "bridge", "last_run.json")
)

# Dédup cache : hash -> expiry datetime
_dedup_cache = {}

# Groupes à filtrer sauf level >= NOISY_GROUPS_MIN_LEVEL
NOISY_GROUPS = {"win_security", "win_system", "windows_security", "windows_defender", "sysmon_event1"}
NOISY_GROUPS_MIN_LEVEL = 13

# Fenêtres de dédup par type
DEDUP_WINDOWS = {
    "suricata": timedelta(hours=6),
    "default":  timedelta(hours=1),
}

def fix_ts(ts):
    return re.sub(r'\+0000$', 'Z', ts)

def dedup_key(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    groups = set(rule.get("groups", []))
    if groups & {"suricata"}:
        src_ip = alert.get("data", {}).get("srcip", "")
        raw = f"suricata|{rule.get('id')}|{src_ip}"
        window = DEDUP_WINDOWS["suricata"]
    else:
        raw = f"{rule.get('id')}|{agent.get('name')}"
        window = DEDUP_WINDOWS["default"]
    return hashlib.md5(raw.encode()).hexdigest(), window

def is_duplicate(alert):
    key, window = dedup_key(alert)
    now = datetime.now(timezone.utc)
    # Purge expired
    expired = [k for k, exp in _dedup_cache.items() if now > exp]
    for k in expired:
        del _dedup_cache[k]
    if key in _dedup_cache:
        return True
    _dedup_cache[key] = now + window
    return False

def should_skip(alert):
    rule = alert.get("rule", {})
    level = rule.get("level", 0)
    groups = set(rule.get("groups", []))
    if groups & NOISY_GROUPS and level < NOISY_GROUPS_MIN_LEVEL:
        return True
    return False

def get_alerts(last_ts):
    q = {"size": 100, "sort": [{"timestamp": {"order": "asc"}}],
         "query": {"bool": {"must": [
             {"range": {"rule.level": {"gte": MIN_LEVEL}}},
             {"range": {"timestamp": {"gt": last_ts}}}
         ]}}}
    r = requests.post(f"{OPENSEARCH_URL}/wazuh-alerts-*/_search",
                      auth=(OPENSEARCH_USER, OPENSEARCH_PASS), json=q, verify=False)
    if r.status_code == 200:
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    print(f"OpenSearch error {r.status_code}: {r.text[:100]}")
    return []

def gql(query, variables=None):
    r = requests.post(f"{OPENCTI_URL}/graphql",
                      headers={"Authorization": f"Bearer {OPENCTI_TOKEN}",
                               "Content-Type": "application/json"},
                      json={"query": query, "variables": variables or {}})
    return r.json()

def get_attack_pattern_id(technique_id):
    """Récupère l'ID OpenCTI d'un Attack Pattern MITRE par technique_id (ex: T1059.001)"""
    result = gql("""
    query Search($filters: FilterGroup) {
      attackPatterns(filters: $filters) {
        edges { node { id name x_mitre_id } }
      }
    }""", {"filters": {
        "mode": "and",
        "filters": [{"key": "x_mitre_id", "values": [technique_id]}],
        "filterGroups": []
    }})
    edges = result.get("data", {}).get("attackPatterns", {}).get("edges", [])
    if edges:
        return edges[0]["node"]["id"]
    return None

def create_incident(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    ts = fix_ts(alert.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")))
    level = rule.get("level", 0)
    name = f"[Wazuh] {rule.get('description','Alert')} - {agent.get('name','unknown')}"
    mitre = rule.get("mitre", {})
    desc = json.dumps({
        "rule_id": rule.get("id"), "level": level,
        "groups": rule.get("groups", []),
        "agent": agent.get("name"), "agent_ip": agent.get("ip"),
        "mitre": mitre,
        "src_ip": alert.get("data", {}).get("srcip", ""),
        "process": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("image", ""),
        "target_file": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetFilename", "")
    }, indent=2)
    severity = "critical" if level >= 15 else "high" if level >= 12 else "medium"
    result = gql("""
    mutation CreateIncident($input: IncidentAddInput!) {
      incidentAdd(input: $input) { id name }
    }""", {"input": {
        "name": name, "description": desc,
        "incident_type": "alert", "severity": severity,
        "first_seen": ts, "last_seen": ts, "confidence": 75
    }})
    errors = result.get("errors")
    if errors:
        print(f"  Incident error: {errors[0].get('message','')[:120]}")
        return None, mitre
    return result.get("data", {}).get("incidentAdd", {}).get("id"), mitre

def create_ipv4(ip):
    result = gql(f"""
    mutation {{
      stixCyberObservableAdd(type: "IPv4-Addr", IPv4Addr: {{value: "{ip}"}}) {{ id }}
    }}""")
    errors = result.get("errors")
    if errors:
        print(f"  IPv4 error: {errors[0].get('message','')[:80]}")
        return None
    return result.get("data", {}).get("stixCyberObservableAdd", {}).get("id")

def create_file(filepath):
    filename = filepath.replace("\\\\", "\\").split("\\")[-1]
    safe = filename.replace('"', '\\"')
    result = gql(f"""
    mutation {{
      stixCyberObservableAdd(type: "StixFile", StixFile: {{name: "{safe}"}}) {{ id }}
    }}""")
    errors = result.get("errors")
    if errors:
        print(f"  File error: {errors[0].get('message','')[:80]}")
        return None
    return result.get("data", {}).get("stixCyberObservableAdd", {}).get("id")

def link_obs_to_incident(obs_id, incident_id):
    result = gql("""
    mutation Link($input: StixCoreRelationshipAddInput!) {
      stixCoreRelationshipAdd(input: $input) { id }
    }""", {"input": {
        "fromId": incident_id, "toId": obs_id,
        "relationship_type": "related-to"
    }})
    errors = result.get("errors")
    if errors:
        print(f"  Link error: {errors[0].get('message','')[:80]}")

def link_attack_pattern(incident_id, attack_pattern_id):
    result = gql("""
    mutation Link($input: StixCoreRelationshipAddInput!) {
      stixCoreRelationshipAdd(input: $input) { id }
    }""", {"input": {
        "fromId": incident_id, "toId": attack_pattern_id,
        "relationship_type": "uses"
    }})
    errors = result.get("errors")
    if errors:
        print(f"  MITRE link error: {errors[0].get('message','')[:80]}")

def process_alert(alert):
    if should_skip(alert):
        return False, "skipped-noisy"
    if is_duplicate(alert):
        return False, "dedup"

    incident_id, mitre = create_incident(alert)
    if not incident_id:
        return False, "incident-error"

    # Observables IPs
    agent_ip = alert.get("agent", {}).get("ip")
    if agent_ip and agent_ip not in ("127.0.0.1", "::1"):
        obs_id = create_ipv4(agent_ip)
        if obs_id: link_obs_to_incident(obs_id, incident_id)

    src_ip = alert.get("data", {}).get("srcip", "")
    if src_ip and src_ip not in ("127.0.0.1", "::1"):
        obs_id = create_ipv4(src_ip)
        if obs_id: link_obs_to_incident(obs_id, incident_id)

    # Observable fichier
    target_file = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetFilename", "")
    if target_file:
        obs_id = create_file(target_file)
        if obs_id: link_obs_to_incident(obs_id, incident_id)

    # MITRE Attack Pattern link
    technique_ids = mitre.get("technique_id", [])
    if isinstance(technique_ids, str):
        technique_ids = [technique_ids]
    for tid in technique_ids:
        if tid:
            ap_id = get_attack_pattern_id(tid)
            if ap_id:
                link_attack_pattern(incident_id, ap_id)
                print(f"    -> MITRE {tid} linked")

    return True, "ok"

def load_state():
    try:
        with open(STATE_FILE) as f: return json.load(f)
    except:
        return {"last_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "processed": 0}

def save_state(state):
    with open(STATE_FILE, "w") as f: json.dump(state, f)

def main():
    print(f"[{datetime.now()}] Bridge v4 started (level>={MIN_LEVEL}, dedup+MITRE)")
    state = load_state()
    print(f"[{datetime.now()}] Depuis: {state['last_timestamp']}, traité: {state['processed']}")
    while True:
        try:
            alerts = get_alerts(state["last_timestamp"])
            skipped = deduped = created = 0
            if alerts:
                for alert in alerts:
                    ok, reason = process_alert(alert)
                    if ok:
                        created += 1
                        state["processed"] += 1
                        rule = alert.get("rule", {})
                        print(f"  -> [{rule.get('level')}] {rule.get('description','')[:60]}")
                    elif reason == "dedup":
                        deduped += 1
                    elif reason == "skipped-noisy":
                        skipped += 1
                    state["last_timestamp"] = fix_ts(alert.get("timestamp", state["last_timestamp"]))
                save_state(state)
                print(f"[{datetime.now()}] created={created} deduped={deduped} skipped={skipped}")
            else:
                print(f"[{datetime.now()}] Aucune alerte level>={MIN_LEVEL}")
        except Exception as e:
            print(f"[{datetime.now()}] ERREUR: {e}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()

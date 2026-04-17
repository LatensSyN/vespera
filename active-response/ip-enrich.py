#!/usr/bin/env python3
# Vespera — AI-powered SOC alert pipeline
# Copyright (c) 2026 Latens.SyN — https://github.com/LatensSyN/vespera
# License: MIT
#
# Integrates with Wazuh (https://wazuh.com) — copyright Wazuh Inc., GPLv2
# This project is not affiliated with or endorsed by Wazuh Inc.

import sys, json, sqlite3, urllib.request, urllib.error, subprocess, os, importlib.util
from datetime import datetime

def _load_config():
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (
        "/var/ossec/integrations/config.py",
        os.path.join(here, "..", "integrations", "config.py"),
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
LOCALE = getattr(_cfg, "LOCALE", "en") if _cfg else "en"
ABUSEIPDB_KEY = getattr(_cfg, "ABUSEIPDB_KEY", "YOUR_ABUSEIPDB_KEY") if _cfg else "YOUR_ABUSEIPDB_KEY"
VT_API_KEY = getattr(_cfg, "VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY") if _cfg else "YOUR_VIRUSTOTAL_API_KEY"
DB_PATH = getattr(_cfg, "DB_PATH", "/var/ossec/var/vespera-cache.db") if _cfg else "/var/ossec/var/vespera-cache.db"
ABUSE_THRESHOLD = int(getattr(_cfg, "ABUSEIPDB_THRESHOLD", 50)) if _cfg else 50
PRIVATE_RANGES = ["10.","192.168.","172.","127.","::1","0.0.0.0"]

def _i18n():
    lang = (str(LOCALE).lower().split("-", 1)[0] or "en")
    if lang == "fr":
        return {
            "vp": "Vrai positif probable", "inv": "À investiguer",
            "abuse_sub": "AbuseIPDB: {score}/100 — {country} — {isp} — {reports} signalements",
            "vt_sub": "Score VT: {score} moteurs détectent ce fichier comme malveillant",
        }
    if lang == "es":
        return {
            "vp": "Verdadero positivo probable", "inv": "A investigar",
            "abuse_sub": "AbuseIPDB: {score}/100 — {country} — {isp} — {reports} informes",
            "vt_sub": "Puntuación VT: {score} motores marcan este archivo como malicioso",
        }
    return {
        "vp": "Likely true positive", "inv": "Needs investigation",
        "abuse_sub": "AbuseIPDB: {score}/100 — {country} — {isp} — {reports} reports",
        "vt_sub": "VT score: {score} engines flag this file as malicious",
    }

def _unwrap_ar_payload(obj):
    """Wazuh active-response passes JSON with parameters.alert; integrations pass the alert root."""
    if not isinstance(obj, dict):
        return obj
    params = obj.get("parameters")
    if isinstance(params, dict) and isinstance(params.get("alert"), dict):
        return params["alert"]
    return obj

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS seen_ips (
        ip TEXT PRIMARY KEY, score INTEGER, country TEXT,
        isp TEXT, reports INTEGER, verdict TEXT,
        first_seen TEXT, last_seen TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS seen_hashes (
        hash TEXT PRIMARY KEY, filename TEXT, verdict TEXT,
        vt_score TEXT, first_seen TEXT, last_seen TEXT)""")
    con.commit()
    return con

def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_RANGES)

def already_seen_ip(con, ip):
    return con.execute("SELECT score, country, isp, reports, verdict FROM seen_ips WHERE ip=?", (ip,)).fetchone()

def save_ip(con, ip, score, country, isp, reports, verdict):
    now = datetime.utcnow().isoformat()
    if con.execute("SELECT ip FROM seen_ips WHERE ip=?", (ip,)).fetchone():
        con.execute("UPDATE seen_ips SET last_seen=?, score=? WHERE ip=?", (now, score, ip))
    else:
        con.execute("INSERT INTO seen_ips VALUES (?,?,?,?,?,?,?,?)",
                   (ip, score, country, isp, reports, verdict, now, now))
    con.commit()

def already_seen_hash(con, h):
    return con.execute("SELECT verdict, vt_score FROM seen_hashes WHERE hash=?", (h,)).fetchone()

def save_hash(con, h, filename, verdict, score):
    now = datetime.utcnow().isoformat()
    if con.execute("SELECT hash FROM seen_hashes WHERE hash=?", (h,)).fetchone():
        con.execute("UPDATE seen_hashes SET last_seen=? WHERE hash=?", (now, h))
    else:
        con.execute("INSERT INTO seen_hashes VALUES (?,?,?,?,?,?)", (h, filename, verdict, score, now, now))
    con.commit()

def query_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.loads(r.read())["data"]
        return d["abuseConfidenceScore"], d.get("countryCode","?"), d.get("isp","?"), d.get("totalReports",0)

def query_vt_hash(h):
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{h}",
        headers={"x-apikey": VT_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return malicious, total
    except urllib.error.HTTPError as e:
        if e.code == 404: return -1, 0
        raise

def send_mail(alert):
    proc = subprocess.Popen(
        ["python3", "/var/ossec/integrations/ollama-alert.py"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=json.dumps(alert).encode(), timeout=200)
    if err and b"Traceback" in err:
        print(f"[MAIL-ERR] {err.decode()[:150]}")
    else:
        print(f"[MAIL-SENT]")

def enrich_ip(alert, ip, label="src_ip"):
    con = init_db()
    if is_private(ip):
        print(f"[IP-SKIP] {ip} private")
        return False

    seen = already_seen_ip(con, ip)
    if seen:
        score, country, isp, reports, verdict = seen
        print(f"[IP-CACHE] {ip} score={score} verdict={verdict} (cached)")
        if score >= ABUSE_THRESHOLD:
            enrich_and_send(alert, ip, score, country, isp, reports, verdict, label)
        return score >= ABUSE_THRESHOLD

    try:
        score, country, isp, reports = query_abuseipdb(ip)
    except Exception as e:
        print(f"[ABUSE-ERR] {e}")
        return False

    verdict = "malicious" if score >= 80 else "suspicious" if score >= ABUSE_THRESHOLD else "clean"
    save_ip(con, ip, score, country, isp, reports, verdict)
    print(f"[ABUSE-RESULT] {ip} score={score}/100 country={country} isp={isp[:40]} verdict={verdict}")

    if score >= ABUSE_THRESHOLD:
        enrich_and_send(alert, ip, score, country, isp, reports, verdict, label)
        return True
    return False

def enrich_and_send(alert, ip, score, country, isp, reports, verdict, label):
    t = _i18n()
    vt_label = t["vp"] if score >= 80 else t["inv"]
    alert["abuse_result"] = {
        "ip": ip, "score": score, "country": country,
        "isp": isp, "reports": reports, "verdict": verdict,
        "forced_verdict": vt_label
    }
    alert["rule"]["_forced_verdict"] = vt_label
    alert["rule"]["_forced_verdict_sub"] = t["abuse_sub"].format(
        score=score, country=country, isp=isp[:35], reports=reports)
    # Upgrader level si score critique
    if score >= 80 and alert["rule"].get("level", 0) < 12:
        alert["rule"]["level"] = 12
    send_mail(alert)

def enrich_hash(alert, path):
    con = init_db()
    syscheck = alert.get("syscheck", {})
    sha256 = syscheck.get("sha256_after") or syscheck.get("sha256", "")
    md5 = syscheck.get("md5_after") or syscheck.get("md5", "")
    hash_val = sha256 or md5
    if not hash_val or hash_val in ("—", ""):
        print("[HASH-SKIP] no hash")
        return False

    filename = path.replace("\\", "/").split("/")[-1]
    seen = already_seen_hash(con, hash_val)
    if seen:
        verdict, vt_score = seen
        print(f"[HASH-CACHE] {filename} -> {verdict} {vt_score} (cached)")
        return False

    try:
        malicious, total = query_vt_hash(hash_val)
    except Exception as e:
        print(f"[VT-ERR] {e}")
        return False

    if malicious == -1:
        save_hash(con, hash_val, filename, "unknown", "0/0")
        print(f"[VT-UNKNOWN] {filename} not in VT")
        return False

    score_str = f"{malicious}/{total}"
    verdict = "malicious" if malicious >= 3 else "suspicious" if malicious >= 1 else "clean"
    save_hash(con, hash_val, filename, verdict, score_str)
    print(f"[VT-RESULT] {filename} {score_str} verdict={verdict}")

    if malicious >= 1:
        t = _i18n()
        vt_label = t["vp"] if malicious >= 5 else t["inv"]
        alert["vt_result"] = {"score": score_str, "verdict": verdict, "hash": hash_val, "filename": filename, "forced_verdict": vt_label}
        alert["rule"]["_forced_verdict"] = vt_label
        alert["rule"]["_forced_verdict_sub"] = t["vt_sub"].format(score=score_str)
        alert["rule"]["level"] = 14 if malicious >= 3 else 12
        send_mail(alert)
        return True
    return False

def main():
    raw = sys.stdin.read().strip()
    if not raw: sys.exit(0)
    try:
        alert = _unwrap_ar_payload(json.loads(raw))
    except Exception:
        sys.exit(0)
    if not isinstance(alert, dict) or "rule" not in alert:
        sys.exit(0)

    rule = alert.get("rule", {})
    groups = set(rule.get("groups", []))
    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})

    # Suricata → check src_ip
    if "suricata" in groups or "ids" in groups:
        src_ip = data.get("src_ip") or data.get("srcip", "")
        if src_ip:
            print(f"[SURICATA] checking {src_ip}")
            enrich_ip(alert, src_ip, "src_ip")
        else:
            send_mail(alert)

    # SSH → check src_ip
    elif "sshd" in groups or "authentication_failures" in groups:
        src_ip = data.get("src_ip") or data.get("srcip", "")
        if src_ip:
            print(f"[SSH] checking {src_ip}")
            enrich_ip(alert, src_ip, "src_ip")
        else:
            send_mail(alert)

    # FIM modified → VT hash check
    elif "syscheck" in groups:
        path = syscheck.get("path", "")
        event = syscheck.get("event", "")
        if event in ("modified", "added") and path:
            print(f"[FIM] checking hash for {path}")
            enriched = enrich_hash(alert, path)
            if not enriched:
                send_mail(alert)
        else:
            send_mail(alert)

    # Autres → mail direct
    else:
        send_mail(alert)

if __name__ == "__main__":
    main()

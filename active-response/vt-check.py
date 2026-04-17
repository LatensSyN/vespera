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
VT_API_KEY = getattr(_cfg, "VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY") if _cfg else "YOUR_VIRUSTOTAL_API_KEY"
DB_PATH = getattr(_cfg, "DB_PATH", "/var/ossec/var/vespera-cache.db") if _cfg else "/var/ossec/var/vespera-cache.db"
SENSITIVE = ["startup", "system32", "sysnative", "appdata", "temp", "tmp", "programdata"]

def _i18n():
    lang = (str(LOCALE).lower().split("-", 1)[0] or "en")
    if lang == "fr":
        return {
            "vp": "Vrai positif probable", "inv": "À investiguer",
            "desc": "[VT:{score}] Fichier ajouté dans un chemin sensible — {filename}",
        }
    if lang == "es":
        return {
            "vp": "Verdadero positivo probable", "inv": "A investigar",
            "desc": "[VT:{score}] Archivo añadido en ruta sensible — {filename}",
        }
    return {
        "vp": "Likely true positive", "inv": "Needs investigation",
        "desc": "[VT:{score}] File added to sensitive path — {filename}",
    }

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS seen (
        hash TEXT PRIMARY KEY, filename TEXT, verdict TEXT,
        vt_score TEXT, first_seen TEXT, last_seen TEXT)""")
    con.commit()
    return con

def already_seen(con, h):
    return con.execute("SELECT verdict, vt_score FROM seen WHERE hash=?", (h,)).fetchone()

def save_result(con, h, filename, verdict, score):
    now = datetime.utcnow().isoformat()
    if con.execute("SELECT hash FROM seen WHERE hash=?", (h,)).fetchone():
        con.execute("UPDATE seen SET last_seen=? WHERE hash=?", (now, h))
    else:
        con.execute("INSERT INTO seen VALUES (?,?,?,?,?,?)", (h, filename, verdict, score, now, now))
    con.commit()

def query_vt(h):
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
        if e.code == 404:
            return -1, 0
        raise

def main():
    raw = sys.stdin.read().strip()
    if not raw:
        sys.exit(0)
    try:
        alert = json.loads(raw)
    except:
        sys.exit(0)

    syscheck = alert.get("syscheck", {})
    if syscheck.get("event") != "added":
        sys.exit(0)

    path = syscheck.get("path", "")
    if not any(p in path.lower() for p in SENSITIVE):
        sys.exit(0)

    sha256 = syscheck.get("sha256_after") or syscheck.get("sha256", "")
    md5 = syscheck.get("md5_after") or syscheck.get("md5", "")
    hash_val = sha256 or md5
    if not hash_val:
        sys.exit(0)

    filename = path.replace("\\", "/").split("/")[-1]
    con = init_db()

    seen = already_seen(con, hash_val)
    if seen:
        print(f"[VT-CACHE] {filename} -> {seen[0]} {seen[1]} (cached, skip)")
        sys.exit(0)

    try:
        malicious, total = query_vt(hash_val)
    except Exception as e:
        print(f"[VT-ERROR] {e}")
        sys.exit(0)

    if malicious == -1:
        save_result(con, hash_val, filename, "unknown", "0/0")
        print(f"[VT-UNKNOWN] {filename} not in VT database")
        sys.exit(0)

    score = f"{malicious}/{total}"
    verdict = "malicious" if malicious >= 3 else "suspicious" if malicious >= 1 else "clean"
    save_result(con, hash_val, filename, verdict, score)
    print(f"[VT-RESULT] {filename} | {score} | verdict={verdict}")

    if malicious >= 1:
        t = _i18n()
        vt_label = t["vp"] if malicious >= 5 else t["inv"]
        alert["vt_result"] = {"score": score, "verdict": verdict, "hash": hash_val, "filename": filename, "forced_verdict": vt_label}
        alert["rule"]["_forced_verdict"] = vt_label
        alert["rule"]["description"] = t["desc"].format(score=score, filename=filename)
        alert["rule"]["level"] = 14 if malicious >= 3 else 12
        proc = subprocess.Popen(
            ["python3", "/var/ossec/integrations/ollama-alert.py"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=json.dumps(alert).encode(), timeout=200)
        if err:
            print(f"[VT-MAIL-ERR] {err.decode()[:100]}")
        else:
            print(f"[VT-MAIL-SENT] {filename} {score}")

if __name__ == "__main__":
    main()

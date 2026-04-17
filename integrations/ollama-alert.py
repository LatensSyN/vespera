#!/usr/bin/env python3
# Vespera — AI-powered SOC alert pipeline
# Copyright (c) 2026 Latens.SyN — https://github.com/LatensSyN/vespera
# License: MIT
#
# Integrates with Wazuh (https://wazuh.com) — copyright Wazuh Inc., GPLv2
# This project is not affiliated with or endorsed by Wazuh Inc.

import sys, json, smtplib, subprocess, importlib.util
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import make_msgid, formatdate
from email.mime.base import MIMEBase
from email import encoders
import os
from datetime import datetime

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
OLLAMA_URL = os.environ.get("VESPERA_OLLAMA_URL") or (getattr(_cfg, "OLLAMA_URL", "http://host-gateway:11434/api/generate") if _cfg else "http://host-gateway:11434/api/generate")
OLLAMA_MODEL = getattr(_cfg, "OLLAMA_MODEL", "llama3.2:3b") if _cfg else "llama3.2:3b"
OLLAMA_TIMEOUT = int(getattr(_cfg, "OLLAMA_TIMEOUT", 180)) if _cfg else 180
SMTP_HOST = os.environ.get("VESPERA_SMTP_HOST") or (getattr(_cfg, "SMTP_HOST", "localhost") if _cfg else "localhost")
SMTP_PORT = int(getattr(_cfg, "SMTP_PORT", 25)) if _cfg else 25
SMTP_USE_TLS = bool(getattr(_cfg, "SMTP_USE_TLS", False)) if _cfg else False
SMTP_SSL = bool(getattr(_cfg, "SMTP_SSL", False)) if _cfg else False
SMTP_USER = getattr(_cfg, "SMTP_USER", "") if _cfg else ""
SMTP_PASS = getattr(_cfg, "SMTP_PASS", "") if _cfg else ""
MAIL_FROM = getattr(_cfg, "MAIL_FROM", "wazuh@local") if _cfg else "wazuh@local"
MAIL_TO = getattr(_cfg, "MAIL_TO", "soc@local") if _cfg else "soc@local"
LOCALE = (getattr(_cfg, "LOCALE", "en") if _cfg else "en") or "en"
REPORT_DIR = getattr(_cfg, "REPORT_DIR", "/var/ossec/logs/vespera-reports") if _cfg else "/var/ossec/logs/vespera-reports"
MIN_ALERT_LEVEL = int(getattr(_cfg, "MIN_ALERT_LEVEL", 7)) if _cfg else 7

def _locale_lang():
    l = (str(LOCALE).lower().split("-", 1)[0] or "en")
    return l if l in ("en", "fr", "es") else "en"

_TR_CACHE = None

def _load_tr():
    global _TR_CACHE
    if _TR_CACHE is not None:
        return _TR_CACHE
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "locales", f"{_locale_lang()}.json")
    try:
        with open(path, encoding="utf-8") as fp:
            _TR_CACHE = json.load(fp)
    except Exception:
        _TR_CACHE = {}
    return _TR_CACHE

def _build_soc_prompt(alert_json, alert_type, vt_score):
    if str(LOCALE).lower().startswith("fr"):
        return f"""Tu es un analyste SOC senior. RÉPONDS UNIQUEMENT EN FRANÇAIS.
Pour cette alerte Wazuh de type {alert_type}, fournis EXACTEMENT ce format sans introduction :

VERDICT: [Vrai positif probable / Faux positif probable / A investiguer] — [raison courte en 1 ligne]

CONTEXTE: [2 lignes max, technique et précis, cite les IPs/fichiers/processus exacts]

IMPACT POTENTIEL: [1 ligne, concret]

FAUX POSITIF: [1 ligne expliquant si possible et pourquoi]

ACTION 1: [action immédiate précise avec commande ou chemin exact si applicable]
ACTION 2: [action secondaire]
ACTION 3: [action préventive]

Sois précis. Jamais de vérifier les logs sans dire lesquels exactement. INTERDIT: ne jamais proposer darréter lagent Wazuh, ne jamais proposer net stop wazuh, ne jamais proposer de désactiver la surveillance.
Score VirusTotal: {vt_score}
Alerte: {alert_json}"""
    if str(LOCALE).lower().startswith("es"):
        return f"""Eres un analista SOC senior. RESPONDE ÚNICAMENTE EN ESPAÑOL.
Para esta alerta Wazuh de tipo {alert_type}, responde EXACTAMENTE en este formato sin introducción:

VERDICT: [Probable verdadero positivo / Probable falso positivo / Requiere investigación] — [una línea breve]

CONTEXTO: [máx. 2 líneas, técnicas, cita IPs/archivos/procesos exactos]

IMPACTO POTENCIAL: [una línea concreta]

FALSO POSITIVO: [una línea si aplica]

ACTION 1: [acción inmediata con comando o ruta si aplica]
ACTION 2: [acción secundaria]
ACTION 3: [acción preventiva]

Sé preciso. No digas "revisar logs" sin indicar cuáles. NUNCA sugieras detener el agente Wazuh ni desactivar el monitoreo.
Puntuación VirusTotal: {vt_score}
Alerta: {alert_json}"""
    return f"""You are a senior SOC analyst. RESPOND IN ENGLISH ONLY.
For this Wazuh alert of type {alert_type}, output EXACTLY this format with no preamble:

VERDICT: [Likely true positive / Likely false positive / Needs investigation] — [one short reason line]

CONTEXT: [max 2 lines, technical, cite exact IPs/files/processes]

POTENTIAL IMPACT: [one concrete line]

FALSE POSITIVE: [one line if applicable]

ACTION 1: [immediate precise action with command or path if applicable]
ACTION 2: [secondary action]
ACTION 3: [preventive action]

Be precise. Never say "check logs" without naming which logs. NEVER suggest stopping the Wazuh agent or disabling monitoring.
VirusTotal score: {vt_score}
Alert: {alert_json}"""

def ask_ollama(alert_json, alert_type):
    vt_score = "N/A"
    try:
        vt = json.loads(alert_json).get("vt_result",{})
        if vt.get("score"): vt_score = vt["score"]+" engines malicious="+vt.get("verdict","")
    except Exception:
        pass
    prompt = _build_soc_prompt(alert_json, alert_type, vt_score)
    payload = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "options": {"temperature": 0.3}})
    result = subprocess.run(
        ["curl", "-s", "-X", "POST", OLLAMA_URL,
         "-H", "Content-Type: application/json",
         "-d", payload,
         "--max-time", str(OLLAMA_TIMEOUT)],
        capture_output=True, text=True, timeout=OLLAMA_TIMEOUT + 10
    )
    if result.returncode != 0:
        raise RuntimeError(f"curl failed (rc={result.returncode}): {result.stderr[:200]}")
    return json.loads(result.stdout)["response"]

def parse_ollama(text):
    import re
    text = text.replace("**","").replace("__","")
    text = re.sub(r"#+\s*", "", text)

    result = {"verdict":"","verdict_sub":"","ce_qui":"","impact":"","faux_positif":"","actions":[]}
    for line in text.strip().split("\n"):
        line = line.strip()
        # Verdict: accept em dash or ASCII hyphen between title and subtitle
        if line.upper().startswith("VERDICT:"):
            rest = line.split(":", 1)[1].strip()
            parts = re.split(r"\s*[—\-]\s*", rest, maxsplit=1)
            result["verdict"] = parts[0].strip()
            if len(parts) > 1:
                result["verdict_sub"] = parts[1].strip()
        # French (LOCALE=fr) vs English (LOCALE=en) section titles from _build_soc_prompt
        elif line.startswith("CONTEXTE:"):
            result["ce_qui"] = line[9:].strip()
        elif line.startswith("CONTEXT:"):
            result["ce_qui"] = line[8:].strip()
        elif line.startswith("IMPACT POTENTIEL:"):
            result["impact"] = line[17:].strip()
        elif line.startswith("POTENTIAL IMPACT:"):
            result["impact"] = line[17:].strip()
        elif line.startswith("FAUX POSITIF:"):
            result["faux_positif"] = line[13:].strip()
        elif line.startswith("FALSE POSITIVE:"):
            result["faux_positif"] = line[16:].strip()
        elif line.startswith("CONTEXTO:"):
            result["ce_qui"] = line[9:].strip()
        elif line.startswith("IMPACTO POTENCIAL:"):
            result["impact"] = line[18:].strip()
        elif line.startswith("FALSO POSITIVO:"):
            result["faux_positif"] = line[15:].strip()
        elif line.startswith("ACTION 1:"):
            result["actions"].append(line[9:].strip())
        elif line.startswith("ACTION 2:"):
            result["actions"].append(line[9:].strip())
        elif line.startswith("ACTION 3:"):
            result["actions"].append(line[9:].strip())
    return result

def detect_type(alert):
    groups = alert.get("rule",{}).get("groups",[])
    desc = alert.get("rule",{}).get("description","").lower()
    level = alert.get("rule",{}).get("level",0)
    if "suricata" in groups or "ids" in groups:
        if alert.get("abuse_result"):
            return "suricata_ip", "crit"
        return "suricata", "crit"
    if "sshd" in groups or "authentication_failures" in groups or "ssh" in desc:
        if alert.get("abuse_result"):
            return "ssh_ip", "high"
        return "ssh", "high"
    if "windows" in groups:
        return "windows", "low"
    if "syscheck" in groups:
        if alert.get("vt_result"):
            return "fim_vt", "crit"
        return "fim", "med"
    if level >= 12:
        return "critical", "crit"
    if level >= 7:
        return "elevated", "high"
    return "generic", "low"

def get_indicators(alert, kind, tr):
    f = tr.get("fields", {})
    ui = tr.get("ui", {})
    dash = ui.get("dash", "—")
    data = alert.get("data", {})
    rule = alert.get("rule", {})
    syscheck = alert.get("syscheck", {})
    agent = alert.get("agent", {})
    inds = []
    if kind in ("suricata", "suricata_ip"):
        _src_ip_sur = data.get("src_ip") or data.get("srcip") or alert.get("abuse_result", {}).get("ip", "")
        if _src_ip_sur:
            inds.append((f.get("source_ip", "Source IP"), _src_ip_sur, "ind-value-red"))
        try:
            cve = data.get("alert",{}).get("metadata",{}).get("cve",[])
            if cve:
                inds.append((f.get("cve", "CVE"), cve[0], "ind-value-red"))
            else:
                sig = data.get("alert",{}).get("signature", dash)[:18]
                inds.append((f.get("signature", "Signature"), sig, "ind-value-red"))
        except Exception:
            pass
        if data.get("dest_ip"):
            inds.append((f.get("destination", "Destination"), data["dest_ip"], "ind-value"))
    elif kind in ("ssh", "ssh_ip"):
        abuse = alert.get("abuse_result",{})
        _src_ip = data.get("src_ip") or data.get("srcip") or abuse.get("ip", "")
        if abuse.get("score") is not None:
            inds.append((f.get("abuse_score", "Abuse Score"), str(abuse["score"]) + "/100", "ind-value-red"))
        if _src_ip:
            inds.append((f.get("ip_attacker", "IP"), _src_ip, "ind-value-amber"))
        if data.get("srcuser"):
            inds.append((f.get("target", "Target"), data["srcuser"], "ind-value-amber"))
        inds.append((f.get("ar_response", "AR"), ui.get("ar_script_val", "firewall-drop"), "ind-value-teal"))
    elif kind == "windows":
        try:
            evtdata = data.get("win",{}).get("eventdata",{})
            proc = evtdata.get("processName","").split("\\")[-1]
            if proc:
                inds.append((f.get("image", "Image"), proc, "ind-value-blue"))
            priv = evtdata.get("privilegeList","")
            if priv:
                inds.append((f.get("privilege", "Privilege"), priv, "ind-value-amber"))
        except Exception:
            pass
        fired = rule.get("firedtimes","")
        if fired:
            suf = f.get("times_suffix", "x")
            inds.append((f.get("frequency", "Freq"), f"{fired} {suf}", "ind-value"))
    elif kind in ("fim", "fim_vt"):
        vt = alert.get("vt_result",{})
        if vt.get("score"):
            inds.append((f.get("vt_score", "VT"), vt["score"] + " engines", "ind-value-red"))
        if syscheck.get("path"):
            inds.append((f.get("path", "Path"), syscheck["path"].split("/")[-1], "ind-value-teal"))
        if syscheck.get("event"):
            inds.append((f.get("event", "Event"), syscheck["event"], "ind-value-amber"))
        inds.append((f.get("mode", "Mode"), ui.get("mode_realtime", "realtime"), "ind-value"))
    else:
        inds.append((f.get("agent", "Agent"), agent.get("name", dash), "ind-value"))
        inds.append((f.get("rule_id", "Rule ID"), str(rule.get("id", dash)), "ind-value"))
        inds.append((f.get("description", "Desc"), (rule.get("description") or dash)[:22], "ind-value"))
    while len(inds) < 3:
        inds.append(("", "", "ind-value"))
    return inds[:3]

def get_cols(alert, kind, tr):
    f = tr.get("fields", {})
    sec = tr.get("sections", {})
    ui = tr.get("ui", {})
    dash = ui.get("dash", "—")
    data = alert.get("data", {})
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    syscheck = alert.get("syscheck", {})
    if kind in ("suricata", "suricata_ip"):
        abuse = alert.get("abuse_result", {})
        _raw_ip_s = data.get("src_ip") or data.get("srcip", "")
        if abuse:
            country_isp = f"{abuse.get('country','?')} — {abuse.get('isp','?')[:25]}"
        elif _raw_ip_s:
            country_isp = _raw_ip_s
        else:
            country_isp = dash
        l = [
            (f.get("protocol", "Protocol"), data.get("proto", dash)),
            (f.get("src_port", "Src port"), str(data.get("src_port", dash))),
            (f.get("dst_port", "Dst port"), str(data.get("dest_port", dash))),
            (f.get("origin", "Origin"), country_isp),
        ]
        try:
            sig_id = str(data.get("alert",{}).get("signature_id", dash))
            sig_name = data.get("alert",{}).get("signature", dash)
        except Exception:
            sig_id = dash
            sig_name = dash
        try:
            cat = data.get("alert",{}).get("category", dash)
        except Exception:
            cat = dash
        r = [
            (f.get("sig_id", "Sig ID"), sig_id),
            (f.get("signature", "Signature"), sig_name[:28]),
            (f.get("category", "Category"), cat),
            (f.get("agent", "Agent"), agent.get("name", dash)),
        ]
        return sec.get("network", "Network"), l, sec.get("signature", "Signature"), r
    if kind in ("ssh", "ssh_ip"):
        abuse = alert.get("abuse_result", {})
        _raw_ip = data.get("src_ip") or data.get("srcip", "")
        if abuse:
            country_isp = f"{abuse.get('country','?')} — {abuse.get('isp','?')[:25]}"
        elif _raw_ip:
            country_isp = _raw_ip
        else:
            country_isp = dash
        l = [
            (f.get("attempts", "Attempts"), str(rule.get("firedtimes", dash))),
            (f.get("src_port_ssh", "Src port"), str(data.get("srcport", dash))),
            (f.get("origin", "Origin"), country_isp),
            (f.get("agent", "Agent"), agent.get("name", dash)),
        ]
        r = [
            (f.get("script", "Script"), ui.get("ar_script_val", "firewall-drop")),
            (f.get("timeout", "Timeout"), ui.get("ar_timeout_val", "600s")),
            (f.get("rule", "Rule"), ui.get("ar_rule_val", "INPUT DROP")),
            (f.get("status", "Status"), ui.get("ar_status_active", "Active")),
        ]
        return sec.get("connection", "Connection"), l, sec.get("active_response", "Active Response"), r
    if kind == "windows":
        try:
            evtdata = data.get("win",{}).get("eventdata",{})
            sys_ = data.get("win",{}).get("system",{})
            l = [
                (f.get("user", "User"), evtdata.get("subjectUserName", dash)),
                (f.get("event_id", "Event ID"), sys_.get("eventID", dash)),
                (f.get("mitre", "MITRE"), str(rule.get("mitre",{}).get("id", [dash])[0]) if rule.get("mitre") else dash),
                (f.get("result", "Result"), ui.get("result_blocked", "Blocked")),
            ]
            r = [
                (f.get("image", "Image"), evtdata.get("processName", dash).split("\\")[-1]),
                (f.get("privilege", "Privilege"), evtdata.get("privilegeList", dash)),
                (f.get("parent", "Parent"), evtdata.get("parentProcessName", dash).split("\\")[-1]),
                (f.get("vendor", "Vendor"), ui.get("vendor_placeholder", "ASUS")),
            ]
        except Exception:
            l = [
                (f.get("agent", "Agent"), agent.get("name", dash)),
                (f.get("rule_id", "Rule ID"), rule.get("id", dash)),
                (f.get("level", "Level"), str(rule.get("level", dash))),
                (f.get("groups", "Groups"), ", ".join(rule.get("groups",[])[:2])),
            ]
            r = [
                (f.get("fired", "Fired"), str(rule.get("firedtimes", dash))),
                (f.get("mail", "Mail"), str(rule.get("mail", dash))),
                (dash, dash),
                (dash, dash),
            ]
        return sec.get("context", "Context"), l, sec.get("process", "Process"), r
    if kind in ("fim", "fim_vt"):
        l = [
            (f.get("path", "Path"), syscheck.get("path", dash)),
            (f.get("event", "Event"), syscheck.get("event", dash)),
            (f.get("mode", "Mode"), ui.get("mode_realtime", "realtime")),
            (f.get("agent", "Agent"), agent.get("name", dash)),
        ]
        vt = alert.get("vt_result", {})
        sha = syscheck.get("sha256_after", vt.get("hash", dash))
        md5_val = syscheck.get("md5_after", "") or syscheck.get("md5", "") or vt.get("md5", "")
        r = [
            (f.get("vt_score", "VT Score"), vt.get("score", dash)),
            (f.get("vt_verdict", "VT Verdict"), vt.get("verdict", dash)),
            (f.get("sha256", "SHA256"), sha if sha and sha != dash else dash),
            (f.get("md5", "MD5"), md5_val if md5_val else "N/A"),
        ]
        return sec.get("file", "File"), l, sec.get("details", "Details"), r
    l = [
        (f.get("agent", "Agent"), agent.get("name", dash)),
        (f.get("rule_id", "Rule ID"), rule.get("id", dash)),
        (f.get("level", "Level"), str(rule.get("level", dash))),
        (f.get("groups", "Groups"), ", ".join(rule.get("groups",[])[:2])),
    ]
    r = [
        (f.get("description", "Description"), (rule.get("description") or dash)[:25]),
        (f.get("fired", "Fired"), str(rule.get("firedtimes", dash))),
        (dash, dash),
        (dash, dash),
    ]
    return sec.get("alert_block", "Alert"), l, sec.get("rule_block", "Rule"), r

LEVEL_COLORS = {"crit":("#a32d2d","#fcebeb","#791f1f"),"high":("#ba7517","#faeeda","#633806"),"med":("#0f6e56","#e1f5ee","#085041"),"low":("#888780","#f1efe8","#444441")}
VERDICT_COLORS = {
    "vrai positif": "#a32d2d", "a investiguer": "#ba7517", "faux positif": "#3b6d11",
    "true positive": "#a32d2d", "likely true": "#a32d2d", "investigation": "#ba7517", "needs investigation": "#ba7517",
    "false positive": "#3b6d11", "likely false": "#3b6d11",
    "verdadero positivo": "#a32d2d", "falso positivo": "#3b6d11", "investigación": "#ba7517",
    "probable": "#ba7517",
}

def build_html(alert, alert_type_title, level_css, parsed, indicators, c1l, c1, c2l, c2, model_label, tr):
    ui = tr.get("ui", {})
    sec = tr.get("sections", {})
    ai = tr.get("ai", {})
    lb = tr.get("level_bands", {})
    dash = ui.get("dash", "—")
    rule = alert.get("rule",{})
    agent = alert.get("agent",{})
    level = rule.get("level",0)
    desc = rule.get("description", sec.get("alert_block", "Alert"))
    import re as _re
    desc_clean = _re.sub(r'^\[VT:\d+/\d+\]\s*', '', desc)
    _vt_fn = alert.get("vt_result",{}).get("filename","")
    low = desc_clean.lower()
    if _vt_fn and any(
        x in low for x in ("sensitive path", "chemin sensible", "ruta sensible")
    ):
        desc_clean = ui.get("fim_malware_title", "Malicious file — {filename}").format(filename=_vt_fn)
    rule_id = rule.get("id","?")
    ts = alert.get("timestamp",datetime.now().isoformat())[:16].replace("T"," · ")
    lc,lbg,ltext = LEVEL_COLORS.get(level_css,LEVEL_COLORS["low"])
    if level >= 13:
        level_label = lb.get("ge13", "CRITICAL")
    elif level >= 10:
        level_label = lb.get("ge10", "HIGH")
    elif level >= 7:
        level_label = lb.get("ge7", "MEDIUM")
    else:
        level_label = lb.get("low", "LOW")
    vdot = "#ba7517"
    vl = parsed["verdict"].lower()
    for k, c in VERDICT_COLORS.items():
        if k in vl:
            vdot = c
            break

    def rows(items):
        def row_val_class(v):
            s = str(v)
            return "row-v-hash" if len(s) > 20 and " " not in s and s != dash else "row-v"
        return "".join(f'<div class="row"><span class="row-k">{k}</span><span class="{row_val_class(v)}">{v}</span></div>' for k,v in items)

    def ind(label,value,cls):
        return f'<div class="indicator"><div class="ind-label">{label}</div><div class="{cls}">{value}</div></div>'

    acts = "".join(f'<div class="action-item"><span class="action-num act-{i+1}">{i+1}.</span><span class="action-text">{a}</span></div>' for i,a in enumerate(parsed["actions"][:3]))
    tags = "".join(f'<span class="tag">{g}</span>' for g in rule.get("groups",[])[:4])

    def cap(s):
        return str(s).capitalize() if s and str(s) not in (dash, "-") else str(s)

    rule_word = ui.get("rule_word", "Rule")
    ai_badge = f'{ai.get("badge", "AI")} · {model_label}'
    none_act = ui.get("none_actions", "—")

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#eef0f4;padding:16px;}}
.card{{background:#fff;border:1px solid #d8dde6;border-radius:12px;overflow:hidden;max-width:620px;margin:0 auto;box-shadow:0 2px 12px rgba(0,0,0,0.08);}}

/* HEADER */
.header{{display:flex;align-items:stretch;border-bottom:1px solid #e8eaed;}}
.level-col{{width:72px;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:16px 8px;flex-shrink:0;border-right:1px solid #e8eaed;background:{lbg};}}
.level-num{{font-size:32px;font-weight:700;line-height:1;color:{lc};letter-spacing:-1px;}}
.level-lbl{{font-size:9px;font-weight:700;letter-spacing:0.1em;margin-top:4px;color:{lc};text-transform:uppercase;}}
.header-right{{flex:1;padding:14px 18px;}}
.header-top{{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;}}
.alert-type{{font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;background:{lbg};color:{ltext};letter-spacing:0.04em;text-transform:uppercase;}}
.header-rule{{font-size:10px;color:#6b7280;font-weight:500;}}
.header-desc{{font-size:14px;font-weight:600;color:#1a1d23;line-height:1.4;}}

/* VERDICT */
.verdict-band{{padding:10px 18px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #e8eaed;background:#f8f9fb;}}
.verdict-pill{{display:inline-flex;align-items:center;gap:7px;background:rgba(0,0,0,0.04);border:1.5px solid {vdot};border-radius:6px;padding:5px 14px;}}
.verdict-dot{{width:7px;height:7px;border-radius:50%;background:{vdot};flex-shrink:0;}}
.verdict-text{{font-size:12px;font-weight:700;color:{vdot};letter-spacing:0.01em;}}
.verdict-sub{{font-size:11px;color:#6b7280;flex:1;}}

/* INDICATORS */
.indicators{{display:flex;border-bottom:1px solid #e8eaed;}}
.indicator{{flex:1;padding:12px 16px;border-right:1px solid #e8eaed;min-width:0;}}
.indicator:last-child{{border-right:none;}}
.ind-label{{font-size:9px;font-weight:800;color:#4b5563;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:5px;}}
.ind-value{{font-size:13px;font-weight:600;color:#1a1d23;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.ind-value-red{{font-size:14px;font-weight:800;color:#c0392b;letter-spacing:-0.3px;}}
.ind-value-amber{{font-size:13px;font-weight:600;color:#c47d0e;}}
.ind-value-teal{{font-size:13px;font-weight:600;color:#0d7a5f;}}
.ind-value-blue{{font-size:13px;font-weight:600;color:#1a5fa8;}}

/* COLS */
.cols{{display:grid;grid-template-columns:1fr 1fr;border-bottom:1px solid #e8eaed;}}
.col{{padding:14px 16px;}}
.col:first-child{{border-right:1px solid #e8eaed;}}
.row-v-hash{{font-size:10px;color:#374151;text-align:right;word-break:break-all;font-weight:500;font-family:"SF Mono","Consolas","Courier New",monospace;max-width:65%;line-height:1.6;letter-spacing:0.01em;}}
.col-label{{font-size:10px;font-weight:800;color:#374151;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:10px;border-bottom:2px solid #e8eaed;padding-bottom:6px;}}
.row{{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f3f4f6;gap:8px;align-items:baseline;}}
.row:last-child{{border-bottom:none;}}
.row-k{{font-size:11px;color:#4b5563;white-space:nowrap;font-weight:600;}}
.row-v{{font-size:11px;color:#111827;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:65%;font-weight:600;font-variant-numeric:tabular-nums;}}

/* AI SECTION */
.ai-section{{padding:16px 18px;border-bottom:1px solid #e8eaed;background:#f8f9fb;}}
.ai-header{{display:flex;align-items:center;gap:8px;margin-bottom:14px;}}
.ai-badge{{font-size:10px;font-weight:600;background:#f0f1f3;color:#4b5563;border:1px solid #d8dde6;padding:3px 10px;border-radius:6px;letter-spacing:0.04em;}}
.ai-block{{display:flex;gap:12px;margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid #e8eaed;}}
.ai-block:last-child{{margin-bottom:0;}}
.ai-arrow{{font-size:11px;color:#8a8f98;width:14px;flex-shrink:0;padding-top:1px;}}
.ai-content{{flex:1;}}
.ai-title{{font-size:10px;font-weight:800;color:#374151;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:4px;}}
.ai-text{{font-size:12px;color:#374151;line-height:1.6;}}

/* ACTIONS */
.actions{{padding:14px 18px;border-bottom:1px solid #e8eaed;}}
.actions-label{{font-size:10px;font-weight:800;color:#374151;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:10px;border-bottom:2px solid #e8eaed;padding-bottom:6px;}}
.action-item{{display:flex;gap:12px;padding:6px 0;border-bottom:1px solid #f3f4f6;align-items:flex-start;}}
.action-item:last-child{{border-bottom:none;}}
.action-num{{font-size:11px;font-weight:700;width:18px;flex-shrink:0;}}
.act-1{{color:#c0392b;}}
.act-2{{color:#c47d0e;}}
.act-3{{color:#0d7a5f;}}
.action-text{{font-size:12px;color:#1a1d23;line-height:1.6;font-weight:400;}}

/* FOOTER */
.footer{{padding:10px 18px;display:flex;justify-content:space-between;align-items:center;background:#f8f9fb;flex-wrap:wrap;gap:6px;}}
.tags{{display:flex;gap:6px;flex-wrap:wrap;}}
.tag{{font-size:10px;font-weight:500;background:#eef0f4;color:#6b7280;padding:2px 8px;border-radius:4px;letter-spacing:0.02em;}}
.footer-ts{{font-size:10px;color:#8a8f98;font-weight:500;}}

/* RESPONSIVE */
@media(max-width:560px){{
  body{{padding:4px;}}
  .card{{border-radius:8px;max-width:100%;}}
  .cols{{grid-template-columns:1fr;}}
  .col:first-child{{border-right:none;border-bottom:1px solid #e8eaed;}}
  .indicators{{flex-direction:column;}}
  .indicator{{border-right:none;border-bottom:1px solid #e8eaed;}}
  .indicator:last-child{{border-bottom:none;}}
  .level-col{{width:60px;}}
  .level-num{{font-size:26px;}}
  .header-desc{{font-size:13px;}}
  .verdict-band{{flex-wrap:wrap;}}
}}
</style></head><body><div class="card">

<div class="header">
  <div class="level-col">
    <div class="level-num">{level}</div>
    <div class="level-lbl">{level_label}</div>
  </div>
  <div class="header-right">
    <div class="header-top">
      <span class="alert-type">{alert_type_title}</span>
      <span class="header-rule">{rule_word} #{rule_id} &middot; {agent.get("name","?")}</span>
    </div>
    <div class="header-desc">{cap(desc_clean)}</div>
  </div>
</div>

<div class="verdict-band">
  <div class="verdict-pill">
    <div class="verdict-dot"></div>
    <span class="verdict-text">{cap(parsed["verdict"])}</span>
  </div>
  <span class="verdict-sub">{(dash+" "+cap(parsed["verdict_sub"])) if parsed["verdict_sub"] else ""}</span>
</div>

<div class="indicators">{ind(*indicators[0])}{ind(*indicators[1])}{ind(*indicators[2])}</div>

<div class="cols">
  <div class="col"><div class="col-label">{c1l}</div>{rows(c1)}</div>
  <div class="col"><div class="col-label">{c2l}</div>{rows(c2)}</div>
</div>

<div class="ai-section">
  <div class="ai-header"><span class="ai-badge">{ai_badge}</span></div>
  <div class="ai-block"><span class="ai-arrow">→</span><div class="ai-content"><div class="ai-title">{ai.get("context","Context")}</div><div class="ai-text">{cap(parsed["ce_qui"]) or dash}</div></div></div>
  <div class="ai-block"><span class="ai-arrow">→</span><div class="ai-content"><div class="ai-title">{ai.get("impact","Impact")}</div><div class="ai-text">{cap(parsed["impact"]) or dash}</div></div></div>
  <div class="ai-block"><span class="ai-arrow">→</span><div class="ai-content"><div class="ai-title">{ai.get("false_positive","FP?")}</div><div class="ai-text">{cap(parsed["faux_positif"]) or dash}</div></div></div>
</div>

<div class="actions">
  <div class="actions-label">{sec.get("actions","Actions")}</div>
  {acts if acts else "<div class='action-item'><span class='action-text'>"+none_act+"</span></div>"}
</div>

<div class="footer">
  <div class="tags">{tags}</div>
  <span class="footer-ts">{ts}</span>
</div>

</div></body></html>"""

def _log(msg):
    print(f"[vespera] {msg}", file=sys.stderr, flush=True)

def main():
    # Wazuh passes alert file path as $1; fall back to stdin for manual testing
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], encoding="utf-8") as _fh:
            alert_str = _fh.read().strip()
    else:
        alert_str = sys.stdin.read().strip()
    if not alert_str:
        _log("no alert data (empty stdin and no valid file argument) — exiting")
        return
    try:
        alert = json.loads(alert_str)
    except Exception as e:
        _log(f"JSON parse error: {e}")
        alert = {"rule":{"level":0,"description":"Parse error","id":"0","groups":[]},"agent":{"name":"unknown"},"timestamp":datetime.now().isoformat()}

    level = alert.get("rule", {}).get("level", 0)
    if level < MIN_ALERT_LEVEL:
        _log(f"alert level {level} < MIN_ALERT_LEVEL {MIN_ALERT_LEVEL} — skipping")
        return
    tr = _load_tr()
    kind, level_css = detect_type(alert)
    alert_types = tr.get("alert_types", {})
    alert_title = alert_types.get(kind, kind)
    _log(f"processing level={level} type={kind} agent={alert.get('agent',{}).get('name','?')}")
    indicators = get_indicators(alert, kind, tr)
    c1l, c1, c2l, c2 = get_cols(alert, kind, tr)
    _log(f"querying Ollama ({OLLAMA_MODEL}) — this may take up to {OLLAMA_TIMEOUT}s ...")
    try:
        ollama_raw = ask_ollama(json.dumps(alert, ensure_ascii=False)[:2500], alert_title)
    except Exception as e:
        _log(f"Ollama error: {e}")
        raise
    _log("Ollama response received, building report ...")
    parsed = parse_ollama(ollama_raw)
    ui = tr.get("ui", {})
    if alert.get("rule",{}).get("_forced_verdict"):
        parsed["verdict"] = alert["rule"]["_forced_verdict"]
        sub = alert["rule"].get("_forced_verdict_sub")
        if sub:
            parsed["verdict_sub"] = sub
        elif alert.get("vt_result",{}).get("score"):
            sc = str(alert.get("vt_result",{}).get("score",""))
            parsed["verdict_sub"] = ui.get("email_vt_sub", "VT: {score}").format(score=sc)
    rule = alert.get("rule",{})
    level = rule.get("level",0)
    desc = rule.get("description", "Alert")
    _vt = alert.get("vt_result",{})
    _sc = _vt.get("score","")
    _fn = _vt.get("filename","") or desc[:20]
    _agent = alert.get("agent",{}).get("name","?")
    _syscheck_path = alert.get("syscheck",{}).get("path","")
    _path_short = _syscheck_path.replace("\\","/").replace("C:/ProgramData/Microsoft/Windows/","").replace("C:/ProgramData/","").split("/")[0] if _syscheck_path else ""
    _vl = parsed["verdict"].lower()
    if any(x in _vl for x in ("faux positif", "false positive", "likely false", "falso positivo", "probable falso")):
        _verdict_short = "FP"
    elif any(x in _vl for x in ("vrai positif", "true positive", "likely true", "verdadero positivo", "probable verdadero")):
        _verdict_short = "VP"
    else:
        _verdict_short = "AI"
    if _sc:
        subject = f"[L{level}][{_verdict_short}] {_fn} — VT:{_sc} — {_path_short} — {_agent}"
    else:
        subject = f"[L{level}][{_verdict_short}] {alert_title} — {_fn} — {_agent}"
    html = build_html(alert, alert_title, level_css, parsed, indicators, c1l, c1, c2l, c2, OLLAMA_MODEL, tr)
    msg = MIMEMultipart("mixed")
    html_part = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO
    msg["Message-ID"] = make_msgid(domain="local")
    msg["Date"] = formatdate(localtime=True)
    html_part.attach(MIMEText(html,"html","utf-8"))
    msg.attach(html_part)
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    attach_fname = f"vespera-alert-{ts_file}-{agent_name}.html"

    # Sauvegarde disque (optionnelle — n'empêche pas l'attachement email si ça échoue)
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
        with open(f"{REPORT_DIR}/{attach_fname}", "w", encoding="utf-8") as f:
            f.write(html)
        _log(f"report saved: {REPORT_DIR}/{attach_fname}")
    except Exception as e:
        _log(f"[WARN] report not saved to disk: {e}")

    # Attachement email — toujours présent, indépendant de la sauvegarde disque
    att = MIMEBase("application", "octet-stream")
    att.set_payload(html.encode("utf-8"))
    encoders.encode_base64(att)
    att.add_header("Content-Disposition", "attachment", filename=attach_fname)
    att.add_header("Content-Type", f'text/html; charset=utf-8; name="{attach_fname}"')
    msg.attach(att)

    def _send_smtp(payload: str) -> None:
        if SMTP_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as s:
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(MAIL_FROM, [MAIL_TO], payload)
            return
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            if SMTP_USE_TLS:
                s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(MAIL_FROM, [MAIL_TO], payload)

    _log(f"sending mail to {MAIL_TO} via {SMTP_HOST}:{SMTP_PORT} ...")
    try:
        _send_smtp(msg.as_string())
    except Exception as e:
        _log(f"SMTP error: {e}")
        raise
    _log(f"done — mail sent: {subject}")

if __name__ == "__main__":
    main()

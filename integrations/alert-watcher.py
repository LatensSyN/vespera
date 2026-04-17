#!/usr/bin/env python3
# Vespera — Alert watcher (workaround for integratord inactivity in Wazuh 4.14)
# Tails /var/ossec/logs/alerts/alerts.json and calls ollama-alert.py directly.
# Runs as a container sidecar via Docker exec or as a systemd service.

import json, os, subprocess, sys, tempfile, time

ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
SCRIPT      = "/var/ossec/integrations/ollama-alert.py"
MIN_LEVEL   = int(os.environ.get("VESPERA_MIN_LEVEL", "7"))
STATE_FILE  = "/var/ossec/logs/vespera-watcher.pos"
POLL_SEC    = 1.0

def read_pos():
    try:
        return int(open(STATE_FILE).read().strip())
    except Exception:
        return None

def write_pos(pos):
    try:
        open(STATE_FILE, "w").write(str(pos))
    except Exception:
        pass

def process_alert(line):
    try:
        alert = json.loads(line)
    except Exception:
        return
    level = alert.get("rule", {}).get("level", 0)
    if level < MIN_LEVEL:
        return
    rule_id = alert.get("rule", {}).get("id", "?")
    print(f"[vespera-watcher] level={level} rule={rule_id} — forwarding to ollama-alert.py", flush=True)
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp.write(line)
            tmppath = tmp.name
        env = dict(os.environ)
        env.setdefault("VESPERA_SMTP_HOST", "host-gateway")
        subprocess.run([sys.executable, SCRIPT, tmppath], env=env, timeout=300)
    except Exception as e:
        print(f"[vespera-watcher] error: {e}", flush=True)
    finally:
        try:
            os.unlink(tmppath)
        except Exception:
            pass

def main():
    print(f"[vespera-watcher] starting, min_level={MIN_LEVEL}, watching {ALERTS_JSON}", flush=True)
    # Wait for file to exist
    while not os.path.isfile(ALERTS_JSON):
        time.sleep(2)

    with open(ALERTS_JSON, "r") as fh:
        # Resume from saved position or start at end
        saved = read_pos()
        if saved is not None:
            fh.seek(saved)
        else:
            fh.seek(0, 2)  # seek to end on first run

        while True:
            line = fh.readline()
            if line:
                line = line.strip()
                if line:
                    process_alert(line)
                write_pos(fh.tell())
            else:
                # Check if file was rotated (new inode)
                try:
                    if os.stat(ALERTS_JSON).st_ino != os.fstat(fh.fileno()).st_ino:
                        print("[vespera-watcher] log rotation detected, reopening", flush=True)
                        fh.close()
                        fh = open(ALERTS_JSON, "r")
                        write_pos(0)
                except Exception:
                    pass
                time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()

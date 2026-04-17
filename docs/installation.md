# Vespera — Installation guide

Reference steps for a **Linux + Docker** deployment. For configuration keys, see [configuration.md](configuration.md). For SMTP / email delivery, see [smtp.md](smtp.md). For a local Postfix + Thunderbird inbox, see [smtp-lan-linux.md](smtp-lan-linux.md) and [thunderbird.md](thunderbird.md).

---

## Prerequisites

### Wazuh manager

| Method | Recommended for | Guide |
|--------|-----------------|-------|
| **Docker** (recommended) | Homelab / dev | [Wazuh Docker](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html) |
| **Linux bare metal** | Dedicated server | [Wazuh install](https://documentation.wazuh.com/current/installation-guide/index.html) |

### Other components

| Component | Required | Notes |
|-----------|----------|-------|
| Ollama | Yes | [ollama.ai](https://ollama.ai) — runs on the Docker host |
| SMTP / Postfix | Yes | Any reachable relay; local Postfix recommended for labs |
| Python 3.9+ | Yes | Already in Wazuh manager image |
| OpenCTI | No | Optional threat intel forwarding |

### Hardware (for Ollama)

| RAM on Ollama host | Recommended model |
|--------------------|-------------------|
| ~8 GB | `llama3.2:3b` |
| ~16 GB | `llama3.1:8b` |

The wizard auto-detects installed models and pre-selects the best one.

### Free API keys

| Service | URL |
|---------|-----|
| VirusTotal | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | https://www.abuseipdb.com/register |

---

## Step 1 — Install Ollama on the host

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b    # or llama3.2:3b on smaller machines
```

Verify Ollama is running:

```bash
curl http://localhost:11434/api/tags
```

---

## Step 2 — Clone Vespera

```bash
git clone https://github.com/LatensSyN/vespera.git
cd vespera
```

---

## Step 3 — Run the wizard

```bash
./install.sh
```

The wizard:
1. Checks prerequisites (python3, curl, nc, docker, Ollama)
2. Auto-detects Wazuh manager container, Ollama models, and Postfix domain
3. Asks for SMTP, API keys, locale, alert level
4. Writes `config/config.py`
5. Deploys files + merges XML + installs `vespera-watcher` systemd service
6. Runs validation tests + optional end-to-end pipeline test

> If `config/config.py` already exists, skip the wizard: `./install.sh --quick`

---

## Step 4 — Docker networking (host-gateway)

The Wazuh manager container must reach **Ollama** and **Postfix** on the host. Vespera uses `host-gateway` as the hostname (Docker resolves it to the host IP automatically if `extra_hosts` is configured).

Add this to your `docker-compose.yml` under the manager service:

```yaml
services:
  wazuh.manager:
    extra_hosts:
      - "host-gateway:host-gateway"
```

Then restart the stack:

```bash
docker compose down && docker compose up -d
```

`./install.sh --validate` checks that `host-gateway` is resolvable from the container.

---

## Step 5 — Verify

```bash
./install.sh --validate
```

Expected output (6/6):

```
✓  wazuh-integratord (or: inactif, normal on Wazuh 4.14+ — watcher active)
✓  Ollama accessible via host-gateway
✓  SMTP (host-gateway:25) accessible
✓  config.py loadable — model: llama3.1:8b
✓  vespera-watcher service active
✓  ossec.conf — single block
```

---

## Step 6 — End-to-end pipeline test

```bash
./install.sh --test-mail
```

Injects a level-12 SSH brute-force alert directly into `alerts.json`, waits for `alert-watcher.py` to pick it up, Ollama to process it, and the HTML report to arrive in your inbox.

---

## install.sh flags reference

| Flag | Action |
|------|--------|
| *(none)* | Wizard + auto-deploy |
| `--quick` | Deploy with existing `config.py` (auto-detect + merge + rules + restart + watcher) |
| `--setup` | Re-run wizard without deploying |
| `--validate` | Post-install health check |
| `--test-mail` | Inject a real test alert and wait for mail delivery |
| `--repair` | Auto-fix: Dovecot `mail_location`, ossec.conf double-block, watcher service |
| `--docker-only` | Copy files into manager container only |
| `--bare-only` | Copy files to local `/var/ossec` |
| `--merge-ossec` | Merge Vespera XML blocks into `ossec.conf` (idempotent) |
| `--install-rules` | Install `config/custom-rules.xml` → `etc/rules/0_vespera.xml` |
| `--restart-wazuh` | Restart Wazuh in the container |
| `--locale en\|fr\|es` | Set `LOCALE` in `config/config.py` before deploying |
| `DRY_RUN=1` | Print commands without executing |

---

## Paths inside the manager container

| Purpose | Path |
|---------|------|
| Vespera config | `/var/ossec/integrations/config.py` |
| Main pipeline | `/var/ossec/integrations/ollama-alert.py` |
| Alert watcher | `/var/ossec/integrations/alert-watcher.py` |
| Locales | `/var/ossec/integrations/locales/{en,fr,es}.json` |
| Active response | `/var/ossec/active-response/bin/ip-enrich.py`, `vt-check.py` |
| Custom rules | `/var/ossec/etc/rules/0_vespera.xml` |
| Watcher log | `/var/ossec/logs/vespera-watcher.log` |
| Integration log | `/var/ossec/logs/integrations.log` |

---

## alert-watcher.py (Wazuh 4.14+ workaround)

On Wazuh 4.14+, `wazuh-integratord` has a known inactivity bug — it loads integrations at startup but never calls them. Vespera works around this with `alert-watcher.py`:

- Tails `/var/ossec/logs/alerts/json` line by line
- Filters by `MIN_ALERT_LEVEL` (default 10)
- Calls `ollama-alert.py` directly for each matching alert
- Persists read position in `vespera-watcher.pos` (survives restarts)
- Detects log rotation

`--quick` and `--repair` both deploy `alert-watcher.py` into the container and create a `vespera-watcher` systemd service on the host that keeps it running permanently via `docker exec`.

Check watcher logs:

```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/logs/vespera-watcher.log
journalctl -u vespera-watcher -n 50
```

---

## Local agent (same machine as Wazuh Docker)

To monitor the host running the Docker stack, install a Wazuh agent locally:

```bash
# Install agent (match Wazuh manager version)
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.4-1_amd64.deb
dpkg -i wazuh-agent_*.deb 2>/dev/null; true
# If binaries are missing (broken dpkg), extract directly:
dpkg-deb -x wazuh-agent_*.deb /

# Fix permissions
chown -R root:wazuh /var/ossec/
mkdir -p /var/ossec/var/run
chown root:wazuh /var/ossec/var/run && chmod 770 /var/ossec/var/run
chown -R root:wazuh /var/ossec/queue/ && chmod -R 770 /var/ossec/queue/
chown -R root:wazuh /var/ossec/etc/shared/ && chmod -R 770 /var/ossec/etc/shared/

# Enroll
/var/ossec/bin/agent-auth -m 127.0.0.1

# Configure /var/ossec/etc/ossec.conf — add auth.log monitoring:
# <localfile>
#   <log_format>syslog</log_format>
#   <location>/var/log/auth.log</location>
# </localfile>

# Start
/var/ossec/bin/wazuh-control start
```

---

## OpenCTI bridge (optional)

```bash
# Edit bridge/wazuh_to_opencti.py with your OpenCTI credentials
sudo cp docs/vespera-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vespera-bridge
```

---

## Clean removal

### Vespera only (keep Wazuh)

```bash
MANAGER=single-node-wazuh.manager-1
docker exec "$MANAGER" rm -f \
  /var/ossec/integrations/ollama-alert.py \
  /var/ossec/integrations/alert-watcher.py \
  /var/ossec/integrations/custom-ollama \
  /var/ossec/integrations/custom-vt-check \
  /var/ossec/integrations/config.py \
  /var/ossec/active-response/bin/vt-check.py \
  /var/ossec/active-response/bin/ip-enrich.py \
  /var/ossec/etc/rules/0_vespera.xml
docker exec "$MANAGER" rm -rf /var/ossec/integrations/locales
# Remove VESPERA_BEGIN...VESPERA_END block from ossec.conf, then:
docker exec "$MANAGER" /var/ossec/bin/wazuh-control restart

systemctl disable --now vespera-watcher 2>/dev/null
rm -f /etc/systemd/system/vespera-watcher.service
systemctl daemon-reload
```

### Full Wazuh stack

```bash
cd /path/to/wazuh-docker/single-node
docker compose down -v
```

---

## Troubleshooting

### No emails

1. `./install.sh --validate` — check which test fails
2. `./install.sh --repair` — auto-fix common issues
3. Check watcher: `docker exec MANAGER cat /var/ossec/logs/vespera-watcher.log`
4. Check Postfix: `tail -20 /var/log/mail.log`

### Ollama timeout

- Raise `OLLAMA_TIMEOUT` in `config.py`
- Use a smaller model (`llama3.2:3b`)
- Verify `host-gateway:11434` is reachable: `docker exec MANAGER curl http://host-gateway:11434/api/tags`

### host-gateway not resolvable

Add to `docker-compose.yml` under the manager service:

```yaml
extra_hosts:
  - "host-gateway:host-gateway"
```

Then `docker compose down && docker compose up -d`.

### ossec.conf double block (analysisd ignores second block)

```bash
./install.sh --repair
```

### Mail in Maildir but Thunderbird shows empty inbox

Dovecot `mail_location` mismatch — run `./install.sh --repair` (fixes `/etc/dovecot/conf.d/10-mail.conf` automatically).

### Watcher not starting

```bash
journalctl -u vespera-watcher -n 30
./install.sh --repair
```

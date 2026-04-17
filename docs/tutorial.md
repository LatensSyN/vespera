# Vespera — Tutorial (Windows + Docker Desktop)

End-to-end path for **Windows 10/11** with **Docker Desktop**, Wazuh in containers, and Ollama on the Windows host or a Linux VM reachable from Docker.

## 1. Prerequisites

1. [Docker Desktop](https://docs.docker.com/desktop/install/windows-install/) (WSL2 backend recommended).
2. Deploy Wazuh **single-node** per the [official Docker guide](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html). The **manager** container name depends on your Compose project (often `single-node-wazuh.manager-1` with Compose v2). The install script **auto-detects** a running container whose image contains `wazuh-manager`, or set `WAZUH_CONTAINER` yourself.
3. [Ollama for Windows](https://ollama.ai/download). Pull models, e.g.:

```text
ollama pull llama3.2:3b
ollama pull llama3.1:8b
```

4. Clone Vespera and create config:

```bash
git clone https://github.com/LatensSyN/vespera.git
cd vespera
cp config/config.example.py config/config.py
```

Edit `config/config.py`: VT / AbuseIPDB keys, `OLLAMA_URL` reachable **from inside the Wazuh container** (not `127.0.0.1` on the manager — use `http://host.docker.internal:11434/api/generate` on Docker Desktop if Ollama runs on the host), `OLLAMA_MODEL`, `LOCALE`.

**SMTP:** configure `SMTP_*` and `MAIL_*` so the manager container can deliver mail (usually an external relay with TLS on port 587, or your host’s IP — not `localhost` from inside the container). See **[smtp.md](smtp.md)**.

## 2. Network: Ollama from the container

From PowerShell (adjust if `curl` is missing in the image; use Python one-liner from [installation.md](installation.md) if needed):

```powershell
docker exec $env:WAZUH_CONTAINER python3 -c "import urllib.request; urllib.request.urlopen('http://host.docker.internal:11434/api/tags', timeout=5).read(); print('OK')"
```

Or set `WAZUH_CONTAINER` first in PowerShell:

```powershell
$env:WAZUH_CONTAINER="single-node-wazuh.manager-1"
```

Example in `config.py`:

```python
OLLAMA_URL = "http://host.docker.internal:11434/api/generate"
```

## 3. One-shot install (`install.sh --quick`)

From **WSL2** or Git Bash, repo root:

```bash
chmod +x install.sh
./install.sh --quick
```

This will:

1. Copy Python scripts, wrappers, `locales/`, and `config/config.py` into the manager container.
2. Merge `config/ossec-integration.xml` + `config/ossec-active-response.xml` into `ossec.conf` (wrapped in `<!-- VESPERA_BEGIN -->` … `<!-- VESPERA_END -->` — safe to re-run).
3. Install `config/custom-rules.xml` as `0_vespera.xml`.
4. Restart Wazuh inside the container.

Override the container name if auto-detection is wrong:

```bash
export WAZUH_CONTAINER=single-node-wazuh.manager-1
./install.sh --quick
```

Partial steps:

```bash
./install.sh --docker-only
./install.sh --docker-only --merge-ossec --install-rules --restart-wazuh
```

## 4. Manual `ossec.conf` (only if you skip `--merge-ossec`)

Merge is automated by `--quick`. To edit by hand: `docker exec -it $WAZUH_CONTAINER bash` then edit `/var/ossec/etc/ossec.conf` before `</ossec_config>`.

## 5. Screenshots

| File | Suggested content |
|------|-------------------|
| `docs/screenshots/suricata-ip-intel.png` | HTML email: Suricata + AbuseIPDB |
| `docs/screenshots/ssh-brute-force.png` | SSH + IP reputation |
| `docs/screenshots/fim-virustotal.png` | FIM + VT context |

Placeholders ship with the repo; replace with real captures after testing.

## 6. Tests without live traffic

JSON samples under [`docs/test-alerts/`](test-alerts/):

- `suricata-min.json` — pipe into `ollama-alert.py`
- `ssh-bruteforce-min.json` — SSH-style alert
- `fim-added-min.json` — FIM “added”
- `active-response-wrapper-min.json` — active-response envelope (`parameters.alert`)

Replace `MANAGER` with your container name:

```bash
docker exec -i MANAGER python3 /var/ossec/integrations/ollama-alert.py < docs/test-alerts/suricata-min.json
docker exec -i MANAGER python3 /var/ossec/active-response/bin/ip-enrich.py < docs/test-alerts/active-response-wrapper-min.json
```

## 7. OpenCTI (optional)

1. Edit variables at the top of `bridge/wazuh_to_opencti.py`.
2. Copy and edit [`docs/vespera-bridge.service`](vespera-bridge.service) (`WorkingDirectory` / `ExecStart`).
3. `sudo cp docs/vespera-bridge.service /etc/systemd/system/vespera-bridge.service && sudo systemctl daemon-reload && sudo systemctl enable --now vespera-bridge`

## 8. Quick checks

- Integrations log: `docker exec MANAGER tail -f /var/ossec/logs/integrations.log`
- Active response log: `docker exec MANAGER tail -f /var/ossec/logs/active-responses.log`
- Secret scan before `git push`: `rg "VT_API_KEY|ABUSEIPDB|api_key|sk-[a-zA-Z]" --glob '!config.example.py'`

---

[Vespera on GitHub](https://github.com/LatensSyN/vespera) — Latens.SyN

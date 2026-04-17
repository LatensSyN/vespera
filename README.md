# Vespera

<img width="2125" height="1031" alt="vespera_logo" src="https://github.com/user-attachments/assets/19da87d1-8ac1-4a0f-a504-ea7a5d7087e0" />


**Version 0.3.0** · AI-powered SOC alert pipeline for Wazuh — local LLM analysis, threat intel enrichment, and rich HTML email reports.

> Built by [Latens.SyN](https://github.com/LatensSyN). Production-minded. No cloud AI required.

---

## What is this?

`vespera` turns Wazuh alerts into **actionable, enriched security reports** in your inbox — without external AI SaaS, with full control over data and models.

Form latin *vesper*, the evening watch.

**Because your SOC never sleeps.**

### Pipeline overview

```
Wazuh Alert (JSON)
    │
    ├─► Active Response: ip-enrich.py ──► AbuseIPDB
    │         └─► Score / country / ISP ──► chains to ollama-alert.py
    │
    ├─► Integration: custom-vt-check ──► vt-check.py ──► VirusTotal (FIM "added")
    │         └─► Detection score ──► ollama-alert.py when hot
    │
    ├─► wazuh_to_opencti.py ──► OpenCTI (optional)
    │
    └─► alert-watcher.py (vespera-watcher systemd service)
              └─► ollama-alert.py ──► Ollama (local LLM)
                        └─► HTML email report → SOC inbox
```

> **Note on Wazuh 4.14+:** `wazuh-integratord` has a known inactivity bug on this version. Vespera ships `alert-watcher.py`, a lightweight Python daemon that tails `alerts.json` directly and drives the pipeline. It is deployed automatically by `--quick` and runs as the `vespera-watcher` systemd service.

### Features

- **Adaptive layout** by alert type: Suricata, SSH, FIM, Windows, generic
- **Threat intel**: AbuseIPDB + VirusTotal (SQLite cache, dedup)
- **AI verdict** via Ollama; forced verdict if VT ≥ 5/76 or AbuseIPDB ≥ 80/100
- **i18n**: `LOCALE=en|fr|es` — HTML report strings, Ollama prompts, and enrichment verdict lines
- **HTML attachment** for archiving / PDF export
- **One-command install** with interactive wizard, auto-repair, and pipeline test

---

## Screenshots

**Installation**



<img width="915" height="532" alt="Capture d&#39;écran 2026-04-17 130830" src="https://github.com/user-attachments/assets/2267415d-160f-41ce-8e33-d0655388bab3" />

---


**Setting Up**



<img width="937" height="530" alt="Capture d&#39;écran 2026-04-17 130923" src="https://github.com/user-attachments/assets/ec2063e4-c45a-4309-b862-c594a3242132" />

---


**Setting Up Ollama's Report**



<img width="936" height="578" alt="Capture d&#39;écran 2026-04-17 130942" src="https://github.com/user-attachments/assets/716dca3b-d6ef-4a9a-b1f3-24e94e98dec7" />

---


**Validation Steps**



<img width="932" height="377" alt="Capture d&#39;écran 2026-04-17 131005" src="https://github.com/user-attachments/assets/76c315ca-038c-4178-91e6-4d33cf48b25e" />

---


**Output The E-mail Report Test**



<img width="932" height="531" alt="Capture d&#39;écran 2026-04-17 131014" src="https://github.com/user-attachments/assets/1ae5dc2e-be30-4ecf-893d-ccfc27a02828" />

---


**A Little Preview Of The Final Report**



<img width="988" height="1100" alt="Capture d&#39;écran 2026-04-17 133224" src="https://github.com/user-attachments/assets/aa733adb-e0f8-403a-b821-15fbdfa15a99" />



---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| Wazuh manager | 4.x | Docker (recommended) or bare metal |
| Ollama | Current | `llama3.2:3b` default; `llama3.1:8b` if ≥ 16 GB RAM |
| Python | 3.9+ | Included in Wazuh manager image |
| OpenCTI | 5.x+ | Optional |

**Free API keys:** [VirusTotal](https://www.virustotal.com/gui/join-us) · [AbuseIPDB](https://www.abuseipdb.com/register)

---

## Quick install

```bash
git clone https://github.com/LatensSyN/vespera.git
cd vespera
./install.sh          # interactive wizard + auto-deploy
```

Or, if `config/config.py` already exists:

```bash
./install.sh --quick
```

`--quick` auto-detects the Wazuh manager container, deploys all files, merges Vespera XML into `ossec.conf` (idempotent), installs optional rules, deploys `alert-watcher.py` + the `vespera-watcher` systemd service, and restarts Wazuh.

Override the container name if needed:

```bash
WAZUH_CONTAINER=single-node-wazuh.manager-1 ./install.sh --quick
```

---

## Post-install

```bash
# Verify everything is working
./install.sh --validate

# Run a real end-to-end pipeline test (injects an alert, waits for the mail)
./install.sh --test-mail

# Fix a broken install without full redeploy (dovecot, ossec.conf, watcher service)
./install.sh --repair
```

---

## install.sh flags

| Flag | Action |
|------|--------|
| *(none)* | Interactive wizard + auto-deploy |
| `--quick` | Deploy with existing `config.py` (Docker auto-detect + merge + rules + restart + watcher) |
| `--setup` | Re-run configuration wizard only |
| `--validate` | Post-install health check (integratord, Ollama, SMTP, config, watcher, ossec.conf) |
| `--test-mail` | Inject a level-12 test alert, wait for Ollama, confirm mail delivery |
| `--repair` | Auto-fix Dovecot maildir, ossec.conf double-block, deploy watcher service |
| `--docker-only` | Copy files into the manager container only |
| `--bare-only` | Copy files to local `/var/ossec` |
| `--merge-ossec` | Merge Vespera XML blocks into `ossec.conf` |
| `--install-rules` | Install `config/custom-rules.xml` → `etc/rules/0_vespera.xml` |
| `--restart-wazuh` | Restart Wazuh in the container |
| `--locale en\|fr\|es` | Set `LOCALE` in `config/config.py` before copying |
| `DRY_RUN=1` | Print commands without executing |

---

## Configuration

All manager-side Python modules read **`/var/ossec/integrations/config.py`** (deployed from `config/config.example.py`).

| Setting | Description |
|---------|-------------|
| `OLLAMA_MODEL` | e.g. `llama3.2:3b` or `llama3.1:8b` — wizard auto-detects installed models |
| `OLLAMA_URL` | Full URL to `/api/generate` — use `http://host-gateway:11434/api/generate` for Docker |
| `SMTP_HOST` | Use `host-gateway` if Postfix runs on the Docker host |
| `MAIL_TO` | SOC recipient — wizard auto-detects Postfix `mydomain` |
| `LOCALE` | `en`, `fr`, or `es` |
| `MIN_ALERT_LEVEL` | Minimum Wazuh alert level to process (default: 10) |
| `DB_PATH` | SQLite cache (`/var/ossec/var/vespera-cache.db`) |

> **Docker networking:** the manager container must reach Ollama and SMTP via `host-gateway`. Add `extra_hosts: ["host-gateway:host-gateway"]` under the manager service in `docker-compose.yml`. `--validate` checks this automatically.

Full reference: [docs/configuration.md](docs/configuration.md)

---

## Project layout

```
vespera/
├── VERSION
├── install.sh                        # wizard, deploy, validate, repair, test-mail
├── setup.sh                          # shortcut → install.sh --setup
├── scripts/
│   ├── vespera-merge-ossec.py        # idempotent XML merge into ossec.conf
│   └── apply-postfix.sh              # deploy config/postfix-main.cf → /etc/postfix/main.cf
├── config/
│   ├── config.example.py             # template — copy to config.py and fill secrets
│   ├── ossec-integration.xml         # custom-ollama, custom-vt-check integration blocks
│   ├── ossec-active-response.xml     # vespera-ip-enrich active response
│   ├── custom-rules.xml              # optional Suricata + FIM rules (IDs 100200–100300)
│   └── postfix-main.cf.example       # Postfix template for local lab delivery
├── integrations/
│   ├── ollama-alert.py               # main pipeline: enrich → Ollama → HTML email
│   ├── alert-watcher.py              # tails alerts.json, drives pipeline (Wazuh 4.14+ workaround)
│   ├── custom-ollama                 # Wazuh integrator wrapper
│   ├── custom-vt-check               # Wazuh integrator wrapper → vt-check.py
│   └── locales/                      # i18n strings (en, fr, es)
├── active-response/
│   ├── ip-enrich.py                  # AbuseIPDB enrichment (active response)
│   └── vt-check.py                   # VirusTotal hash check (FIM active response)
├── bridge/
│   └── wazuh_to_opencti.py           # optional OpenCTI forwarding service
└── docs/
    ├── installation.md
    ├── configuration.md
    ├── smtp.md
    ├── smtp-lan-linux.md
    ├── thunderbird.md
    ├── tutorial.md
    ├── logo.svg
    ├── vespera-bridge.service
    ├── test-alerts/                  # 7 sample JSON alerts for testing
    └── screenshots/
```

---

## Roadmap

- [ ] YARA local scan integration
- [ ] Slack / Teams / Telegram notifications
- [ ] Alert history UI
- [ ] URLhaus URL reputation
- [ ] Richer MITRE mapping for custom rules
- [ ] Optional Docker Compose stack

---

## Contributing

PRs and issues welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). **Never commit `config.py` or real API keys.**

Before pushing:

```bash
rg "VT_API_KEY|ABUSEIPDB|x-apikey|sk-[a-zA-Z]" --glob '!config.example.py'
```

---

## Support

- Star the repo, report issues, add translations
- [Buy me a coffee](https://buymeacoffee.com/LatensSyN) · [GitHub Sponsors](https://github.com/sponsors/LatensSyN)

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Provided as-is for education and homelab use. Respect third-party API terms. Test rules before production deployment.

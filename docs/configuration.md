# Vespera — Configuration

Runtime settings for the manager scripts (`ollama-alert.py`, `ip-enrich.py`, `vt-check.py`) are read from **`/var/ossec/integrations/config.py`** on the Wazuh manager (copy from [`config/config.example.py`](../config/config.example.py) before deployment).

| Variable | Role |
|----------|------|
| `VT_API_KEY` | VirusTotal API |
| `ABUSEIPDB_KEY` | AbuseIPDB API |
| `OLLAMA_URL` | Ollama `.../api/generate` endpoint |
| `OLLAMA_MODEL` | e.g. `llama3.2:3b` or `llama3.1:8b` |
| `OLLAMA_TIMEOUT` | Seconds for LLM request |
| `SMTP_HOST` / `SMTP_PORT` | Mail server (must be reachable **from the manager container**) |
| `SMTP_USE_TLS` | `True` for STARTTLS (common on port **587**) |
| `SMTP_SSL` | `True` for implicit SSL on port **465** |
| `SMTP_USER` / `SMTP_PASS` | Authenticated SMTP when required |
| `MAIL_FROM` / `MAIL_TO` | Envelope sender and SOC recipient |
| `LOCALE` | `en`, `fr`, or `es` — HTML labels (`integrations/locales/`), Ollama instructions, and verdict text in `ip-enrich.py` / `vt-check.py` |
| `DB_PATH` | SQLite cache (AbuseIPDB + VT) |
| `REPORT_DIR` | HTML report attachments directory |

`WAZUH_API_*`, `OPENCTI_*`, and `OPENSEARCH_*` in `config.example.py` are for optional tooling (e.g. OpenCTI bridge); the core Vespera mail pipeline does not require them.

**Email setup (providers, Docker networking, TLS):** [smtp.md](smtp.md)

See also: [installation.md](installation.md), [tutorial.md](tutorial.md).

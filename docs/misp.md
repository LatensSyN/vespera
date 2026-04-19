# Vespera — MISP threat intel integration

Vespera can enrich Wazuh alerts with [MISP](https://www.misp-project.org/) threat intelligence. When an alert contains an IP address or file hash that matches a MISP indicator, the enrichment script writes a JSON file that `ollama-alert.py` reads and injects into the LLM prompt — so the AI analysis includes MITRE ATT&CK context, campaign tags, and IOC source feeds.

---

## Pipeline

```
Wazuh Alert (JSON)
    |
    |-> custom-misp-enrich (integration, level >= 7)
    |     |-> misp-enrich.py
    |           |-> extract IOCs (IPs, hashes)
    |           |-> skip private IP ranges
    |           |-> query MISP /attributes/restSearch
    |           |-> SQLite cache (24h TTL)
    |           |-> write /var/ossec/var/misp-enrich-{alert_id}.json
    |
    |-> custom-ollama (integration, level >= 10)
          |-> ollama-alert.py
                |-> _load_misp_context() reads enrichment JSON
                |-> inject into LLM prompt (EN/FR/ES)
                |-> HTML email report with MISP context
```

---

## Deploy MISP (optional, self-hosted)

Official Docker deploy:

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
# Edit .env — set BASE_URL, admin email, DB password, GPG passphrase
docker compose up -d
```

First-time setup:

1. Browse `https://<your-host>:<port>` (default 443 or as configured in `.env`).
2. Default credentials: `admin@admin.test` / `admin`.
3. Change the admin password immediately.
4. **Administration → List Users → your user → Auth Keys** → create a new API key. Save it — Vespera needs it.

Activate OSINT feeds:

1. **Sync Actions → List Feeds** → click **Load default feed metadata**.
2. Enable and cache these priority feeds (**Enable** + **Caching enabled**):
   - CIRCL OSINT Feed
   - abuse.ch URLhaus
   - abuse.ch Feodo Tracker
   - abuse.ch ThreatFox
   - Botvrij.eu
   - Tor exit nodes
3. Click **Fetch and store all feed data**. First ingest takes 10-30 min.

---

## Configure Vespera

Edit `config/config.py` (copy from `config/config.example.py` if needed):

```python
# --- MISP (optional threat intel lookup) ---
MISP_URL = "https://misp.local:8443"
MISP_KEY = "YOUR_MISP_API_KEY"
MISP_VERIFY_SSL = False
MISP_TIMEOUT = 10
MISP_CACHE_TTL_HOURS = 24
```

Leave `MISP_URL` empty to disable MISP enrichment entirely — the rest of the pipeline still works.

---

## Deploy

`install.sh --quick` deploys the MISP scripts automatically:

- `integrations/misp-enrich.py` copied to `/var/ossec/integrations/misp-enrich.py`
- `integrations/custom-misp-enrich` copied to `/var/ossec/integrations/custom-misp-enrich`
- XML integration block inserted in `ossec.conf` via `scripts/vespera-merge-ossec.py`

Wazuh requires the wrapper to share the same base name as the script the integrator calls. That is why both files are named `custom-misp-enrich*`.

Manual deploy (if skipping `--quick`):

```bash
WAZUH_CONTAINER=single-node-wazuh.manager-1
docker cp integrations/misp-enrich.py       "$WAZUH_CONTAINER:/var/ossec/integrations/"
docker cp integrations/custom-misp-enrich   "$WAZUH_CONTAINER:/var/ossec/integrations/"
docker exec "$WAZUH_CONTAINER" chmod 750 /var/ossec/integrations/misp-enrich.py /var/ossec/integrations/custom-misp-enrich
docker exec "$WAZUH_CONTAINER" chown root:wazuh /var/ossec/integrations/misp-enrich.py /var/ossec/integrations/custom-misp-enrich

# Create log and cache files with correct ownership
docker exec "$WAZUH_CONTAINER" touch /var/ossec/logs/misp-enrich.log /var/ossec/var/misp-cache.db
docker exec "$WAZUH_CONTAINER" chown wazuh:wazuh /var/ossec/logs/misp-enrich.log /var/ossec/var/misp-cache.db
docker exec "$WAZUH_CONTAINER" chmod 660 /var/ossec/logs/misp-enrich.log /var/ossec/var/misp-cache.db
```

---

## Test

End-to-end validation with a known Tor exit node IP (present in the Tor exit nodes feed):

```bash
cat > /tmp/test-misp.json <<EOF
{"id":"misp-test-$(date +%s)","data":{"srcip":"185.220.101.1"},"rule":{"level":12,"description":"MISP test","id":"100200"}}
EOF

/var/ossec/framework/python/bin/python3 /var/ossec/integrations/misp-enrich.py /tmp/test-misp.json
cat /var/ossec/logs/misp-enrich.log | tail -3
ls /var/ossec/var/misp-enrich-*.json
```

Expected log output:

```
2026-04-20T07:00:00 MISP MATCH: ip=185.220.101.1 found in 1 events
2026-04-20T07:00:00 Enrichment written: /var/ossec/var/misp-enrich-misp-test-<ts>.json
```

Full pipeline test (level 12, Ollama email with MISP context):

```bash
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/ollama-alert.py /tmp/test-misp.json
```

The resulting HTML email AI Analysis section should mention the MISP source feed.

---

## Troubleshooting

### wazuh-integratord: Unable to run integration for custom-misp-enrich

The wrapper and script must share the same base name. Verify both files exist:

```bash
docker exec "$WAZUH_CONTAINER" ls -la /var/ossec/integrations/ | grep misp
```

You should see both `custom-misp-enrich` (wrapper) and `misp-enrich.py` (script).

### PermissionError on /var/ossec/logs/misp-enrich.log

The log file must be owned by `wazuh:wazuh` with mode 660:

```bash
docker exec "$WAZUH_CONTAINER" chown wazuh:wazuh /var/ossec/logs/misp-enrich.log /var/ossec/var/misp-cache.db
docker exec "$WAZUH_CONTAINER" chmod 660 /var/ossec/logs/misp-enrich.log /var/ossec/var/misp-cache.db
docker exec "$WAZUH_CONTAINER" chmod 775 /var/ossec/var
```

### MISP THREAT INTEL MATCH missing from LLM output

The prompt template in `ollama-alert.py` must contain literal newlines around `{misp_ctx}`, not escaped `\n` strings. Validate with:

```bash
docker exec "$WAZUH_CONTAINER" grep -A2 "vt_score" /var/ossec/integrations/ollama-alert.py | head -10
```

You should see actual line breaks before `{misp_ctx}`, not `\n` characters.

### MISP query timeouts on large IOCs

Increase `MISP_TIMEOUT` in `config.py` if MISP takes longer than 10s to respond — typical when the attribute table grows beyond 100K entries.

### API returns Authentication failed

The API key must belong to a user with API access enabled. In MISP UI: **Administration → List Users → your user → Role** — the role must have API access enabled.

---

## Data flow summary

| Stage | File | Role |
|-------|------|------|
| Extract | `misp-enrich.py:extract_iocs()` | Parse `data.srcip`, `data.dstip`, `syscheck.sha256_after`, etc. |
| Filter | `is_private_ip()` | Skip RFC1918 ranges |
| Query | `query_misp()` | `POST /attributes/restSearch` with `{value, limit}` |
| Cache | SQLite `/var/ossec/var/misp-cache.db` | 24h TTL per IOC |
| Output | `/var/ossec/var/misp-enrich-{alert_id}.json` | Read by `ollama-alert.py` |
| Inject | `_load_misp_context()` | Adds MISP THREAT INTEL MATCH block to LLM prompt |

---

See also: [installation.md](installation.md), [configuration.md](configuration.md), [tutorial.md](tutorial.md)
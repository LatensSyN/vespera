# =============================================================================
# Vespera — configuration template
# Copy to config.py and fill in your values. NEVER commit config.py.
# =============================================================================

# --- VirusTotal ---
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

# --- AbuseIPDB ---
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_API_KEY"

# --- OpenCTI ---
OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = "YOUR_OPENCTI_API_TOKEN"

# --- Wazuh API ---
WAZUH_API_URL = "https://localhost:55000"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "YOUR_WAZUH_API_PASSWORD"

# --- OpenSearch ---
OPENSEARCH_URL = "https://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "YOUR_OPENSEARCH_PASSWORD"

# --- Mail (SMTP) ---
# Plain relay (port 25, local Postfix): leave TLS/auth off.
# Most providers (Gmail, SendGrid, Mailjet, Office365): use port 587 + TLS + login — see docs/smtp.md
SMTP_HOST = "localhost"
SMTP_PORT = 25
SMTP_USE_TLS = False   # True for STARTTLS (typical on port 587)
SMTP_SSL = False       # True for implicit SSL on port 465 (use instead of SMTP_USE_TLS)
SMTP_USER = ""         # set for authenticated SMTP
SMTP_PASS = ""
MAIL_FROM = "wazuh@yourdomain.local"
MAIL_TO = "soc@yourdomain.local"

# --- Ollama ---
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"
OLLAMA_TIMEOUT = 180

# --- Thresholds ---
MIN_ALERT_LEVEL = 10
ABUSEIPDB_THRESHOLD = 50
VT_MALICIOUS_THRESHOLD = 1

# --- Locale (HTML report + Ollama prompts + ip-enrich/vt-check verdict strings) ---
# Supported: en, fr, es — matches JSON under integrations/locales/
LOCALE = "en"

# --- Storage (SQLite: AbuseIPDB + VT caches; shared by ip-enrich + vt-check) ---
DB_PATH = "/var/ossec/var/vespera-cache.db"
REPORT_DIR = "/var/ossec/logs/vespera-reports"

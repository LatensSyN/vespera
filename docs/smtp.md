# Vespera — SMTP setup for HTML alert emails

`ollama-alert.py` sends reports via **SMTP**. The Wazuh manager (especially in Docker) must reach `SMTP_HOST:SMTP_PORT` from **inside the manager container**. `localhost` inside the container is **not** your Docker host unless you run an MTA in the same container.

---

## 1. Network: where the mail server lives

| Setup | What to put in `SMTP_HOST` |
|--------|----------------------------|
| SMTP on the **same host** as Docker, not in the container | Default gateway IP from the container, e.g. `docker exec MANAGER ip route \| awk '/default/ {print $3}'` (often `172.17.0.1`), or the host’s LAN IP |
| **External** provider (Gmail, SendGrid, Mailjet, etc.) | Provider hostname, e.g. `smtp.sendgrid.net` |
| Local **Postfix** on the host listening on all interfaces | Host gateway IP as above, port `25` |

After editing `config/config.py`, redeploy:

```bash
docker cp config/config.py MANAGER:/var/ossec/integrations/
```

(`MANAGER` = your Wazuh manager container name.)

---

## 2. LAN-only relay (lab)

Point `SMTP_HOST` at an MTA the **manager container** can reach (Docker bridge gateway, e.g. `172.17.0.1`, or a LAN IP — never `localhost` unless the MTA runs inside the same container). Use plain SMTP on the LAN when appropriate (`SMTP_USE_TLS = False`, `SMTP_USER` / `SMTP_PASS` empty unless required).

**Detailed guides (no duplication here):**

| Topic | Doc |
|-------|-----|
| Postfix + Maildir + Dovecot + `config.py` on Linux | [smtp-lan-linux.md](smtp-lan-linux.md) |
| Thunderbird (IMAP/SMTP) | [thunderbird.md](thunderbird.md) |

**Connectivity test** (substitute IP/port):

```bash
docker exec MANAGER python3 -c "import socket; s=socket.create_connection(('192.168.x.x', 25), 5); print('OK'); s.close()"
```

---

## 3. Authentication and encryption (`config.py`)

Supported options (see `config/config.example.py`):

| Variable | Meaning |
|----------|---------|
| `SMTP_HOST` | Server hostname or IP |
| `SMTP_PORT` | `25` (plain relay), `587` (STARTTLS), `465` (SSL) |
| `SMTP_USE_TLS` | `True` → `STARTTLS` after connect (typical for **587**) |
| `SMTP_SSL` | `True` → use implicit SSL (**465**); do not enable TLS + SSL together |
| `SMTP_USER` / `SMTP_PASS` | Login if the server requires authentication |
| `MAIL_FROM` | Envelope sender (must be allowed by your provider) |
| `MAIL_TO` | Recipient SOC mailbox |

**Examples**

- **Port 587 + STARTTLS** (SendGrid, Mailjet, many ISPs):

```python
SMTP_HOST = "smtp.sendgrid.net"
SMTP_PORT = 587
SMTP_USE_TLS = True
SMTP_SSL = False
SMTP_USER = "apikey"
SMTP_PASS = "YOUR_SENDGRID_API_KEY"
MAIL_FROM = "alerts@your-verified-domain.com"
MAIL_TO = "soc@yourcompany.com"
```

- **Port 465 (SSL)**:

```python
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 465
SMTP_USE_TLS = False
SMTP_SSL = True
SMTP_USER = "user@example.com"
SMTP_PASS = "secret"
```

- **Local Postfix on Docker host**, no auth, port 25:

```python
SMTP_HOST = "172.17.0.1"   # verify with ip route inside container
SMTP_PORT = 25
SMTP_USE_TLS = False
SMTP_SSL = False
SMTP_USER = ""
SMTP_PASS = ""
```

---

## 4. Quick connectivity test (from the manager container)

Replace host/port with your values:

```bash
docker exec MANAGER python3 -c "
import socket
s=socket.create_connection(('SMTP_HOST', PORT), 5)
print('OK', s)
s.close()
"
```

---

## 5. Gmail / Google Workspace

Google requires an **App Password** (2FA enabled) or OAuth. App Password example:

```python
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USE_TLS = True
SMTP_SSL = False
SMTP_USER = "you@gmail.com"
SMTP_PASS = "your-16-char-app-password"
MAIL_FROM = "you@gmail.com"
MAIL_TO = "soc@example.com"
```

---

## 6. Troubleshooting

| Symptom | Check |
|---------|--------|
| `Connection refused` | Wrong host/port; nothing listening; `localhost` from container ≠ host |
| `Authentication failed` | User/password; provider requires app password |
| `STARTTLS` / TLS errors | Set `SMTP_USE_TLS = True` on 587, or `SMTP_SSL = True` on 465 |
| Mail goes to spam | SPF/DKIM for `MAIL_FROM` domain at your DNS provider |

---

## 7. Re-test Vespera after SMTP changes

```bash
docker cp config/config.py MANAGER:/var/ossec/integrations/
docker exec -i MANAGER python3 /var/ossec/integrations/ollama-alert.py < docs/test-alerts/suricata-min.json
```

See also: [configuration.md](configuration.md), [installation.md](installation.md).

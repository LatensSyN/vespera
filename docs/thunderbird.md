# Thunderbird — read Vespera reports (local lab)

Receives Vespera HTML email reports via IMAP from a local Dovecot server.

Prerequisites: Postfix and Dovecot configured per [smtp-lan-linux.md](smtp-lan-linux.md).

---

## Working configuration

| Layer | Value |
|-------|-------|
| Postfix delivery | `home_mailbox = Maildir/` → `~/Maildir/` |
| Dovecot `mail_location` | `maildir:~/Maildir` (must match Postfix) |
| SOC user | `wazuh` (non-root) |
| `MAIL_TO` in config.py | `wazuh@localhost` |

> **If Thunderbird shows an empty inbox:** Dovecot `mail_location` is pointing to `mbox` while Postfix writes `Maildir`. Run `./install.sh --repair` — it fixes `/etc/dovecot/conf.d/10-mail.conf` automatically.

---

## Thunderbird account settings

### Incoming server (IMAP)

| Field | Value |
|-------|-------|
| Protocol | IMAP |
| Server | `127.0.0.1` (or LAN IP if Thunderbird is on another machine) |
| Port | `143` |
| SSL/TLS | None (lab) |
| Authentication | Normal password |
| Username | `wazuh` (Unix login name) |
| Password | Unix password for `wazuh` |

### Outgoing server (SMTP)

| Field | Value |
|-------|-------|
| Server | `127.0.0.1` |
| Port | `25` |
| SSL/TLS | None |
| Authentication | None |

---

## Setup steps

1. **Install Dovecot** (if not done):
   ```bash
   sudo apt install -y dovecot-imapd
   ```

2. **Set correct mail_location** in `/etc/dovecot/conf.d/10-mail.conf`:
   ```conf
   mail_location = maildir:~/Maildir
   ```
   Then restart: `sudo systemctl restart dovecot`

3. **In Thunderbird**: File → New → Existing Mail Account
   - Name: `SOC Wazuh`
   - Email: `wazuh@localhost`
   - Password: (Unix password for `wazuh`)
   - Configure manually with the settings above

4. **Quick test**:
   ```bash
   echo "Test Vespera" | mail -s "Test SOC" wazuh@localhost
   ```
   Then **Get Messages** in Thunderbird (or F5).

5. **Run a full pipeline test**:
   ```bash
   ./install.sh --test-mail
   ```
   Injects a real level-12 alert, processes it through Ollama, and sends the HTML report to your inbox.

---

## Checklist

- [ ] `ls /home/wazuh/Maildir/new/` shows new files after sending a test mail
- [ ] `nc -vz 127.0.0.1 143` — IMAP listening
- [ ] Thunderbird INBOX is subscribed (right-click inbox → Subscribe)
- [ ] `mail_location = maildir:~/Maildir` in Dovecot (not mbox)
- [ ] `MAIL_TO = "wazuh@localhost"` in `config.py`

---

See also: [smtp-lan-linux.md](smtp-lan-linux.md) · [installation.md](installation.md)

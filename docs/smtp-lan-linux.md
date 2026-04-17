# LAN-only SMTP on Linux (Postfix + Dovecot) for Vespera

Sets up a minimal local mail path on Debian/Ubuntu: Postfix receives from the Wazuh manager container, delivers to a local Unix user's **Maildir**, and Dovecot exposes **IMAP** for Thunderbird.

---

## Architecture

| Component | Role |
|-----------|------|
| **Postfix** | Listens on TCP 25; receives mail from Vespera via `host-gateway` |
| **Local user** (e.g. `wazuh`) | Mail delivered to `~/Maildir/` |
| **Dovecot** | IMAP on port 143 — Thunderbird reads mail here |
| **Vespera** | `SMTP_HOST = "host-gateway"` in Docker mode |

When Wazuh Docker and Postfix run on the **same host**, the container reaches Postfix via `host-gateway` (Docker resolves this to the host IP when `extra_hosts` is configured).

---

## 1. Install Postfix

```bash
sudo apt update
sudo apt install -y postfix mailutils
```

When prompted:
- **General type**: `Internet Site`
- **System mail name**: your hostname (e.g. `wazuhh`)

---

## 2. Configure Postfix

Apply the Vespera template:

```bash
cp config/postfix-main.cf.example config/postfix-main.cf
# Edit myhostname / mydomain if needed
chmod +x scripts/apply-postfix.sh
./scripts/apply-postfix.sh
```

Or manually edit `/etc/postfix/main.cf`:

```conf
myhostname = wazuhh
mydomain = localhost
myorigin = $mydomain

# Listen on all interfaces (Docker bridge needs this)
inet_interfaces = all
inet_protocols = ipv4

# Trust localhost + Docker/LAN ranges
mynetworks = 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# Accept mail for local users
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

# Maildir delivery (MUST match Dovecot mail_location below)
home_mailbox = Maildir/
mailbox_command =
```

```bash
sudo postfix check
sudo systemctl reload postfix
```

---

## 3. Create the SOC inbox user

```bash
sudo adduser wazuh --disabled-password --gecos "SOC inbox"
# or use an existing user
```

---

## 4. Install and configure Dovecot

```bash
sudo apt install -y dovecot-imapd
```

Edit `/etc/dovecot/conf.d/10-mail.conf` — set `mail_location` to **Maildir** (must match Postfix `home_mailbox`):

```conf
mail_location = maildir:~/Maildir
```

> **Common mistake:** if this is set to `mbox:~/mail:INBOX=/var/mail/%u`, Dovecot reads from `/var/mail/` while Postfix writes to `~/Maildir/` — Thunderbird shows an empty inbox. Always use `maildir:~/Maildir`.

Allow plain auth on localhost (lab only):

```conf
# /etc/dovecot/conf.d/10-auth.conf
disable_plaintext_auth = no
```

Enable and start:

```bash
sudo systemctl enable --now dovecot
```

---

## 5. Firewall

```bash
sudo ufw allow from 172.16.0.0/12 to any port 25 proto tcp   # Docker bridge
sudo ufw allow from 127.0.0.1 to any port 143 proto tcp       # IMAP localhost
sudo ufw reload
```

---

## 6. Vespera config.py

In Docker mode with `host-gateway` configured:

```python
SMTP_HOST = "host-gateway"   # wizard sets this automatically
SMTP_PORT = 25
SMTP_USE_TLS = False
SMTP_SSL = False
SMTP_USER = ""
SMTP_PASS = ""
MAIL_FROM = "wazuh@localhost"
MAIL_TO = "wazuh@localhost"
```

The wizard auto-detects `mydomain` from Postfix and sets the correct `@domain` in `MAIL_TO`.

---

## 7. Test

```bash
# From the host
echo "Vespera test" | mail -s "test" wazuh@localhost
ls ~/Maildir/new/   # should show a new file

# From the manager container
docker exec MANAGER python3 -c "
import socket
s = socket.create_connection(('host-gateway', 25), 5)
print(s.recv(220))
s.close()
"
```

Or use the built-in pipeline test:

```bash
./install.sh --test-mail
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Thunderbird inbox empty | Dovecot reads mbox, Postfix writes Maildir | `./install.sh --repair` or set `mail_location = maildir:~/Maildir` |
| `userdb returned 0 as uid` | Dovecot refuses uid 0 (root) | Use a non-root user (`wazuh`, `soc`) |
| Connection refused from container | Postfix not listening on Docker bridge | Check `inet_interfaces = all` and Postfix is running |
| Mail rejected | Sender domain not in `mydestination` | Add `localhost` or your domain to `mydestination` |

---

See also: [thunderbird.md](thunderbird.md) · [smtp.md](smtp.md) · [installation.md](installation.md)

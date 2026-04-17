# Changelog

## [0.3.0] — 2026-04-14

### Added

- **`alert-watcher.py`** — persistent Python daemon that tails `alerts.json` directly and drives the Ollama pipeline. Workaround for `wazuh-integratord` inactivity bug on Wazuh 4.14+.
- **`vespera-watcher` systemd service** — deployed by `--quick` and `--repair`; keeps the watcher running permanently via `docker exec`. Survives container and host restarts.
- **`install.sh --validate`** — 6-point post-install health check: integratord status, Ollama via `host-gateway`, SMTP via `host-gateway`, config.py loadability, watcher service, ossec.conf block count.
- **`install.sh --test-mail`** — injects a real level-12 alert into `alerts.json`, waits for Ollama to process it, and confirms mail delivery.
- **`install.sh --repair`** — auto-fixes: Dovecot `mail_location` (maildir vs mbox), ossec.conf double `<ossec_config>` block, watcher service deployment.
- **`detect_best_ollama_model()`** — wizard now auto-selects the best installed Ollama model instead of suggesting one that may not be present.
- **`detect_postfix_domain()`** — wizard reads `postconf mydomain` to set the correct `@domain` in `MAIL_TO` automatically.
- **`check_host_gateway()`** — after deploy, validates that `host-gateway` is resolvable from the container and shows the exact `extra_hosts` fix if not.
- **`check_duplicate_rules()`** — skips `0_vespera.xml` install if rule IDs 100200–100300 already exist in other rule files.

### Fixed

- **`vespera-merge-ossec.py`**: double `<ossec_config>` block — `analysisd` only parses the first block; the script now merges all blocks into one before inserting Vespera XML.
- **`vespera-merge-ossec.py`**: detects pre-existing `<integration>` blocks not managed by Vespera and warns before merging (prevents silent overwrite).
- **`vespera-merge-ossec.py`**: `--non-interactive` flag for use with `--quick` (no prompt in CI/automated installs).
- **Dovecot `mail_location`**: was `mbox:~/mail:INBOX=/var/mail/%u`; must be `maildir:~/Maildir` to match Postfix `home_mailbox = Maildir/`. Fixed automatically by `--repair`.
- **`ossec.conf` split block**: `--quick` used to add a second `<ossec_config>` block that `analysisd` ignored, causing `<integration>` entries to never fire.
- **Agent `/var/ossec/etc/shared/` permissions**: `wazuh-agentd` could not write `ar.conf`, generating `Permission denied` errors every 20 seconds. Fixed by `--repair`.
- **Thunderbird inbox empty**: Dovecot pointing at mbox while Postfix writes Maildir — documented and fixed by `--repair`.

### Changed

- `install.sh --quick` now also: fixes ossec.conf double block, fixes shared/ permissions, deploys `alert-watcher.py`, creates `vespera-watcher` systemd service, and restarts the manager.
- Wizard default SMTP user changed from `root` to `wazuh` (Dovecot refuses uid 0).
- `install.sh` usage block and all docs updated with new flags.
- VERSION bumped to 0.3.0.

---

## [0.2.0] — 2026-04-09

### Added

- Full i18n wizard: language selection at startup (EN / FR / ES)
- Prerequisite detection with auto-install (python3, curl, nc, Ollama)
- Post-install validation tests (Ollama, SMTP, Docker, Python modules)
- Thunderbird setup guide (option 6 in SMTP wizard)
- `host-gateway` explanation inline during Docker auto-detection
- `printf`-based string interpolation for i18n (replaces broken `sed` substitution)
- `git update-index --chmod=+x` for install.sh executable bit

### Fixed

- `ollama-alert.py`: reads from `sys.argv[1]` (file path) when called by Wazuh integratord; falls back to stdin for manual testing
- `ollama-alert.py`: `MIN_ALERT_LEVEL` check before calling Ollama
- `ollama-alert.py`: `VESPERA_OLLAMA_URL` / `VESPERA_SMTP_HOST` env var overrides (for on-host test where `host-gateway` does not resolve)
- Test email: substitutes `host-gateway → localhost` for on-host pipeline test
- Thunderbird guide: garbled text from broken `sed '\$TB_USER'` substitution

---

## [0.1.0] — 2026-03-xx

Initial release.

# Contributing to Vespera

Thank you for your interest in contributing.

## What we need

- **Bug reports** — open an issue with steps to reproduce
- **Translations** — copy `integrations/locales/en.json`, translate values, submit PR
- **New alert types** — extend `detect_type()` and `get_indicators()` in `ollama-alert.py`
- **Documentation** — installation guides, screenshots, use cases
- **Integrations** — Slack, Teams, Telegram, URLhaus, new threat intel sources

## Ground rules

1. **Never commit API keys** — use `config.example.py` placeholders only
2. **Test before submitting** — verify your changes work on a real Wazuh alert
3. **Keep it self-hosted** — no mandatory cloud dependencies
4. **Document your changes** — update README or docs/ if needed

## How to submit a PR

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Verify no API keys in diff: `git diff | grep -i "key\|token\|pass\|secret"`
5. Submit PR with description of what and why

## Adding a new locale

1. Copy `integrations/locales/en.json` → `integrations/locales/YOUR_LANG.json`
2. Translate all values (keep keys unchanged)
3. Test by setting `LOCALE = "YOUR_LANG"` in config.py and triggering a test alert
4. Submit PR with the new locale file

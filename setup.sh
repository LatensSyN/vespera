#!/usr/bin/env bash
# Vespera — raccourci pour (re)lancer le wizard de configuration.
# Équivalent à : ./install.sh --setup
#
# Usage:
#   ./setup.sh          → wizard complet (génère config/config.py)
#   ./setup.sh --deploy → wizard puis déploiement immédiat (--quick)
exec "$(dirname "${BASH_SOURCE[0]}")/install.sh" --setup "$@"

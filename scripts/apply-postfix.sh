#!/usr/bin/env bash
# Vespera — copie un main.cf Postfix (depuis le dépôt) vers /etc/postfix/ et recharge le service.
set -euo pipefail

VESPERA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:-}"

if [[ -z "$SRC" ]]; then
  if [[ -f "$VESPERA_ROOT/config/postfix-main.cf" ]]; then
    SRC="$VESPERA_ROOT/config/postfix-main.cf"
  else
    SRC="$VESPERA_ROOT/config/postfix-main.cf.example"
  fi
elif [[ "$SRC" != /* ]]; then
  SRC="$VESPERA_ROOT/$SRC"
fi

if [[ ! -f "$SRC" ]]; then
  echo "Fichier introuvable: $SRC"
  exit 1
fi

echo "Source : $SRC"
echo "Cible  : /etc/postfix/main.cf"

if [[ "${DRY_RUN:-}" == "1" ]]; then
  echo "[dry-run] sudo cp + postfix check + reload"
  exit 0
fi

sudo cp "$SRC" /etc/postfix/main.cf
sudo postfix check
sudo systemctl reload postfix

echo "Postfix rechargé. Vérifie : systemctl status postfix"

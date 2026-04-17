#!/usr/bin/env bash
# =============================================================================
# Vespera — Setup Wizard + Installer
# =============================================================================
# First run  : ./install.sh              → wizard si pas de config.py, puis deploy
# Re-configurer : ./install.sh --setup   → relance le wizard
# Deploy seul : ./install.sh --quick     → déploie avec config.py existant
#
# Flags:
#   --setup           Lance le wizard (re)configuration, ne déploie pas
#   --docker-only     Copie les fichiers dans le container Docker manager
#   --bare-only       Copie dans /var/ossec local (bare metal)
#   --merge-ossec     Fusionne les blocs XML dans ossec.conf (idempotent)
#   --install-rules   Installe config/custom-rules.xml → 0_vespera.xml
#   --restart-wazuh   Redémarre le manager Wazuh
#   --quick           --docker-only + --merge-ossec + --install-rules + --restart-wazuh
#   --repair          Corrections auto sans redéployer (dovecot, ossec.conf, watcher)
#   --validate        Vérification post-install (integratord, Ollama, SMTP, config, watcher)
#   --test-mail       Injecte alerte test dans alerts.json et attend le mail
#   --locale LANG     Force LOCALE dans config.py (en, fr, es)
#   --prompt-locale   Choix interactif de LOCALE
#   DRY_RUN=1         Affiche les commandes sans les exécuter
# =============================================================================
set -euo pipefail

VESPERA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_BASE="${WAZUH_BASE:-/var/ossec}"

# ─── Couleurs ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ─── Flags ────────────────────────────────────────────────────────────────────
DOCKER_ONLY=0; BARE_ONLY=0; MERGE_OSSEC=0; INSTALL_RULES=0; RESTART_WAZUH=0
QUICK=0; DEPLOY_FILES=0; LOCALE_FLAG=""; PROMPT_LOCALE=0; SETUP_ONLY=0; REPAIR=0
TEST_MAIL=0; VALIDATE=0

usage() {
  cat <<EOF
Usage: $0 [flags]

Sans flag   : wizard de configuration si config.py absent, puis déploiement auto-détecté.
--setup     : (re)lancer le wizard sans déployer.
--quick     : déployer avec config.py existant (Docker auto-détecté + merge + règles + restart).

Flags de déploiement:
  --docker-only      Copier dans le container Docker manager
  --bare-only        Copier dans /var/ossec local
  --merge-ossec      Fusionner les XML Vespera dans ossec.conf
  --install-rules    Installer config/custom-rules.xml → 0_vespera.xml
  --restart-wazuh    Redémarrer le manager Wazuh
  --locale LANG      Forcer LOCALE dans config.py (en, fr, es)
  --prompt-locale    Choix interactif de LOCALE
  --quick            Tout faire en une commande (docker + merge + regles + restart)
  --repair          Appliquer les corrections auto sans redeployer (dovecot, ossec.conf, watcher)
  --validate        Verifier l etat post-install (integratord, Ollama, SMTP, config, watcher)
  --test-mail       Injecter une alerte test dans alerts.json et attendre le mail

Variables d environnement:
  WAZUH_CONTAINER   Nom du container manager (auto-detecte si absent)
  WAZUH_BASE        Chemin Wazuh (defaut: /var/ossec)
  DRY_RUN=1         Afficher sans executer

Exemples:
  ./install.sh                              # wizard + deploy
  ./install.sh --setup                      # reconfigurer seulement
  ./install.sh --quick                      # deployer config existante
  ./install.sh --validate                   # verifier post-install
  ./install.sh --test-mail                  # tester le pipeline
  ./install.sh --locale fr --quick
  WAZUH_CONTAINER=mon-manager ./install.sh --quick
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup)         SETUP_ONLY=1; shift ;;
    --docker-only)   DOCKER_ONLY=1; DEPLOY_FILES=1; shift ;;
    --bare-only)     BARE_ONLY=1; DEPLOY_FILES=1; shift ;;
    --merge-ossec)   MERGE_OSSEC=1; shift ;;
    --install-rules) INSTALL_RULES=1; shift ;;
    --restart-wazuh) RESTART_WAZUH=1; shift ;;
    --quick)         QUICK=1; shift ;;
    --repair)        REPAIR=1; shift ;;
    --test-mail)     TEST_MAIL=1; shift ;;
    --validate)      VALIDATE=1; shift ;;
    --locale)        LOCALE_FLAG="$2"; shift 2 ;;
    --prompt-locale) PROMPT_LOCALE=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "Option inconnue: $1"; usage; exit 1 ;;
  esac
done

[[ "$QUICK" == 1 ]] && { DOCKER_ONLY=1; DEPLOY_FILES=1; MERGE_OSSEC=1; INSTALL_RULES=1; RESTART_WAZUH=1; }

run() {
  if [[ "${DRY_RUN:-}" == "1" ]]; then echo "[dry-run] $*"; else eval "$@"; fi
}

# ─── Détection ────────────────────────────────────────────────────────────────
detect_wazuh_manager_container() {
  docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null \
    | awk -F'\t' '$2 ~ /wazuh-manager/ {print $1; exit}'
}

resolve_docker_container() {
  if [[ -n "${WAZUH_CONTAINER:-}" ]]; then echo "$WAZUH_CONTAINER"; return; fi
  local auto; auto="$(detect_wazuh_manager_container)"
  [[ -n "$auto" ]] && echo "$auto" || echo "wazuh.manager"
}

CONTAINER="$(resolve_docker_container)"

suggest_ollama_model() {
  local mem_kb=""
  [[ -r /proc/meminfo ]] && mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  if [[ -n "$mem_kb" && "$mem_kb" -ge 15728640 ]]; then
    echo "Conseil: RAM >= 15 Go → envisager OLLAMA_MODEL=\"llama3.1:8b\"  (ollama pull llama3.1:8b)"
  else
    echo "Conseil: RAM modeste → OLLAMA_MODEL=\"llama3.2:3b\"  (ollama pull llama3.2:3b)"
  fi
}

# Retourne le meilleur modèle installé, ou "" si aucun
detect_best_ollama_model() {
  curl -sf --max-time 3 http://localhost:11434/api/tags 2>/dev/null \
    | python3 -c "
import sys, json
try:
    models = [m['name'] for m in json.load(sys.stdin).get('models', [])]
    # Préférence : taille décroissante — 70b > 13b > 8b > 7b > 3b > 1b
    order = ['70b','13b','8b','7b','3b','2b','1b']
    def rank(n):
        for i,s in enumerate(order):
            if s in n: return i
        return 99
    models.sort(key=rank)
    print(models[0] if models else '')
except: print('')
" 2>/dev/null || echo ""
}

# Retourne le domaine mail Postfix depuis l'hôte ou un container
detect_postfix_domain() {
  local cname="$1"
  local domain=""
  if [[ -n "$cname" ]]; then
    # Essayer de trouver un container mailserver
    local mail_cname
    mail_cname=$(docker ps --format '{{.Names}}' 2>/dev/null \
      | grep -iE "mail|postfix|smtp" | head -1)
    if [[ -n "$mail_cname" ]]; then
      domain=$(docker exec "$mail_cname" postconf mydomain 2>/dev/null \
        | awk -F'=' '{print $2}' | tr -d ' \t\n' || echo "")
    fi
  fi
  # Fallback : postfix local sur l'hôte
  if [[ -z "$domain" ]]; then
    domain=$(postconf mydomain 2>/dev/null \
      | awk -F'=' '{print $2}' | tr -d ' \t\n' || echo "")
  fi
  # Nettoyer — on veut seulement le domaine simple, pas "localhost" ou vide
  if [[ -z "$domain" || "$domain" == "localhost" || "$domain" == "localdomain" ]]; then
    echo ""
  else
    echo "$domain"
  fi
}

# Vérifie que host-gateway est résolvable depuis le container
check_host_gateway() {
  local cname="$1"
  [[ -z "$cname" ]] && return 0
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname" || return 0
  docker exec "$cname" getent hosts host-gateway >/dev/null 2>&1
}

# Vérifie les règles dupliquées avant install
check_duplicate_rules() {
  local cname="$1"
  local rules_file="$VESPERA_ROOT/config/custom-rules.xml"
  [[ -f "$rules_file" ]] || return 0

  local ids; ids=$(grep -oP 'rule id="\K[0-9]+' "$rules_file" 2>/dev/null)
  local conflicts=()
  for rid in $ids; do
    if [[ -n "$cname" ]]; then
      if docker exec "$cname" grep -rq "rule id=\"${rid}\"" \
           "$WAZUH_BASE/etc/rules/" 2>/dev/null; then
        # Ignorer si c'est dans notre propre fichier déjà installé
        if ! docker exec "$cname" test -f "$WAZUH_BASE/etc/rules/0_vespera.xml" 2>/dev/null || \
           ! docker exec "$cname" grep -q "rule id=\"${rid}\"" \
               "$WAZUH_BASE/etc/rules/0_vespera.xml" 2>/dev/null; then
          conflicts+=("$rid")
        fi
      fi
    elif [[ -d "$WAZUH_BASE/etc/rules" ]]; then
      if grep -rq "rule id=\"${rid}\"" "$WAZUH_BASE/etc/rules/" 2>/dev/null; then
        if ! grep -q "rule id=\"${rid}\"" "$WAZUH_BASE/etc/rules/0_vespera.xml" 2>/dev/null; then
          conflicts+=("$rid")
        fi
      fi
    fi
  done

  if [[ ${#conflicts[@]} -gt 0 ]]; then
    _wiz_warn "Rule ID conflict(s) detected: ${conflicts[*]}"
    _wiz_warn "These IDs already exist in other rule files — skipping rule install to avoid duplicates."
    return 1
  fi
  return 0
}

# ─── Wizard helpers ───────────────────────────────────────────────────────────
_wiz_ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
_wiz_info() { echo -e "  ${CYAN}ℹ${RESET} $*"; }
_wiz_warn() { echo -e "  ${YELLOW}⚠${RESET} $*"; }
_wiz_step() {
  echo ""
  echo -e "${BOLD}${BLUE}[$1/5] $2${RESET}"
  echo -e "${DIM}$(printf '─%.0s' {1..56})${RESET}"
}
_wiz_ask() {
  # _wiz_ask VARNAME "Question" "default"
  local _vn="$1" _q="$2" _d="${3:-}" _in=""
  if [[ -n "$_d" ]]; then
    printf "  %s [${BOLD}%s${RESET}]: " "$_q" "$_d"
  else
    printf "  %s: " "$_q"
  fi
  read -r _in
  printf -v "$_vn" '%s' "${_in:-$_d}"
}
_wiz_ask_secret() {
  local _vn="$1" _q="$2" _in=""
  printf "  %s: " "$_q"
  read -rs _in; echo ""
  printf -v "$_vn" '%s' "$_in"
}

# ─── i18n wizard ──────────────────────────────────────────────────────────────
_wiz_lang_init() {
  echo ""
  echo -e "  ${BOLD}Language / Langue / Idioma${RESET}"
  echo -e "  ${BOLD}1)${RESET} English   ${BOLD}2)${RESET} Français   ${BOLD}3)${RESET} Español"
  local _ch; read -r -p "  Choice / Choix / Opción [2]: " _ch
  case "${_ch:-2}" in
    1|en|EN) _WIZ_LANG="en" ;;
    3|es|ES) _WIZ_LANG="es" ;;
    *)        _WIZ_LANG="fr" ;;
  esac
}

# Translations — usage: ${_L[key]}
declare -A _L=()
_wiz_set_lang() {
  case "$_WIZ_LANG" in
  # ── FRENCH ──────────────────────────────────────────────────────────────────
  fr)
    _L[title]="Assistant de configuration"
    _L[hint]="Appuie sur Entrée pour accepter la valeur affichée entre [ ]."
    _L[detecting]="Détection de l'environnement…"
    _L[wazuh_found]="Container Wazuh détecté"
    _L[wazuh_bare]="Wazuh bare metal détecté"
    _L[wazuh_none]="Aucun Wazuh détecté — configuration sauvegardée, déploiement plus tard."
    _L[ollama_found]="Ollama détecté sur localhost:11434"
    _L[ollama_models]="Modèles installés"
    _L[ollama_none]="Ollama non détecté (configurable manuellement)"
    _L[ollama_docker]="Mode Docker → URL par défaut"
    _L[ollama_warn]="Ajouter dans docker-compose.yml sous wazuh.manager :"
    _L[host_gw_explain]="host-gateway = adresse de ta machine Ubuntu vue depuis Docker. Le container Wazuh s'en sert pour joindre Ollama et Postfix qui tournent sur l'hôte."
    _L[smtp_found]="SMTP/Postfix détecté sur localhost:25"
    _L[s1]="WAZUH"; _L[s2]="OLLAMA — Analyse IA"; _L[s3]="SMTP — Envoi des rapports"
    _L[s4]="CLÉS API  (gratuites — laisser vide pour désactiver)"
    _L[s5]="OPTIONS"
    _L[container]="Nom du container manager"
    _L[bare_info]="Déploiement bare metal dans"
    _L[ollama_url]="URL Ollama (vue depuis Wazuh)"
    _L[ollama_model]="Modèle Ollama"
    _L[ollama_timeout]="Timeout (secondes)"
    _L[smtp_o1]="Relai local Postfix  (port 25, sans auth)"
    _L[smtp_o2]="Provider externe STARTTLS  (SendGrid, Mailjet, OVH — port 587)"
    _L[smtp_o3]="Gmail / Google Workspace  (port 587 + mot de passe application)"
    _L[smtp_o4]="SSL implicite  (port 465)"
    _L[smtp_o5]="Saisie manuelle"
    _L[smtp_o6]="Thunderbird local  (Postfix + boîte locale + guide Thunderbird)"
    _L[choice]="Choix"
    _L[smtp_host]="Hôte SMTP"; _L[smtp_port]="Port SMTP"
    _L[smtp_user]="Login SMTP"; _L[smtp_pass]="Mot de passe SMTP"
    _L[smtp_noauth]="Login (vide = sans auth)"
    _L[starttls]="STARTTLS (o/N)"; _L[ssl]="SSL implicite (o/N)"
    _L[gmail_hint]="Crée un mot de passe application → myaccount.google.com/apppasswords"
    _L[tb_user]="Utilisateur local pour recevoir le mail"
    _L[mail_from]="Adresse expéditeur"; _L[mail_to]="Adresse destinataire SOC"
    _L[mail_req]="L'adresse destinataire est obligatoire."
    _L[smtp_hg_warn]="host-gateway pour SMTP nécessite extra_hosts dans docker-compose.yml."
    _L[vt_info]="VirusTotal → virustotal.com/gui/join-us  (analyse hash fichiers suspects)"
    _L[vt_key]="VirusTotal API key"
    _L[abuse_info]="AbuseIPDB → abuseipdb.com/register  (réputation IPs SSH/IDS)"
    _L[abuse_key]="AbuseIPDB API key"
    _L[lang_title]="Langue des rapports HTML et des prompts Ollama :"
    _L[level_info]="Niveau minimum pour l'analyse IA (1-15, recommandé : 10)"
    _L[level_q]="Niveau minimum d'alerte"
    _L[thr_info]="Seuil AbuseIPDB pour enrichir l'alerte (0-100, recommandé : 50)"
    _L[thr_q]="Seuil AbuseIPDB"
    _L[summary]="RÉSUMÉ DE CONFIGURATION"
    _L[confirm]="Écrire config/config.py et continuer ? [O/n]"
    _L[cancelled]="Annulé."; _L[done]="config/config.py créé."
    _L[action]="ACTION REQUISE — docker-compose.yml"
    _L[action_body]="Ajouter sous le service wazuh.manager :"
    _L[action_restart]="Puis redémarrer : docker compose down && docker compose up -d"
    _L[tb_title]="CONFIGURATION THUNDERBIRD"
    _L[tb_step1]="1. Installer Dovecot (serveur IMAP local) :"
    _L[tb_step1b]="   sudo apt install dovecot-imapd -y"
    _L[tb_step2]="2. Dans Thunderbird → Nouveau compte → Adresse email :"
    _L[tb_step2b]="   Nom : SOC Wazuh · Adresse : %s@localhost · Mot de passe : (vide)"
    _L[tb_step3]="3. Serveur entrant (IMAP) :"
    _L[tb_step3b]="   Hôte : localhost · Port : 143 · SSL : Aucun · Auth : Mot de passe normal"
    _L[tb_step4]="4. Serveur sortant (SMTP) :"
    _L[tb_step4b]="   Hôte : localhost · Port : 25  · SSL : Aucun · Auth : Aucune"
    _L[tb_test]="5. Test rapide :"
    _L[tb_testb]='   echo "Test Vespera" | mail -s "Test SOC" %s@localhost'
    _L[enabled]="✓ activé"; _L[disabled]="désactivé"
    _L[container_lbl]="Container Wazuh"; _L[url_lbl]="Ollama URL"
    _L[model_lbl]="Modèle"; _L[timeout_lbl]="Timeout Ollama"
    _L[smtp_lbl]="SMTP"; _L[tls_lbl]="STARTTLS activé"; _L[ssl_lbl]="SSL activé"
    _L[login_lbl]="Login SMTP"; _L[from_lbl]="Expéditeur"; _L[to_lbl]="Destinataire SOC"
    _L[vt_lbl]="VirusTotal"; _L[abuse_lbl]="AbuseIPDB"
    _L[lang_lbl]="Langue rapports"; _L[level_lbl]="Niveau minimum"
    _L[thr_lbl]="Seuil AbuseIPDB"
    # Prérequis
    _L[prereq_title]="Vérification des prérequis"
    _L[prereq_missing]="Manquant"
    _L[prereq_install_q]="Installer automatiquement ? [O/n]"
    _L[prereq_auto_installing]="Installation en cours…"
    _L[prereq_ollama_label]="Ollama non installé — commande d'installation :"
    _L[prereq_model_q]="Aucun modèle Ollama — télécharger maintenant ? [O/n]"
    _L[prereq_model_pulling]="Téléchargement en cours (peut prendre plusieurs minutes)…"
    _L[prereq_start_q]="Démarrer Ollama maintenant ? [O/n]"
    # Tests
    _L[test_title]="TESTS DE VALIDATION"
    _L[test_ollama]="Connexion Ollama"
    _L[test_smtp]="Connexion SMTP"
    _L[test_docker]="Container Wazuh"
    _L[test_script]="Modules Python"
    _L[test_fail]="ÉCHEC"
    _L[test_all_ok]="Tous les tests ont passé — pipeline prête !"
    _L[test_warn]="Certains tests ont échoué — voir les suggestions ci-dessus."
    _L[test_fix_ollama_docker]="Vérifie extra_hosts dans docker-compose.yml et redémarre le stack."
    _L[test_fix_ollama_local]="Démarre Ollama :  sudo systemctl start ollama  ou  ollama serve &"
    _L[test_fix_smtp]="Vérifie Postfix :  sudo systemctl status postfix  |  sudo systemctl start postfix"
    _L[test_fix_docker]="Démarre le stack :  docker compose up -d"
    _L[test_fix_script]="Vérifie python3 :  python3 -c 'import smtplib, subprocess, json'"
    _L[test_send_mail_q]="Envoyer un mail de test maintenant ? [o/N]"
    _L[test_mail_ok]="Mail de test envoyé à"
    _L[test_mail_fail]="Échec envoi mail"
    _L[test_mail_check]="Vérifie ta boîte mail :"
    # Watcher / pipeline
    _L[watcher_deploying]="Déploiement du watcher Vespera…"
    _L[watcher_ok]="Service vespera-watcher actif"
    _L[watcher_fail]="Service non actif — vérifier : journalctl -u vespera-watcher"
    _L[watcher_service]="Service systemd vespera-watcher créé et activé"
    _L[dovecot_fix]="Correction Dovecot mail_location → maildir (aligné avec Postfix)"
    _L[ossec_fix]="Fusion ossec.conf → bloc unique (fix analysisd)"
    _L[pipeline_test]="Test pipeline complet"
    _L[pipeline_inject]="Injection alerte niveau 10 dans alerts.json…"
    _L[pipeline_wait]="Attente réponse Ollama (max 180s)…"
    _L[pipeline_ok]="Pipeline OK — mail envoyé !"
    _L[pipeline_fail]="Pipeline KO — vérifier les logs du watcher"
    _L[pipeline_q]="Tester le pipeline avec une vraie alerte ? [O/n]"
    _L[watcher_check]="Watcher Vespera"
    _L[repair_title]="Réparation automatique Vespera"
    _L[config_pushed]="config.py synchronisé dans le container"
    _L[ollama_lang_title]="Langue de l'analyse IA Ollama (rapports HTML + prompts) :"
    ;;
  # ── ENGLISH ─────────────────────────────────────────────────────────────────
  en)
    _L[title]="Configuration Wizard"
    _L[hint]="Press Enter to accept the default value shown in [ ]."
    _L[detecting]="Detecting environment…"
    _L[wazuh_found]="Wazuh container detected"
    _L[wazuh_bare]="Wazuh bare metal detected"
    _L[wazuh_none]="No Wazuh detected — config saved, deploy later."
    _L[ollama_found]="Ollama detected on localhost:11434"
    _L[ollama_models]="Installed models"
    _L[ollama_none]="Ollama not detected (configure manually)"
    _L[ollama_docker]="Docker mode → default Ollama URL"
    _L[ollama_warn]="Add to docker-compose.yml under wazuh.manager:"
    _L[host_gw_explain]="host-gateway = your Ubuntu machine's address as seen from Docker. The Wazuh container uses it to reach Ollama and Postfix running on the host."
    _L[smtp_found]="SMTP/Postfix detected on localhost:25"
    _L[s1]="WAZUH"; _L[s2]="OLLAMA — AI Analysis"; _L[s3]="SMTP — HTML Report Delivery"
    _L[s4]="API KEYS  (free — leave blank to disable)"
    _L[s5]="OPTIONS"
    _L[container]="Manager container name"
    _L[bare_info]="Bare metal deployment at"
    _L[ollama_url]="Ollama URL (as seen from Wazuh)"
    _L[ollama_model]="Ollama model"
    _L[ollama_timeout]="Timeout (seconds)"
    _L[smtp_o1]="Local Postfix relay  (port 25, no auth)"
    _L[smtp_o2]="External STARTTLS provider  (SendGrid, Mailjet, port 587)"
    _L[smtp_o3]="Gmail / Google Workspace  (port 587 + app password)"
    _L[smtp_o4]="Implicit SSL  (port 465)"
    _L[smtp_o5]="Manual configuration"
    _L[smtp_o6]="Local Thunderbird  (Postfix + local mailbox + Thunderbird guide)"
    _L[choice]="Choice"
    _L[smtp_host]="SMTP host"; _L[smtp_port]="SMTP port"
    _L[smtp_user]="SMTP login"; _L[smtp_pass]="SMTP password"
    _L[smtp_noauth]="Login (blank = no auth)"
    _L[starttls]="STARTTLS (y/N)"; _L[ssl]="Implicit SSL (y/N)"
    _L[gmail_hint]="Create an app password → myaccount.google.com/apppasswords"
    _L[tb_user]="Local username to receive mail"
    _L[mail_from]="Sender address"; _L[mail_to]="SOC recipient address"
    _L[mail_req]="Recipient address is required."
    _L[smtp_hg_warn]="host-gateway for SMTP requires extra_hosts in docker-compose.yml."
    _L[vt_info]="VirusTotal → virustotal.com/gui/join-us  (file hash analysis)"
    _L[vt_key]="VirusTotal API key"
    _L[abuse_info]="AbuseIPDB → abuseipdb.com/register  (SSH/IDS attacker IP reputation)"
    _L[abuse_key]="AbuseIPDB API key"
    _L[lang_title]="HTML report and Ollama prompt language:"
    _L[level_info]="Minimum level to trigger AI analysis (1-15, recommended: 10)"
    _L[level_q]="Minimum alert level"
    _L[thr_info]="AbuseIPDB threshold for alert enrichment (0-100, recommended: 50)"
    _L[thr_q]="AbuseIPDB threshold"
    _L[summary]="CONFIGURATION SUMMARY"
    _L[confirm]="Write config/config.py and continue? [Y/n]"
    _L[cancelled]="Cancelled."; _L[done]="config/config.py created."
    _L[action]="ACTION REQUIRED — docker-compose.yml"
    _L[action_body]="Add under the wazuh.manager service:"
    _L[action_restart]="Then restart: docker compose down && docker compose up -d"
    _L[tb_title]="THUNDERBIRD SETUP"
    _L[tb_step1]="1. Install Dovecot (local IMAP server):"
    _L[tb_step1b]="   sudo apt install dovecot-imapd -y"
    _L[tb_step2]="2. In Thunderbird → New account → Email address:"
    _L[tb_step2b]="   Name: SOC Wazuh · Address: %s@localhost · Password: (blank)"
    _L[tb_step3]="3. Incoming server (IMAP):"
    _L[tb_step3b]="   Host: localhost · Port: 143 · SSL: None · Auth: Normal password"
    _L[tb_step4]="4. Outgoing server (SMTP):"
    _L[tb_step4b]="   Host: localhost · Port: 25  · SSL: None · Auth: None"
    _L[tb_test]="5. Quick test:"
    _L[tb_testb]='   echo "Vespera test" | mail -s "SOC Test" %s@localhost'
    _L[enabled]="✓ enabled"; _L[disabled]="disabled"
    _L[container_lbl]="Wazuh Container"; _L[url_lbl]="Ollama URL"
    _L[model_lbl]="Model"; _L[timeout_lbl]="Ollama Timeout"
    _L[smtp_lbl]="SMTP"; _L[tls_lbl]="STARTTLS enabled"; _L[ssl_lbl]="SSL enabled"
    _L[login_lbl]="SMTP Login"; _L[from_lbl]="Sender"; _L[to_lbl]="SOC Recipient"
    _L[vt_lbl]="VirusTotal"; _L[abuse_lbl]="AbuseIPDB"
    _L[lang_lbl]="Report language"; _L[level_lbl]="Min. level"
    _L[thr_lbl]="AbuseIPDB threshold"
    # Prerequisites
    _L[prereq_title]="Checking prerequisites"
    _L[prereq_missing]="Missing"
    _L[prereq_install_q]="Install automatically? [Y/n]"
    _L[prereq_auto_installing]="Installing…"
    _L[prereq_ollama_label]="Ollama not installed — install command:"
    _L[prereq_model_q]="No Ollama model found — download one now? [Y/n]"
    _L[prereq_model_pulling]="Pulling model (may take several minutes)…"
    _L[prereq_start_q]="Start Ollama now? [Y/n]"
    # Tests
    _L[test_title]="VALIDATION TESTS"
    _L[test_ollama]="Ollama connection"
    _L[test_smtp]="SMTP connection"
    _L[test_docker]="Wazuh container"
    _L[test_script]="Python modules"
    _L[test_fail]="FAILED"
    _L[test_all_ok]="All tests passed — pipeline is ready!"
    _L[test_warn]="Some tests failed — see the suggestions above."
    _L[test_fix_ollama_docker]="Check extra_hosts in docker-compose.yml and restart the stack."
    _L[test_fix_ollama_local]="Start Ollama:  sudo systemctl start ollama  or  ollama serve &"
    _L[test_fix_smtp]="Check Postfix:  sudo systemctl status postfix  |  sudo systemctl start postfix"
    _L[test_fix_docker]="Start the stack:  docker compose up -d"
    _L[test_fix_script]="Check python3:  python3 -c 'import smtplib, subprocess, json'"
    _L[test_send_mail_q]="Send a test email now? [y/N]"
    _L[test_mail_ok]="Test email sent to"
    _L[test_mail_fail]="Email send failed"
    _L[test_mail_check]="Check your mailbox:"
    # Watcher / pipeline
    _L[watcher_deploying]="Deploying Vespera watcher…"
    _L[watcher_ok]="vespera-watcher service is active"
    _L[watcher_fail]="Service not active — check: journalctl -u vespera-watcher"
    _L[watcher_service]="systemd service vespera-watcher created and enabled"
    _L[dovecot_fix]="Fixing Dovecot mail_location → maildir (aligned with Postfix)"
    _L[ossec_fix]="Merging ossec.conf → single block (analysisd fix)"
    _L[pipeline_test]="Full pipeline test"
    _L[pipeline_inject]="Injecting level-10 alert into alerts.json…"
    _L[pipeline_wait]="Waiting for Ollama response (max 180s)…"
    _L[pipeline_ok]="Pipeline OK — mail sent!"
    _L[pipeline_fail]="Pipeline KO — check watcher logs"
    _L[pipeline_q]="Run a full pipeline test with a real alert? [y/N]"
    _L[watcher_check]="Vespera watcher"
    _L[repair_title]="Vespera automatic repair"
    _L[config_pushed]="config.py pushed to container"
    _L[ollama_lang_title]="Ollama AI analysis language (HTML reports + prompts):"
    ;;
  # ── ESPAÑOL ─────────────────────────────────────────────────────────────────
  es)
    _L[title]="Asistente de configuración"
    _L[hint]="Pulsa Enter para aceptar el valor predeterminado entre [ ]."
    _L[detecting]="Detectando entorno…"
    _L[wazuh_found]="Contenedor Wazuh detectado"
    _L[wazuh_bare]="Wazuh bare metal detectado"
    _L[wazuh_none]="Wazuh no detectado — config guardada, desplegar después."
    _L[ollama_found]="Ollama detectado en localhost:11434"
    _L[ollama_models]="Modelos instalados"
    _L[ollama_none]="Ollama no detectado (configurable manualmente)"
    _L[ollama_docker]="Modo Docker → URL Ollama por defecto"
    _L[ollama_warn]="Añadir en docker-compose.yml bajo wazuh.manager:"
    _L[host_gw_explain]="host-gateway = la dirección de tu máquina Ubuntu vista desde Docker. El contenedor Wazuh lo usa para alcanzar Ollama y Postfix en el host."
    _L[smtp_found]="SMTP/Postfix detectado en localhost:25"
    _L[s1]="WAZUH"; _L[s2]="OLLAMA — Análisis IA"; _L[s3]="SMTP — Envío de informes"
    _L[s4]="CLAVES API  (gratuitas — dejar vacío para desactivar)"
    _L[s5]="OPCIONES"
    _L[container]="Nombre del contenedor manager"
    _L[bare_info]="Despliegue bare metal en"
    _L[ollama_url]="URL de Ollama (vista desde Wazuh)"
    _L[ollama_model]="Modelo Ollama"
    _L[ollama_timeout]="Tiempo límite (segundos)"
    _L[smtp_o1]="Relay Postfix local  (puerto 25, sin auth)"
    _L[smtp_o2]="Proveedor externo STARTTLS  (SendGrid, Mailjet, puerto 587)"
    _L[smtp_o3]="Gmail / Google Workspace  (puerto 587 + contraseña de aplicación)"
    _L[smtp_o4]="SSL implícito  (puerto 465)"
    _L[smtp_o5]="Configuración manual"
    _L[smtp_o6]="Thunderbird local  (Postfix + buzón local + guía Thunderbird)"
    _L[choice]="Opción"
    _L[smtp_host]="Host SMTP"; _L[smtp_port]="Puerto SMTP"
    _L[smtp_user]="Login SMTP"; _L[smtp_pass]="Contraseña SMTP"
    _L[smtp_noauth]="Login (vacío = sin auth)"
    _L[starttls]="STARTTLS (s/N)"; _L[ssl]="SSL implícito (s/N)"
    _L[gmail_hint]="Crea una contraseña de aplicación → myaccount.google.com/apppasswords"
    _L[tb_user]="Usuario local para recibir el correo"
    _L[mail_from]="Dirección remitente"; _L[mail_to]="Dirección SOC destinataria"
    _L[mail_req]="La dirección destinataria es obligatoria."
    _L[smtp_hg_warn]="host-gateway para SMTP requiere extra_hosts en docker-compose.yml."
    _L[vt_info]="VirusTotal → virustotal.com/gui/join-us  (análisis hash de archivos)"
    _L[vt_key]="Clave API VirusTotal"
    _L[abuse_info]="AbuseIPDB → abuseipdb.com/register  (reputación IPs SSH/IDS)"
    _L[abuse_key]="Clave API AbuseIPDB"
    _L[lang_title]="Idioma de los informes HTML y prompts Ollama:"
    _L[level_info]="Nivel mínimo para análisis IA (1-15, recomendado: 10)"
    _L[level_q]="Nivel mínimo de alerta"
    _L[thr_info]="Umbral AbuseIPDB para enriquecer la alerta (0-100, recomendado: 50)"
    _L[thr_q]="Umbral AbuseIPDB"
    _L[summary]="RESUMEN DE CONFIGURACIÓN"
    _L[confirm]="¿Escribir config/config.py y continuar? [S/n]"
    _L[cancelled]="Cancelado."; _L[done]="config/config.py creado."
    _L[action]="ACCIÓN REQUERIDA — docker-compose.yml"
    _L[action_body]="Añadir bajo el servicio wazuh.manager:"
    _L[action_restart]="Luego reiniciar: docker compose down && docker compose up -d"
    _L[tb_title]="CONFIGURACIÓN THUNDERBIRD"
    _L[tb_step1]="1. Instalar Dovecot (servidor IMAP local):"
    _L[tb_step1b]="   sudo apt install dovecot-imapd -y"
    _L[tb_step2]="2. En Thunderbird → Nueva cuenta → Correo electrónico:"
    _L[tb_step2b]="   Nombre: SOC Wazuh · Dirección: %s@localhost · Contraseña: (vacía)"
    _L[tb_step3]="3. Servidor entrante (IMAP):"
    _L[tb_step3b]="   Host: localhost · Puerto: 143 · SSL: Ninguno · Auth: Contraseña normal"
    _L[tb_step4]="4. Servidor saliente (SMTP):"
    _L[tb_step4b]="   Host: localhost · Puerto: 25  · SSL: Ninguno · Auth: Ninguna"
    _L[tb_test]="5. Test rápido:"
    _L[tb_testb]='   echo "Test Vespera" | mail -s "Test SOC" %s@localhost'
    _L[enabled]="✓ activado"; _L[disabled]="desactivado"
    _L[container_lbl]="Contenedor Wazuh"; _L[url_lbl]="URL Ollama"
    _L[model_lbl]="Modelo"; _L[timeout_lbl]="Timeout Ollama"
    _L[smtp_lbl]="SMTP"; _L[tls_lbl]="STARTTLS activado"; _L[ssl_lbl]="SSL activado"
    _L[login_lbl]="Login SMTP"; _L[from_lbl]="Remitente"; _L[to_lbl]="Destinatario SOC"
    _L[vt_lbl]="VirusTotal"; _L[abuse_lbl]="AbuseIPDB"
    _L[lang_lbl]="Idioma informes"; _L[level_lbl]="Nivel mínimo"
    _L[thr_lbl]="Umbral AbuseIPDB"
    # Requisitos previos
    _L[prereq_title]="Verificando requisitos previos"
    _L[prereq_missing]="Faltante"
    _L[prereq_install_q]="¿Instalar automáticamente? [S/n]"
    _L[prereq_auto_installing]="Instalando…"
    _L[prereq_ollama_label]="Ollama no instalado — comando de instalación:"
    _L[prereq_model_q]="Sin modelo Ollama — ¿descargar uno ahora? [S/n]"
    _L[prereq_model_pulling]="Descargando modelo (puede tardar varios minutos)…"
    _L[prereq_start_q]="¿Iniciar Ollama ahora? [S/n]"
    # Tests
    _L[test_title]="PRUEBAS DE VALIDACIÓN"
    _L[test_ollama]="Conexión Ollama"
    _L[test_smtp]="Conexión SMTP"
    _L[test_docker]="Contenedor Wazuh"
    _L[test_script]="Módulos Python"
    _L[test_fail]="FALLO"
    _L[test_all_ok]="Todas las pruebas pasaron — ¡pipeline lista!"
    _L[test_warn]="Algunas pruebas fallaron — revisa las sugerencias arriba."
    _L[test_fix_ollama_docker]="Verifica extra_hosts en docker-compose.yml y reinicia el stack."
    _L[test_fix_ollama_local]="Inicia Ollama:  sudo systemctl start ollama  o  ollama serve &"
    _L[test_fix_smtp]="Verifica Postfix:  sudo systemctl status postfix  |  sudo systemctl start postfix"
    _L[test_fix_docker]="Inicia el stack:  docker compose up -d"
    _L[test_fix_script]="Verifica python3:  python3 -c 'import smtplib, subprocess, json'"
    _L[test_send_mail_q]="¿Enviar un correo de prueba ahora? [s/N]"
    _L[test_mail_ok]="Correo de prueba enviado a"
    _L[test_mail_fail]="Error al enviar correo"
    _L[test_mail_check]="Revisa tu buzón:"
    # Watcher / pipeline
    _L[watcher_deploying]="Desplegando watcher de Vespera…"
    _L[watcher_ok]="Servicio vespera-watcher activo"
    _L[watcher_fail]="Servicio no activo — verificar: journalctl -u vespera-watcher"
    _L[watcher_service]="Servicio systemd vespera-watcher creado y activado"
    _L[dovecot_fix]="Corrigiendo Dovecot mail_location → maildir (alineado con Postfix)"
    _L[ossec_fix]="Fusionando ossec.conf → bloque único (fix analysisd)"
    _L[pipeline_test]="Prueba completa del pipeline"
    _L[pipeline_inject]="Inyectando alerta nivel 10 en alerts.json…"
    _L[pipeline_wait]="Esperando respuesta de Ollama (máx 180s)…"
    _L[pipeline_ok]="Pipeline OK — ¡correo enviado!"
    _L[pipeline_fail]="Pipeline KO — revisar logs del watcher"
    _L[pipeline_q]="¿Ejecutar prueba completa del pipeline con alerta real? [s/N]"
    _L[watcher_check]="Watcher de Vespera"
    _L[repair_title]="Reparación automática de Vespera"
    _L[config_pushed]="config.py sincronizado en el container"
    _L[ollama_lang_title]="Idioma del análisis IA Ollama (informes HTML + prompts):"
    ;;
  esac
}

# ─── Vérification des prérequis ───────────────────────────────────────────────
check_prerequisites() {
  echo ""
  echo -e "${BOLD}${CYAN}  ── ${_L[prereq_title]} ──────────────────────────────${RESET}"

  local _need_pkgs="" _has_py=0 _has_curl=0 _has_nc=0 _has_docker=0 _has_ollama=0
  local _ollama_running=0 _ollama_has_models=0

  command -v python3 >/dev/null 2>&1 && _has_py=1
  command -v curl    >/dev/null 2>&1 && _has_curl=1
  command -v nc      >/dev/null 2>&1 && _has_nc=1
  command -v docker  >/dev/null 2>&1 && _has_docker=1
  command -v ollama  >/dev/null 2>&1 && _has_ollama=1

  _pchk() {
    local n="$1" ok="$2"
    if [[ "$ok" == 1 ]]; then
      echo -e "  ${GREEN}✓${RESET}  $n"
    else
      echo -e "  ${RED}✗${RESET}  ${BOLD}$n${RESET} — ${YELLOW}${_L[prereq_missing]}${RESET}"
    fi
  }
  _pchk "python3"       "$_has_py"
  _pchk "curl"          "$_has_curl"
  _pchk "nc (netcat)"   "$_has_nc"
  _pchk "docker"        "$_has_docker"
  _pchk "ollama (cli)"  "$_has_ollama"

  # Ollama service
  if curl -sf --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
    _ollama_running=1
    local _nm; _nm=$(curl -s http://localhost:11434/api/tags 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('models',[])))" 2>/dev/null || echo "0")
    echo -e "  ${GREEN}✓${RESET}  ollama service  (${_nm} model(s) installed)"
    [[ "${_nm:-0}" -gt 0 ]] && _ollama_has_models=1
  else
    echo -e "  ${YELLOW}⚠${RESET}  ollama service — not running"
  fi

  # ── Auto-install system packages (python3, curl, nc) ─────────────────────
  [[ "$_has_py" == 0 ]]   && _need_pkgs="$_need_pkgs python3"
  [[ "$_has_curl" == 0 ]] && _need_pkgs="$_need_pkgs curl"
  [[ "$_has_nc" == 0 ]]   && _need_pkgs="$_need_pkgs netcat-openbsd"

  if [[ -n "$_need_pkgs" ]]; then
    echo ""
    local _cmd="sudo apt-get install -y${_need_pkgs}"
    echo -e "  ${YELLOW}→${RESET}  ${BOLD}${_cmd}${RESET}"
    local _yn; read -r -p "  ${_L[prereq_install_q]} " _yn
    if [[ "${_yn:-o}" =~ ^[oOyYsS] ]]; then
      echo -e "  ${DIM}${_L[prereq_auto_installing]}${RESET}"
      eval "$_cmd" || true
      command -v python3 >/dev/null 2>&1 && _has_py=1
      command -v curl    >/dev/null 2>&1 && _has_curl=1
      command -v nc      >/dev/null 2>&1 && _has_nc=1
    fi
  fi

  # ── Install Ollama ────────────────────────────────────────────────────────
  if [[ "$_has_ollama" == 0 ]]; then
    echo ""
    echo -e "  ${YELLOW}→${RESET}  ${_L[prereq_ollama_label]}"
    echo -e "    ${BOLD}curl -fsSL https://ollama.com/install.sh | sh${RESET}"
    local _yn; read -r -p "  ${_L[prereq_install_q]} " _yn
    if [[ "${_yn:-o}" =~ ^[oOyYsS] ]]; then
      echo -e "  ${DIM}${_L[prereq_auto_installing]}${RESET}"
      curl -fsSL https://ollama.com/install.sh | sh && _has_ollama=1 || true
    fi
  fi

  # ── Start Ollama service ──────────────────────────────────────────────────
  if [[ "$_has_ollama" == 1 && "$_ollama_running" == 0 ]]; then
    echo ""
    echo -e "  ${YELLOW}→${RESET}  ${_L[test_fix_ollama_local]}"
    local _yn; read -r -p "  ${_L[prereq_start_q]} " _yn
    if [[ "${_yn:-o}" =~ ^[oOyYsS] ]]; then
      systemctl start ollama 2>/dev/null || (ollama serve >/dev/null 2>&1 &)
      sleep 3
      curl -sf --max-time 5 http://localhost:11434/api/tags >/dev/null 2>&1 \
        && _ollama_running=1 || true
    fi
  fi

  # ── Pull Ollama model ─────────────────────────────────────────────────────
  if [[ "$_ollama_running" == 1 && "$_ollama_has_models" == 0 ]]; then
    local _m_sug="llama3.2:3b"
    if [[ -r /proc/meminfo ]]; then
      local _mk; _mk=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
      [[ "$_mk" -ge 15728640 ]] && _m_sug="llama3.1:8b"
    fi
    echo ""
    echo -e "  ${YELLOW}→${RESET}  ${_L[prereq_model_q]}  (${BOLD}ollama pull ${_m_sug}${RESET})"
    local _yn; read -r -p "  " _yn
    if [[ "${_yn:-o}" =~ ^[oOyYsS] ]]; then
      echo -e "  ${DIM}${_L[prereq_model_pulling]}${RESET}"
      ollama pull "$_m_sug" && _ollama_has_models=1 || true
    fi
  fi

  echo ""
}

# ─── Tests post-configuration ─────────────────────────────────────────────────
run_post_install_tests() {
  local _ol_url="$1" _smtp_host="$2" _smtp_port="$3"
  local _is_docker="$4" _cname="$5" _mail_to="$6"

  echo ""
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
  echo -e "${BOLD}  ${_L[test_title]}${RESET}"
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"

  local _ok=0 _tot=0

  # ── 1. Ollama ─────────────────────────────────────────────────────────────
  _tot=$((_tot+1))
  local _ol_test="${_ol_url//host-gateway/localhost}"
  local _ol_tags="${_ol_test%/api/generate}/api/tags"
  if curl -sf --max-time 5 "$_ol_tags" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${RESET}  ${_L[test_ollama]}"
    _ok=$((_ok+1))
  else
    echo -e "  ${RED}✗${RESET}  ${_L[test_ollama]} — ${RED}${_L[test_fail]}${RESET}"
    if [[ "$_ol_url" == *"host-gateway"* ]]; then
      echo -e "    ${YELLOW}→${RESET} ${_L[test_fix_ollama_docker]}"
    else
      echo -e "    ${YELLOW}→${RESET} ${_L[test_fix_ollama_local]}"
    fi
  fi

  # ── 2. SMTP ───────────────────────────────────────────────────────────────
  _tot=$((_tot+1))
  local _sh="${_smtp_host//host-gateway/localhost}"
  if nc -z -w3 "$_sh" "$_smtp_port" 2>/dev/null || \
     timeout 3 bash -c "echo '' >/dev/tcp/${_sh}/${_smtp_port}" 2>/dev/null; then
    echo -e "  ${GREEN}✓${RESET}  ${_L[test_smtp]} (${_sh}:${_smtp_port})"
    _ok=$((_ok+1))
  else
    echo -e "  ${RED}✗${RESET}  ${_L[test_smtp]} (${_sh}:${_smtp_port}) — ${RED}${_L[test_fail]}${RESET}"
    echo -e "    ${YELLOW}→${RESET} ${_L[test_fix_smtp]}"
  fi

  # ── 3. Docker container ───────────────────────────────────────────────────
  if [[ "$_is_docker" == 1 ]]; then
    _tot=$((_tot+1))
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$_cname"; then
      echo -e "  ${GREEN}✓${RESET}  ${_L[test_docker]} (${_cname})"
      _ok=$((_ok+1))
    else
      echo -e "  ${RED}✗${RESET}  ${_L[test_docker]} (${_cname}) — ${RED}${_L[test_fail]}${RESET}"
      echo -e "    ${YELLOW}→${RESET} ${_L[test_fix_docker]}"
    fi
  fi

  # ── 4. Python modules ─────────────────────────────────────────────────────
  _tot=$((_tot+1))
  if python3 -c \
    "import smtplib, subprocess, json, importlib.util, email.mime.multipart" \
    2>/dev/null; then
    echo -e "  ${GREEN}✓${RESET}  ${_L[test_script]}"
    _ok=$((_ok+1))
  else
    echo -e "  ${RED}✗${RESET}  ${_L[test_script]} — ${RED}${_L[test_fail]}${RESET}"
    echo -e "    ${YELLOW}→${RESET} ${_L[test_fix_script]}"
  fi

  # ── 5. Vespera watcher (Docker uniquement) ────────────────────────────────
  if [[ "$_is_docker" == 1 ]]; then
    _tot=$((_tot+1))
    if systemctl is-active --quiet vespera-watcher 2>/dev/null; then
      echo -e "  ${GREEN}✓${RESET}  ${_L[watcher_check]}"
      _ok=$((_ok+1))
    else
      echo -e "  ${YELLOW}⚠${RESET}  ${_L[watcher_check]} — not running"
      echo -e "    ${YELLOW}→${RESET} systemctl start vespera-watcher"
    fi
  fi

  # ── Résultat ──────────────────────────────────────────────────────────────
  echo ""
  if [[ "$_ok" == "$_tot" ]]; then
    echo -e "  ${GREEN}${BOLD}${_L[test_all_ok]}${RESET}  (${_ok}/${_tot})"
    # Test pipeline réel via injection dans alerts.json (Docker uniquement)
    if [[ "$_is_docker" == 1 ]]; then
      run_pipeline_test "$_cname" "$_mail_to"
    else
      echo ""
      local _yn; read -r -p "  ${_L[test_send_mail_q]} " _yn
      if [[ "${_yn:-n}" =~ ^[oOyYsS] ]]; then
        local _ts; _ts="$(date -u +%Y-%m-%dT%H:%M:%S).000+0000"
        local _tj="{\"rule\":{\"id\":\"9999\",\"level\":10,\"description\":\"Vespera install test — pipeline OK\",\"groups\":[\"test\"],\"firedtimes\":1},\"agent\":{\"id\":\"000\",\"name\":\"install-test\",\"ip\":\"127.0.0.1\"},\"data\":{\"src_ip\":\"127.0.0.1\"},\"timestamp\":\"${_ts}\"}"
        echo -e "  ${DIM}${_L[prereq_auto_installing]}${RESET}"
        local _test_ollama_url="${_ol_url//host-gateway/localhost}"
        local _test_smtp_host="${_smtp_host//host-gateway/localhost}"
        if echo "$_tj" | VESPERA_OLLAMA_URL="$_test_ollama_url" VESPERA_SMTP_HOST="$_test_smtp_host" \
           python3 "$VESPERA_ROOT/integrations/ollama-alert.py" 2>&1; then
          _wiz_ok "${_L[test_mail_ok]} ${BOLD}${_mail_to}${RESET}"
          _wiz_info "${_L[test_mail_check]} ${_mail_to}"
        else
          _wiz_warn "${_L[test_mail_fail]}"
        fi
      fi
    fi
  else
    echo -e "  ${YELLOW}${BOLD}⚠  ${_L[test_warn]}${RESET}  (${_ok}/${_tot})"
  fi
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
}

# ─── Réparations automatiques ────────────────────────────────────────────────
# Corrige les 3 problèmes découverts lors du troubleshooting :
#   1. Dovecot mail_location mbox vs Maildir (Postfix livre en Maildir par défaut)
#   2. ossec.conf avec double bloc <ossec_config> (analysisd ignore le 2ème)
#   3. integratord inactif sur Wazuh 4.14+ (bug connu — workaround alert-watcher.py)

fix_dovecot_maildir() {
  # Aligne Dovecot avec Postfix home_mailbox = Maildir/
  local conf="/etc/dovecot/conf.d/10-mail.conf"
  [[ -f "$conf" ]] || return 0
  if grep -q "mail_location" "$conf" 2>/dev/null; then
    if ! grep -q "maildir:~/Maildir" "$conf" 2>/dev/null; then
      _wiz_info "${_L[dovecot_fix]}"
      sed -i 's|mail_location = mbox.*|mail_location = maildir:~/Maildir|g' "$conf"
      # S'assurer qu'une ligne existe si grep a trouvé un commentaire
      if ! grep -q "^mail_location" "$conf"; then
        echo "mail_location = maildir:~/Maildir" >> "$conf"
      fi
      systemctl restart dovecot 2>/dev/null || true
    fi
  else
    # Pas de mail_location → on l'ajoute
    _wiz_info "${_L[dovecot_fix]}"
    echo "mail_location = maildir:~/Maildir" >> "$conf"
    systemctl restart dovecot 2>/dev/null || true
  fi
}

fix_ossec_double_block() {
  # Fusionne les doubles <ossec_config> en un seul bloc (Docker)
  local cname="$1"
  [[ -z "$cname" ]] && return 0
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname" || return 0

  local count
  count=$(docker exec "$cname" grep -c "^<ossec_config>" /var/ossec/etc/ossec.conf 2>/dev/null || echo 0)
  [[ "$count" -le 1 ]] && return 0

  _wiz_info "${_L[ossec_fix]}"
  docker exec "$cname" python3 -c "
content = open('/var/ossec/etc/ossec.conf').read()
parts = content.split('</ossec_config>')
if len(parts) == 3:
    second = parts[1]
    idx = second.find('<ossec_config>')
    if idx >= 0:
        inner = second[idx+len('<ossec_config>'):]
        merged = parts[0] + inner + '</ossec_config>\n'
        open('/var/ossec/etc/ossec.conf','w').write(merged)
        print('merged')
" 2>/dev/null && _wiz_ok "ossec.conf → single block" || _wiz_warn "ossec.conf merge skipped"
}

fix_ossec_shared_perms() {
  # Corrige les permissions de /var/ossec/etc/shared/ (agentd ne peut pas écrire)
  local cname="$1"
  [[ -z "$cname" ]] && return 0
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname" || return 0
  docker exec "$cname" bash -c '
    chown -R root:wazuh /var/ossec/etc/shared/ 2>/dev/null
    chmod -R 770 /var/ossec/etc/shared/ 2>/dev/null
  ' 2>/dev/null || true
}

deploy_alert_watcher() {
  # Déploie alert-watcher.py dans le container et crée un service systemd sur l'hôte
  # qui le maintient vivant en permanence via `docker exec`.
  local cname="$1"
  [[ -z "$cname" ]] && return 0
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname" || return 0

  echo ""
  echo -e "${BOLD}${CYAN}  ── ${_L[watcher_deploying]} ──────────────────────────────${RESET}"

  # 1. Écrire alert-watcher.py dans le container
  docker exec "$cname" bash -c 'cat > /var/ossec/integrations/alert-watcher.py << '"'"'PYEOF'"'"'
#!/usr/bin/env python3
# Vespera alert-watcher — workaround for integratord inactivity (Wazuh 4.14+)
import json, os, subprocess, sys, tempfile, time

ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
SCRIPT      = "/var/ossec/integrations/ollama-alert.py"
MIN_LEVEL   = int(os.environ.get("VESPERA_MIN_LEVEL", "7"))
STATE_FILE  = "/var/ossec/logs/vespera-watcher.pos"

def read_pos():
    try: return int(open(STATE_FILE).read().strip())
    except: return None

def write_pos(pos):
    try: open(STATE_FILE, "w").write(str(pos))
    except: pass

def process_alert(line):
    try: alert = json.loads(line)
    except: return
    level = alert.get("rule", {}).get("level", 0)
    if level < MIN_LEVEL: return
    rule_id = alert.get("rule", {}).get("id", "?")
    print(f"[vespera-watcher] level={level} rule={rule_id} — calling ollama-alert.py", flush=True)
    tmppath = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp.write(line); tmppath = tmp.name
        env = dict(os.environ)
        env.setdefault("VESPERA_SMTP_HOST", "host-gateway")
        subprocess.run([sys.executable, SCRIPT, tmppath], env=env, timeout=300)
    except Exception as e:
        print(f"[vespera-watcher] error: {e}", flush=True)
    finally:
        if tmppath:
            try: os.unlink(tmppath)
            except: pass

def main():
    print(f"[vespera-watcher] started, min_level={MIN_LEVEL}", flush=True)
    while not os.path.isfile(ALERTS_JSON): time.sleep(2)
    with open(ALERTS_JSON) as fh:
        saved = read_pos()
        if saved is not None: fh.seek(saved)
        else: fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                line = line.strip()
                if line: process_alert(line)
                write_pos(fh.tell())
            else:
                # Rotation check
                try:
                    if os.stat(ALERTS_JSON).st_ino != os.fstat(fh.fileno()).st_ino:
                        fh.close(); fh = open(ALERTS_JSON); write_pos(0)
                except: pass
                time.sleep(1.0)

if __name__ == "__main__": main()
PYEOF
chmod 750 /var/ossec/integrations/alert-watcher.py
chown root:wazuh /var/ossec/integrations/alert-watcher.py'

  # 2. Créer un service systemd sur l'hôte qui fait tourner le watcher dans le container
  cat > /etc/systemd/system/vespera-watcher.service << SVCEOF
[Unit]
Description=Vespera Alert Watcher (Wazuh integratord workaround)
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=/bin/bash -c 'until docker ps --format "{{.Names}}" | grep -qx "${cname}"; do sleep 5; done'
ExecStart=/usr/bin/docker exec -i ${cname} python3 /var/ossec/integrations/alert-watcher.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload 2>/dev/null || true
  systemctl enable vespera-watcher 2>/dev/null || true
  systemctl restart vespera-watcher 2>/dev/null || true
  sleep 3

  if systemctl is-active --quiet vespera-watcher 2>/dev/null; then
    _wiz_ok "${_L[watcher_service]}"
    _wiz_ok "${_L[watcher_ok]}"
  else
    _wiz_warn "${_L[watcher_fail]}"
  fi
}

run_pipeline_test() {
  # Injecte une alerte level 10 directement dans alerts.json du container
  # et attend que le watcher la traite + envoie le mail
  local cname="$1" mail_to="$2"
  [[ -z "$cname" ]] && return 0
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname" || return 0

  echo ""
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
  echo -e "${BOLD}  ${_L[pipeline_test]}${RESET}"
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"

  local _yn
  read -r -p "  ${_L[pipeline_q]} " _yn
  [[ "${_yn:-n}" =~ ^[oOyYsS] ]] || return 0

  _wiz_info "${_L[pipeline_inject]}"
  # Mémoriser la position courante du log AVANT l'injection pour éviter
  # de détecter un ancien "mail sent" comme un succès
  local log_lines_before
  log_lines_before=$(docker exec "$cname" bash -c 'cat /var/ossec/logs/vespera-watcher.log 2>/dev/null | wc -l || echo 0' 2>/dev/null || echo 0)

  local ts; ts="$(docker exec "$cname" date -u +%Y-%m-%dT%H:%M:%S.000+0000 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S.000+0000)"
  local alert_json="{\"timestamp\":\"${ts}\",\"rule\":{\"level\":10,\"description\":\"Vespera pipeline test — SSH brute force\",\"id\":\"5712\",\"groups\":[\"sshd\",\"authentication_failures\"],\"firedtimes\":10},\"agent\":{\"id\":\"001\",\"name\":\"vespera-test\",\"ip\":\"127.0.0.1\"},\"manager\":{\"name\":\"wazuh.manager\"},\"id\":\"vespera_pipeline_test_001\",\"data\":{\"srcip\":\"10.0.0.99\"},\"full_log\":\"pipeline test\",\"location\":\"/var/log/auth.log\"}"

  docker exec "$cname" bash -c "echo '${alert_json}' >> /var/ossec/logs/alerts/alerts.json"

  _wiz_info "${_L[pipeline_wait]}"

  local waited=0 mail_sent=0
  while [[ $waited -lt 200 ]]; do
    sleep 5; waited=$((waited+5))
    # Chercher "mail sent" uniquement dans les lignes APRÈS l'injection
    if docker exec "$cname" bash -c "tail -n +$((log_lines_before+1)) /var/ossec/logs/vespera-watcher.log 2>/dev/null | grep -q 'mail sent'" 2>/dev/null; then
      mail_sent=1; break
    fi
    printf "  %s %ds…\r" "${CYAN}⏳${RESET}" "$waited"
  done
  echo ""

  if [[ "$mail_sent" == 1 ]]; then
    _wiz_ok "${_L[pipeline_ok]}"
    _wiz_info "${_L[test_mail_check]} ${BOLD}${mail_to}${RESET}"
  else
    _wiz_warn "${_L[pipeline_fail]}"
    echo -e "    ${DIM}docker exec ${cname} cat /var/ossec/logs/vespera-watcher.log${RESET}"
  fi
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
}

# ─── Setup Wizard ─────────────────────────────────────────────────────────────
run_setup_wizard() {
  local py="$VESPERA_ROOT/config/config.py"

  # Langue déjà initialisée par le bloc global (print_banner → _wiz_lang_init)
  # On recharge juste les traductions au cas où --locale a été passé
  _wiz_set_lang

  echo -e "${BOLD}${CYAN}  ── ${_L[title]} ──${RESET}"
  echo -e "${DIM}  ${_L[hint]}${RESET}"

  # ── Prérequis ─────────────────────────────────────────────────────────────
  check_prerequisites

  # ── Auto-détection ────────────────────────────────────────────────────────
  echo ""
  echo -e "${DIM}  ${_L[detecting]}${RESET}"

  local _has_docker=0 _auto_container="" _tb_mode=0 _tb_user=""
  if command -v docker >/dev/null 2>&1; then
    _auto_container="$(detect_wazuh_manager_container)"
    [[ -n "$_auto_container" ]] && _has_docker=1
  fi

  if [[ "$_has_docker" == 1 ]]; then
    _wiz_ok "${_L[wazuh_found]} : ${BOLD}${_auto_container}${RESET}"
  elif [[ -d "$WAZUH_BASE/integrations" ]]; then
    _wiz_ok "${_L[wazuh_bare]} : ${BOLD}${WAZUH_BASE}${RESET}"
  else
    _wiz_info "${_L[wazuh_none]}"
  fi

  local _ollama_ok=0 _ollama_models="" _detected_model=""
  local _default_ollama_url="http://localhost:11434/api/generate"
  if curl -sf --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
    _ollama_ok=1
    _ollama_models=$(curl -s http://localhost:11434/api/tags 2>/dev/null \
      | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    names = [m['name'] for m in d.get('models', [])]
    print(', '.join(names) if names else '')
except Exception:
    print('')
" 2>/dev/null || true)
    _detected_model="$(detect_best_ollama_model)"
    _wiz_ok "${_L[ollama_found]}"
    [[ -n "$_ollama_models" ]] && _wiz_info "${_L[ollama_models]} : ${BOLD}${_ollama_models}${RESET}"
    [[ -n "$_detected_model" ]] && _wiz_info "→ ${_L[ollama_model]} auto-sélectionné : ${BOLD}${_detected_model}${RESET}"
  else
    _wiz_info "${_L[ollama_none]}"
  fi

  if [[ "$_has_docker" == 1 ]]; then
    _default_ollama_url="http://host-gateway:11434/api/generate"
    _wiz_info "${_L[ollama_docker]} : ${BOLD}http://host-gateway:11434${RESET}"
    _wiz_info "${DIM}${_L[host_gw_explain]}${RESET}"
  fi

  local _smtp_local=0 _default_smtp_host="localhost"
  if nc -z -w1 localhost 25 2>/dev/null; then
    _smtp_local=1
    _wiz_ok "${_L[smtp_found]}"
    [[ "$_has_docker" == 1 ]] && _default_smtp_host="host-gateway"
  fi

  # Modèle suggéré : utiliser le meilleur installé, sinon fallback RAM
  local _suggested_model=""
  if [[ -n "$_detected_model" ]]; then
    _suggested_model="$_detected_model"
  else
    _suggested_model="llama3.2:3b"
    if [[ -r /proc/meminfo ]]; then
      local _mem_kb; _mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
      [[ "$_mem_kb" -ge 15728640 ]] && _suggested_model="llama3.1:8b"
    fi
  fi

  # Domaine mail Postfix
  local _postfix_domain=""
  _postfix_domain="$(detect_postfix_domain "${_auto_container:-}")"

  # ── [1/5] WAZUH ───────────────────────────────────────────────────────────
  _wiz_step "1" "${_L[s1]}"

  local W_CONTAINER="${_auto_container:-}"
  if [[ "$_has_docker" == 1 ]]; then
    _wiz_ask W_CONTAINER "${_L[container]}" "$_auto_container"
  else
    _wiz_info "${_L[bare_info]} ${WAZUH_BASE}"
  fi

  # ── [2/5] OLLAMA ──────────────────────────────────────────────────────────
  _wiz_step "2" "${_L[s2]}"

  local W_OLLAMA_URL W_OLLAMA_MODEL W_OLLAMA_TIMEOUT
  _wiz_ask W_OLLAMA_URL     "${_L[ollama_url]}"     "$_default_ollama_url"
  _wiz_ask W_OLLAMA_MODEL   "${_L[ollama_model]}"   "$_suggested_model"
  _wiz_ask W_OLLAMA_TIMEOUT "${_L[ollama_timeout]}" "180"

  if [[ "$W_OLLAMA_URL" == *"host-gateway"* ]]; then
    _wiz_warn "${_L[ollama_warn]}"
    echo -e "          ${BOLD}extra_hosts:${RESET}"
    echo -e "            ${BOLD}- \"host-gateway:host-gateway\"${RESET}"
  fi

  # ── [3/5] SMTP ────────────────────────────────────────────────────────────
  _wiz_step "3" "${_L[s3]}"

  echo ""
  echo -e "  ${BOLD}1)${RESET} ${_L[smtp_o1]}"
  echo -e "  ${BOLD}2)${RESET} ${_L[smtp_o2]}"
  echo -e "  ${BOLD}3)${RESET} ${_L[smtp_o3]}"
  echo -e "  ${BOLD}4)${RESET} ${_L[smtp_o4]}"
  echo -e "  ${BOLD}5)${RESET} ${_L[smtp_o5]}"
  echo -e "  ${BOLD}6)${RESET} ${CYAN}${_L[smtp_o6]}${RESET}"

  local _smtp_choice
  _wiz_ask _smtp_choice "${_L[choice]}" "1"

  local W_SMTP_HOST="$_default_smtp_host"
  local W_SMTP_PORT="25" W_SMTP_TLS="False" W_SMTP_SSL="False"
  local W_SMTP_USER="" W_SMTP_PASS=""

  case "$_smtp_choice" in
    2)
      W_SMTP_PORT="587"; W_SMTP_TLS="True"
      _wiz_ask W_SMTP_HOST "${_L[smtp_host]}"  "$W_SMTP_HOST"
      _wiz_ask W_SMTP_USER "${_L[smtp_user]}"  ""
      _wiz_ask_secret W_SMTP_PASS "${_L[smtp_pass]}"
      ;;
    3)
      W_SMTP_HOST="smtp.gmail.com"; W_SMTP_PORT="587"; W_SMTP_TLS="True"
      _wiz_info "${_L[gmail_hint]}"
      _wiz_ask W_SMTP_USER "${_L[smtp_user]}" ""
      _wiz_ask_secret W_SMTP_PASS "${_L[smtp_pass]}"
      ;;
    4)
      W_SMTP_PORT="465"; W_SMTP_SSL="True"
      _wiz_ask W_SMTP_HOST "${_L[smtp_host]}"  "$W_SMTP_HOST"
      _wiz_ask W_SMTP_USER "${_L[smtp_user]}"  ""
      _wiz_ask_secret W_SMTP_PASS "${_L[smtp_pass]}"
      ;;
    5)
      _wiz_ask W_SMTP_HOST "${_L[smtp_host]}"  "$W_SMTP_HOST"
      _wiz_ask W_SMTP_PORT "${_L[smtp_port]}"  "25"
      local _yn_tls; _wiz_ask _yn_tls "${_L[starttls]}" "n"
      [[ "$_yn_tls" =~ ^[oOsySY] ]] && W_SMTP_TLS="True"
      local _yn_ssl; _wiz_ask _yn_ssl "${_L[ssl]}" "n"
      [[ "$_yn_ssl" =~ ^[oOsySY] ]] && W_SMTP_SSL="True"
      _wiz_ask W_SMTP_USER "${_L[smtp_noauth]}" ""
      [[ -n "$W_SMTP_USER" ]] && _wiz_ask_secret W_SMTP_PASS "${_L[smtp_pass]}"
      ;;
    6)
      # ── Thunderbird local ────────────────────────────────────────────────
      _tb_mode=1
      W_SMTP_HOST="$_default_smtp_host"; W_SMTP_PORT="25"
      _wiz_ask W_SMTP_HOST "${_L[smtp_host]}" "$W_SMTP_HOST"
      local _tb_default_user="wazuh"
      _wiz_ask _tb_user "${_L[tb_user]}" "$_tb_default_user"
      ;;
    *)
      # Option 1 — relai local
      _wiz_ask W_SMTP_HOST "${_L[smtp_host]}" "$W_SMTP_HOST"
      ;;
  esac

  local W_MAIL_FROM W_MAIL_TO
  # Domaine mail : utiliser mydomain Postfix si détecté, sinon localhost
  local _mail_domain="${_postfix_domain:-localhost}"
  if [[ "$_tb_mode" == 1 ]]; then
    W_MAIL_FROM="wazuh@${_mail_domain}"
    W_MAIL_TO="${_tb_user:-wazuh}@${_mail_domain}"
    _wiz_info "→ MAIL_FROM=${W_MAIL_FROM}  MAIL_TO=${W_MAIL_TO}"
    [[ -n "$_postfix_domain" ]] && _wiz_info "  (domaine Postfix détecté : ${BOLD}${_postfix_domain}${RESET})"
  else
    _wiz_ask W_MAIL_FROM "${_L[mail_from]}" "wazuh@${_mail_domain}"
    _wiz_ask W_MAIL_TO   "${_L[mail_to]}"   ""
    while [[ -z "$W_MAIL_TO" ]]; do
      _wiz_warn "${_L[mail_req]}"
      _wiz_ask W_MAIL_TO "${_L[mail_to]}" ""
    done
  fi

  if [[ "$W_SMTP_HOST" == "host-gateway" ]]; then
    _wiz_warn "${_L[smtp_hg_warn]}"
  fi

  # ── [4/5] CLÉS API ────────────────────────────────────────────────────────
  _wiz_step "4" "${_L[s4]}"

  echo ""
  _wiz_info "${_L[vt_info]}"
  local W_VT_KEY; _wiz_ask W_VT_KEY "${_L[vt_key]}" ""
  echo ""
  _wiz_info "${_L[abuse_info]}"
  local W_ABUSE_KEY; _wiz_ask W_ABUSE_KEY "${_L[abuse_key]}" ""

  local _vt_status _abuse_status
  if [[ -n "$W_VT_KEY" ]]; then
    _vt_status="${GREEN}${_L[enabled]}${RESET}"
  else
    _vt_status="${YELLOW}${_L[disabled]}${RESET}"
  fi
  if [[ -n "$W_ABUSE_KEY" ]]; then
    _abuse_status="${GREEN}${_L[enabled]}${RESET}"
  else
    _abuse_status="${YELLOW}${_L[disabled]}${RESET}"
  fi

  # ── [5/5] OPTIONS ─────────────────────────────────────────────────────────
  _wiz_step "5" "${_L[s5]}"

  echo ""
  echo -e "  ${BOLD}${_L[ollama_lang_title]:-Ollama AI analysis language (HTML reports + prompts):}${RESET}"
  echo -e "  ${DIM}(This controls the language Ollama uses in its analysis — independent of this wizard's UI language)${RESET}"
  echo -e "  ${BOLD}1)${RESET} English   ${BOLD}2)${RESET} Français   ${BOLD}3)${RESET} Español"
  local _lang_ch; _wiz_ask _lang_ch "${_L[choice]}" "$( [[ "$_WIZ_LANG" == fr ]] && echo 2 || [[ "$_WIZ_LANG" == es ]] && echo 3 || echo 1 )"
  local W_LOCALE="$_WIZ_LANG"
  case "$_lang_ch" in
    1|en|EN) W_LOCALE="en" ;;
    2|fr|FR) W_LOCALE="fr" ;;
    3|es|ES) W_LOCALE="es" ;;
  esac

  echo ""
  _wiz_info "${_L[level_info]}"
  local W_MIN_LEVEL; _wiz_ask W_MIN_LEVEL "${_L[level_q]}" "10"

  _wiz_info "${_L[thr_info]}"
  local W_ABUSE_THR; _wiz_ask W_ABUSE_THR "${_L[thr_q]}" "50"

  # ── RÉSUMÉ ────────────────────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
  echo -e "${BOLD}  ${_L[summary]}${RESET}"
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
  [[ "$_has_docker" == 1 ]] && printf "  %-26s ${BOLD}%s${RESET}\n" "${_L[container_lbl]}" "$W_CONTAINER"
  printf   "  %-26s ${BOLD}%s${RESET}\n"   "${_L[url_lbl]}"    "$W_OLLAMA_URL"
  printf   "  %-26s ${BOLD}%s${RESET}\n"   "${_L[model_lbl]}"  "$W_OLLAMA_MODEL"
  printf   "  %-26s %s\n"                  "${_L[timeout_lbl]}" "${W_OLLAMA_TIMEOUT}s"
  printf   "  %-26s ${BOLD}%s:%s${RESET}\n" "${_L[smtp_lbl]}"  "$W_SMTP_HOST" "$W_SMTP_PORT"
  [[ "$W_SMTP_TLS" == "True" ]] && printf "  %-26s %s\n" "" "${_L[tls_lbl]}"
  [[ "$W_SMTP_SSL" == "True" ]] && printf "  %-26s %s\n" "" "${_L[ssl_lbl]}"
  [[ -n "$W_SMTP_USER" ]]       && printf "  %-26s %s\n" "${_L[login_lbl]}" "$W_SMTP_USER"
  printf   "  %-26s %s\n"                  "${_L[from_lbl]}"   "$W_MAIL_FROM"
  printf   "  %-26s ${BOLD}%s${RESET}\n"   "${_L[to_lbl]}"     "$W_MAIL_TO"
  echo -e  "  $(printf '%-26s' "${_L[vt_lbl]}") $_vt_status"
  echo -e  "  $(printf '%-26s' "${_L[abuse_lbl]}") $_abuse_status"
  printf   "  %-26s %s\n"                  "${_L[lang_lbl]}"   "$W_LOCALE"
  printf   "  %-26s %s\n"                  "${_L[level_lbl]}"  "$W_MIN_LEVEL"
  printf   "  %-26s %s\n"                  "${_L[thr_lbl]}"    "${W_ABUSE_THR}/100"
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"

  echo ""
  local _confirm
  read -r -p "  ${_L[confirm]} " _confirm
  [[ "${_confirm:-o}" =~ ^[nN] ]] && { echo "  ${_L[cancelled]}"; exit 0; }

  # ── Écriture de config.py ─────────────────────────────────────────────────
  cat > "$py" <<PYEOF
# =============================================================================
# Vespera — config.py  (généré le $(date '+%Y-%m-%d %H:%M') par install.sh --setup)
# NE JAMAIS COMMITTER CE FICHIER — il contient des secrets.
# Pour reconfigurer : ./install.sh --setup
# =============================================================================

# --- VirusTotal ---
VT_API_KEY = "${W_VT_KEY:-YOUR_VIRUSTOTAL_API_KEY}"

# --- AbuseIPDB ---
ABUSEIPDB_KEY = "${W_ABUSE_KEY:-YOUR_ABUSEIPDB_API_KEY}"

# --- OpenCTI (optionnel) ---
OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = "YOUR_OPENCTI_API_TOKEN"

# --- Wazuh API (optionnel) ---
WAZUH_API_URL = "https://localhost:55000"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "YOUR_WAZUH_API_PASSWORD"

# --- OpenSearch (optionnel) ---
OPENSEARCH_URL = "https://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "YOUR_OPENSEARCH_PASSWORD"

# --- Mail (SMTP) ---
SMTP_HOST = "${W_SMTP_HOST}"
SMTP_PORT = ${W_SMTP_PORT}
SMTP_USE_TLS = ${W_SMTP_TLS}
SMTP_SSL = ${W_SMTP_SSL}
SMTP_USER = "${W_SMTP_USER}"
SMTP_PASS = "${W_SMTP_PASS}"
MAIL_FROM = "${W_MAIL_FROM}"
MAIL_TO = "${W_MAIL_TO}"

# --- Ollama ---
OLLAMA_URL = "${W_OLLAMA_URL}"
OLLAMA_MODEL = "${W_OLLAMA_MODEL}"
OLLAMA_TIMEOUT = ${W_OLLAMA_TIMEOUT}

# --- Seuils ---
MIN_ALERT_LEVEL = ${W_MIN_LEVEL}
ABUSEIPDB_THRESHOLD = ${W_ABUSE_THR}
VT_MALICIOUS_THRESHOLD = 1

# --- Langue (en / fr / es) ---
LOCALE = "${W_LOCALE}"

# --- Stockage (cache SQLite + rapports HTML) ---
DB_PATH = "/var/ossec/var/vespera-cache.db"
REPORT_DIR = "/var/ossec/logs/vespera-reports"
PYEOF

  _wiz_ok "${_L[done]}"

  # Mettre à jour le nom du container pour le déploiement qui suit
  [[ -n "$W_CONTAINER" ]] && CONTAINER="$W_CONTAINER"

  # Rappel docker-compose si host-gateway utilisé
  if [[ "$_has_docker" == 1 ]] && \
     [[ "$W_OLLAMA_URL" == *"host-gateway"* || "$W_SMTP_HOST" == "host-gateway" ]]; then
    echo ""
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${BOLD}${_L[action]}${RESET}"
    echo -e "  ${_L[action_body]}"
    echo ""
    echo -e "    ${BOLD}    extra_hosts:${RESET}"
    echo -e "    ${BOLD}      - \"host-gateway:host-gateway\"${RESET}"
    echo ""
    echo -e "  ${_L[action_restart]}"
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  fi

  # Guide Thunderbird si option 6 choisie
  if [[ "$_tb_mode" == 1 ]]; then
    local TB_USER="${_tb_user:-root}"
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${BOLD}${CYAN}${_L[tb_title]}${RESET}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    echo -e "  ${_L[tb_step1]}"
    echo -e "  ${BOLD}${_L[tb_step1b]}${RESET}"
    echo ""
    echo -e "  ${_L[tb_step2]}"
    printf "  ${BOLD}${_L[tb_step2b]}${RESET}\n" "$TB_USER"
    echo ""
    echo -e "  ${_L[tb_step3]}"
    echo -e "  ${BOLD}${_L[tb_step3b]}${RESET}"
    echo ""
    echo -e "  ${_L[tb_step4]}"
    echo -e "  ${BOLD}${_L[tb_step4b]}${RESET}"
    echo ""
    echo -e "  ${_L[tb_test]}"
    printf "  ${BOLD}${_L[tb_testb]}${RESET}\n" "$TB_USER"
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  fi

  # ── Push config.py dans le container pour que le pipeline test
  #    utilise la bonne LOCALE (et tous les autres paramètres à jour)
  if [[ "$_has_docker" == 1 ]] && \
     docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${W_CONTAINER:-}"; then
    docker cp "$VESPERA_ROOT/config/config.py" \
      "${W_CONTAINER}:${WAZUH_BASE}/integrations/config.py" 2>/dev/null \
      && _wiz_ok "${_L[config_pushed]:-config.py pushed to container}" \
      || _wiz_warn "Could not push config.py to container — run ./install.sh --quick"
  fi

  # ── Tests de validation ───────────────────────────────────────────────────
  run_post_install_tests \
    "$W_OLLAMA_URL" "$W_SMTP_HOST" "$W_SMTP_PORT" \
    "$_has_docker"  "${W_CONTAINER:-}" "$W_MAIL_TO"
}

# ─── Configuration ────────────────────────────────────────────────────────────
ensure_config() {
  local py="$VESPERA_ROOT/config/config.py"
  if [[ ! -f "$py" ]]; then
    if [[ -t 0 && -t 1 ]]; then
      echo -e "${YELLOW}⚠${RESET}  config/config.py not found — launching setup wizard."
      run_setup_wizard
    else
      echo "config/config.py not found. Create it first:"
      echo "  cp \"$VESPERA_ROOT/config/config.example.py\" \"$VESPERA_ROOT/config/config.py\""
      echo "  # Edit config.py then re-run"
      echo "  # Or interactively: ./install.sh --setup"
      exit 1
    fi
  fi
}

apply_locale_config() {
  local py="$VESPERA_ROOT/config/config.py" loc="$1"
  [[ -f "$py" && -n "$loc" ]] || return 0
  case "$loc" in en|fr|es) ;; *) return 0 ;; esac
  if sed --version >/dev/null 2>&1; then
    sed -i -E "s/^LOCALE = .*/LOCALE = \"$loc\"/" "$py"
  else
    sed -i '' -E "s/^LOCALE = .*/LOCALE = \"$loc\"/" "$py"
  fi
}

run_locale_step() {
  if [[ -n "$LOCALE_FLAG" ]]; then
    apply_locale_config "$LOCALE_FLAG"
    echo "LOCALE=$LOCALE_FLAG updated in config/config.py"
  elif [[ "$PROMPT_LOCALE" == 1 && -t 0 ]]; then
    echo ""
    echo "Report language / Langue des rapports / Idioma informes:"
    echo "  1) English  2) Français  3) Español"
    read -r -p "Choice [1-3, default 1]: " _ch
    case "${_ch:-1}" in
      2|fr|FR) apply_locale_config fr ;;
      3|es|ES) apply_locale_config es ;;
      *)        apply_locale_config en ;;
    esac
    echo "LOCALE updated in config/config.py"
  fi
}

# ─── Déploiement Docker ───────────────────────────────────────────────────────
merge_ossec_docker() {
  local merge_script="$VESPERA_ROOT/scripts/vespera-merge-ossec.py"
  [[ -f "$merge_script" ]]             || { echo "Introuvable: $merge_script"; exit 1; }
  command -v python3 >/dev/null 2>&1   || { echo "python3 requis pour --merge-ossec"; exit 1; }
  docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
    || { echo "Container \"$CONTAINER\" non démarré."; exit 1; }
  local tmp_in tmp_out
  tmp_in="$(mktemp)"; tmp_out="$(mktemp)"
  _cleanup() { rm -f "$tmp_in" "$tmp_out"; }
  trap _cleanup EXIT
  echo "--- Fusion XML Vespera dans ossec.conf ($CONTAINER) ---"
  run docker cp "$CONTAINER:$WAZUH_BASE/etc/ossec.conf" "$tmp_in"
  local _ni_flag=""
  [[ "$QUICK" == 1 ]] && _ni_flag="--non-interactive"
  run python3 "$merge_script" "$tmp_in" "$tmp_out" --vespera-root "$VESPERA_ROOT" $_ni_flag
  run docker cp "$tmp_out" "$CONTAINER:$WAZUH_BASE/etc/ossec.conf"
  run docker exec "$CONTAINER" chown root:wazuh "$WAZUH_BASE/etc/ossec.conf"
  run docker exec "$CONTAINER" chmod 660 "$WAZUH_BASE/etc/ossec.conf"
  trap - EXIT; _cleanup
  echo "ossec.conf mis à jour (marqueurs VESPERA_BEGIN/END)."
}

merge_ossec_bare() {
  local merge_script="$VESPERA_ROOT/scripts/vespera-merge-ossec.py"
  local conf="$WAZUH_BASE/etc/ossec.conf"
  [[ -f "$merge_script" ]] || { echo "Introuvable: $merge_script"; exit 1; }
  command -v python3 >/dev/null 2>&1 || { echo "python3 requis"; exit 1; }
  [[ -r "$conf" ]] || { echo "Impossible de lire $conf"; exit 1; }
  local tmp_out; tmp_out="$(mktemp)"
  _cleanup() { rm -f "$tmp_out"; }
  trap _cleanup EXIT
  echo "--- Fusion XML Vespera dans $conf ---"
  local _ni_flag=""
  [[ "$QUICK" == 1 ]] && _ni_flag="--non-interactive"
  run python3 "$merge_script" "$conf" "$tmp_out" --vespera-root "$VESPERA_ROOT" $_ni_flag
  if [[ -w "$conf" ]]; then run cp "$tmp_out" "$conf"
  else run sudo cp "$tmp_out" "$conf"; fi
  run sudo chown root:wazuh "$conf" 2>/dev/null || true
  run sudo chmod 660 "$conf" 2>/dev/null || true
  trap - EXIT; _cleanup
}

install_rules_docker() {
  docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
    || { echo "Container \"$CONTAINER\" non démarré."; exit 1; }
  echo "--- Installation des règles ($CONTAINER) ---"
  if check_duplicate_rules "$CONTAINER"; then
    run docker cp "$VESPERA_ROOT/config/custom-rules.xml" \
      "$CONTAINER:$WAZUH_BASE/etc/rules/0_vespera.xml"
  else
    echo "  Règles non installées (conflits détectés — voir avertissement ci-dessus)."
  fi
}

install_rules_bare() {
  if check_duplicate_rules ""; then
    if [[ -w "$WAZUH_BASE/etc/rules" ]]; then
      run cp "$VESPERA_ROOT/config/custom-rules.xml" "$WAZUH_BASE/etc/rules/0_vespera.xml"
    else
      run sudo cp "$VESPERA_ROOT/config/custom-rules.xml" "$WAZUH_BASE/etc/rules/0_vespera.xml"
    fi
  else
    echo "  Règles non installées (conflits détectés — voir avertissement ci-dessus)."
  fi
}

restart_docker() {
  echo "--- Redémarrage Wazuh ($CONTAINER) ---"
  run docker exec "$CONTAINER" "$WAZUH_BASE/bin/wazuh-control" restart
}

restart_bare() {
  echo "--- Redémarrage wazuh-manager ---"
  if command -v systemctl >/dev/null 2>&1; then
    run sudo systemctl restart wazuh-manager
  else
    run "$WAZUH_BASE/bin/wazuh-control" restart
  fi
}

deploy_docker() {
  ensure_config
  run_locale_step
  command -v docker >/dev/null 2>&1 || { echo "Docker not found."; exit 1; }
  docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" || {
    echo "Container \"$CONTAINER\" is not running."
    echo "Set WAZUH_CONTAINER or start the stack."
    exit 1
  }

  echo ""
  echo -e "${BOLD}--- Vespera → Docker (${CONTAINER}) ---${RESET}"
  suggest_ollama_model

  run docker cp "$VESPERA_ROOT/integrations/ollama-alert.py"  "$CONTAINER:$WAZUH_BASE/integrations/"
  run docker cp "$VESPERA_ROOT/integrations/locales"           "$CONTAINER:$WAZUH_BASE/integrations/"
  run docker cp "$VESPERA_ROOT/config/config.py"               "$CONTAINER:$WAZUH_BASE/integrations/"
  run docker cp "$VESPERA_ROOT/integrations/custom-ollama"     "$CONTAINER:$WAZUH_BASE/integrations/"
  run docker cp "$VESPERA_ROOT/integrations/custom-vt-check"   "$CONTAINER:$WAZUH_BASE/integrations/"
  run docker cp "$VESPERA_ROOT/active-response/vt-check.py"    "$CONTAINER:$WAZUH_BASE/active-response/bin/"
  run docker cp "$VESPERA_ROOT/active-response/ip-enrich.py"   "$CONTAINER:$WAZUH_BASE/active-response/bin/"

  run docker exec "$CONTAINER" chmod 750 \
    "$WAZUH_BASE/integrations/ollama-alert.py" \
    "$WAZUH_BASE/integrations/custom-ollama" \
    "$WAZUH_BASE/integrations/custom-vt-check" \
    "$WAZUH_BASE/active-response/bin/vt-check.py" \
    "$WAZUH_BASE/active-response/bin/ip-enrich.py"

  run docker exec "$CONTAINER" chown root:wazuh \
    "$WAZUH_BASE/integrations/ollama-alert.py" \
    "$WAZUH_BASE/integrations/custom-ollama" \
    "$WAZUH_BASE/integrations/custom-vt-check" \
    "$WAZUH_BASE/active-response/bin/vt-check.py" \
    "$WAZUH_BASE/active-response/bin/ip-enrich.py"

  # ── Validation extra_hosts ──────────────────────────────────────────────────
  if ! check_host_gateway "$CONTAINER"; then
    echo -e "  ${YELLOW}⚠${RESET}  host-gateway not resolvable from container ${CONTAINER}."
    echo -e "    ${YELLOW}→${RESET} Add to docker-compose.yml under ${BOLD}${CONTAINER}${RESET}:"
    echo -e "         ${BOLD}extra_hosts:${RESET}"
    echo -e "           ${BOLD}- \"host-gateway:host-gateway\"${RESET}"
    echo -e "    Then: ${BOLD}docker compose down && docker compose up -d${RESET}"
  else
    echo -e "  ${GREEN}✓${RESET}  host-gateway resolvable from container"
  fi

  # ── Réparations automatiques ────────────────────────────────────────────────
  fix_ossec_double_block  "$CONTAINER"
  fix_ossec_shared_perms  "$CONTAINER"
  fix_dovecot_maildir

  # ── Watcher (workaround integratord Wazuh 4.14+) ───────────────────────────
  deploy_alert_watcher "$CONTAINER"

  # ── Restart manager après corrections ───────────────────────────────────────
  echo "--- Redémarrage Wazuh ($CONTAINER) ---"
  run docker exec "$CONTAINER" "$WAZUH_BASE/bin/wazuh-control" restart

  echo -e "${GREEN}✓${RESET} Files deployed."
}

deploy_bare() {
  ensure_config
  run_locale_step
  local I="$WAZUH_BASE/integrations" B="$WAZUH_BASE/active-response/bin"
  [[ -d "$I" && -d "$B" ]] || { echo "Wazuh paths not found under $WAZUH_BASE."; exit 1; }
  [[ -w "$I" && -w "$B" ]] || { echo "Write access required (sudo?)."; exit 1; }

  echo ""
  echo -e "${BOLD}--- Vespera → bare metal (${WAZUH_BASE}) ---${RESET}"
  suggest_ollama_model

  run cp "$VESPERA_ROOT/integrations/ollama-alert.py"  "$I/"
  run cp -r "$VESPERA_ROOT/integrations/locales"        "$I/"
  run cp "$VESPERA_ROOT/config/config.py"               "$I/"
  run cp "$VESPERA_ROOT/integrations/custom-ollama"     "$I/"
  run cp "$VESPERA_ROOT/integrations/custom-vt-check"   "$I/"
  run cp "$VESPERA_ROOT/active-response/vt-check.py"    "$B/"
  run cp "$VESPERA_ROOT/active-response/ip-enrich.py"   "$B/"

  run chmod 750 "$I/ollama-alert.py" "$I/custom-ollama" "$I/custom-vt-check" \
                "$B/vt-check.py" "$B/ip-enrich.py"
  run chown root:wazuh "$I/ollama-alert.py" "$I/custom-ollama" "$I/custom-vt-check" \
                       "$B/vt-check.py" "$B/ip-enrich.py" 2>/dev/null || true

  echo -e "${GREEN}✓${RESET} Files deployed."
}

# ─── Validate ────────────────────────────────────────────────────────────────
run_validate() {
  local cname="$CONTAINER"
  local is_docker=0
  command -v docker >/dev/null 2>&1 && \
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname" && is_docker=1

  echo ""
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
  echo -e "${BOLD}  Vespera — Validation post-install${RESET}"
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"

  local ok=0 tot=0

  # 1. integratord running (informatif — le watcher est le vrai pipeline sur Wazuh 4.14+)
  if [[ "$is_docker" == 1 ]]; then
    tot=$((tot+1))
    if docker exec "$cname" /var/ossec/bin/wazuh-control status 2>/dev/null \
        | grep -qE "wazuh-integratord.*(running|is running)"; then
      echo -e "  ${GREEN}✓${RESET}  wazuh-integratord running"
      ok=$((ok+1))
    else
      # Sur Wazuh 4.14+, integratord peut être inactif — le watcher compense
      echo -e "  ${YELLOW}⚠${RESET}  wazuh-integratord inactif (normal sur Wazuh 4.14+ — vespera-watcher actif)"
      ok=$((ok+1))  # ne pas pénaliser le score si le watcher tourne
    fi
  fi

  # 2. Ollama accessible depuis le container
  if [[ "$is_docker" == 1 ]]; then
    tot=$((tot+1))
    if docker exec "$cname" curl -sf --max-time 5 \
        http://host-gateway:11434/api/tags >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${RESET}  Ollama accessible via host-gateway"
      ok=$((ok+1))
    else
      echo -e "  ${RED}✗${RESET}  Ollama inaccessible via host-gateway"
      echo -e "    ${YELLOW}→${RESET}  Vérifier extra_hosts dans docker-compose.yml"
      echo -e "    ${YELLOW}→${RESET}  Vérifier que Ollama tourne : systemctl status ollama"
    fi
  else
    tot=$((tot+1))
    if curl -sf --max-time 5 http://localhost:11434/api/tags >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${RESET}  Ollama accessible sur localhost"
      ok=$((ok+1))
    else
      echo -e "  ${RED}✗${RESET}  Ollama inaccessible"
      echo -e "    ${YELLOW}→${RESET}  sudo systemctl start ollama"
    fi
  fi

  # 3. SMTP accessible depuis le container
  if [[ "$is_docker" == 1 ]]; then
    tot=$((tot+1))
    if docker exec "$cname" bash -c \
        'timeout 3 bash -c "echo > /dev/tcp/host-gateway/25" 2>/dev/null'; then
      echo -e "  ${GREEN}✓${RESET}  SMTP (host-gateway:25) accessible"
      ok=$((ok+1))
    else
      echo -e "  ${RED}✗${RESET}  SMTP inaccessible depuis le container"
      echo -e "    ${YELLOW}→${RESET}  sudo systemctl start postfix"
      echo -e "    ${YELLOW}→${RESET}  Vérifier extra_hosts dans docker-compose.yml"
    fi
  fi

  # 4. config.py chargeable
  if [[ "$is_docker" == 1 ]]; then
    tot=$((tot+1))
    local model
    model=$(docker exec "$cname" python3 -c \
      "import sys; sys.path.insert(0,'/var/ossec/integrations'); import config; print(config.OLLAMA_MODEL)" \
      2>/dev/null || echo "")
    if [[ -n "$model" ]]; then
      echo -e "  ${GREEN}✓${RESET}  config.py chargeable — modèle : ${BOLD}${model}${RESET}"
      ok=$((ok+1))
    else
      echo -e "  ${RED}✗${RESET}  config.py invalide ou absent dans le container"
      echo -e "    ${YELLOW}→${RESET}  ./install.sh --quick"
    fi
  fi

  # 5. alert-watcher service
  tot=$((tot+1))
  if systemctl is-active --quiet vespera-watcher 2>/dev/null; then
    echo -e "  ${GREEN}✓${RESET}  vespera-watcher service actif"
    ok=$((ok+1))
  else
    echo -e "  ${YELLOW}⚠${RESET}  vespera-watcher non actif"
    echo -e "    ${YELLOW}→${RESET}  ./install.sh --repair"
  fi

  # 6. ossec.conf — un seul bloc
  if [[ "$is_docker" == 1 ]]; then
    tot=$((tot+1))
    local nblocks
    nblocks=$(docker exec "$cname" grep -c "^<ossec_config>" \
      /var/ossec/etc/ossec.conf 2>/dev/null || echo 0)
    if [[ "$nblocks" -le 1 ]]; then
      echo -e "  ${GREEN}✓${RESET}  ossec.conf — bloc unique"
      ok=$((ok+1))
    else
      echo -e "  ${RED}✗${RESET}  ossec.conf — ${nblocks} blocs détectés (analysisd ignore les suivants)"
      echo -e "    ${YELLOW}→${RESET}  ./install.sh --repair"
    fi
  fi

  echo ""
  if [[ "$ok" == "$tot" ]]; then
    echo -e "  ${GREEN}${BOLD}✓ Tous les checks OK (${ok}/${tot})${RESET}"
  else
    echo -e "  ${YELLOW}${BOLD}⚠ ${ok}/${tot} checks OK — voir suggestions ci-dessus${RESET}"
  fi
  echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..58})${RESET}"
}

# ─── Test mail ────────────────────────────────────────────────────────────────
run_test_mail() {
  local cname="$CONTAINER"
  command -v docker >/dev/null 2>&1 && \
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname" || {
    echo "Container $cname non disponible."; exit 1
  }

  # Lire MAIL_TO depuis config.py dans le container
  local mail_to
  mail_to=$(docker exec "$cname" python3 -c \
    "import sys; sys.path.insert(0,'/var/ossec/integrations'); import config; print(config.MAIL_TO)" \
    2>/dev/null || echo "")
  [[ -z "$mail_to" ]] && {
    echo "Impossible de lire MAIL_TO depuis config.py — run ./install.sh --quick d'abord."
    exit 1
  }

  echo ""
  echo -e "${BOLD}  Vespera — Test mail (injection alerte réelle)${RESET}"
  echo -e "  Destinataire : ${BOLD}${mail_to}${RESET}"
  echo ""

  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)
  local alert_json
  alert_json="{\"timestamp\":\"${ts}\",\"rule\":{\"level\":12,\"description\":\"[TEST] Vespera install test — SSH brute force simulation\",\"id\":\"5712\",\"groups\":[\"sshd\",\"authentication_failures\"],\"firedtimes\":10},\"agent\":{\"id\":\"001\",\"name\":\"vespera-test\",\"ip\":\"127.0.0.1\"},\"manager\":{\"name\":\"wazuh.manager\"},\"id\":\"vespera_test_$(date +%s)\",\"data\":{\"srcip\":\"192.0.2.1\"},\"full_log\":\"test alert\",\"location\":\"/var/log/auth.log\"}"

  # Mémoriser la position courante du log AVANT l'injection
  local log_lines_before
  log_lines_before=$(docker exec "$cname" bash -c 'cat /var/ossec/logs/vespera-watcher.log 2>/dev/null | wc -l || echo 0' 2>/dev/null || echo 0)

  echo -e "  ${CYAN}→${RESET} Injection dans alerts.json…"
  docker exec "$cname" bash -c "echo '${alert_json}' >> /var/ossec/logs/alerts/alerts.json"

  echo -e "  ${CYAN}→${RESET} Attente réponse Ollama (max 180s)…"
  local waited=0
  while [[ $waited -lt 200 ]]; do
    sleep 5; waited=$((waited+5))
    # Chercher "mail sent" uniquement dans les lignes APRÈS l'injection
    if docker exec "$cname" bash -c "tail -n +$((log_lines_before+1)) /var/ossec/logs/vespera-watcher.log 2>/dev/null | grep -q 'mail sent'" 2>/dev/null; then
      echo -e "  ${GREEN}${BOLD}✓ Pipeline OK — mail envoyé à ${mail_to}${RESET}"
      return 0
    fi
    printf "  ⏳ %ds…\r" "$waited"
  done
  echo ""
  echo -e "  ${YELLOW}⚠${RESET}  Timeout — vérifier le watcher :"
  echo -e "    docker exec ${cname} cat /var/ossec/logs/vespera-watcher.log"
  echo -e "    journalctl -u vespera-watcher -n 20"
}

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
  local _VER; _VER="$(cat "${VESPERA_ROOT}/VERSION" 2>/dev/null || echo '?')"
  # Centrage dynamique : largeur art = 52, pad = (cols - 52) / 2
  local _cols _pad _p
  _cols=$(tput cols 2>/dev/null || echo 80)
  _pad=$(( (_cols - 52) / 2 ))
  [[ $_pad -lt 0 ]] && _pad=0
  _p=$(printf '%*s' "$_pad" '')
  printf '\n'
  while IFS= read -r _line; do
    printf "${RED}%s%s${RESET}\n" "$_p" "$_line"
  done << 'VESPERA_BANNER'
:::::.:::::.::::.::;%SX@88@XS%;:.::::.:::::.:::::.
:.:.:::.:.::.:;%%%S%SSSS@@SSSSS%S%%;:::.:.:::.:.::
::.::.:::;;%S%S%%SSS8888888888X%%t%%%%%t:::.::::.:
::::.:.;SX%%S%%%SXSXXX8%88888@XXS%SSS%%SSS:::.::::
:.:.;t%%%%S%%%%%XX8X888:   888888%%S%%%%S%%%t::.:.
::;S8%%SSS%%%%S@X8X8@X ....; X8888%%S%%S%SS%S@S;::
SX%X8S%SSSSS%%SX8%@S  8XSStSt%S888XtSSS%XSSS%8X%S%
%@%%Xt%SSS%%%%SX@X8X .X888@X8 @888@t%X%%%SSS%%%%@t
::%SStSSS%S%%SSXX888X8;;@;: 8X8888@ttSS%S%%SS%%%::
:.:.t%t%S%%%%%%Xt8888S8  S 8X88888%;%SS%%%SS;:.:.:
::.:..:;%XSt%%%SS;88X88888888@888S;;%S%%SX;::::..:
::.:.::::;%XS%%SXt%8888888888888%;;;%S%%;:::::::::
::::::::::::;t%%tttSX@888888@@S%SSSt.:::::::::::::
::::::::::::::::::.;t%%S@@S%%tt::..:..::::::::::::
VESPERA_BANNER
  printf '\n'
  printf "%s${BOLD}V  E  S  P  E  R  A${RESET}\n" "$(printf '%*s' $(( (_cols - 19) / 2 )) '')"
  printf "%s${RED}AI-POWERED SOC ALERT PIPELINE  v${_VER}${RESET}\n" "$(printf '%*s' $(( (_cols - 38 - ${#_VER}) / 2 )) '')"
  printf '\n'
}

# Afficher le banner sauf en mode scripté (--quick / --docker-only / --bare-only)
if [[ "$QUICK" != 1 && "$DOCKER_ONLY" != 1 && "$BARE_ONLY" != 1 ]]; then
  print_banner
fi

# Initialiser les traductions (_L) dès maintenant — certaines fonctions (deploy_alert_watcher,
# run_validate, run_post_install_tests…) les utilisent avant que run_setup_wizard soit appelé.
_wiz_lang_init
_WIZ_LANG="${LOCALE_FLAG:-fr}"
_wiz_set_lang

# ─── Dispatch principal ───────────────────────────────────────────────────────

# --setup : wizard seul, sans déploiement
if [[ "$SETUP_ONLY" == 1 ]]; then
  run_setup_wizard
  echo ""
  echo -e "${GREEN}✓${RESET} Setup complete. Run ${BOLD}./install.sh --quick${RESET} to deploy."
  exit 0
fi

# --validate
if [[ "$VALIDATE" == 1 ]]; then
  run_validate
  exit 0
fi

# --test-mail
if [[ "$TEST_MAIL" == 1 ]]; then
  run_test_mail
  exit 0
fi

# --repair : applique les corrections sans redéployer les fichiers
if [[ "$REPAIR" == 1 ]]; then
  _WIZ_LANG="${LOCALE_FLAG:-fr}"
  # Charger les traductions minimales
  command -v _wiz_set_lang >/dev/null 2>&1 && _wiz_set_lang || true
  echo ""
  echo -e "${BOLD}${CYAN}  ── ${_L[repair_title]:-Vespera repair} ──────────────────────────${RESET}"
  fix_dovecot_maildir
  fix_ossec_double_block  "$CONTAINER"
  fix_ossec_shared_perms  "$CONTAINER"
  deploy_alert_watcher    "$CONTAINER"
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
    echo "--- Redémarrage Wazuh ($CONTAINER) ---"
    docker exec "$CONTAINER" "$WAZUH_BASE/bin/wazuh-control" restart
  fi
  echo -e "${GREEN}✓${RESET} Repair complete."
  exit 0
fi

# Inférer cible Docker/bare si --merge/--rules/--restart sans --docker-only/--bare-only
if [[ "$MERGE_OSSEC" == 1 || "$INSTALL_RULES" == 1 || "$RESTART_WAZUH" == 1 ]]; then
  if [[ "$DOCKER_ONLY" != 1 && "$BARE_ONLY" != 1 ]]; then
    if command -v docker >/dev/null 2>&1 && \
       docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
      DOCKER_ONLY=1
    elif [[ -d "$WAZUH_BASE/integrations" ]]; then
      BARE_ONLY=1
    else
      echo "Utilise --docker-only ou --bare-only avec --merge-ossec / --install-rules / --restart-wazuh"
      exit 1
    fi
  fi
fi

if [[ "$DEPLOY_FILES" == 1 ]]; then
  [[ "$DOCKER_ONLY" == 1 && "$BARE_ONLY" == 1 ]] && { echo "Choisir --docker-only OU --bare-only"; exit 1; }
  [[ "$DOCKER_ONLY" == 1 ]] && deploy_docker
  [[ "$BARE_ONLY" == 1 ]]   && deploy_bare
fi

[[ "$MERGE_OSSEC" == 1 ]]   && { [[ "$DOCKER_ONLY" == 1 ]] && merge_ossec_docker || merge_ossec_bare; }
[[ "$INSTALL_RULES" == 1 ]] && { [[ "$DOCKER_ONLY" == 1 ]] && install_rules_docker || install_rules_bare; }
[[ "$RESTART_WAZUH" == 1 ]] && { [[ "$DOCKER_ONLY" == 1 ]] && restart_docker || restart_bare; }

# Sans flag : auto-détection et déploiement (wizard si pas de config.py)
if [[ "$DEPLOY_FILES" == 0 && "$MERGE_OSSEC" == 0 && "$INSTALL_RULES" == 0 && "$RESTART_WAZUH" == 0 ]]; then
  ensure_config   # lance le wizard si config.py absent
  if command -v docker >/dev/null 2>&1 && \
     docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
    deploy_docker; exit 0
  fi
  if [[ -d "$WAZUH_BASE/integrations" && -d "$WAZUH_BASE/active-response/bin" ]]; then
    deploy_bare; exit 0
  fi
  echo "Wazuh not detected. Options:"
  echo "  1) Start the stack then: ./install.sh --quick"
  echo "  2) WAZUH_CONTAINER=my-manager ./install.sh --docker-only"
  echo "  3) On the manager directly: ./install.sh --bare-only"
  exit 1
fi

echo -e "${GREEN}✓${RESET} All steps completed."

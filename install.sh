#!/bin/bash

# Script d'installation pour ZDefender
# Doit être exécuté en tant que root

set -e

# Vérifier si l'utilisateur est root
if [ "$EUID" -ne 0 ]; then
  echo "Ce script doit être exécuté en tant que root"
  exit 1
fi

# Vérifier si le système est Linux
if [ "$(uname)" != "Linux" ]; then
  echo "Ce script ne fonctionne que sous Linux"
  exit 1
fi

# Vérifier si les dépendances sont installées
echo "Vérification des dépendances..."
MISSING_DEPS=()

# Vérifier les commandes requises
for cmd in iptables; do
  if ! command -v $cmd &> /dev/null; then
    MISSING_DEPS+=($cmd)
  fi
done

# Vérifier la disponibilité de libsystemd
if ! ldconfig -p | grep libsystemd > /dev/null; then
  echo "libsystemd non trouvée. Installation en cours..."
  
  # Détecter le gestionnaire de paquets
  if command -v apt &> /dev/null; then
    apt update
    apt install -y libsystemd-dev
  elif command -v dnf &> /dev/null; then
    dnf install -y systemd-devel
  elif command -v yum &> /dev/null; then
    yum install -y systemd-devel
  elif command -v pacman &> /dev/null; then
    pacman -Sy --noconfirm systemd
  else
    echo "Votre gestionnaire de paquets n'est pas pris en charge. Veuillez installer manuellement libsystemd-dev"
    echo "L'installation continuera mais sans support systemd-journal"
    USE_SYSTEMD=0
  fi
  
  if ldconfig -p | grep libsystemd > /dev/null; then
    echo "libsystemd a été installée avec succès!"
    USE_SYSTEMD=1
  else
    echo "Impossible d'installer libsystemd. L'installation continuera sans support systemd-journal."
    USE_SYSTEMD=0
  fi
else
  echo "libsystemd est déjà installée."
  USE_SYSTEMD=1
fi

# Vérifier rust
if ! command -v cargo &> /dev/null || ! command -v rustc &> /dev/null; then
  echo "Rust n'est pas installé. Installation en cours..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source $HOME/.cargo/env
  echo "Rust a été installé avec succès!"
fi

# Installer les dépendances manquantes
if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
  echo "Installation des dépendances manquantes: ${MISSING_DEPS[*]}"
  
  # Détecter le gestionnaire de paquets
  if command -v apt &> /dev/null; then
    apt update
    apt install -y ${MISSING_DEPS[*]}
  elif command -v dnf &> /dev/null; then
    dnf install -y ${MISSING_DEPS[*]}
  elif command -v yum &> /dev/null; then
    yum install -y ${MISSING_DEPS[*]}
  elif command -v pacman &> /dev/null; then
    pacman -Sy --noconfirm ${MISSING_DEPS[*]}
  else
    echo "Votre gestionnaire de paquets n'est pas pris en charge. Veuillez installer manuellement: ${MISSING_DEPS[*]}"
    exit 1
  fi
fi

echo "Installation de ZDefender..."

# Compiler le projet avec ou sans support systemd
echo "Compilation du projet..."
if [ "$USE_SYSTEMD" -eq 1 ]; then
  echo "Compilation avec support systemd-journal..."
  cargo build --release --features systemd
else
  echo "Compilation sans support systemd-journal..."
  cargo build --release
fi

# Créer les répertoires nécessaires
echo "Création des répertoires..."
mkdir -p /etc/zdefender
mkdir -p /var/log/zdefender

# Copier l'exécutable
echo "Installation de l'exécutable..."
cp target/release/zdefender /usr/local/bin/
chmod +x /usr/local/bin/zdefender

# Installer le script daemon
echo "Installation du script daemon..."
cat > /usr/local/bin/zdefender-daemon << EOF
#!/bin/bash

# Script pour lancer ZDefender comme un vrai daemon
# Ce script est utilisé pour démarrer ZDefender en arrière-plan de manière fiable

# Fonction pour vérifier si ZDefender est déjà en cours d'exécution
is_running() {
    pgrep -f "zdefender start" > /dev/null
    return \$?
}

# Fonction pour obtenir le PID de ZDefender
get_pid() {
    pgrep -f "zdefender start"
}

# Répertoire où stocker le PID
PID_DIR="/var/run"
PID_FILE="\$PID_DIR/zdefender.pid"

# S'assurer que le script est exécuté en tant que root
if [ "\$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root"
    exit 1
fi

# Vérifier si le service est déjà en cours d'exécution
if is_running; then
    echo "ZDefender est déjà en cours d'exécution (PID: \$(get_pid))"
    exit 0
fi

# Vérifier si l'exécutable existe
if [ ! -f "/usr/local/bin/zdefender" ]; then
    echo "L'exécutable ZDefender n'a pas été trouvé."
    exit 1
fi

# Créer le répertoire de log si nécessaire
mkdir -p /var/log/zdefender

# Lancer ZDefender en tant que daemon
echo "Démarrage de ZDefender en arrière-plan..."
nohup /usr/local/bin/zdefender start > /var/log/zdefender/daemon.log 2>&1 &

# Stocker le PID
PID=\$!
echo \$PID > "\$PID_FILE"

echo "ZDefender démarré en arrière-plan (PID: \$PID)"
echo "Logs disponibles dans /var/log/zdefender/daemon.log"
exit 0
EOF

chmod +x /usr/local/bin/zdefender-daemon

# Installer le service systemd
echo "Installation du service systemd..."
cat > /etc/systemd/system/zdefender.service << EOF
[Unit]
Description=ZDefender - Protection contre les attaques DDoS
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/zdefender start
ExecStop=/usr/local/bin/zdefender stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Recharger systemd
systemctl daemon-reload
systemctl enable zdefender.service

# Configurer les interfaces réseau
echo "Configuration des interfaces réseau..."
INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo\|virbr\|docker" | head -n1)

# Préparer la configuration log_mode
if [ "$USE_SYSTEMD" -eq 1 ]; then
  LOG_MODE="SystemdJournal"
else
  LOG_MODE="File" 
fi

if [ -n "$INTERFACES" ]; then
  # Créer la configuration par défaut
  cat > /etc/zdefender/config.json << EOF
{
  "interfaces": ["$INTERFACES"],
  "packet_threshold": 1000,
  "check_interval": 5,
  "block_duration": 300,
  "log_file": "/var/log/zdefender/zdefender.log",
  "log_level": "info",
  "log_mode": "$LOG_MODE",
  "service_state": "Stopped",
  "fortress_mode": false,
  "whitelist": ["127.0.0.1", "::1"]
}
EOF
  echo "Interface $INTERFACES configurée automatiquement."
else
  echo "Aucune interface réseau détectée automatiquement."
  echo "Vous devrez configurer les interfaces manuellement dans /etc/zdefender/config.json"
fi

echo "ZDefender a été installé avec succès!"
if [ "$USE_SYSTEMD" -eq 1 ]; then
  echo "Installé avec support systemd-journal."
else
  echo "Installé sans support systemd-journal. Utilisation du mode de journalisation par fichier."
fi
echo ""
echo "Commandes disponibles:"
echo "  - zdefender start              : Démarrer le service"
echo "  - zdefender start --daemon     : Démarrer le service en arrière-plan (peut nécessiter Ctrl+C)"
echo "  - zdefender-daemon             : Démarrer le service en arrière-plan (recommandé)"
echo "  - zdefender stop               : Arrêter le service"
echo "  - zdefender status             : Afficher le statut du service"
echo "  - zdefender stats              : Afficher les statistiques"
echo "  - zdefender reload             : Recharger la configuration"
echo "  - zdefender fortress --enable  : Activer le mode forteresse"
echo "  - zdefender fortress --disable : Désactiver le mode forteresse"
echo "  - zdefender --mode active      : Configurer le mode actif (protection)"
echo "  - zdefender --mode passive     : Configurer le mode passif (surveillance)"
echo ""
echo "Pour démarrer le service maintenant, exécutez: systemctl start zdefender"
echo "Pour voir les logs, exécutez: journalctl -u zdefender -f" 
#!/bin/bash

# Script pour lancer ZDefender comme un vrai daemon
# Ce script est utilisé pour démarrer ZDefender en arrière-plan de manière fiable

# Fonction pour vérifier si ZDefender est déjà en cours d'exécution
is_running() {
    pgrep -f "zdefender start" > /dev/null
    return $?
}

# Fonction pour obtenir le PID de ZDefender
get_pid() {
    pgrep -f "zdefender start"
}

# Répertoire où stocker le PID
PID_DIR="/var/run"
PID_FILE="$PID_DIR/zdefender.pid"

# S'assurer que le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root"
    exit 1
fi

# Vérifier si le service est déjà en cours d'exécution
if is_running; then
    echo "ZDefender est déjà en cours d'exécution (PID: $(get_pid))"
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
PID=$!
echo $PID > "$PID_FILE"

echo "ZDefender démarré en arrière-plan (PID: $PID)"
echo "Logs disponibles dans /var/log/zdefender/daemon.log"
exit 0 
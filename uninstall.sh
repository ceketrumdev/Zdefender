#!/bin/bash

# Script de désinstallation pour ZDefender
# Doit être exécuté en tant que root

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Fonction pour afficher des messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[ATTENTION]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERREUR]${NC} $1"
}

# Vérifier si l'utilisateur est root
if [ "$EUID" -ne 0 ]; then
  print_error "Ce script doit être exécuté en tant que root"
  exit 1
fi

print_message "Démarrage de la désinstallation de ZDefender..."

# Arrêter et désactiver le service
print_message "Arrêt du service ZDefender..."
systemctl stop zdefender 2>/dev/null
systemctl disable zdefender 2>/dev/null
print_message "Service ZDefender arrêté et désactivé."

# Supprimer le fichier de service
print_message "Suppression du fichier de service systemd..."
if [ -f /etc/systemd/system/zdefender.service ]; then
    rm /etc/systemd/system/zdefender.service
    systemctl daemon-reload
    print_message "Fichier de service supprimé."
else
    print_warning "Fichier de service non trouvé."
fi

# Supprimer l'exécutable
print_message "Suppression des exécutables ZDefender..."
if [ -f /usr/local/bin/zdefender ]; then
    rm /usr/local/bin/zdefender
    print_message "Exécutable principal supprimé."
else
    print_warning "Exécutable principal non trouvé."
fi

if [ -f /usr/local/bin/zdefender-daemon ]; then
    rm /usr/local/bin/zdefender-daemon
    print_message "Script daemon supprimé."
else
    print_warning "Script daemon non trouvé."
fi

# Supprimer le fichier PID s'il existe
if [ -f /var/run/zdefender.pid ]; then
    rm /var/run/zdefender.pid
    print_message "Fichier PID supprimé."
fi

# Supprimer les règles iptables
print_message "Nettoyage des règles iptables..."
iptables -F INPUT 2>/dev/null
iptables -X ZDEFENDER 2>/dev/null
print_message "Règles iptables nettoyées."

# Demander à l'utilisateur s'il veut supprimer les fichiers de configuration et logs
echo ""
read -p "Voulez-vous également supprimer les fichiers de configuration et logs? (o/n): " choice
if [[ "$choice" =~ ^[Oo]$ ]]; then
    # Supprimer les fichiers de configuration
    print_message "Suppression des fichiers de configuration..."
    if [ -d /etc/zdefender ]; then
        rm -rf /etc/zdefender
        print_message "Répertoire de configuration supprimé."
    else
        print_warning "Répertoire de configuration non trouvé."
    fi

    # Supprimer les logs
    print_message "Suppression des fichiers de logs..."
    if [ -d /var/log/zdefender ]; then
        rm -rf /var/log/zdefender
        print_message "Logs supprimés."
    else
        print_warning "Répertoire de logs non trouvé."
    fi
else
    print_message "Les fichiers de configuration et logs ont été conservés."
    print_message "Ils se trouvent dans /etc/zdefender et /var/log/zdefender."
fi

# Nettoyage final
print_message "Actualisation du système..."
systemctl daemon-reload
ldconfig

echo ""
print_message "Désinstallation de ZDefender terminée avec succès!"
print_message "Si vous souhaitez réinstaller ZDefender ultérieurement, utilisez le script install.sh."
echo "" 
====================================================
                    ZDEFENDER
        Protection avancée contre les attaques DDoS
====================================================

Version: 0.1.0
Licence: MIT
Langage: Rust

ZDefender est un système avancé de protection contre les attaques DDoS 
pour les applications Linux. Il fournit une solution complète pour 
détecter et atténuer les menaces réseau en temps réel.

----------------------------------------------------
                  FONCTIONNALITÉS
----------------------------------------------------

- Détection multi-couches: Analyse sophistiquée des paquets et 
  statistiques de trafic
- Mode forteresse: Protection renforcée activable instantanément 
  en cas d'attaque massive
- Blocage intelligent: Durée de blocage adaptée selon la gravité 
  de l'attaque
- Limitation de débit: Régulation du flux pour les comportements 
  suspects
- Journalisation flexible: Support des fichiers de logs classiques 
  et systemd-journal
- Configuration facile: Options configurables via fichier JSON
- Mode passif/actif: Fonctionnement en mode détection seule ou 
  avec mitigation active

----------------------------------------------------
              TYPES D'ATTAQUES DÉTECTÉS
----------------------------------------------------

- SYN Flood: Saturation par paquets SYN (TCP)
- ICMP Flood: Saturation par pings
- UDP Flood: Saturation par paquets UDP
- Amplification DNS: Amplification par serveurs DNS
- Scan de ports: Tentatives de découverte de services
- Fragmentation: Attaques par fragmentation de paquets
- Comportements anormaux: Toute déviation des modèles normaux

----------------------------------------------------
                  ARCHITECTURE
----------------------------------------------------

Le système est structuré en modules spécialisés:

zdefender/
├── src/
│   ├── models.rs       # Structures de données fondamentales
│   ├── log_mode.rs     # Configuration des modes de journalisation
│   ├── logger.rs       # Gestion de la journalisation
│   ├── config.rs       # Configuration et paramètres
│   ├── protection.rs   # Coordination des stratégies de protection
│   ├── analyzer.rs     # Analyse du trafic
│   ├── packet_inspection.rs  # Inspection profonde des paquets
│   ├── detect_attacks.rs     # Algorithmes de détection
│   ├── defender.rs     # Actions de défense
│   └── service.rs      # Gestion du service
└── ...

----------------------------------------------------
                  INSTALLATION
----------------------------------------------------

PRÉREQUIS:
- Système Linux (testé sur Ubuntu 20.04+, Debian 11+, CentOS 8+)
- Rust 1.56+ (pour compilation)
- libpcap-dev
- build-essential

INSTALLATION AUTOMATIQUE:
  # Cloner le dépôt
  git clone https://github.com/your-username/zdefender.git
  cd zdefender

  # Installer le service (requiert les droits d'administrateur)
  sudo ./install.sh

  # Vérifier le statut du service
  sudo systemctl status zdefender

INSTALLATION MANUELLE:
  # Compiler le projet
  cargo build --release

  # Copier le binaire
  sudo cp target/release/zdefender /usr/local/bin/

  # Créer le répertoire de configuration
  sudo mkdir -p /etc/zdefender

  # Copier la configuration par défaut
  sudo cp config/default.json /etc/zdefender/config.json

  # Installer le service systemd
  sudo cp config/zdefender.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable zdefender
  sudo systemctl start zdefender

----------------------------------------------------
                 CONFIGURATION
----------------------------------------------------

Le fichier de configuration se trouve à '/etc/zdefender/config.json':

{
  "interfaces": ["eth0"],
  "packet_threshold": 1000,
  "check_interval": 5,
  "block_duration": 300,
  "log_file": "/var/log/zdefender/zdefender.log",
  "log_level": "info",
  "log_mode": "File",
  "service_state": "Active",
  "fortress_mode": false,
  "whitelist": ["127.0.0.1", "::1"]
}

OPTIONS PRINCIPALES:
- interfaces: Interfaces réseau à surveiller (défaut: ["eth0"])
- packet_threshold: Seuil de paquets par seconde (défaut: 1000)
- check_interval: Intervalle de vérification en secondes (défaut: 5)
- block_duration: Durée de blocage en secondes (défaut: 300)
- log_mode: Mode de journalisation (File ou SystemdJournal) (défaut: File)
- fortress_mode: Mode forteresse activé (défaut: false)
- whitelist: IPs à ne jamais bloquer (défaut: ["127.0.0.1", "::1"])

----------------------------------------------------
                JOURNALISATION
----------------------------------------------------

ZDefender supporte deux modes de journalisation:

- Fichier: Logs écrits dans un fichier classique 
  (/var/log/zdefender/zdefender.log par défaut)
- SystemdJournal: Logs envoyés à systemd-journal 
  (nécessite la feature 'systemd')

ACTIVER LE SUPPORT SYSTEMD-JOURNAL:
  # Compiler avec la feature systemd
  cargo build --release --features systemd

  # Activer dans la configuration
  sudo sed -i 's/"log_mode": "File"/"log_mode": "SystemdJournal"/' /etc/zdefender/config.json

----------------------------------------------------
                  UTILISATION
----------------------------------------------------

INTERFACE CLI:
  # Démarrer le service
  zdefender start

  # Démarrer en daemon
  zdefender start --daemon

  # Arrêter le service
  zdefender stop

  # Afficher le statut
  zdefender status

  # Afficher les statistiques détaillées
  zdefender stats

  # Activer le mode forteresse
  zdefender fortress --enable

  # Désactiver le mode forteresse
  zdefender fortress --disable

  # Recharger la configuration
  zdefender reload

BIBLIOTHÈQUE:
  Intégrez ZDefender dans vos applications Rust en ajoutant
  le crate à votre Cargo.toml:

  [dependencies]
  zdefender = "0.1.0"

  Exemple d'utilisation:

  use zdefender::{ProtectionManager, PacketInfo, Action, LogMode};
  use std::sync::Arc;
  use tokio::sync::{mpsc, RwLock};

  #[tokio::main]
  async fn main() {
      // Initialiser les canaux de communication
      let (report_tx, mut report_rx) = mpsc::channel(100);

      // Charger la configuration
      let config = Arc::new(RwLock::new(Config::default()));

      // Initialiser le gestionnaire de protection
      let mut protection = ProtectionManager::new(config, report_tx).await;

      // Configurer les seuils de détection
      protection.set_thresholds(100.0, 0.8);

      // Traiter un paquet
      if let Some(action) = protection.process_packet(packet) {
          match action {
              Action::Drop => println!("Paquet supprimé"),
              Action::Block(ip, duration) => println!("IP {} bloquée pour {:?}", ip, duration),
              Action::RateLimit(ip) => println!("Limitation de débit pour l'IP {}", ip),
              _ => {}
          }
      }
  }

----------------------------------------------------
                   LICENCE
----------------------------------------------------

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus 
de détails. 
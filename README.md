# ZDefender 🛡️

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1.2-blue.svg)]()

**ZDefender** est un système avancé de protection contre les attaques DDoS pour les applications Linux. Il fournit une solution complète pour détecter et atténuer les menaces réseau en temps réel.

<p align="center">
  <img src="https://user-images.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/raw/main/docs/zdefender-logo.png" alt="ZDefender Logo" width="1024" height="343" />
</p>

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Types d'attaques détectés](#-types-dattaques-détectés)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Journalisation](#-journalisation)
- [Utilisation](#-utilisation)
  - [Interface CLI](#interface-cli)
  - [Bibliothèque](#bibliothèque)
- [Comparer avec d'autres solutions](#-comparer-avec-dautres-solutions)
- [Licence](#-licence)

## ✨ Fonctionnalités

- **🔍 Détection multi-couches**: Analyse sophistiquée des paquets et statistiques de trafic
- **🏰 Mode forteresse**: Protection renforcée activable instantanément en cas d'attaque massive
- **🚫 Blocage intelligent**: Durée de blocage adaptée selon la gravité de l'attaque
- **⚖️ Limitation de débit**: Régulation du flux pour les comportements suspects
- **📝 Journalisation flexible**: Support des fichiers de logs classiques et systemd-journal
- **⚙️ Configuration facile**: Options configurables via fichier JSON
- **🔄 Mode passif/actif**: Fonctionnement en mode détection seule ou avec mitigation active

## 🛡️ Types d'attaques détectés

| Type d'attaque | Description | Méthode de détection |
|---------------|-------------|----------------------|
| SYN Flood     | Saturation par paquets SYN | Analyse de ratio SYN/ACK |
| ICMP Flood    | Saturation par pings | Comptage de paquets ICMP |
| UDP Flood     | Saturation par paquets UDP | Analyse volumétrique |
| DNS Amplification | Amplification par serveurs DNS | Analyse de trafic DNS |
| Scan de ports | Tentatives de découverte de services | Détection de connexions multiples |
| Fragmentation | Attaques par fragmentation de paquets | Analyse de fragments |
| Comportements anormaux | Toute déviation des modèles normaux | Analyses statistiques |

## 🏗️ Architecture

Le système est structuré en modules spécialisés:

```
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
```

## 🚀 Installation

### Prérequis

- Système Linux (testé sur Ubuntu 20.04+, Debian 11+, CentOS 8+)
- Rust 1.56+ (pour compilation)
- libpcap-dev
- build-essential

### Installation automatique

```bash
# Cloner le dépôt
git clone https://github.com/ceketrumdev/Zdefender.git
cd zdefender

# Installer le service (requiert les droits d'administrateur)
sudo ./install.sh

# Vérifier le statut du service
sudo systemctl status zdefender
```

### Installation manuelle

```bash
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
```

## ⚙️ Configuration

Le fichier de configuration se trouve à `/etc/zdefender/config.json` :

```json
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
```

### Options principales

| Option | Description | Valeur par défaut |
|--------|-------------|------------------|
| `interfaces` | Interfaces réseau à surveiller | `["eth0"]` |
| `packet_threshold` | Seuil de paquets par seconde | `1000` |
| `check_interval` | Intervalle de vérification (secondes) | `5` |
| `block_duration` | Durée de blocage (secondes) | `300` |
| `log_mode` | Mode de journalisation (`File` ou `SystemdJournal`) | `File` |
| `fortress_mode` | Mode forteresse activé | `false` |
| `whitelist` | IPs à ne jamais bloquer | `["127.0.0.1", "::1"]` |

## 📝 Journalisation

ZDefender supporte deux modes de journalisation:

- **📄 Fichier**: Logs écrits dans un fichier classique (`/var/log/zdefender/zdefender.log` par défaut)
- **📊 SystemdJournal**: Logs envoyés à systemd-journal (nécessite la feature `systemd`)

### Activer le support SystemdJournal

```bash
# Compiler avec la feature systemd
cargo build --release --features systemd

# Activer dans la configuration
sudo sed -i 's/"log_mode": "File"/"log_mode": "SystemdJournal"/' /etc/zdefender/config.json
```

## 🖥️ Utilisation

### Interface CLI

```bash
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
```

### Bibliothèque

Intégrez ZDefender dans vos applications Rust:

```rust
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
```

## 📊 Comparer avec d'autres solutions

| Fonctionnalité | ZDefender | Fail2Ban | Cloudflare | NFTables |
|----------------|-----------|----------|------------|---------|
| Détection temps réel | ✅ | ⚠️ (basé sur logs) | ✅ | ❌ |
| Mode forteresse | ✅ | ❌ | ✅ | ⚠️ (manuel) |
| Limitation de débit | ✅ | ❌ | ✅ | ✅ |
| Inspection de paquets | ✅ | ❌ | ✅ | ❌ |
| Auto-adaptation | ✅ | ❌ | ✅ | ❌ |
| Open Source | ✅ | ✅ | ❌ | ✅ |
| Facilité d'installation | ✅ | ✅ | ❌ (service externe) | ✅ |

## 📄 Licence

Ce projet est sous licence [MIT](LICENSE). Voir le fichier LICENSE pour plus de détails. 
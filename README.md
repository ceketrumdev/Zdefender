# ZDefender 🛡️

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1.3-blue.svg)]()

**ZDefender** est un système avancé de protection contre les attaques DDoS pour les applications Linux. Il fournit une solution complète pour détecter et atténuer les menaces réseau en temps réel.

<p align="center">
  <img src="https://github.com/ceketrumdev/Zdefender/blob/master/Zdefenderlogo.png" alt="ZDefender Logo" width="1024" height="343" />
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
- **🏰 Mode forteresse amélioré**: Protection renforcée avec whitelist automatique pour les connexions établies
- **🚫 Blocage intelligent**: Durée de blocage adaptée selon la gravité de l'attaque
- **⚖️ Limitation de débit**: Régulation du flux pour les comportements suspects
- **📊 Statistiques en temps réel**: Visualisation des métriques de sécurité et connexions établies
- **💯 Système de confiance des IPs**: Score calculé en fonction du comportement, région et historique
- **📝 Journalisation flexible**: Support des fichiers de logs classiques et systemd-journal
- **⚙️ Configuration facile**: Options configurables via fichier JSON
- **🔄 Mode passif/actif**: Fonctionnement en mode détection seule ou avec mitigation active
- **🔒 Sécurisation automatique**: Commande pour verrouiller rapidement le serveur en cas d'urgence

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
│   ├── analyzer.rs     # Analyse du trafic et détection des attaques
│   ├── packet_inspection.rs  # Inspection profonde des paquets
│   ├── detect_attacks.rs     # Algorithmes de détection
│   ├── defender.rs     # Actions de défense et gestion des connexions établies
│   ├── service.rs      # Gestion du service et statistiques en temps réel
│   └── main.rs         # Point d'entrée et CLI
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
# Compiler le projet (sans support systemd)
cargo build --release

# Compiler avec support systemd-journal
cargo build --release --features systemd

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
  "whitelist": ["127.0.0.1", "::1"],
  "realtime_stats": false,
  "display_realtime_stats": false,
  "allowed_ports": [22, 80, 443],
  "trust_threshold": 0.7,
  "region_trust_scores": {},
  "auto_block_threshold": 0.2,
  "auto_whitelist_threshold": 0.9,
  "connection_time_for_trust": 300,
  "essential_ports": [22, 80, 443]
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
| `allowed_ports` | Ports autorisés lors de la sécurisation | `[22, 80, 443]` |
| `trust_threshold` | Seuil de confiance pour considérer une IP fiable | `0.7` |
| `region_trust_scores` | Scores de confiance par région | `{}` |
| `auto_block_threshold` | Seuil de confiance pour blocage automatique | `0.2` |
| `auto_whitelist_threshold` | Seuil de confiance pour mise en liste blanche auto | `0.9` |
| `connection_time_for_trust` | Durée de connexion (sec) pour être fiable | `300` |

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

# Afficher les statistiques en temps réel (Ctrl+C pour quitter)
zdefender stats

# Afficher un rapport statique des statistiques de base
zdefender check

# Afficher les statistiques détaillées avec scores de confiance
zdefender detailed-stats

# Consulter les informations sur une IP spécifique
zdefender ip-info 192.168.1.10

# Activer le mode forteresse
zdefender fortress --enable

# Désactiver le mode forteresse
zdefender fortress --disable

# Sécuriser rapidement le serveur
zdefender secure

# Sécuriser le serveur en spécifiant les ports à laisser ouverts
zdefender secure --ports=22,80,443,3306

# Configurer le score de confiance pour une région
zdefender configure-region FR 0.8

# Recharger la configuration
zdefender reload

# Afficher les logs
zdefender logs

# Afficher les N dernières lignes de logs
zdefender logs --lines=50

# Afficher uniquement les logs d'erreur
zdefender logs --level=error

# Combiner les options
zdefender logs --lines=30 --level=warn

# Configurer les paramètres de mise à jour
zdefender update-settings --enable          # Activer les mises à jour automatiques
zdefender update-settings --disable         # Désactiver les mises à jour automatiques
zdefender update-settings --channel=beta    # Configurer le canal des mises à jour (stable, beta, dev)
zdefender update-settings --interval=48     # Configurer l'intervalle de vérification (en heures)
zdefender update-settings --check-now       # Forcer une vérification immédiate des mises à jour
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

    // Définir un score de confiance régional
    protection.set_region_trust("FR", 0.8).await;

    // Traiter un paquet
    if let Some(action) = protection.process_packet(packet) {
        match action {
            Action::Drop => println!("Paquet supprimé"),
            Action::Block(ip, duration) => println!("IP {} bloquée pour {:?}", ip, duration),
            Action::RateLimit(ip) => println!("Limitation de débit pour l'IP {}", ip),
            _ => {}
        }
    }
    
    // Activer le mode forteresse
    protection.enable_fortress_mode().await;
    
    // Consulter les statistiques de sécurité
    let stats = protection.get_security_stats().await;
    println!("Score de sécurité: {}", stats.average_security_score);
}
```

## 🔄 Comparer avec d'autres solutions

| Fonctionnalité | ZDefender | Fail2Ban | Crowdsec |
|----------------|-----------|----------|----------|
| Détection en temps réel | ✅ | ❌ | ✅ |
| Analyse comportementale | ✅ | ❌ | ✅ |
| Sécurisation automatique | ✅ | ✅ | ✅ |
| Mode forteresse | ✅ | ❌ | ❌ |
| Statistiques en temps réel | ✅ | ❌ | ✅ |
| Système de confiance | ✅ | ❌ | ✅ |
| Écrit en Rust | ✅ | ❌ | ❌ |
| Peut être utilisé comme lib | ✅ | ❌ | ✅ |
| Analyses personnalisées | ✅ | ✅ | ✅ |
| Protection DDoS | ✅ | ❌ | ✅ |

## 📜 Licence

Ce projet est sous licence MIT - voir le fichier LICENSE pour plus de détails. 
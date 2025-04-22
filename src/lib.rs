//! Bibliothèque Zdefender pour la protection contre les attaques réseau
//!
//! Cette bibliothèque fournit des outils pour détecter et bloquer les attaques réseau
//! comme les DDoS, SYN floods, et autres attaques courantes.
//!
//! Elle offre une protection en temps réel, un mode forteresse renforcé,
//! et des mécanismes d'analyse de trafic adaptative.

// Modules principaux
pub mod models;     // Structures de données et modèles
pub mod config;     // Configuration du système
pub mod logger;     // Journalisation des événements
pub mod defender;   // Système de défense principale
pub mod protection; // Mécanismes de protection
pub mod analyzer;   // Analyse de paquets et détection d'attaques

// Modules d'analyse et de détection
pub mod packet_inspection;     // Inspection des paquets
pub mod intelligent_detection; // Détection basée sur l'apprentissage
pub mod detect_attacks;        // Fonctions de détection d'attaques
pub mod log_mode;              // Modes de journalisation

// Modules utilitaires et services
pub mod services;  // Services divers (captures réseau, etc.)
pub mod benchmark; // Outils de benchmark et tests de performance

// Si cette bibliothèque est utilisée comme exécutable, utiliser les modules appropriés pour démarrer
#[cfg(feature = "binary")]
pub mod cli; // Interface en ligne de commande

// Re-export des structures principales pour faciliter l'utilisation
pub use models::{PacketInfo, Report, ReportType, Action, IpStats, BlockedIp, GlobalStats};
pub use protection::ProtectionManager;
pub use log_mode::LogMode;
pub use services::ZdefenderService;
pub use benchmark::{ZDefenderBenchmark, BenchmarkResults}; 
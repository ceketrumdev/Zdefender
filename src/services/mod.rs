#![allow(dead_code)]
mod command_handler;
mod network_capture;
mod security;
pub mod stats;
mod utils;

// Exports
pub use network_capture::*;
pub use crate::analyzer::AnalyzerInterface;

use crate::analyzer::Analyzer;
use async_trait::async_trait;
use crate::config::{Config, ServiceState};
use crate::defender::Defender;
use crate::logger::Logger;
use crate::models::{PacketInfo, Report, SecurityStats};
use log::{error, info};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use futures::executor;

pub struct ZdefenderService {
    config: Arc<RwLock<Config>>,
    logger: Arc<Logger>,
    analyzer: Option<Arc<Analyzer>>,
    defender: Option<Arc<RwLock<Defender>>>,
    packet_tx: Option<mpsc::Sender<PacketInfo>>,
    report_tx: Option<mpsc::Sender<Report>>,
    tasks: Vec<JoinHandle<()>>,
    running: bool,
    security_stats: Arc<RwLock<SecurityStats>>,
    realtime_stats_enabled: bool,
}

impl ZdefenderService {
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        // Récupérer les paramètres de configuration pour le logger
        let log_config = executor::block_on(async {
            let config_guard = config.read().await;
            (config_guard.log_file.clone(), config_guard.log_mode)
        });
        
        Self {
            config,
            logger: Arc::new(Logger::new_with_mode(log_config.0, log_config.1)),
            analyzer: None,
            defender: None,
            packet_tx: None,
            report_tx: None,
            tasks: Vec::new(),
            running: false,
            security_stats: Arc::new(RwLock::new(SecurityStats::new())),
            realtime_stats_enabled: false,
        }
    }

    pub async fn start_active(&self) {
        self.start(true).await;
    }

    pub async fn start_passive(&self) {
        self.start(false).await;
    }

    async fn start(&self, active: bool) {
        // Vérifier si le service est déjà en cours d'exécution
        if self.running {
            info!("Le service est déjà en cours d'exécution");
            return;
        }

        // Mise à jour de la configuration
        {
            let mut config = self.config.write().await;
            config.service_state = if active {
                ServiceState::Active
            } else {
                ServiceState::Passive
            };
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
            }
        }

        // Récupérer les valeurs de configuration
        let (packet_queue_size, report_queue_size, analyzer_threads, parallel_processing) = {
            let config = self.config.read().await;
            (
                config.packet_queue_size,
                config.report_queue_size,
                config.analyzer_threads,
                config.parallel_processing,
            )
        };

        // Initialiser les canaux de communication avec des tailles de files d'attente plus grandes
        let (packet_tx, mut packet_rx) = mpsc::channel::<PacketInfo>(packet_queue_size);
        let (report_tx, mut report_rx) = mpsc::channel::<Report>(report_queue_size);

        // Créer l'analyseur
        let analyzer = Arc::new(Analyzer::new(self.config.clone(), report_tx.clone()));

        // Créer le défenseur si en mode actif
        let defender = if active {
            Some(Arc::new(RwLock::new(Defender::new(
                self.config.clone(),
                self.logger.clone(),
            ).await)))
        } else {
            None
        };

        // Démarrer des travailleurs multiples pour analyser les paquets
        info!("Démarrage de {} threads d'analyse de paquets", analyzer_threads);
        let mut packet_tasks = Vec::new();
        
        if parallel_processing {
            // Mode multithread: créer plusieurs workers avec plusieurs canaux
            // Créer un channel broadcast pour distribuer les paquets
            let (packet_broadcast_tx, _) = tokio::sync::broadcast::channel(packet_queue_size);
            let packet_broadcast_tx = Arc::new(packet_broadcast_tx);
            
            // Tâche pour transférer les paquets du mpsc au broadcast
            let packet_broadcast_tx_clone = packet_broadcast_tx.clone();
            tokio::spawn(async move {
                while let Some(packet) = packet_rx.recv().await {
                    // On ignore les erreurs de send (pas de récepteurs)
                    let _ = packet_broadcast_tx_clone.send(packet);
                }
            });
            
            // Créer plusieurs workers pour traiter les paquets
            for _ in 0..analyzer_threads {
                let analyzer_clone = analyzer.clone();
                let mut packet_rx = packet_broadcast_tx.subscribe();
                
                let task = tokio::spawn(async move {
                    while let Ok(packet) = packet_rx.recv().await {
                        analyzer_clone.analyze_packet(packet).await;
                    }
                });
                
                packet_tasks.push(task);
            }
        } else {
            // Mode single-thread: utiliser un seul worker
            let analyzer_clone = analyzer.clone();
            let task = tokio::spawn(async move {
                while let Some(packet) = packet_rx.recv().await {
                    analyzer_clone.analyze_packet(packet).await;
                }
            });
            packet_tasks.push(task);
        }

        // Démarrer la tâche de traitement des rapports si en mode actif
        let _report_tasks = if active {
            let defender_clone = defender.clone().unwrap();
            
            // Créer plusieurs travailleurs pour le traitement des rapports
            let mut tasks = Vec::new();
            if parallel_processing {
                // Créer un canal broadcast pour les rapports
                let (report_broadcast_tx, _) = tokio::sync::broadcast::channel(report_queue_size);
                let report_broadcast_tx = Arc::new(report_broadcast_tx);
                
                // Tâche pour transférer les rapports du mpsc au broadcast
                let report_broadcast_tx_clone = report_broadcast_tx.clone();
                tokio::spawn(async move {
                    while let Some(report) = report_rx.recv().await {
                        // On ignore les erreurs de send (pas de récepteurs)
                        let _ = report_broadcast_tx_clone.send(report);
                    }
                });
                
                // Créer plusieurs workers pour traiter les rapports
                for _ in 0..analyzer_threads.min(4) { // Limiter à 4 threads max pour les rapports
                    let defender_clone = defender_clone.clone();
                    let mut report_rx = report_broadcast_tx.subscribe();
                    
                    let task = tokio::spawn(async move {
                        while let Ok(report) = report_rx.recv().await {
                            let mut defender = defender_clone.write().await;
                            defender.handle_report(report).await;
                        }
                    });
                    
                    tasks.push(task);
                }
            } else {
                let task = tokio::spawn(async move {
                    while let Some(report) = report_rx.recv().await {
                        let mut defender = defender_clone.write().await;
                        defender.handle_report(report).await;
                    }
                });
                tasks.push(task);
            }
            
            Some(tasks)
        } else {
            None
        };

        // Démarrer la tâche de nettoyage périodique
        let analyzer_clone = analyzer.clone();
        let _cleanup_task = tokio::spawn(async move {
            let interval = Duration::from_secs(60); // Nettoyer toutes les minutes
            loop {
                tokio::time::sleep(interval).await;
                analyzer_clone.clear_expired_blocks().await;
            }
        });
        
        // Tâche périodique pour la détection des attaques (optimisé)
        let analyzer_clone = analyzer.clone();
        let config_clone = self.config.clone();
        let _attack_detection_task = tokio::spawn(async move {
            let mut interval = {
                let config = config_clone.read().await;
                Duration::from_secs(config.check_interval)
            };
            
            loop {
                tokio::time::sleep(interval).await;
                
                let start = std::time::Instant::now();
                analyzer_clone.periodic_attack_detection().await;
                let duration = start.elapsed();
                
                // Ajuster dynamiquement l'intervalle en fonction de la charge
                // Si l'analyse prend beaucoup de temps, on augmente l'intervalle
                if duration > Duration::from_millis(500) {
                    interval = std::cmp::max(
                        interval,
                        Duration::from_secs(
                            (config_clone.read().await.check_interval).saturating_add(1)
                        )
                    );
                }
            }
        });

        // Démarrer la capture de paquets pour chaque interface
        start_packet_capture(
            self.config.clone(),
            packet_tx.clone(),
            self.logger.clone()
        ).await;

        // Lancer le thread des statistiques en temps réel
        self.start_stats_thread(
            analyzer.clone(),
            defender.clone()
        );

        info!("Service {} démarré avec {} threads d'analyse", 
            if active { "actif" } else { "passif" },
            analyzer_threads
        );
    }

    pub async fn stop(&self) {
        // Mise à jour de la configuration
        {
            let mut config = self.config.write().await;
            config.service_state = ServiceState::Stopped;
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
            }
        }

        // Ici, nous devrions annuler toutes les tâches en cours, mais cela nécessiterait
        // une conception différente avec des signaux d'arrêt ou des drapeaux d'annulation
        
        info!("Service arrêté");
    }

    pub async fn reload_config(&self) {
        info!("Rechargement de la configuration...");
        
        // Charger la nouvelle configuration depuis le fichier
        match Config::load() {
            Ok(new_config) => {
                let mut config = self.config.write().await;
                *config = new_config;
                info!("Configuration rechargée avec succès");
                
                // Afficher un résumé des paramètres importants
                let state = match config.service_state {
                    ServiceState::Active => "Actif",
                    ServiceState::Passive => "Passif",
                    ServiceState::Stopped => "Arrêté",
                };
                
                let fortress_mode = if config.fortress_mode {
                    "Activé"
                } else {
                    "Désactivé"
                };
                
                info!("État actuel: {}", state);
                info!("Mode forteresse: {}", fortress_mode);
                info!("Interfaces surveillées: {}", config.interfaces.join(", "));
                info!("Seuil de paquets: {} paquets/sec", config.packet_threshold);
            },
            Err(e) => {
                error!("Erreur lors du rechargement de la configuration: {}", e);
            }
        }
    }

    /// Lit les logs depuis le fichier de log
    pub async fn read_logs(&self, lines: Option<usize>, level: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
        let config = self.config.read().await;
        
        // Si le mode de journalisation est systdm-journal, on informe l'utilisateur d'utiliser journalctl
        if config.log_mode == crate::log_mode::LogMode::SystemdJournal {
            return Ok("Le mode de journalisation est systemd-journal. Utilisez 'journalctl -u zdefender' pour voir les logs.".to_string());
        }
        
        // Si le mode est File, on lit le fichier de log
        let log_path = &config.log_file;
        
        // Vérifier si le fichier existe
        if !std::path::Path::new(log_path).exists() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Fichier de log non trouvé: {}", log_path),
            )));
        }
        
        // Lire le contenu du fichier
        let content = match std::fs::read_to_string(log_path) {
            Ok(content) => content,
            Err(e) => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Erreur lors de la lecture du fichier de log: {}", e),
                )));
            }
        };
        
        // Filtrer les lignes par niveau si demandé
        let filtered_lines: Vec<&str> = if let Some(log_level) = level {
            let level_upper = log_level.to_uppercase();
            content.lines()
                .filter(|line| line.contains(&format!("[{}]", level_upper)))
                .collect()
        } else {
            content.lines().collect()
        };
        
        // Si un nombre de lignes est spécifié, prendre les dernières lignes
        let result = if let Some(n) = lines {
            if filtered_lines.len() > n {
                filtered_lines.iter()
                    .skip(filtered_lines.len() - n)
                    .cloned()
                    .collect::<Vec<&str>>()
                    .join("\n")
            } else {
                filtered_lines.join("\n")
            }
        } else {
            filtered_lines.join("\n")
        };
        
        Ok(result)
    }
} 
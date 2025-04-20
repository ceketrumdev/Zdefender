mod analyzer;
mod defender;
mod logger;
mod config;
mod models;
mod service;
mod cli;
mod intelligent_detection;
mod packet_inspection;
mod protection;
mod log_mode;

use clap::Parser;
use cli::{Cli, Mode};
use config::Config;
use log::{info, warn, error};
use std::sync::Arc;
use std::process::{exit, Command as ProcessCommand};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use service::ZdefenderService;
use crate::models::{PacketInfo, Report, ReportType, Action, PacketType};
use crate::protection::ProtectionManager;
use crate::log_mode::LogMode;
use tokio::sync::{mpsc};
use tokio::time;
use crate::cli::Command;
// Ne pas utiliser d'instruction `use` en dehors du bloc cfg
// #[cfg(feature = "systemd")]
// use systemd_journal_logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Charger la configuration pour déterminer le mode de log
    let config = Config::load().unwrap_or_else(|_| Config::default());
    
    // Initialiser le logger approprié
    match config.log_mode {
        LogMode::File => {
            // Initialiser le logger de fichier standard
            env_logger::init_from_env(env_logger::Env::default().default_filter_or(&config.log_level));
        },
        LogMode::SystemdJournal => {
            // Initialiser le logger systemd-journal uniquement si la feature est activée
            #[cfg(feature = "systemd")]
            {
                // Import inline dans le bloc où il est utilisé
                use systemd_journal_logger::JournalLog;
                
                // Convertir le niveau de log de la configuration
                let log_level = match config.log_level.to_lowercase().as_str() {
                    "trace" => log::LevelFilter::Trace,
                    "debug" => log::LevelFilter::Debug,
                    "info" => log::LevelFilter::Info,
                    "warn" => log::LevelFilter::Warn,
                    "error" => log::LevelFilter::Error,
                    _ => log::LevelFilter::Info,
                };
                
                // Initialiser le logger systemd avec le bon niveau
                match JournalLog::new() {
                    Ok(logger) => {
                        if let Err(e) = logger
                            .with_syslog_identifier("zdefender".to_string())
                            .install() {
                            eprintln!("Erreur lors de l'installation du logger systemd: {}", e);
                            env_logger::init_from_env(env_logger::Env::default().default_filter_or(&config.log_level));
                        } else {
                            log::set_max_level(log_level);
                            info!("Logger systemd initialisé avec niveau: {}", config.log_level);
                        }
                    },
                    Err(e) => {
                        eprintln!("Erreur lors de l'initialisation du logger systemd: {}", e);
                        env_logger::init_from_env(env_logger::Env::default().default_filter_or(&config.log_level));
                    }
                }
            }
            
            // Fallback si la feature systemd n'est pas activée
            #[cfg(not(feature = "systemd"))]
            {
                eprintln!("AVERTISSEMENT: Le mode SystemdJournal n'est pas disponible (feature 'systemd' non activée). Utilisation du logger standard à la place.");
                env_logger::init_from_env(env_logger::Env::default().default_filter_or(&config.log_level));
            }
        }
    }
    
    // Analyser les arguments de ligne de commande
    let cli = Cli::parse();
    
    // Recharger la configuration dans un Arc<RwLock>
    let config = Arc::new(RwLock::new(config));
    
    // Traiter l'option de mode globale si présente
    if let Some(mode) = cli.mode {
        handle_mode_change(mode).await;
        return Ok(());
    }

    // Créer le service
    let service = ZdefenderService::new(config.clone());
    
    // Exécuter la commande
    match cli.command {
        Command::Start { daemon } => {
            if daemon {
                launch_daemon();
                Ok(())
            } else {
                // En mode interactif, démarrer le service en mode actif
                service.start_active().await;
                
                // Canaux pour les rapports
                let (report_tx, mut report_rx) = mpsc::channel::<Report>(100);
                
                // Initialiser le gestionnaire de protection
                let mut protection_manager = ProtectionManager::new(
                    Arc::clone(&config),
                    report_tx.clone(),
                ).await;
                
                // Démarrer la tâche de traitement des rapports
                tokio::spawn(async move {
                    while let Some(report) = report_rx.recv().await {
                        process_report(&report).await;
                    }
                });
                
                // Boucle principale de traitement des paquets
                let mut interval = time::interval(Duration::from_millis(100));
                loop {
                    interval.tick().await;
                    
                    // Dans un système réel, nous recevrions des paquets d'une interface réseau
                    // Pour cet exemple, nous simulons un paquet
                    if let Some(packet) = simulate_packet().await {
                        // Analyser le paquet
                        match protection_manager.analyze_packet(&packet).await {
                            Some(Action::Drop) => {
                                // Le paquet est simplement supprimé
                                info!("Paquet de {} supprimé (IP bloquée)", packet.source_ip);
                            },
                            Some(Action::Block(ip, duration)) => {
                                // Bloquer l'IP
                                warn!("Blocage de l'IP {} pour {} secondes", ip, duration.as_secs());
                                protection_manager.block_ip(ip, duration).await;
                            },
                            Some(Action::RateLimit(ip)) => {
                                // Limitation du débit
                                info!("Limitation du débit pour l'IP {}", ip);
                                // Implémentation de la limitation de débit...
                            },
                            None => {
                                // Paquet autorisé
                                // Traitement normal du paquet...
                            }
                            _ => {}
                        }
                    }
                }
            }
        },
        Command::Stop => {
            service.stop().await;
            Ok(())
        },
        Command::Status => {
            service.status().await;
            Ok(())
        },
        Command::Fortress { enable, disable } => {
            if disable {
                service.disable_fortress().await;
            } else if enable {
                service.enable_fortress().await;
            } else {
                service.disable_fortress().await;
            }
            Ok(())
        },
        Command::Stats => {
            service.show_stats().await;
            Ok(())
        },
        Command::Reload => {
            service.reload_config().await;
            Ok(())
        },
    }
    
    // Retour implicite de Ok(())
}

/// Traite un rapport reçu
async fn process_report(report: &Report) {
    match report.report_type {
        ReportType::Attack => {
            warn!("ALERTE ATTAQUE: {}", report.message);
            // Actions supplémentaires pour une attaque...
        },
        ReportType::Action => {
            info!("ACTION: {}", report.message);
            // Enregistrement de l'action...
        },
        ReportType::Info => {
            info!("INFO: {}", report.message);
        },
        _ => {}
    }
    
    // On pourrait envoyer ces rapports à un système externe de journalisation ou d'alerte
}

/// Traite un rapport de manière synchrone (renommé avec _ puisque non utilisé)
fn _process_report_sync(report: &Report) {
    match report.report_type {
        ReportType::Attack => {
            warn!("ALERTE ATTAQUE: {}", report.message);
            // Actions supplémentaires pour une attaque...
        },
        ReportType::Action => {
            info!("ACTION: {}", report.message);
            // Enregistrement de l'action...
        },
        ReportType::Info => {
            info!("INFO: {}", report.message);
        },
        _ => {}
    }
    
    // On pourrait envoyer ces rapports à un système externe de journalisation ou d'alerte
}

/// Simule la réception d'un paquet réseau
/// Dans un système réel, cette fonction serait remplacée par une vraie capture de paquets
async fn simulate_packet() -> Option<PacketInfo> {
    // Pour simplifier cet exemple, nous générons un paquet simulé aléatoirement
    use rand::Rng;
    use std::net::{Ipv4Addr, IpAddr};
    
    let mut rng = rand::rng();
    
    // Simuler différents types de paquets avec différentes probabilités
    let packet_type = match rng.random_range(0..100) {
        0..=70 => PacketType::Tcp,
        71..=85 => PacketType::Udp,
        _ => PacketType::Icmp,
    };
    
    // Générer une IP source aléatoire
    let source_ip = IpAddr::V4(Ipv4Addr::new(
        rng.random_range(1..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(1..255),
    ));
    
    // Générer des ports aléatoires
    let source_port = match packet_type {
        PacketType::Tcp | PacketType::Udp => Some(rng.random_range(1024..65535)),
        _ => None
    };
    
    let dest_port = match packet_type {
        PacketType::Tcp | PacketType::Udp => Some(rng.random_range(1..65535)),
        _ => None
    };
    
    // Créer le paquet
    Some(PacketInfo {
        timestamp: SystemTime::now(),
        source_ip,
        dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // IP de destination fixe pour l'exemple
        source_port,
        dest_port,
        protocol: packet_type,
        size: rng.random_range(40..1500),
        flags: if packet_type == PacketType::Tcp {
            Some(vec!["ACK".to_string(), "SYN".to_string()])
        } else {
            None
        },
        ttl: Some(rng.random_range(32..128)),
    })
}

// Fonction pour changer le mode de fonctionnement
async fn handle_mode_change(mode: Mode) {
    let mut config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            error!("Erreur lors du chargement de la configuration: {}", e);
            exit(1);
        }
    };
    
    match mode {
        Mode::Active => {
            info!("Changement vers le mode actif");
            config.service_state = config::ServiceState::Active;
        },
        Mode::Passive => {
            info!("Changement vers le mode passif");
            config.service_state = config::ServiceState::Passive;
        },
    }
    
    if let Err(e) = config.save() {
        error!("Erreur lors de la sauvegarde de la configuration: {}", e);
        exit(1);
    }
    
    info!("Mode changé avec succès. Redémarrez le service pour appliquer les changements.");
}

// Fonction pour lancer le service en arrière-plan
fn launch_daemon() {
    let args = std::env::args().collect::<Vec<String>>();
    let executable = &args[0];
    
    let status = ProcessCommand::new(executable)
        .args(&["start"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    
    match status {
        Ok(_) => {
            info!("ZDefender démarré en arrière-plan");
            
            // Attendre un court instant pour que le processus enfant démarre
            std::thread::sleep(Duration::from_millis(500));
            
            // Quitter immédiatement le processus parent
            std::process::exit(0);
        },
        Err(e) => {
            error!("Erreur lors du démarrage en arrière-plan: {}", e);
            std::process::exit(1);
        }
    }
}

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
use zdefender::config::Config;
use log::{info, warn, error};
use std::sync::Arc;
use std::process::{exit, Command as ProcessCommand};
use std::time::{Duration, SystemTime, Instant};
use tokio::sync::RwLock;
use zdefender::services::ZdefenderService;
use crate::models::{PacketInfo, Report, ReportType, Action, PacketType};
use tokio::sync::{mpsc};
use tokio::time;
use crate::cli::Command;
use anyhow::Result;
// Ne pas utiliser d'instruction `use` en dehors du bloc cfg
// #[cfg(feature = "systemd")]
// use systemd_journal_logger;

#[tokio::main]
async fn main() -> Result<()> {
    // Charger la configuration pour déterminer le mode de log
    let config = Config::load().unwrap_or_else(|_| Config::default());
    
    // Initialiser le logger approprié
    match config.log_mode {
        zdefender::LogMode::File => {
            // Initialiser le logger de fichier standard
            env_logger::init_from_env(env_logger::Env::default().default_filter_or(&config.log_level));
        },
        zdefender::LogMode::SystemdJournal => {
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
        handle_mode_change(mode).await?;
        return Ok(());
    }

    // Créer le service
    let config_arc = Arc::clone(&config);
    let mut service = ZdefenderService::new(config_arc);
    
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
                
                // Initialiser le gestionnaire de protection avec la fonction de création
                let protection_manager_arc = protection::create_protection_manager(report_tx.clone());
                
                // Démarrer la tâche de traitement des rapports
                tokio::spawn(async move {
                    while let Some(report) = report_rx.recv().await {
                        process_report(report).await;
                    }
                });
                
                // Boucle principale de traitement des paquets
                let mut interval = time::interval(Duration::from_millis(100));
                loop {
                    interval.tick().await;
                    
                    // Dans un système réel, nous recevrions des paquets d'une interface réseau
                    // Pour cet exemple, nous simulons un paquet
                    if let Some(packet) = simulate_packet() {
                        // Analyser le paquet
                        let mut protection_manager = protection_manager_arc.write().await;
                        match protection_manager.process_packet(packet.clone()).await {
                            Some(Action::Drop) => {
                                // Le paquet est simplement supprimé
                                info!("Paquet de {} supprimé (IP bloquée)", packet.source_ip);
                            },
                            Some(Action::Block(ip, duration)) => {
                                // Bloquer l'IP est déjà géré dans process_packet
                                warn!("Blocage de l'IP {} pour {} secondes", ip, duration.as_secs());
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
        Command::Check => {
            service.show_stats().await;
            Ok(())
        },
        Command::Stats => {
            // Affichage direct des statistiques en temps réel (jusqu'à Ctrl+C)
            match service.toggle_realtime_stats(true).await {
                Ok(_) => {
                    println!("Affichage des statistiques en temps réel. Appuyez sur Ctrl+C pour quitter.");
                    
                    // Créer une boucle qui attend un signal d'interruption
                    if let Ok(_) = tokio::signal::ctrl_c().await {
                        // Désactiver les statistiques en temps réel avant de quitter
                        match service.toggle_realtime_stats(false).await {
                            Ok(_) => Ok(()),
                            Err(e) => {
                                error!("Erreur lors de la désactivation des statistiques en temps réel: {}", e);
                                Err(anyhow::anyhow!("Erreur lors de la désactivation des statistiques en temps réel: {}", e))
                            }
                        }
                    } else {
                        // En cas d'erreur avec ctrl_c
                        let _ = service.toggle_realtime_stats(false).await;
                        Ok(())
                    }
                },
                Err(e) => {
                    error!("Erreur lors de l'activation des statistiques en temps réel: {}", e);
                    Err(anyhow::anyhow!("Erreur lors de l'activation des statistiques en temps réel: {}", e))
                }
            }
        },
        Command::DetailedStats => {
            let result = service.handle_command("detailed_stats").await;
            match result {
                Ok(message) => {
                    println!("{}", message);
                    Ok(())
                },
                Err(e) => {
                    error!("Erreur lors de l'affichage des statistiques détaillées: {}", e);
                    Err(anyhow::anyhow!("Erreur lors de l'affichage des statistiques détaillées: {}", e))
                }
            }
        },
        Command::Realtime { mode } => {
            let result = match mode {
                cli::RealtimeMode::On => service.handle_command("realtime on").await,
                cli::RealtimeMode::Off => service.handle_command("realtime off").await,
            };
            
            match result {
                Ok(message) => {
                    println!("{}", message);
                    Ok(())
                },
                Err(e) => {
                    error!("Erreur lors de la modification des statistiques en temps réel: {}", e);
                    Err(anyhow::anyhow!("Erreur lors de la modification des statistiques en temps réel: {}", e))
                }
            }
        },
        Command::Secure { ports } => {
            // Construire la commande avec les ports si spécifiés
            let cmd = if let Some(port_list) = ports {
                format!("secure ports={}", port_list)
            } else {
                "secure".to_string()
            };
            
            let result = service.handle_command(&cmd).await;
            match result {
                Ok(message) => {
                    println!("{}", message);
                    Ok(())
                },
                Err(e) => {
                    error!("Erreur lors de la sécurisation du serveur: {}", e);
                    Err(anyhow::anyhow!("Erreur lors de la sécurisation du serveur: {}", e))
                }
            }
        },
        Command::ConfigureRegion { region, score } => {
            let mut config_write = config.write().await;
            
            // Vérifier que le score est dans la plage valide
            let score = score.max(0.0).min(1.0);
            
            // Mettre à jour le score de confiance de la région
            config_write.set_region_trust(&region, score);
            
            // Sauvegarder la configuration
            match config_write.save() {
                Ok(_) => {
                    println!("Score de confiance pour la région {} configuré à {:.2}", region, score);
                    Ok(())
                },
                Err(e) => {
                    error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                    Err(anyhow::anyhow!("Erreur lors de la sauvegarde de la configuration: {}", e))
                }
            }
        },
        Command::IpInfo { ip } => {
            // Vérifier que l'IP est valide
            match ip.parse::<std::net::IpAddr>() {
                Ok(_ip_addr) => {
                    let result = service.handle_command(&format!("ip_info {}", ip)).await;
                    match result {
                        Ok(message) => {
                            println!("{}", message);
                            Ok(())
                        },
                        Err(e) => {
                            error!("Erreur lors de la récupération des informations sur l'IP: {}", e);
                            Err(anyhow::anyhow!("Erreur lors de la récupération des informations sur l'IP: {}", e))
                        }
                    }
                },
                Err(_) => {
                    println!("Adresse IP invalide: {}", ip);
                    Ok(())
                }
            }
        },
        Command::Reload => {
            service.reload_config().await;
            println!("Configuration rechargée avec succès");
            Ok(())
        },
        Command::Logs { lines, level } => {
            if let Some(lines) = lines {
                // Afficher un nombre spécifique de lignes
                match service.read_logs(Some(lines), level).await {
                    Ok(logs) => {
                        println!("{}", logs);
                        Ok(())
                    },
                    Err(e) => {
                        error!("Erreur lors de la lecture des logs: {}", e);
                        Err(anyhow::anyhow!("Erreur lors de la lecture des logs: {}", e))
                    }
                }
            } else {
                // Afficher les logs en continu (à implémenter avec un tail -f)
                match service.read_logs(Some(100), level).await {
                    Ok(logs) => {
                        println!("{}", logs);
                        println!("\nSuivi des logs en temps réel à implémenter...");
                        Ok(())
                    },
                    Err(e) => {
                        error!("Erreur lors de la lecture des logs: {}", e);
                        Err(anyhow::anyhow!("Erreur lors de la lecture des logs: {}", e))
                    }
                }
            }
        },
        Command::Benchmark { packets, normal_ratio, output } => {
            run_benchmark(packets, normal_ratio, output).await
        },
        Command::DDoSProtection { enable, disable, ratio, min_ips, packets_per_second, duration, auto_fortress, no_auto_fortress } => {
            // Charger la configuration actuelle
            let mut config = match Config::load() {
                Ok(config) => config,
                Err(e) => {
                    error!("Erreur lors du chargement de la configuration: {}", e);
                    return Err(anyhow::anyhow!("Erreur lors du chargement de la configuration: {}", e));
                }
            };
            
            // Priorité à disable si les deux options sont spécifiées
            if disable {
                config.ddos_detection_enabled = false;
                info!("Détection des attaques DDoS distribuées désactivée");
            } else if enable {
                config.ddos_detection_enabled = true;
                info!("Détection des attaques DDoS distribuées activée");
            }
            
            // Priorité à no_auto_fortress si les deux options sont spécifiées
            if no_auto_fortress {
                config.ddos_auto_fortress = false;
                info!("Mode forteresse automatique désactivé");
            } else if auto_fortress {
                config.ddos_auto_fortress = true;
                info!("Mode forteresse automatique activé");
            }
            
            // Mettre à jour les seuils si spécifiés
            if let Some(r) = ratio {
                config.ddos_ratio_threshold = r;
                info!("Seuil de ratio paquets/IPs configuré à {}", r);
            }
            
            if let Some(ips) = min_ips {
                config.ddos_min_ips_threshold = ips;
                info!("Nombre minimum d'IPs distinctes configuré à {}", ips);
            }
            
            if let Some(pps) = packets_per_second {
                config.ddos_pps_threshold = pps;
                info!("Seuil de paquets par seconde configuré à {}", pps);
            }
            
            if let Some(d) = duration {
                config.ddos_protection_duration = d;
                info!("Durée de protection configurée à {} secondes", d);
            }
            
            // Sauvegarder la configuration mise à jour
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                return Err(anyhow::anyhow!("Erreur lors de la sauvegarde de la configuration: {}", e));
            }
            
            println!("Configuration de la protection DDoS mise à jour avec succès");
            println!("Détection: {}", if config.ddos_detection_enabled { "Activée" } else { "Désactivée" });
            println!("Mode forteresse auto: {}", if config.ddos_auto_fortress { "Activé" } else { "Désactivé" });
            println!("Seuil de ratio paquets/IPs: {}", config.ddos_ratio_threshold);
            println!("Nombre minimum d'IPs: {}", config.ddos_min_ips_threshold);
            println!("Seuil paquets/seconde: {}", config.ddos_pps_threshold);
            println!("Durée de protection: {} secondes", config.ddos_protection_duration);
            
            // Si le service est en cours d'exécution, recharger la configuration
            println!("Redémarrez le service pour appliquer les changements");
            
            Ok(())
        },
        Command::UpdateSettings { enable, disable, channel, interval, check_now } => {
            // Priorité au flag disable sur enable
            if disable {
                let mut config_write = config.write().await;
                config_write.auto_update = false;
                
                if let Err(e) = config_write.save() {
                    error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                    return Err(anyhow::anyhow!("Erreur lors de la sauvegarde de la configuration: {}", e));
                }
                
                println!("Mises à jour automatiques désactivées");
            } else if enable {
                let mut config_write = config.write().await;
                config_write.auto_update = true;
                
                if let Err(e) = config_write.save() {
                    error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                    return Err(anyhow::anyhow!("Erreur lors de la sauvegarde de la configuration: {}", e));
                }
                
                println!("Mises à jour automatiques activées");
            }
            
            // Traiter les autres options si spécifiées
            if let Some(update_channel) = channel {
                let mut config_write = config.write().await;
                config_write.update_channel = match update_channel {
                    cli::UpdateChannel::Stable => zdefender::config::UpdateChannel::Stable,
                    cli::UpdateChannel::Beta => zdefender::config::UpdateChannel::Beta,
                    cli::UpdateChannel::Dev => zdefender::config::UpdateChannel::Dev,
                };
                
                if let Err(e) = config_write.save() {
                    error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                    return Err(anyhow::anyhow!("Erreur lors de la sauvegarde de la configuration: {}", e));
                }
                
                println!("Canal de mise à jour configuré: {:?}", update_channel);
            }
            
            if let Some(check_interval) = interval {
                let mut config_write = config.write().await;
                config_write.update_check_interval = check_interval;
                
                if let Err(e) = config_write.save() {
                    error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                    return Err(anyhow::anyhow!("Erreur lors de la sauvegarde de la configuration: {}", e));
                }
                
                println!("Intervalle de vérification des mises à jour configuré: {} heures", check_interval);
            }
            
            // Vérifier les mises à jour maintenant si demandé
            if check_now {
                println!("Vérification des mises à jour...");
                println!("Fonctionnalité non disponible dans cette version.");
                
                // Mettre à jour la date de dernière vérification
                let mut config_write = config.write().await;
                let now = chrono::Local::now();
                config_write.last_update_check = Some(now.to_rfc3339());
                
                if let Err(e) = config_write.save() {
                    error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                    return Err(anyhow::anyhow!("Erreur lors de la sauvegarde de la configuration: {}", e));
                }
            }
            
            // Afficher l'état actuel des paramètres de mise à jour
            let config_read = config.read().await;
            println!("\nParamètres de mise à jour actuels:");
            println!("  Mises à jour automatiques: {}", if config_read.auto_update { "Activées" } else { "Désactivées" });
            println!("  Canal de mise à jour: {:?}", config_read.update_channel);
            println!("  Intervalle de vérification: {} heures", config_read.update_check_interval);
            match &config_read.last_update_check {
                Some(last_check) => println!("  Dernière vérification: {}", last_check),
                None => println!("  Dernière vérification: Jamais"),
            }
            
            Ok(())
        },
    }
    
    // Retour implicite de Ok(())
}

/// Traite un rapport reçu
async fn process_report(report: Report) {
    match report.report_type {
        ReportType::Attack => {
            error!("ALERTE ATTAQUE: {}", report.message);
            // Actions supplémentaires pour une attaque...
        },
        ReportType::Action => {
            info!("ACTION: {}", report.message);
            // Enregistrement de l'action...
        },
        ReportType::Info => {
            info!("INFO: {}", report.message);
        },
        ReportType::Alert => {
            error!("ALERTE: {}", report.message);
        },
        ReportType::Warning => {
            warn!("AVERTISSEMENT: {}", report.message);
        }
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
        ReportType::Alert => {
            error!("ALERTE: {}", report.message);
        },
        ReportType::Warning => {
            warn!("AVERTISSEMENT: {}", report.message);
        }
    }
    
    // On pourrait envoyer ces rapports à un système externe de journalisation ou d'alerte
}

/// Simule la réception d'un paquet réseau
/// Dans un système réel, cette fonction serait remplacée par une vraie capture de paquets
fn simulate_packet() -> Option<PacketInfo> {
    // Pour simplifier cet exemple, nous générons un paquet simulé aléatoirement
    use rand::Rng;
    use std::net::{Ipv4Addr, IpAddr};
    
    let mut rng = rand::thread_rng();
    
    // Simuler différents types de paquets avec différentes probabilités
    let packet_type = match rng.gen_range(0..100) {
        0..=70 => PacketType::Tcp,
        71..=85 => PacketType::Udp,
        _ => PacketType::Icmp,
    };
    
    // Générer une IP source aléatoire
    let source_ip = IpAddr::V4(Ipv4Addr::new(
        rng.gen_range(1..255),
        rng.gen_range(0..255),
        rng.gen_range(0..255),
        rng.gen_range(1..255),
    ));
    
    // Générer des ports aléatoires
    let source_port = match packet_type {
        PacketType::Tcp | PacketType::Udp => Some(rng.gen_range(1024..65535)),
        _ => None
    };
    
    let dest_port = match packet_type {
        PacketType::Tcp | PacketType::Udp => Some(rng.gen_range(1..65535)),
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
        size: rng.gen_range(40..1500),
        flags: if packet_type == PacketType::Tcp {
            Some(vec!["ACK".to_string(), "SYN".to_string()])
        } else {
            None
        },
        ttl: Some(rng.gen_range(32..128)),
    })
}

// Fonction pour changer le mode de fonctionnement
async fn handle_mode_change(mode: Mode) -> Result<()> {
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
            config.service_state = zdefender::config::ServiceState::Active;
        },
        Mode::Passive => {
            info!("Changement vers le mode passif");
            config.service_state = zdefender::config::ServiceState::Passive;
        },
    }
    
    if let Err(e) = config.save() {
        error!("Erreur lors de la sauvegarde de la configuration: {}", e);
        exit(1);
    }
    
    info!("Mode changé avec succès. Redémarrez le service pour appliquer les changements.");
    Ok(())
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

/// Lance un benchmark du système anti-DDoS
async fn run_benchmark(packets: u64, normal_ratio: f64, output: Option<String>) -> Result<()> {
    println!("Démarrage du benchmark ZDefender...");
    
    // Charger la configuration
    let config = Config::load().unwrap_or_else(|_| Config::default());
    let config = Arc::new(RwLock::new(config));
    
    let start = Instant::now();
    
    // Créer et exécuter le benchmark
    let mut benchmark = zdefender::ZDefenderBenchmark::new(
        config.clone(),
        normal_ratio,         // Ratio de trafic normal
        1.0 - normal_ratio,   // Ratio de trafic d'attaque (complémentaire)
        packets,
    ).await;
    
    // Exécuter le benchmark
    let results = benchmark.run().await;
    
    // Afficher les résultats
    benchmark.print_results(&results);
    
    // Sauvegarder les résultats dans un fichier CSV si demandé
    if let Some(file_path) = output {
        if let Err(e) = benchmark.save_results_to_csv(&results, &file_path) {
            eprintln!("Erreur lors de la sauvegarde des résultats dans {}: {}", file_path, e);
        } else {
            println!("Résultats sauvegardés dans {}", file_path);
        }
    }
    
    Ok(())
}

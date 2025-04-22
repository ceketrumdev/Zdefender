#![allow(unused_variables)]
use crate::models::SecurityStats;
use crate::config::Config;
use crate::defender::Defender;
use crate::analyzer::AnalyzerInterface;
use log::{error, info};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use std::io::Write;
use chrono;
use async_trait::async_trait;

use crate::services::ZdefenderService;

impl ZdefenderService {
    /// Démarre le thread des statistiques en temps réel
    pub fn start_stats_thread(
        &self,
        analyzer: Arc<dyn AnalyzerInterface>,
        defender: Option<Arc<RwLock<Defender>>>,
    ) {
        let stats_security = self.security_stats.clone();
        let stats_config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            let mut prev_total_packets = 0;
            let mut prev_time = Instant::now();
            
            loop {
                interval.tick().await;
                
                let config_read = stats_config.read().await;
                if !config_read.realtime_stats {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                
                // Calculer les statistiques en temps réel
                let now = Instant::now();
                let elapsed = now.duration_since(prev_time).as_secs_f64();
                
                // Obtenir les statistiques actuelles
                let total_packets = analyzer.get_total_packets().await;
                let packets_per_sec = ((total_packets - prev_total_packets) as f64 / elapsed) as u64;
                
                // Mettre à jour les statistiques de sécurité
                {
                    let mut security_stats = stats_security.write().await;
                    security_stats.total_packets_analyzed = total_packets;
                    
                    // Mettre à jour le débit
                    let inbound_packets = analyzer.get_inbound_packets().await;
                    let outbound_packets = analyzer.get_outbound_packets().await;
                    
                    if prev_time.elapsed() < Duration::from_secs(2) {
                        security_stats.inbound_bps = inbound_packets;
                        security_stats.outbound_bps = outbound_packets;
                    } else {
                        security_stats.inbound_bps = ((inbound_packets as f64) / elapsed) as u64;
                        security_stats.outbound_bps = ((outbound_packets as f64) / elapsed) as u64;
                    }
                    
                    // Mettre à jour la date de dernière mise à jour
                    security_stats.last_update = SystemTime::now();
                }
                
                // Récupérer les IPs bloquées
                let blocked_ips = analyzer.get_blocked_ips().await;
                let established_conns = if let Some(defender) = &defender {
                    let defender_read = defender.read().await;
                    defender_read.get_established_connections().await
                } else {
                    Vec::new()
                };
                
                // Calculer les scores de confiance moyens
                let mut total_trust = 0.0;
                let mut conn_count = 0;
                
                for conn in &established_conns {
                    total_trust += conn.trust_score;
                    conn_count += 1;
                }
                
                let avg_trust = if conn_count > 0 {
                    total_trust / (conn_count as f64)
                } else {
                    0.0
                };
                
                // Mettre à jour le score de sécurité moyen
                {
                    let mut security_stats = stats_security.write().await;
                    security_stats.average_security_score = avg_trust;
                    
                    // Afficher les statistiques en temps réel si activé
                    if config_read.display_realtime_stats {
                        // Effacer la ligne précédente (compatible avec la plupart des terminaux)
                        print!("\x1B[2J\x1B[1;1H");
                        
                        println!("┌─────────────────────────────────────────────────────┐");
                        println!("│           ZDefender - Statistiques en temps réel    │");
                        println!("├─────────────────────────────────────────────────────┤");
                        println!("│ Score de sécurité global: {:.2}                     │", security_stats.average_security_score);
                        println!("│ Paquets analysés: {} ({}/s)                         │", 
                                security_stats.total_packets_analyzed, packets_per_sec);
                        println!("│ Trafic entrant: {}/s                                │", 
                                security_stats.inbound_bps);
                        println!("│ Trafic sortant: {}/s                                │", 
                                security_stats.outbound_bps);
                        println!("│ Attaques détectées: {}                              │", 
                                security_stats.attacks_detected);
                        println!("│ IPs bloquées: {}                                    │", 
                                blocked_ips.len());
                        println!("│ Connexions établies: {}                             │", 
                                established_conns.len());
                        println!("└─────────────────────────────────────────────────────┘");
                        
                        // Afficher les connexions avec le meilleur score de confiance
                        if !established_conns.is_empty() {
                            let mut sorted_conns = established_conns.clone();
                            sorted_conns.sort_by(|a, b| b.trust_score.partial_cmp(&a.trust_score).unwrap_or(std::cmp::Ordering::Equal));
                            
                            println!("\nTop 5 connexions les plus fiables:");
                            println!("┌────────────────────┬─────────┬──────────────────┬─────────────┐");
                            println!("│ IP                 │ Score   │ Durée            │ Activité    │");
                            println!("├────────────────────┼─────────┼──────────────────┼─────────────┤");
                            
                            for (i, conn) in sorted_conns.iter().take(5).enumerate() {
                                let age = conn.get_connection_age();
                                let age_str = format!("{:.0}m {:.0}s", age.as_secs() / 60, age.as_secs() % 60);
                                
                                let last_activity = conn.get_inactivity_duration();
                                let activity_str = format!("{:.0}s", last_activity.as_secs());
                                
                                println!("│ {:18} │ {:.2}   │ {:16} │ {:11} │", 
                                    conn.ip, conn.trust_score, age_str, activity_str);
                            }
                            println!("└────────────────────┴─────────┴──────────────────┴─────────────┘");
                        }
                    }
                }
                
                // Mettre à jour les valeurs pour la prochaine itération
                prev_total_packets = total_packets;
                prev_time = now;
            }
        });
    }

    /// Active ou désactive l'affichage des statistiques en temps réel
    pub async fn toggle_realtime_stats(&mut self, enable: bool) -> Result<(), Box<dyn std::error::Error>> {
        // Mise à jour de la configuration
        {
            let mut config = self.config.write().await;
            config.realtime_stats = enable;
            config.display_realtime_stats = enable;
            
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Impossible de sauvegarder la configuration: {}", e),
                )));
            }
        }
        
        self.realtime_stats_enabled = enable;
        
        if enable {
            // Lancer l'affichage des statistiques en temps réel
            let analyzer_clone = self.analyzer.clone();
            let security_stats_clone = self.security_stats.clone();
            let defender_clone = self.defender.clone();
            
            tokio::spawn(async move {
                let interval = Duration::from_millis(500); // 0.5 secondes
                let mut stdout = std::io::stdout();
                
                loop {
                    // Espace pour effacer l'écran et positionner le curseur en haut
                    print!("\x1B[2J\x1B[1;1H");
                    stdout.flush().unwrap();
                    
                    // Récupérer les statistiques
                    let sec_stats = security_stats_clone.read().await.clone();
                    
                    // En-tête avec timestamp
                    let now = SystemTime::now();
                    let datetime = chrono::DateTime::<chrono::Local>::from(now);
                    let formatted_time = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                    
                    println!("=== STATISTIQUES EN TEMPS RÉEL - ZDefender ({})) ===", formatted_time);
                    println!();
                    
                    // Statistiques de sécurité globales
                    println!("--- STATISTIQUES GLOBALES ---");
                    println!("Score de sécurité: {:.2}", sec_stats.average_security_score);
                    println!("Paquets traités: {}", sec_stats.total_packets_analyzed);
                    println!("Débit entrant: {} octets/s", sec_stats.inbound_bps);
                    println!("Débit sortant: {} octets/s", sec_stats.outbound_bps);
                    println!("Attaques détectées: {}", sec_stats.attacks_detected);
                    println!();
                    
                    // Top IPs actives
                    if let Some(analyzer) = &analyzer_clone {
                        let (_, ip_stats) = analyzer.get_stats().await;
                        
                        println!("--- TOP 5 IPs ACTIVES ---");
                        for (i, (ip, stats)) in ip_stats.iter().take(5).enumerate() {
                            let status = if stats.is_blocked { 
                                "BLOQUÉE" 
                            } else { 
                                "active" 
                            };
                            
                            println!("{}. {} - {:.2} p/s | {} octets | {} | Score de confiance: {:.2}",
                                i + 1, ip, stats.packets_per_second, 
                                stats.total_bytes, status, stats.trust_score);
                        }
                        println!();
                    }
                    
                    // Connexions établies
                    if let Some(defender) = &defender_clone {
                        let defender_read = defender.read().await;
                        let established = defender_read.get_established_connections().await;
                        
                        println!("--- CONNEXIONS ÉTABLIES ({}) ---", established.len());
                        let mut connections = Vec::new();
                        for conn in &established {
                            connections.push(format!("{}", conn.ip));
                        }
                        
                        // Ajouter les 5 connexions les plus récentes
                        let mut sorted_conns = established.iter().collect::<Vec<_>>();
                        sorted_conns.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
                        for (_i, conn) in sorted_conns.iter().take(5).enumerate() {
                            connections.push(format!("{} (last: {}s ago)", 
                                conn.ip, 
                                conn.get_inactivity_duration().as_secs()
                            ));
                        }
                    }
                    
                    // Attendre l'intervalle
                    tokio::time::sleep(interval).await;
                    
                    // Vérifier si on doit continuer ou arrêter l'affichage
                    let config_read = match Config::load() {
                        Ok(cfg) => cfg,
                        Err(_) => break, // Arrêter si on ne peut pas lire la config
                    };
                    
                    if !config_read.display_realtime_stats {
                        // La configuration a changé, on arrête l'affichage
                        break;
                    }
                }
            });
            
            info!("Statistiques en temps réel activées");
        } else {
            info!("Statistiques en temps réel désactivées");
        }
        
        Ok(())
    }

    /// Affiche les statistiques du service
    pub async fn status(&self) {
        // Recharger la configuration depuis le fichier pour avoir l'état le plus récent
        let config = match Config::load() {
            Ok(loaded_config) => {
                // Si la config a été chargée avec succès, on l'utilise
                loaded_config
            },
            Err(e) => {
                // En cas d'erreur, on utilise la config en mémoire
                error!("Erreur lors du chargement de la configuration: {}", e);
                self.config.read().await.clone()
            }
        };
        
        let state = match config.service_state {
            crate::config::ServiceState::Active => "Actif",
            crate::config::ServiceState::Passive => "Passif",
            crate::config::ServiceState::Stopped => "Arrêté",
        };
        
        let fortress_mode = if config.fortress_mode {
            "Activé"
        } else {
            "Désactivé"
        };
        
        println!("=== Statut de ZDefender ===");
        println!("État: {}", state);
        println!("Mode forteresse: {}", fortress_mode);
        println!("Interfaces surveillées: {}", config.interfaces.join(", "));
        println!("Seuil de paquets: {} paquets/sec", config.packet_threshold);
        println!("Intervalle de vérification: {} secondes", config.check_interval);
        println!("Durée de blocage: {} secondes", config.block_duration);
        
        // Afficher les statistiques si disponibles
        if let Some(analyzer) = &self.analyzer {
            let (global_stats, ip_stats) = analyzer.get_stats().await;
            
            println!("\n=== Statistiques globales ===");
            println!("Total de paquets analysés: {}", global_stats.total_packets);
            println!("Total d'octets analysés: {} octets", global_stats.total_bytes);
            println!("Nombre d'IPs bloquées: {}", global_stats.blocked_ips);
            println!("Tentatives d'attaque détectées: {}", global_stats.attack_attempts);
            
            if !ip_stats.is_empty() {
                println!("\n=== Top 5 IPs par nombre de paquets ===");
                for (i, (ip, stats)) in ip_stats.iter().take(5).enumerate() {
                    println!("{}. {} - {} paquets, {:.2} paquets/sec", 
                            i + 1, 
                            ip,
                            stats.packet_count,
                            stats.packets_per_second);
                }
            }
        }

        if let Some(analyzer) = &self.analyzer {
            // Récupérer les IPs actuellement bloquées
            let blocked_ips = analyzer.get_blocked_ips().await;
            
            println!("\n=== IPs bloquées ===");
            if blocked_ips.is_empty() {
                println!("Aucune IP bloquée");
            } else {
                for (i, (ip, expiry)) in blocked_ips.iter().enumerate() {
                    if let Ok(remaining) = expiry.duration_since(SystemTime::now()) {
                        println!("{}. {} - Déblocage dans {} secondes", 
                            i + 1, 
                            ip, 
                            remaining.as_secs());
                    }
                }
            }
        }
    }

    /// Affiche les statistiques détaillées
    pub async fn show_stats(&self) {
        // Obtenir les statistiques actuelles de toutes les connexions
        let ss_output = Command::new("ss")
            .args(["-s"])
            .output();
        
        // Obtenir les statistiques iptables
        let iptables_output = Command::new("iptables")
            .args(["-L", "-n", "-v"])
            .output();
        
        println!("=== Statistiques de ZDefender ===");
        
        // Afficher les statistiques du service si disponibles
        if let Some(analyzer) = &self.analyzer {
            let (global_stats, ip_stats) = analyzer.get_stats().await;
            
            println!("\n=== Statistiques globales ===");
            println!("Total de paquets analysés: {}", global_stats.total_packets);
            println!("Total d'octets analysés: {} octets", global_stats.total_bytes);
            println!("Nombre d'IPs bloquées: {}", global_stats.blocked_ips);
            println!("Tentatives d'attaque détectées: {}", global_stats.attack_attempts);
            
            if !ip_stats.is_empty() {
                println!("\n=== Top 10 IPs par nombre de paquets ===");
                for (i, (ip, stats)) in ip_stats.iter().take(10).enumerate() {
                    println!(
                        "{}. {} - {} paquets, {} octets, {}",
                        i + 1,
                        ip,
                        stats.packet_count,
                        stats.total_bytes,
                        if stats.is_blocked { "BLOQUÉE" } else { "non bloquée" }
                    );
                }
            }
        } else {
            println!("Aucune statistique disponible (service non démarré)");
        }
        
        // Afficher les statistiques de connexion système
        println!("\n=== Statistiques de connexion système ===");
        match ss_output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("{}", stdout);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("Erreur lors de l'obtention des statistiques de connexion: {}", stderr);
                }
            }
            Err(e) => {
                println!("Erreur lors de l'exécution de la commande ss: {}", e);
            }
        }
        
        // Afficher les règles iptables
        println!("\n=== Règles iptables actives ===");
        match iptables_output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("{}", stdout);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("Erreur lors de l'obtention des règles iptables: {}", stderr);
                }
            }
            Err(e) => {
                println!("Erreur lors de l'exécution de la commande iptables: {}", e);
            }
        }
    }

    /// Récupère les statistiques de sécurité actuelles
    pub async fn get_security_stats(&self) -> SecurityStats {
        self.security_stats.read().await.clone()
    }
} 
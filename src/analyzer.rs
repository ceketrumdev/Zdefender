use crate::models::{
    Action, GlobalStats, IpStats, IpStatsMap, PacketInfo, Report, ReportType
};
use crate::config::Config;
use log::{debug, error, info, warn};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use dashmap::DashMap;
use std::collections::HashMap;

pub struct Analyzer {
    config: Arc<RwLock<Config>>,
    ip_stats: IpStatsMap,
    global_stats: Arc<RwLock<GlobalStats>>,
    report_tx: mpsc::Sender<Report>,
}

impl Analyzer {
    pub fn new(
        config: Arc<RwLock<Config>>,
        report_tx: mpsc::Sender<Report>,
    ) -> Self {
        Self {
            config,
            ip_stats: Arc::new(DashMap::new()),
            global_stats: Arc::new(RwLock::new(GlobalStats::default())),
            report_tx,
        }
    }

    pub async fn analyze_packet(&self, packet: PacketInfo) {
        // Mettre à jour les statistiques globales
        {
            let mut stats = self.global_stats.write().await;
            stats.total_packets += 1;
            stats.total_bytes += packet.size as u64;
        }

        // Obtenir et mettre à jour les statistiques pour cette IP
        let ip = packet.source_ip;
        let mut should_report = false;
        let mut report = None;

        // Mettre à jour les statistiques pour cette IP
        {
            let mut entry = self.ip_stats.entry(ip).or_insert_with(|| {
                debug!("Nouvelle IP détectée: {}", ip);
                IpStats::new()
            });

            // Si l'IP est bloquée mais que le temps de blocage est écoulé, la débloquer
            if entry.is_blocked && entry.should_unblock() {
                entry.unblock();
                should_report = true;
                report = Some(Report {
                    timestamp: SystemTime::now(),
                    report_type: ReportType::Info,
                    source_ip: Some(ip),
                    message: format!("IP {} débloquée (fin de la période de blocage)", ip),
                    details: None,
                    severity: 4,
                    suggested_action: Some(Action::Unblock(ip)),
                });
            }

            // Mettre à jour les statistiques si l'IP n'est pas bloquée
            if !entry.is_blocked {
                entry.add_packet(packet.size);
            }
        }

        // Envoyer le rapport si nécessaire
        if should_report {
            if let Some(report) = report {
                if let Err(e) = self.report_tx.send(report).await {
                    error!("Erreur lors de l'envoi du rapport: {}", e);
                }
            }
        }

        // Analyser pour détecter une attaque potentielle
        self.detect_attacks().await;
    }

    pub async fn detect_attacks(&self) {
        let config = self.config.read().await;
        let threshold = config.packet_threshold;
        let block_duration = config.block_duration;
        let whitelist = &config.whitelist;
        
        // Parcourir toutes les IP pour détecter des comportements suspects
        for mut entry in self.ip_stats.iter_mut() {
            let ip = *entry.key();
            let stats = entry.value_mut();
            
            // Ne pas analyser les IPs en liste blanche
            if whitelist.iter().any(|allowed| allowed == &ip.to_string()) {
                continue;
            }
            
            // Ne pas analyser les IPs déjà bloquées
            if stats.is_blocked {
                continue;
            }
            
            // Calculer le taux de paquets pour cette IP
            let elapsed = stats.last_seen
                .duration_since(stats.first_seen)
                .unwrap_or(Duration::from_secs(1));
            
            let packets_per_second = if elapsed.as_secs() > 0 {
                stats.packet_count as f64 / elapsed.as_secs() as f64
            } else {
                stats.packet_count as f64
            };
            
            // Si le taux de paquets dépasse le seuil, signaler une attaque potentielle
            if packets_per_second > threshold as f64 {
                // Bloquer l'IP
                stats.block(Duration::from_secs(block_duration));
                
                // Mettre à jour les statistiques globales
                {
                    let mut global_stats = self.global_stats.write().await;
                    global_stats.blocked_ips += 1;
                    global_stats.attack_attempts += 1;
                }
                
                // Créer un rapport d'alerte
                let report = Report {
                    timestamp: SystemTime::now(),
                    report_type: ReportType::Attack,
                    source_ip: Some(ip),
                    message: format!(
                        "Attaque DDoS potentielle détectée: {} paquets/sec depuis l'IP {}",
                        packets_per_second, ip
                    ),
                    details: Some(format!("Taux: {:.2} paquets/sec, seuil: {}", packets_per_second, threshold)),
                    severity: 8,
                    suggested_action: Some(Action::Block(ip, Duration::from_secs(block_duration))),
                };
                
                // Envoyer le rapport
                if let Err(e) = self.report_tx.send(report).await {
                    error!("Erreur lors de l'envoi du rapport d'attaque: {}", e);
                }
            }
        }
    }
    
    pub async fn get_stats(&self) -> (GlobalStats, Vec<(IpAddr, IpStats)>) {
        // Récupérer les statistiques globales
        let global_stats = self.global_stats.read().await.clone();
        
        // Récupérer les statistiques des IPs
        let mut ip_stats = Vec::new();
        for entry in self.ip_stats.iter() {
            let ip = *entry.key();
            let stats = entry.value().clone();
            ip_stats.push((ip, stats));
        }
        
        // Trier par nombre de paquets (décroissant)
        ip_stats.sort_by(|a, b| b.1.packet_count.cmp(&a.1.packet_count));
        
        (global_stats, ip_stats)
    }
    
    pub async fn clear_expired_blocks(&self) {
        let mut unblocked_ips = Vec::new();
        
        // Parcourir toutes les IPs pour trouver celles dont le blocage a expiré
        for mut entry in self.ip_stats.iter_mut() {
            let ip = *entry.key();
            let stats = entry.value_mut();
            
            if stats.is_blocked && stats.should_unblock() {
                stats.unblock();
                unblocked_ips.push(ip);
            }
        }
        
        // Envoyer des rapports pour toutes les IPs débloquées
        for ip in unblocked_ips {
            let report = Report {
                timestamp: SystemTime::now(),
                report_type: ReportType::Info,
                source_ip: Some(ip),
                message: format!("IP {} débloquée (fin de la période de blocage)", ip),
                details: None,
                severity: 4,
                suggested_action: Some(Action::Unblock(ip)),
            };
            
            if let Err(e) = self.report_tx.send(report).await {
                error!("Erreur lors de l'envoi du rapport de déblocage: {}", e);
            }
        }
    }

    pub async fn get_blocked_ips(&self) -> Vec<(IpAddr, SystemTime)> {
        let mut blocked_ips = Vec::new();
        
        // Parcourir toutes les IPs et recueillir celles qui sont bloquées
        for entry in self.ip_stats.iter() {
            let ip = *entry.key();
            let stats = entry.value();
            
            if stats.is_blocked {
                // Comme nous n'avons pas d'information sur l'expiration directement dans IpStats,
                // utilisons un temps d'expiration basé sur la configuration actuelle
                let config = self.config.read().await;
                let block_duration = Duration::from_secs(config.block_duration);
                
                // Assurer que le temps d'expiration est toujours dans le futur
                let current_time = SystemTime::now();
                // On suppose que l'IP a été bloquée récemment, donc le temps d'expiration
                // est le temps actuel + la durée de blocage configurée
                let expiry_time = current_time + block_duration;
                
                blocked_ips.push((ip, expiry_time));
            }
        }
        
        // Trier par temps d'expiration
        blocked_ips.sort_by(|a, b| a.1.cmp(&b.1));
        
        blocked_ips
    }
} 
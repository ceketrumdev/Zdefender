//! Module d'analyse de paquets
//!
//! Ce module est responsable de l'analyse des paquets réseau pour détecter
//! des comportements suspects ou malveillants.

use super::ProtectionManager;
use crate::models::{Action, PacketInfo, IpStats, PacketType};
use dashmap::DashMap;
use log::{debug, info, warn};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

impl ProtectionManager {
    /// Analyse un paquet avec tous les modules de protection
    pub async fn analyze_packet(&mut self, packet: &PacketInfo) -> Option<Action> {
        // Vérifier d'abord si l'IP est déjà bloquée
        if self.is_blocked(packet.source_ip).await {
            return Some(Action::Drop);
        }
        
        // Mettre à jour les statistiques de trafic
        self.update_traffic_stats(packet).await;
        
        // Inspection approfondie des paquets
        if let Some(attack_type) = self.packet_inspector.inspect_packet(packet).await {
            info!("Attaque détectée par l'inspecteur de paquets: {}", attack_type.to_string());
            return Some(Action::Block(
                packet.source_ip, 
                Duration::from_secs(self.get_block_duration().await)
            ));
        }
        
        // Analyse comportementale par le détecteur intelligent
        if let Some(analysis_result) = self.perform_intelligent_analysis(packet).await {
            return Some(analysis_result);
        }
        
        // Utiliser la détection intelligente pour analyser le comportement
        // Vérifier si l'IP existe dans le HashMap avant d'y accéder
        let stats = if let Some(stats) = self.ip_stats.get(&packet.source_ip) {
            stats
        } else {
            // Si l'IP n'existe pas encore dans les statistiques, on l'ajoute
            // avec des valeurs par défaut et on ne bloque pas pour l'instant
            self.ip_stats.entry(packet.source_ip).or_insert_with(IpStats::new)
        };
        
        let detection_result = detect_attacks(packet, stats, 
            self.threshold_packets_per_second, 
            self.threshold_syn_percentage, 
            self.fortress_mode);
        
        if let Some(action) = detection_result {
            self.handle_action(action.clone(), packet);
            return Some(action);
        }
        
        // Aucune menace détectée
        None
    }
    
    /// Met à jour les statistiques de trafic pour une IP
    pub async fn update_traffic_stats(&self, packet: &PacketInfo) {
        let mut stats = self.traffic_stats.write().await;
        let ip_stats = stats.entry(packet.source_ip).or_insert_with(|| IpStats::new());
        
        // Mettre à jour les statistiques
        ip_stats.update_with_packet(packet);
        
        // Partager les statistiques avec le détecteur intelligent
        drop(stats); // Libérer le verrou avant d'appeler une autre méthode async
        let _ = self.intelligent_detector.update_ip_stats(packet.source_ip).await;
    }
    
    /// Effectue une analyse intelligente du comportement
    async fn perform_intelligent_analysis(&self, packet: &PacketInfo) -> Option<Action> {
        // Préparer les statistiques pour l'analyseur
        let ip_stats_for_analyzer = Arc::new(DashMap::new());
        for (ip, stats) in &self.ip_stats {
            ip_stats_for_analyzer.insert(*ip, stats.clone());
        }
        
        // Analyser le paquet avec le détecteur intelligent
        if let Some(anomaly_score) = self.intelligent_detector.analyze_packet(packet, &ip_stats_for_analyzer).await {
            if anomaly_score > 0.8 { // Seuil arbitraire pour l'exemple
                info!("Comportement anormal détecté: score={}", anomaly_score);
                return Some(Action::Block(
                    packet.source_ip, 
                    Duration::from_secs(self.get_block_duration().await)
                ));
            } else if anomaly_score > 0.5 {
                // Seuil de suspicion mais pas encore de blocage
                warn!("Comportement suspect détecté: score={}", anomaly_score);
                return Some(Action::RateLimit(packet.source_ip));
            }
        }
        
        None
    }
    
    /// Traite une action détectée
    pub fn handle_action(&mut self, action: Action, packet: &PacketInfo) {
        match &action {
            Action::Block(ip, duration) => {
                let blocked_ip = crate::models::BlockedIp::new(*ip, *duration, "Comportement suspect détecté".to_string());
                self.blocked_ips_vec.push(blocked_ip);
                self.send_report(
                    crate::models::ReportType::Action,
                    format!("IP {} bloquée pour {:?}", ip, duration),
                    Some(*ip),
                    Some(format!("Trafic suspect détecté de {}", ip)),
                    7,
                );
            }
            Action::RateLimit(ip) => {
                self.send_report(
                    crate::models::ReportType::Action,
                    format!("Limitation de débit appliquée pour l'IP {}", ip),
                    Some(*ip),
                    Some(format!("Trafic élevé de {}", ip)),
                    6,
                );
            }
            Action::Drop => {
                debug!("Paquet supprimé: {:?}", packet);
            }
            _ => {}
        }
    }
}

// Définir la fonction detect_attacks directement plutôt que de l'importer
fn detect_attacks(
    packet: &PacketInfo,
    stats: &IpStats,
    threshold_packets_per_second: f64,
    threshold_syn_percentage: f64,
    fortress_mode: bool
) -> Option<Action> {
    // En mode forteresse, bloquer tout le trafic suspect
    if fortress_mode {
        if stats.packet_count < 5 {
            // Autoriser au moins quelques paquets pour établir une session légitime
            return None;
        }

        // Bloquer les nouvelles connexions TCP SYN en mode forteresse
        if packet.protocol == PacketType::Tcp &&
           stats.syn_count > 3 &&
           packet.flags.as_ref().map_or(false, |f| f.contains(&"SYN".to_string()) && !f.contains(&"ACK".to_string())) {
            debug!("Mode forteresse: Blocage préventif de l'IP {}", packet.source_ip);
            return Some(Action::Block(packet.source_ip, Duration::from_secs(300)));
        }
    }

    // Vérifier le taux de paquets par seconde
    if stats.packets_per_second > threshold_packets_per_second {
        info!("Débit élevé détecté depuis l'IP {}: {:.2} paquets/s",
              packet.source_ip, stats.packets_per_second);

        // Si le débit est extrêmement élevé, bloquer immédiatement
        if stats.packets_per_second > threshold_packets_per_second * 3.0 {
            return Some(Action::Block(packet.source_ip, Duration::from_secs(600)));
        }

        // Sinon appliquer une limitation de débit
        return Some(Action::RateLimit(packet.source_ip));
    }

    // Détecter une attaque SYN flood
    if stats.tcp_count > 10 {
        let syn_ratio = stats.syn_count as f64 / stats.tcp_count as f64;

        if syn_ratio > threshold_syn_percentage {
            warn!("SYN flood suspecté depuis l'IP {}: ratio={:.2}",
                  packet.source_ip, syn_ratio);
            return Some(Action::Block(packet.source_ip, Duration::from_secs(900)));
        }
    }

    // Détecter les attaques ICMP
    if stats.icmp_count > 50 && stats.packets_per_second > threshold_packets_per_second * 0.7 {
        warn!("Flood ICMP suspecté depuis l'IP {}", packet.source_ip);
        return Some(Action::Block(packet.source_ip, Duration::from_secs(600)));
    }

    // Détection de scan de ports - trop de paquets TCP vers différents ports
    if packet.protocol == PacketType::Tcp &&
       stats.tcp_count > 20 &&
       stats.tcp_count as f64 / stats.packet_count as f64 > 0.9 {
        warn!("Scan de ports suspecté depuis l'IP {}", packet.source_ip);
        return Some(Action::Block(packet.source_ip, Duration::from_secs(1800)));
    }

    // Pas d'attaque détectée
    None
} 
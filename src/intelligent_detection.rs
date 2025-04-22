#![allow(dead_code)]
use crate::models::{PacketInfo, IpStatsMap, Report, ReportType, Action};
use crate::config::Config;
use log::{info, error};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use dashmap::DashMap;
use std::collections::VecDeque;

/// Nombre de paquets à conserver pour l'analyse comportementale
const BEHAVIOR_WINDOW_SIZE: usize = 100;

/// Profil comportemental pour l'analyse de trafic réseau
/// Permet de détecter les anomalies dans le comportement d'une IP
pub struct BehaviorProfile {
    /// Historique des taux de paquets par seconde (20 dernières mesures)
    packet_rates: VecDeque<f64>,
    /// Moyenne mobile des taux de paquets
    mean_rate: f64,
    /// Écart-type des taux de paquets pour la détection d'anomalies
    std_deviation: f64,
    /// Historique des nouvelles connexions TCP par intervalle
    tcp_connections: VecDeque<u32>,
    /// Distribution des protocoles utilisés par cette IP (%)
    protocol_distribution: HashMap<String, f64>,
    /// Horodatage de la dernière mise à jour du profil
    last_update: SystemTime,
    /// Score d'anomalie normalisé (0-100)
    anomaly_score: f64,
}

impl BehaviorProfile {
    pub fn new() -> Self {
        Self {
            packet_rates: VecDeque::with_capacity(20),
            mean_rate: 0.0,
            std_deviation: 0.0,
            tcp_connections: VecDeque::with_capacity(10),
            protocol_distribution: HashMap::new(),
            last_update: SystemTime::now(),
            anomaly_score: 0.0,
        }
    }

    /// Ajoute un nouveau taux de paquets à l'historique et recalcule les statistiques
    pub fn update_packet_rate(&mut self, rate: f64) {
        // Ajouter le nouveau taux
        self.packet_rates.push_back(rate);
        
        // Limiter la taille de l'historique aux 20 dernières mesures
        if self.packet_rates.len() > 20 {
            self.packet_rates.pop_front();
        }
        
        // Recalculer la moyenne
        self.mean_rate = self.packet_rates.iter().sum::<f64>() / self.packet_rates.len() as f64;
        
        // Recalculer l'écart-type pour la détection d'anomalies statistiques
        if self.packet_rates.len() > 1 {
            let variance = self.packet_rates.iter()
                .map(|x| {
                    let diff = x - self.mean_rate;
                    diff * diff
                })
                .sum::<f64>() / (self.packet_rates.len() - 1) as f64;
            
            self.std_deviation = variance.sqrt();
        }
        
        self.last_update = SystemTime::now();
    }
    
    /// Met à jour la distribution des protocoles utilisés par cette IP
    pub fn update_protocol_distribution(&mut self, protocol: &str) {
        // Recalculer les pourcentages pour que la somme reste à 100%
        let total = self.protocol_distribution.values().sum::<f64>() + 1.0;
        
        for (_, count) in self.protocol_distribution.iter_mut() {
            *count = *count / total;
        }
        
        // Incrémenter le compteur pour ce protocole
        *self.protocol_distribution.entry(protocol.to_string()).or_insert(0.0) += 1.0 / total;
        
        self.last_update = SystemTime::now();
    }
    
    /// Calcule un score d'anomalie (0-100) basé sur les comportements observés
    /// Plus le score est élevé, plus le comportement est considéré comme suspect
    pub fn calculate_anomaly_score(&mut self, current_rate: f64) -> f64 {
        let mut score = 0.0;
        
        // Détection statistique: taux anormalement élevé (z-score)
        if self.packet_rates.len() >= 5 && self.std_deviation > 0.0 {
            // Calcul du z-score (nombre d'écarts-types par rapport à la moyenne)
            let z_score = (current_rate - self.mean_rate) / self.std_deviation;
            
            // Score proportionnel au dépassement du seuil de 3 écarts-types
            if z_score > 3.0 {
                score += 40.0 * (z_score - 3.0).min(5.0) / 5.0;
            }
        }
        
        // Détection par signature: analyse de la distribution des protocoles
        if let Some(tcp_ratio) = self.protocol_distribution.get("TCP") {
            // Une concentration très élevée de TCP peut indiquer un scan ou SYN flood
            if *tcp_ratio > 0.9 {
                score += 20.0;
            }
        }
        
        if let Some(icmp_ratio) = self.protocol_distribution.get("ICMP") {
            // Une forte concentration d'ICMP peut indiquer un ping flood
            if *icmp_ratio > 0.5 {
                score += 30.0;
            }
        }
        
        // Seuil absolu: taux de paquets très élevé
        if current_rate > 1000.0 {
            score += 10.0;
        }
        
        // Normaliser le score entre 0 et 100
        self.anomaly_score = score.min(100.0);
        self.anomaly_score
    }
}

/// Système de détection d'intrusion intelligent basé sur l'analyse comportementale
/// Surveille les tendances du trafic et détecte les anomalies
pub struct IntelligentDetector {
    /// Configuration globale du système
    config: Arc<RwLock<Config>>,
    /// Profils comportementaux par adresse IP
    behavior_profiles: Arc<DashMap<IpAddr, BehaviorProfile>>,
    /// Canal pour envoyer des rapports d'alertes
    report_tx: mpsc::Sender<Report>,
    /// Seuil d'anomalie pour déclencher une alerte (0-100)
    anomaly_threshold: f64,
    /// Profil de référence du trafic normal (baseline)
    baseline_profile: BehaviorProfile,
    /// Horodatage de la dernière mise à jour de la baseline
    last_baseline_update: SystemTime,
}

impl IntelligentDetector {
    pub fn new(
        config: Arc<RwLock<Config>>,
        report_tx: mpsc::Sender<Report>,
    ) -> Self {
        Self {
            config,
            behavior_profiles: Arc::new(DashMap::new()),
            report_tx,
            anomaly_threshold: 70.0, // Seuil par défaut
            baseline_profile: BehaviorProfile::new(),
            last_baseline_update: SystemTime::now(),
        }
    }
    
    /// Analyse un paquet et met à jour les profils comportementaux
    /// Retourne le score d'anomalie normalisé (0.0-1.0) si disponible
    pub async fn analyze_packet(&self, packet: &PacketInfo, ip_stats: &IpStatsMap) -> Option<f64> {
        let ip = packet.source_ip;
        
        // Obtenir ou créer le profil comportemental pour cette IP
        let mut profile = self.behavior_profiles
            .entry(ip)
            .or_insert_with(BehaviorProfile::new);
            
        // Mettre à jour la distribution des protocoles
        let protocol_str = match packet.protocol {
            crate::models::PacketType::Tcp => "TCP",
            crate::models::PacketType::Udp => "UDP",
            crate::models::PacketType::Icmp => "ICMP",
            crate::models::PacketType::Other => "OTHER",
        };
        
        profile.update_protocol_distribution(protocol_str);
        
        // Calculer le taux de paquets actuel pour cette IP
        if let Some(stats) = ip_stats.get(&ip) {
            let elapsed = stats.last_seen
                .duration_since(stats.first_seen)
                .unwrap_or(Duration::from_secs(1));
                
            let packet_rate = if elapsed.as_secs() > 0 {
                stats.packet_count as f64 / elapsed.as_secs() as f64
            } else {
                stats.packet_count as f64
            };
            
            // Mettre à jour le profil avec ce taux
            profile.update_packet_rate(packet_rate);
            
            // Calculer le score d'anomalie
            let anomaly_score = profile.calculate_anomaly_score(packet_rate);
            
            // Si le score dépasse le seuil, générer un rapport d'alerte
            if anomaly_score > self.anomaly_threshold {
                self.generate_anomaly_report(ip, anomaly_score, packet_rate).await;
            }
            
            // Retourner le score normalisé entre 0 et 1
            Some(anomaly_score / 100.0)
        } else {
            None
        }
    }
    
    /// Génère un rapport d'anomalie avec un niveau de sévérité adapté au score
    async fn generate_anomaly_report(&self, ip: IpAddr, score: f64, rate: f64) {
        // Créer un message descriptif adapté au niveau de criticité
        let message = if score > 90.0 {
            format!("ALERTE CRITIQUE: Comportement très suspect détecté pour l'IP {}. Score d'anomalie: {:.1}, Taux: {:.1} paquets/sec", ip, score, rate)
        } else if score > 80.0 {
            format!("ALERTE ÉLEVÉE: Comportement suspect détecté pour l'IP {}. Score d'anomalie: {:.1}, Taux: {:.1} paquets/sec", ip, score, rate)
        } else {
            format!("ALERTE MOYENNE: Comportement anormal détecté pour l'IP {}. Score d'anomalie: {:.1}, Taux: {:.1} paquets/sec", ip, score, rate)
        };
        
        // Récupérer la durée de blocage depuis la configuration
        let config = self.config.read().await;
        let block_duration = config.block_duration;
        
        // Créer le rapport avec une sévérité adaptée au score
        let report = Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Alert,
            source_ip: Some(ip),
            message,
            details: Some(format!("Score d'anomalie: {:.1}", score)),
            severity: if score > 90.0 { 9 } else if score > 80.0 { 8 } else { 6 },
            suggested_action: Some(Action::Block(ip, Duration::from_secs(block_duration))),
        };
        
        // Envoyer le rapport au gestionnaire central
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport d'anomalie: {}", e);
        }
    }
    
    /// Met à jour le profil de référence (baseline) du trafic normal
    /// Effectué périodiquement pour s'adapter aux changements de comportement réseau
    pub async fn update_baseline(&mut self, ip_stats: &IpStatsMap) {
        // Mise à jour limitée à une fois par heure
        let now = SystemTime::now();
        if let Ok(elapsed) = now.duration_since(self.last_baseline_update) {
            if elapsed.as_secs() < 3600 {
                return;
            }
        }
        
        info!("Mise à jour de la baseline du trafic normal...");
        
        // Calcul de la baseline basé sur les IPs légitimes et stables
        let mut total_rate = 0.0;
        let mut count = 0;
        
        for entry in ip_stats.iter() {
            let stats = entry.value();
            
            // Exclure les IPs bloquées
            if stats.is_blocked {
                continue;
            }
            
            // Exclure les IPs avec un historique trop court (< 5 minutes)
            let elapsed = stats.last_seen
                .duration_since(stats.first_seen)
                .unwrap_or(Duration::from_secs(1));
                
            if elapsed.as_secs() < 300 {
                continue;
            }
            
            // Calculer le taux moyen de paquets pour cette IP
            let packet_rate = if elapsed.as_secs() > 0 {
                stats.packet_count as f64 / elapsed.as_secs() as f64
            } else {
                stats.packet_count as f64
            };
            
            total_rate += packet_rate;
            count += 1;
        }
        
        // Mettre à jour la baseline si suffisamment de données
        if count > 0 {
            let avg_rate = total_rate / count as f64;
            self.baseline_profile.update_packet_rate(avg_rate);
            
            info!("Baseline mise à jour. Taux moyen: {:.2} paquets/sec basé sur {} IPs", 
                  avg_rate, count);
        }
        
        self.last_baseline_update = now;
    }
    
    /// Ajuste automatiquement le seuil d'anomalie en fonction du feedback
    /// Permet de réduire les faux positifs et faux négatifs au fil du temps
    pub async fn adjust_threshold(&mut self, false_positives: u32, false_negatives: u32) {
        if false_positives > false_negatives && self.anomaly_threshold < 95.0 {
            // Plus de faux positifs: augmenter le seuil pour plus de tolérance
            self.anomaly_threshold += 5.0;
            info!("Seuil d'anomalie augmenté à {:.1} en raison de faux positifs", 
                  self.anomaly_threshold);
        } else if false_negatives > false_positives && self.anomaly_threshold > 50.0 {
            // Plus de faux négatifs: réduire le seuil pour plus de sensibilité
            self.anomaly_threshold -= 5.0;
            info!("Seuil d'anomalie réduit à {:.1} en raison de faux négatifs", 
                  self.anomaly_threshold);
        }
    }
    
    /// Met à jour les statistiques avancées pour une IP spécifique
    pub async fn update_ip_stats(&self, _ip: IpAddr) -> Result<(), &'static str> {
        // Fonction préparée pour des extensions futures
        Ok(())
    }
    
    /// Clone l'instance pour les besoins des traitements asynchrones
    pub fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            behavior_profiles: Arc::clone(&self.behavior_profiles),
            report_tx: self.report_tx.clone(),
            anomaly_threshold: self.anomaly_threshold,
            baseline_profile: BehaviorProfile::new(),
            last_baseline_update: self.last_baseline_update,
        }
    }
} 
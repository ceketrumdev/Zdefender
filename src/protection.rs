use crate::config::Config;
use crate::intelligent_detection::IntelligentDetector;
use crate::packet_inspection::PacketInspector;
use crate::models::{PacketInfo, Report, ReportType, Action, IpStats, BlockedIp, PacketType};
use log::{debug, info, warn, error};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use crossbeam_channel::{self};
use crate::packet_inspection::inspect_packet;
use dashmap::DashMap;
use futures;

// Fonction directement intégrée dans le fichier protection.rs pour éviter les problèmes d'importation
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

/// Structure coordonnant les différentes méthodes de protection
pub struct ProtectionManager {
    /// Configuration du système
    config: Arc<RwLock<Config>>,
    /// Détecteur intelligent de comportements anormaux
    intelligent_detector: IntelligentDetector,
    /// Inspecteur de paquets pour l'analyse profonde
    packet_inspector: PacketInspector,
    /// Canal pour envoyer des rapports
    report_tx: mpsc::Sender<Report>,
    /// IPs actuellement bloquées
    blocked_ips: RwLock<HashSet<IpAddr>>,
    /// Timestamp des expirations de blocage par IP
    block_expiry: RwLock<HashMap<IpAddr, SystemTime>>,
    /// Statistiques globales de trafic
    traffic_stats: RwLock<HashMap<IpAddr, IpStats>>,
    ip_stats: HashMap<IpAddr, IpStats>,
    blocked_ips_vec: Vec<BlockedIp>,
    threshold_packets_per_second: f64,
    threshold_syn_percentage: f64,
    fortress_mode: bool,
}

impl ProtectionManager {
    pub async fn new(
        config: Arc<RwLock<Config>>,
        report_tx: mpsc::Sender<Report>,
    ) -> Self {
        // Canaux pour les rapports internes
        let (internal_tx, mut internal_rx) = mpsc::channel::<Report>(100);
        
        // Créer les modules de protection
        let intelligent_detector = IntelligentDetector::new(
            Arc::clone(&config),
            internal_tx.clone(),
        );
        
        let packet_inspector = PacketInspector::new(
            Arc::clone(&config),
            internal_tx.clone(),
        );
        
        let manager = Self {
            config,
            intelligent_detector,
            packet_inspector,
            report_tx: report_tx.clone(),
            blocked_ips: RwLock::new(HashSet::new()),
            block_expiry: RwLock::new(HashMap::new()),
            traffic_stats: RwLock::new(HashMap::new()),
            ip_stats: HashMap::new(),
            blocked_ips_vec: Vec::new(),
            threshold_packets_per_second: 100.0, // Valeur par défaut
            threshold_syn_percentage: 0.8,      // 80% de SYN = probable SYN flood
            fortress_mode: false,
        };
        
        // Démarrer la tâche de traitement des rapports internes
        let report_tx_clone = report_tx.clone();
        tokio::spawn(async move {
            while let Some(report) = internal_rx.recv().await {
                if let Err(e) = report_tx_clone.send(report).await {
                    error!("Erreur lors du transfert d'un rapport interne: {}", e);
                }
            }
        });
        
        // Charger les données initiales si nécessaire
        manager.initialize().await;
        
        manager
    }
    
    /// Initialisation des ressources et données
    async fn initialize(&self) {
        // Tâche périodique pour nettoyer les IPs bloquées expirées
        let mut self_clone = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                self_clone.cleanup_expired_blocks().await;
                self_clone.packet_inspector.cleanup_counters().await;
            }
        });
        
        info!("Gestionnaire de protection initialisé");
    }
    
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
        let ip_stats_for_analyzer = Arc::new(DashMap::new());
        for (ip, stats) in &self.ip_stats {
            ip_stats_for_analyzer.insert(*ip, stats.clone());
        }
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
    
    /// Vérifie si une IP est actuellement bloquée
    pub async fn is_blocked(&self, ip: IpAddr) -> bool {
        let blocked_ips = self.blocked_ips.read().await;
        blocked_ips.contains(&ip)
    }
    
    /// Vérifie si une IP est actuellement bloquée (version synchrone)
    pub fn is_blocked_sync(&self, ip: IpAddr) -> bool {
        // Vérifier dans le vecteur des IPs bloquées
        self.blocked_ips_vec.iter().any(|blocked| blocked.ip == ip && !blocked.is_expired())
    }
    
    /// Ajoute une IP à la liste des bloquées avec une durée d'expiration
    pub async fn block_ip(&self, ip: IpAddr, duration: Duration) {
        // Ajouter l'IP à la liste des bloquées
        {
            let mut blocked_ips = self.blocked_ips.write().await;
            blocked_ips.insert(ip);
        }
        
        // Définir l'heure d'expiration
        let expiry = SystemTime::now() + duration;
        {
            let mut block_expiry = self.block_expiry.write().await;
            block_expiry.insert(ip, expiry);
        }
        
        // Générer un rapport de blocage
        let message = format!(
            "IP {} bloquée pour {} secondes", 
            ip, 
            duration.as_secs()
        );
        
        let report = Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Action,
            source_ip: Some(ip),
            message,
            details: None,
            severity: 0,
            suggested_action: None, // L'action a déjà été effectuée
        };
        
        // Envoyer le rapport
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport de blocage: {}", e);
        }
    }
    
    /// Retire une IP de la liste des bloquées
    pub async fn unblock_ip(&self, ip: IpAddr) {
        // Retirer l'IP de la liste des bloquées
        {
            let mut blocked_ips = self.blocked_ips.write().await;
            blocked_ips.remove(&ip);
        }
        
        // Retirer l'expiration
        {
            let mut block_expiry = self.block_expiry.write().await;
            block_expiry.remove(&ip);
        }
        
        // Générer un rapport de déblocage
        let message = format!("IP {} débloquée", ip);
        
        let report = Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Info,
            source_ip: Some(ip),
            message,
            details: None,
            severity: 0,
            suggested_action: None,
        };
        
        // Envoyer le rapport
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport de déblocage: {}", e);
        }
    }
    
    /// Nettoie les blocages expirés
    async fn cleanup_expired_blocks(&self) {
        let now = SystemTime::now();
        let mut ips_to_unblock = Vec::new();
        
        // Identifier les IPs à débloquer
        {
            let block_expiry = self.block_expiry.read().await;
            for (ip, expiry) in block_expiry.iter() {
                if let Ok(_) = expiry.duration_since(now) {
                    // Pas encore expiré
                    continue;
                }
                
                // Expiré, ajouter à la liste à débloquer
                ips_to_unblock.push(*ip);
            }
        }
        
        // Débloquer les IPs expirées
        for ip in ips_to_unblock {
            self.unblock_ip(ip).await;
        }
    }
    
    /// Met à jour les statistiques de trafic pour une IP
    async fn update_traffic_stats(&self, packet: &PacketInfo) {
        let mut stats = self.traffic_stats.write().await;
        let ip_stats = stats.entry(packet.source_ip).or_insert_with(|| IpStats::new());
        
        // Mettre à jour les statistiques
        ip_stats.update_with_packet(packet);
        
        // Partager les statistiques avec le détecteur intelligent
        drop(stats); // Libérer le verrou avant d'appeler une autre méthode async
        let _ = self.intelligent_detector.update_ip_stats(packet.source_ip).await;
    }
    
    /// Récupère la durée de blocage depuis la configuration
    async fn get_block_duration(&self) -> u64 {
        let config = self.config.read().await;
        config.block_duration
    }
    
    /// Crée un clone pour utilisation dans les tâches async
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            intelligent_detector: self.intelligent_detector.clone(),
            packet_inspector: self.packet_inspector.clone(),
            report_tx: self.report_tx.clone(),
            blocked_ips: RwLock::new(HashSet::new()),
            block_expiry: RwLock::new(HashMap::new()),
            traffic_stats: RwLock::new(HashMap::new()),
            ip_stats: self.ip_stats.clone(),
            blocked_ips_vec: self.blocked_ips_vec.clone(),
            threshold_packets_per_second: self.threshold_packets_per_second,
            threshold_syn_percentage: self.threshold_syn_percentage,
            fortress_mode: self.fortress_mode,
        }
    }

    pub fn set_thresholds(&mut self, packets_per_second: f64, syn_percentage: f64) {
        self.threshold_packets_per_second = packets_per_second;
        self.threshold_syn_percentage = syn_percentage;
    }

    pub fn enable_fortress_mode(&mut self) {
        self.fortress_mode = true;
        self.send_report(
            ReportType::Info,
            "Mode forteresse activé".to_string(),
            None,
            Some("Protection maximale activée, toutes les connexions non établies seront rejetées".to_string()),
            8,
        );
    }

    pub fn disable_fortress_mode(&mut self) {
        self.fortress_mode = false;
        self.send_report(
            ReportType::Info,
            "Mode forteresse désactivé".to_string(),
            None,
            None,
            5,
        );
    }

    pub fn process_packet(&mut self, packet: PacketInfo) -> Option<Action> {
        // Vérifier si l'IP source est bloquée
        if let Some(idx) = self.blocked_ips_vec.iter().position(|b| b.ip == packet.source_ip) {
            if self.blocked_ips_vec[idx].is_expired() {
                // Débloquer l'IP si la durée est expirée
                let blocked_ip = self.blocked_ips_vec.remove(idx);
                self.send_report(
                    ReportType::Action,
                    format!("IP {} débloquée après expiration", blocked_ip.ip),
                    Some(blocked_ip.ip),
                    None,
                    4,
                );
            } else {
                // L'IP est toujours bloquée
                debug!("Paquet rejeté de l'IP bloquée: {}", packet.source_ip);
                return Some(Action::Drop);
            }
        }

        // Mettre à jour les statistiques de l'IP
        let stats = self.ip_stats
            .entry(packet.source_ip)
            .or_insert_with(|| IpStats::new());
        stats.update(&packet);

        // Inspecter le paquet pour détecter des anomalies
        let inspection_result = inspect_packet(&packet);
        if let Some(action) = inspection_result {
            self.handle_action(action, &packet);
            return Some(action);
        }

        // Utiliser la détection intelligente pour analyser le comportement
        let detection_result = detect_attacks(&packet, stats, 
            self.threshold_packets_per_second, 
            self.threshold_syn_percentage, 
            self.fortress_mode);
        
        if let Some(action) = detection_result {
            self.handle_action(action.clone(), &packet);
            return Some(action);
        }

        None
    }

    fn handle_action(&mut self, action: Action, packet: &PacketInfo) {
        match &action {
            Action::Block(ip, duration) => {
                let blocked_ip = BlockedIp::new(*ip, *duration, "Comportement suspect détecté".to_string());
                self.blocked_ips_vec.push(blocked_ip);
                self.send_report(
                    ReportType::Action,
                    format!("IP {} bloquée pour {:?}", ip, duration),
                    Some(*ip),
                    Some(format!("Trafic suspect détecté de {}", ip)),
                    7,
                );
            }
            Action::RateLimit(ip) => {
                self.send_report(
                    ReportType::Action,
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

    fn send_report(&self, report_type: ReportType, message: String, source_ip: Option<IpAddr>, details: Option<String>, severity: u8) {
        let mut report = Report::new(report_type, message);
        
        if let Some(ip) = source_ip {
            report = report.with_ip(ip);
        }
        
        if let Some(det) = details {
            report = report.with_details(det);
        }
        
        report = report.with_severity(severity);
        
        // Utiliser try_send pour éviter de bloquer dans un contexte non-async
        if let Err(e) = self.report_tx.try_send(report) {
            warn!("Échec de l'envoi du rapport: {}", e);
        }
    }

    pub fn synchronous_cleanup_expired_blocks(&mut self) -> usize {
        let initial_count = self.blocked_ips_vec.len();
        self.blocked_ips_vec.retain(|blocked| !blocked.is_expired());
        let removed = initial_count - self.blocked_ips_vec.len();
        if removed > 0 {
            info!("{} IP(s) débloquée(s) après expiration", removed);
        }
        removed
    }

    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.ip_stats.len(),
            self.blocked_ips_vec.len(),
            self.ip_stats.values().map(|s| s.packet_count as usize).sum(),
        )
    }
}

pub fn create_protection_manager(report_tx: mpsc::Sender<Report>) -> Arc<RwLock<ProtectionManager>> {
    // Créer une future qui sera exécutée dans le runtime existant
    let protection_manager = ProtectionManager::new(Arc::new(RwLock::new(Config::default())), report_tx);
    
    // Nous utilisons futures::executor::block_on qui ne dépend pas d'un runtime Tokio
    // pour exécuter la future de manière synchrone
    // Alternativement, laissez l'appelant gérer l'exécution asynchrone
    let protection_manager = futures::executor::block_on(protection_manager);
    
    Arc::new(RwLock::new(protection_manager))
} 
//! Module de protection
//!
//! Ce module fournit un système de protection contre diverses attaques réseau,
//! en analysant les paquets et en appliquant des mesures de protection appropriées.

mod detection;
mod blocked_ips;
mod packet_analyzer;
mod fortress;
pub mod suspend;

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
use dashmap::DashMap;

pub use detection::*;
pub use blocked_ips::*;
pub use packet_analyzer::*;
pub use fortress::*;

/// Structure coordonnant les différentes méthodes de protection
pub struct ProtectionManager {
    /// Configuration du système
    pub(crate) config: Arc<RwLock<Config>>,
    /// Détecteur intelligent de comportements anormaux
    pub(crate) intelligent_detector: IntelligentDetector,
    /// Inspecteur de paquets pour l'analyse profonde
    pub(crate) packet_inspector: PacketInspector,
    /// Canal pour envoyer des rapports
    pub(crate) report_tx: mpsc::Sender<Report>,
    /// IPs actuellement bloquées
    pub(crate) blocked_ips: RwLock<HashSet<IpAddr>>,
    /// Timestamp des expirations de blocage par IP
    pub(crate) block_expiry: RwLock<HashMap<IpAddr, SystemTime>>,
    /// Statistiques globales de trafic
    pub(crate) traffic_stats: RwLock<HashMap<IpAddr, IpStats>>,
    /// Statistiques par IP
    pub(crate) ip_stats: HashMap<IpAddr, IpStats>,
    /// Liste des IPs bloquées (pour accès synchrone)
    pub(crate) blocked_ips_vec: Vec<BlockedIp>,
    /// Seuil de paquets par seconde pour la détection
    pub(crate) threshold_packets_per_second: f64,
    /// Seuil de pourcentage SYN pour la détection
    pub(crate) threshold_syn_percentage: f64,
    /// Mode forteresse
    pub(crate) fortress_mode: bool,
    /// Mode forteresse actif
    pub(crate) fortress_mode_active: bool,
    /// Protection DDoS active
    pub(crate) ddos_protection_active: bool,
    /// Facteur de limitation de débit
    pub(crate) rate_limit_factor: f64,
    /// Compteur de paquets SYN
    pub(crate) syn_count: u64,
    /// Compteur total de paquets
    pub(crate) total_count: u64,
}

impl ProtectionManager {
    /// Crée une nouvelle instance du gestionnaire de protection
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
            fortress_mode_active: false,
            ddos_protection_active: false,
            rate_limit_factor: 1.0,
            syn_count: 0,
            total_count: 0,
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
    
    /// Envoie un rapport d'événement
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
    
    /// Récupère des statistiques globales
    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.ip_stats.len(),
            self.blocked_ips_vec.len(),
            self.ip_stats.values().map(|s| s.packet_count as usize).sum(),
        )
    }
}

impl Clone for ProtectionManager {
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
            fortress_mode_active: self.fortress_mode_active,
            ddos_protection_active: self.ddos_protection_active,
            rate_limit_factor: self.rate_limit_factor,
            syn_count: self.syn_count,
            total_count: self.total_count,
        }
    }
}

/// Crée une instance du gestionnaire de protection
pub fn create_protection_manager(report_tx: mpsc::Sender<Report>) -> Arc<RwLock<ProtectionManager>> {
    // Créer une configuration par défaut
    let config = Arc::new(RwLock::new(Config::default()));
    
    // Créer une future qui sera exécutée dans le runtime existant
    let protection_manager_future = ProtectionManager::new(config, report_tx);
    
    // Exécuter de manière synchrone et emballer dans un Arc<RwLock>
    let protection_manager = tokio::runtime::Handle::current().block_on(protection_manager_future);
    Arc::new(RwLock::new(protection_manager))
} 
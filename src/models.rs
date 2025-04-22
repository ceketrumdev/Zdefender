#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use dashmap::DashMap;
use std::sync::Arc;
use std::collections::HashMap;

/// Types de protocoles réseau supportés
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum PacketType {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// Structure contenant les métadonnées d'un paquet réseau analysé
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: SystemTime,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: PacketType,
    pub size: usize,
    pub flags: Option<Vec<String>>,
    pub ttl: Option<u8>,
}

/// Actions possibles à appliquer suite à l'analyse d'un paquet
#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum Action {
    Drop,                       // Supprimer le paquet
    Block(IpAddr, Duration),    // Bloquer l'IP source pour une durée spécifiée
    Unblock(IpAddr),            // Débloquer l'IP
    RateLimit(IpAddr),          // Limiter le débit pour cette IP
    EnableFortress,             // Activer le mode forteresse (protection maximale)
    DisableFortress,            // Désactiver le mode forteresse
    None,                       // Aucune action requise
}

/// Types de rapports générés par le système
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    Attack,     // Attaque détectée
    Action,     // Action effectuée
    Info,       // Information générale
    Alert,      // Alerte (niveau intermédiaire)
    Warning,    // Avertissement
}

/// Rapport généré suite à une détection ou une action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub timestamp: SystemTime,
    pub report_type: ReportType,
    pub source_ip: Option<IpAddr>,
    pub message: String,
    pub details: Option<String>,
    pub severity: u8,                  // 0-10, 10 étant le plus sévère
    pub suggested_action: Option<Action>,
}

impl Report {
    pub fn new(report_type: ReportType, message: String) -> Self {
        Self {
            timestamp: SystemTime::now(),
            report_type,
            source_ip: None,
            message,
            details: None,
            severity: 5,
            suggested_action: None,
        }
    }

    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_severity(mut self, severity: u8) -> Self {
        self.severity = severity.min(10);
        self
    }
}

/// Statistiques complètes pour une adresse IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpStats {
    // Compteurs de base
    pub packet_count: u64,
    pub total_bytes: u64,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
    pub other_count: u64,
    
    // Compteurs de flags TCP
    pub syn_count: u64,
    pub fin_count: u64,
    pub rst_count: u64,
    pub psh_count: u64,
    pub ack_count: u64,
    pub urg_count: u64,
    
    // Horodatages
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    
    // Taux de trafic
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    
    // État de blocage
    pub is_blocked: bool,
    pub block_expiry: Option<SystemTime>,
    
    // Métriques d'évaluation de confiance
    pub anomaly_score: f64,           // Score d'anomalie (0.0-1.0)
    pub suspicious_count: u32,        // Nombre d'actions suspectes détectées
    pub trust_score: f64,             // Score de confiance global (0.0-1.0)
    pub connection_stability: f64,    // Stabilité de la connexion (0.0-1.0)
    pub request_diversity: u32,       // Diversité des types de requêtes
    pub region_trust: f64,            // Confiance basée sur la région d'origine (0.0-1.0)
    
    // Métriques de régularité
    pub connection_count: u64,
    pub connection_regularity: f64,   // Régularité des connexions (0.0-1.0)
    pub average_interval: Duration,   // Intervalle moyen entre connexions
    pub last_interval_update: SystemTime,
}

impl IpStats {
    /// Crée une nouvelle instance de statistiques d'IP avec des valeurs par défaut
    pub fn new() -> Self {
        Self {
            // Initialisation avec des valeurs par défaut
            packet_count: 0,
            total_bytes: 0,
            tcp_count: 0,
            udp_count: 0,
            icmp_count: 0,
            other_count: 0,
            syn_count: 0,
            fin_count: 0,
            rst_count: 0,
            psh_count: 0,
            ack_count: 0,
            urg_count: 0,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            is_blocked: false,
            block_expiry: None,
            anomaly_score: 0.0,
            suspicious_count: 0,
            trust_score: 0.5,          // Score de confiance neutre par défaut
            connection_stability: 0.0,
            request_diversity: 0,
            region_trust: 0.5,         // Confiance régionale neutre par défaut
            connection_count: 0,
            connection_regularity: 0.0,
            average_interval: Duration::from_secs(0),
            last_interval_update: SystemTime::now(),
        }
    }

    pub fn new_with_ip(_source_ip: IpAddr) -> Self {
        Self::new()
    }

    /// Met à jour les statistiques avec les données d'un nouveau paquet
    pub fn update(&mut self, packet: &PacketInfo) {
        let now = SystemTime::now();
        self.last_seen = now;
        self.packet_count += 1;
        self.total_bytes += packet.size as u64;

        // Mise à jour des compteurs par type de protocole
        match packet.protocol {
            PacketType::Tcp => {
                self.tcp_count += 1;
                // Détection des paquets SYN sans ACK (début de connexion TCP)
                if let Some(ref flags) = packet.flags {
                    if flags.contains(&"SYN".to_string()) && !flags.contains(&"ACK".to_string()) {
                        self.syn_count += 1;
                    }
                }
            }
            PacketType::Udp => self.udp_count += 1,
            PacketType::Icmp => self.icmp_count += 1,
            _ => self.other_count += 1,
        }

        // Calcul des taux (paquets/sec et octets/sec)
        if let Ok(elapsed) = now.duration_since(self.first_seen) {
            let seconds = elapsed.as_secs_f64().max(1.0);
            self.packets_per_second = self.packet_count as f64 / seconds;
            self.bytes_per_second = self.total_bytes as f64 / seconds;
        }
    }

    // Méthode alias pour update pour la compatibilité avec le code existant
    pub fn update_with_packet(&mut self, packet: &PacketInfo) {
        self.update(packet)
    }

    /// Ajoute un paquet connu uniquement par sa taille
    pub fn add_packet(&mut self, size: usize) {
        let now = SystemTime::now();
        self.last_seen = now;
        self.packet_count += 1;
        self.total_bytes += size as u64;

        // Recalcul des taux
        if let Ok(elapsed) = now.duration_since(self.first_seen) {
            let seconds = elapsed.as_secs_f64().max(1.0);
            self.packets_per_second = self.packet_count as f64 / seconds;
            self.bytes_per_second = self.total_bytes as f64 / seconds;
        }
    }

    /// Bloque l'IP associée pour la durée spécifiée
    pub fn block(&mut self, duration: Duration) {
        self.is_blocked = true;
        self.block_expiry = Some(SystemTime::now() + duration);
    }

    /// Débloque l'IP associée
    pub fn unblock(&mut self) {
        self.is_blocked = false;
        self.block_expiry = None;
    }

    /// Vérifie si la période de blocage est terminée
    pub fn should_unblock(&self) -> bool {
        if !self.is_blocked {
            return false;
        }

        if let Some(expiry) = self.block_expiry {
            return SystemTime::now() >= expiry;
        }

        false
    }

    /// Calcule le score de confiance global basé sur plusieurs facteurs
    pub fn calculate_trust_score(&mut self) {
        // Facteurs positifs
        let connection_age = self.connection_age_factor();
        let stability = self.connection_stability;
        let diversity = self.request_diversity_factor();
        let region = self.region_trust;
        let regularity = self.connection_regularity;
        
        // Facteurs négatifs
        let anomaly = self.anomaly_score;
        let suspicious = self.suspicious_factor();
        
        // Calcul du score (0.0 à 1.0)
        let base_score = (connection_age + stability + diversity + region + regularity) / 5.0;
        let penalty = (anomaly + suspicious) / 2.0;
        
        // Application du score avec limitation entre 0 et 1
        self.trust_score = (base_score - penalty).max(0.0).min(1.0);
    }
    
    // Calcule un facteur de confiance basé sur l'âge de la connexion
    fn connection_age_factor(&self) -> f64 {
        if let Ok(duration) = self.last_seen.duration_since(self.first_seen) {
            let hours = duration.as_secs() as f64 / 3600.0;
            // Plafonner à 0.9 maximum pour les connexions très anciennes (24h+)
            (hours / 24.0).min(0.9)
        } else {
            0.0
        }
    }
    
    // Calcule un facteur de confiance basé sur la diversité des requêtes
    fn request_diversity_factor(&self) -> f64 {
        match self.request_diversity {
            0 => 0.1,              // Aucune diversité = faible confiance
            1 => 0.3,              // Peu de diversité = confiance limitée
            2..=4 => 0.7,          // Diversité modérée = bonne confiance
            5..=8 => 0.9,          // Bonne diversité = haute confiance
            _ => 0.5,              // Trop de diversité pourrait être suspect
        }
    }
    
    // Calcule un facteur de méfiance basé sur les actions suspectes
    fn suspicious_factor(&self) -> f64 {
        if self.packet_count < 10 {
            return 0.0;  // Pas assez de données pour évaluer
        }
        
        // Ratio d'actions suspectes sur le total des paquets
        let suspicious_ratio = self.suspicious_count as f64 / self.packet_count as f64;
        suspicious_ratio.min(1.0)
    }
    
    /// Met à jour le score de régularité des connexions
    pub fn update_connection_regularity(&mut self) {
        let now = SystemTime::now();
        
        // Mise à jour du compteur de connexions
        self.connection_count += 1;
        
        // Calcul de l'intervalle depuis la dernière mise à jour
        if let Ok(interval) = now.duration_since(self.last_interval_update) {
            // Mise à jour de l'intervalle moyen avec lissage
            if self.connection_count > 1 {
                let weight = 0.8;  // Facteur de lissage
                self.average_interval = Duration::from_secs_f64(
                    weight * self.average_interval.as_secs_f64() + 
                    (1.0 - weight) * interval.as_secs_f64()
                );
                
                // Calcul de la régularité basée sur la variation des intervalles
                let deviation = (interval.as_secs_f64() - self.average_interval.as_secs_f64()).abs();
                let relative_deviation = if self.average_interval.as_secs_f64() > 0.0 {
                    deviation / self.average_interval.as_secs_f64()
                } else {
                    1.0
                };
                
                // Plus la déviation est faible, plus la régularité est élevée
                self.connection_regularity = (1.0 - relative_deviation.min(1.0)).max(0.0);
            }
        }
        
        self.last_interval_update = now;
    }
    
    /// Définit le score de confiance basé sur la région géographique
    pub fn set_region_trust(&mut self, region_score: f64) {
        self.region_trust = region_score;
        // Mise à jour automatique du score global
        self.calculate_trust_score();
    }
}

/// Information sur une adresse IP bloquée
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIp {
    pub ip: IpAddr,
    pub blocked_at: SystemTime,
    pub block_duration: Duration,
    pub reason: String,
}

impl BlockedIp {
    pub fn new(ip: IpAddr, duration: Duration, reason: String) -> Self {
        Self {
            ip,
            blocked_at: SystemTime::now(),
            block_duration: duration,
            reason,
        }
    }

    /// Vérifie si la période de blocage est expirée
    pub fn is_expired(&self) -> bool {
        if let Ok(elapsed) = SystemTime::now().duration_since(self.blocked_at) {
            elapsed > self.block_duration
        } else {
            false
        }
    }
}

/// Statistiques globales du système de protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub start_time: SystemTime,
    pub blocked_ips: u32,
    pub attack_attempts: u32,
    pub fortress_mode_activations: u32,
}

impl Default for GlobalStats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            start_time: SystemTime::now(),
            blocked_ips: 0,
            attack_attempts: 0,
            fortress_mode_activations: 0,
        }
    }
}

/// Type alias pour simplifier l'utilisation des statistiques d'IPs avec DashMap
pub type IpStatsMap = Arc<DashMap<IpAddr, IpStats>>;

/// Statistiques de sécurité en temps réel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    pub average_security_score: f64,    // Score de sécurité moyen global
    pub total_packets_analyzed: u64,    // Nombre total de paquets analysés
    pub inbound_bps: u64,               // Débit entrant en octets par seconde
    pub outbound_bps: u64,              // Débit sortant en octets par seconde
    pub attacks_detected: u64,          // Nombre d'attaques détectées
    pub last_update: SystemTime,        // Dernière mise à jour des statistiques
}

impl SecurityStats {
    pub fn new() -> Self {
        Self {
            average_security_score: 0.0,
            total_packets_analyzed: 0,
            inbound_bps: 0,
            outbound_bps: 0,
            attacks_detected: 0,
            last_update: SystemTime::now(),
        }
    }

    /// Incrémente le compteur d'attaques détectées
    pub fn increment_attacks(&mut self) {
        self.attacks_detected += 1;
    }

    /// Calcule le temps écoulé depuis la dernière mise à jour
    pub fn time_since_update(&self) -> Duration {
        SystemTime::now().duration_since(self.last_update).unwrap_or(Duration::from_secs(0))
    }
}

/// Structure pour détecter et analyser les attaques DDoS distribuées
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DDoSDetectionStats {
    // Fenêtres de temps pour l'analyse
    pub interval_1s: HashMap<u32, u64>,   // Hashage par secondes
    pub interval_10s: HashMap<u32, u64>,  // Hashage par 10 secondes
    pub interval_60s: HashMap<u32, u64>,  // Hashage par minutes
    
    // Compteurs de paquets par intervalle de temps
    pub total_packets_1s: u64,
    pub total_packets_10s: u64,
    pub total_packets_60s: u64,
    
    // Nombre d'IPs uniques par intervalle
    pub unique_ips_1s: u32,
    pub unique_ips_10s: u32,
    pub unique_ips_60s: u32,
    
    // Dernières mises à jour des fenêtres
    pub last_update_1s: SystemTime,
    pub last_update_10s: SystemTime,
    pub last_update_60s: SystemTime,
    
    // Seuils de détection configurables
    pub threshold_ratio: f64,            // Rapport paquets/IPs pour alerte
    pub threshold_min_ips: u32,          // Nombre minimum d'IPs pour considérer une attaque distribuée
    pub threshold_packets_per_second: u64, // Paquets/s minimum pour déclencher une alerte
    
    // État d'une attaque DDoS en cours
    pub attack_in_progress: bool,
    pub attack_start_time: Option<SystemTime>,
    pub attack_intensity: f64,           // Intensité normalisée de l'attaque (0.0-1.0)
}

impl DDoSDetectionStats {
    pub fn new() -> Self {
        Self {
            interval_1s: HashMap::new(),
            interval_10s: HashMap::new(),
            interval_60s: HashMap::new(),
            total_packets_1s: 0,
            total_packets_10s: 0,
            total_packets_60s: 0,
            unique_ips_1s: 0,
            unique_ips_10s: 0,
            unique_ips_60s: 0,
            last_update_1s: SystemTime::now(),
            last_update_10s: SystemTime::now(),
            last_update_60s: SystemTime::now(),
            threshold_ratio: 50.0,            // 50 paquets par IP en moyenne
            threshold_min_ips: 50,            // Au moins 50 IPs distinctes
            threshold_packets_per_second: 5000, // 5000 paquets/s minimum
            attack_in_progress: false,
            attack_start_time: None,
            attack_intensity: 0.0,
        }
    }
    
    /// Traite une nouvelle IP source et met à jour les statistiques
    pub fn process_ip(&mut self, ip: &IpAddr) {
        let now = SystemTime::now();
        
        // Hachage de l'IP pour le stockage
        let ip_hash = self.hash_ip(ip);
        
        // Mise à jour des compteurs d'intervalle de 1 seconde
        if now.duration_since(self.last_update_1s).unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(1) {
            // Réinitialiser les compteurs pour le nouvel intervalle
            self.interval_1s.clear();
            self.total_packets_1s = 0;
            self.unique_ips_1s = 0;
            self.last_update_1s = now;
        }
        
        // Mise à jour des compteurs d'intervalle de 10 secondes
        if now.duration_since(self.last_update_10s).unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(10) {
            self.interval_10s.clear();
            self.total_packets_10s = 0;
            self.unique_ips_10s = 0;
            self.last_update_10s = now;
        }
        
        // Mise à jour des compteurs d'intervalle de 60 secondes
        if now.duration_since(self.last_update_60s).unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(60) {
            self.interval_60s.clear();
            self.total_packets_60s = 0;
            self.unique_ips_60s = 0;
            self.last_update_60s = now;
        }
        
        // Incrémenter les compteurs pour chaque intervalle
        let prev_count_1s = *self.interval_1s.get(&ip_hash).unwrap_or(&0);
        self.interval_1s.insert(ip_hash, prev_count_1s + 1);
        self.total_packets_1s += 1;
        if prev_count_1s == 0 {
            self.unique_ips_1s += 1;
        }
        
        let prev_count_10s = *self.interval_10s.get(&ip_hash).unwrap_or(&0);
        self.interval_10s.insert(ip_hash, prev_count_10s + 1);
        self.total_packets_10s += 1;
        if prev_count_10s == 0 {
            self.unique_ips_10s += 1;
        }
        
        let prev_count_60s = *self.interval_60s.get(&ip_hash).unwrap_or(&0);
        self.interval_60s.insert(ip_hash, prev_count_60s + 1);
        self.total_packets_60s += 1;
        if prev_count_60s == 0 {
            self.unique_ips_60s += 1;
        }
    }
    
    /// Vérifie si une attaque DDoS distribuée est en cours
    pub fn is_ddos_attack_in_progress(&mut self) -> bool {
        // Vérifier les critères d'attaque sur l'intervalle de 10 secondes
        if self.unique_ips_10s >= self.threshold_min_ips {
            let packets_per_ip = self.total_packets_10s as f64 / self.unique_ips_10s as f64;
            let packets_per_second = self.total_packets_10s / 10;
            
            if packets_per_ip >= self.threshold_ratio && packets_per_second >= self.threshold_packets_per_second {
                // Si une attaque n'était pas déjà détectée, enregistrer le moment de début
                if !self.attack_in_progress {
                    self.attack_in_progress = true;
                    self.attack_start_time = Some(SystemTime::now());
                }
                
                // Calculer l'intensité de l'attaque (normalisée entre 0 et 1)
                let base_intensity = (packets_per_second as f64 / self.threshold_packets_per_second as f64).min(10.0) / 10.0;
                let ip_factor = (self.unique_ips_10s as f64 / self.threshold_min_ips as f64).min(10.0) / 10.0;
                self.attack_intensity = (base_intensity + ip_factor) / 2.0;
                
                return true;
            }
        }
        
        // Si les critères ne sont plus remplis mais une attaque était en cours
        if self.attack_in_progress {
            // Vérifier si l'attaque a cessé depuis au moins 20 secondes
            if let Some(start_time) = self.attack_start_time {
                let attack_duration = SystemTime::now().duration_since(start_time).unwrap_or(Duration::from_secs(0));
                if attack_duration > Duration::from_secs(20) {
                    self.attack_in_progress = false;
                    self.attack_start_time = None;
                    self.attack_intensity = 0.0;
                } else {
                    // L'attaque est considérée en cours jusqu'à ce que nous soyons sûrs qu'elle a cessé
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Obtient des détails sur l'attaque en cours
    pub fn get_attack_details(&self) -> Option<(SystemTime, Duration, f64, u32, u64)> {
        if self.attack_in_progress {
            if let Some(start_time) = self.attack_start_time {
                let duration = SystemTime::now().duration_since(start_time).unwrap_or(Duration::from_secs(0));
                return Some((
                    start_time,
                    duration,
                    self.attack_intensity,
                    self.unique_ips_10s,
                    self.total_packets_10s / 10
                ));
            }
        }
        None
    }
    
    /// Fonction de hachage simple pour les adresses IP
    fn hash_ip(&self, ip: &IpAddr) -> u32 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        hasher.finish() as u32
    }
    
    /// Définit les seuils de détection
    pub fn set_thresholds(&mut self, ratio: f64, min_ips: u32, packets_per_second: u64) {
        self.threshold_ratio = ratio;
        self.threshold_min_ips = min_ips;
        self.threshold_packets_per_second = packets_per_second;
    }
}

/// Représentation d'une connexion réseau établie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstablishedConnection {
    pub ip: IpAddr,                     // Adresse IP de la connexion
    pub created_at: SystemTime,         // Moment de création de la connexion
    pub last_activity: SystemTime,      // Dernière activité sur cette connexion
    pub trust_score: f64,               // Score de confiance (entre 0.0 et 1.0)
    pub packet_count: u64,              // Nombre de paquets échangés
    pub is_established: bool,           // Indique si la connexion est établie
    pub request_types: Vec<String>,     // Types de requêtes effectuées
}

impl EstablishedConnection {
    pub fn new(ip: IpAddr) -> Self {
        let now = SystemTime::now();
        Self {
            ip,
            created_at: now,
            last_activity: now,
            trust_score: 0.5,           // Score de confiance initial moyen
            packet_count: 1,
            is_established: false,
            request_types: Vec::new(),
        }
    }

    /// Ajoute un type de requête à la connexion
    pub fn add_request_type(&mut self, request_type: String) {
        if !self.request_types.contains(&request_type) {
            self.request_types.push(request_type);
        }
    }

    /// Met à jour l'activité de la connexion
    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
        self.packet_count += 1;
        
        // Augmentation progressive du score de confiance pour les connexions durables
        if self.trust_score < 0.95 {
            self.trust_score += 0.01;
            self.trust_score = self.trust_score.min(1.0);
        }
        
        // Marquer comme établie après un certain nombre de paquets
        if self.packet_count > 5 && !self.is_established {
            self.is_established = true;
        }
    }

    /// Calcule la durée depuis la dernière activité
    pub fn get_inactivity_duration(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or(Duration::from_secs(0))
    }

    /// Calcule l'âge total de la connexion
    pub fn get_connection_age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.created_at)
            .unwrap_or(Duration::from_secs(0))
    }

    /// Vérifie si la connexion est inactive depuis la durée spécifiée
    pub fn is_inactive_for(&self, duration: Duration) -> bool {
        self.get_inactivity_duration() >= duration
    }
}

/// Structure pour représenter le taux de transfert d'une IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRate {
    pub ip: IpAddr,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub last_update: SystemTime,
}

impl IpRate {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            last_update: SystemTime::now(),
        }
    }
}

/// État d'une adresse IP dans le système
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IpState {
    Normal,     // État normal
    Suspicious, // Comportement suspect
    Throttled,  // Débit limité
    Blocked,    // IP bloquée
    Trusted,    // IP de confiance
}

/// Structure pour représenter un paquet au niveau syscall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPacket {
    pub timestamp: SystemTime,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: u8,
    pub size: usize,
    pub interface: String,
    pub direction: PacketDirection,
}

/// Direction du trafic de paquets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum PacketDirection {
    Inbound,
    Outbound,
    Unknown,
} 
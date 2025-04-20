use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use dashmap::DashMap;
use std::sync::Arc;

/// Type de paquets détectés
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum PacketType {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// Informations sur un paquet réseau
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

/// Type d'action à effectuer sur un paquet
#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum Action {
    /// Supprimer simplement le paquet
    Drop,
    /// Bloquer l'adresse IP pour une certaine durée
    Block(IpAddr, Duration),
    /// Débloquer l'adresse IP
    Unblock(IpAddr),
    /// Limiter le débit pour cette adresse IP
    RateLimit(IpAddr),
    /// Activer le mode forteresse
    EnableFortress,
    /// Désactiver le mode forteresse
    DisableFortress,
    /// Aucune action
    None,
}

/// Type de rapport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    /// Rapport d'attaque détectée
    Attack,
    /// Rapport d'action effectuée
    Action,
    /// Information générale
    Info,
    /// Alerte (niveau intermédiaire entre Info et Attack)
    Alert,
    /// Avertissement
    Warning,
}

/// Structure d'un rapport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub timestamp: SystemTime,
    pub report_type: ReportType,
    pub source_ip: Option<IpAddr>,
    pub message: String,
    pub details: Option<String>,
    pub severity: u8, // 0-10, 10 étant le plus sévère
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

/// Structure de statistiques pour une adresse IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpStats {
    pub packet_count: u64,
    pub total_bytes: u64,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
    pub other_count: u64,
    pub syn_count: u64,
    pub fin_count: u64,
    pub rst_count: u64,
    pub psh_count: u64,
    pub ack_count: u64,
    pub urg_count: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub is_blocked: bool,
    pub anomaly_score: f64,
    pub suspicious_count: u32,
}

impl IpStats {
    pub fn new() -> Self {
        Self {
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
            anomaly_score: 0.0,
            suspicious_count: 0,
        }
    }

    pub fn new_with_ip(_source_ip: IpAddr) -> Self {
        // Pour l'instant, on ne fait rien de spécial avec l'IP source
        Self::new()
    }

    pub fn update(&mut self, packet: &PacketInfo) {
        let now = SystemTime::now();
        self.last_seen = now;
        self.packet_count += 1;
        self.total_bytes += packet.size as u64;

        match packet.protocol {
            PacketType::Tcp => {
                self.tcp_count += 1;
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

        // Calculer les taux par seconde
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

    // Ajoute un paquet aux statistiques en ne connaissant que sa taille
    pub fn add_packet(&mut self, size: usize) {
        let now = SystemTime::now();
        self.last_seen = now;
        self.packet_count += 1;
        self.total_bytes += size as u64;

        // Calculer les taux par seconde
        if let Ok(elapsed) = now.duration_since(self.first_seen) {
            let seconds = elapsed.as_secs_f64().max(1.0);
            self.packets_per_second = self.packet_count as f64 / seconds;
            self.bytes_per_second = self.total_bytes as f64 / seconds;
        }
    }

    // Marque cette IP comme bloquée pour la durée spécifiée
    pub fn block(&mut self, _duration: Duration) {
        self.is_blocked = true;
    }

    // Débloque cette IP
    pub fn unblock(&mut self) {
        self.is_blocked = false;
    }

    // Vérifie si le blocage devrait être levé
    pub fn should_unblock(&self) -> bool {
        // Dans une implémentation complète, on vérifierait si la durée de blocage est écoulée
        // Pour l'instant, on retourne false par défaut
        false
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

    pub fn is_expired(&self) -> bool {
        if let Ok(elapsed) = SystemTime::now().duration_since(self.blocked_at) {
            elapsed > self.block_duration
        } else {
            false
        }
    }
}

/// Statistiques globales du système
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

/// Contient toutes les statistiques des IPs
pub type IpStatsMap = Arc<DashMap<IpAddr, IpStats>>; 
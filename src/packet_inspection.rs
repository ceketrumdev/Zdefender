use crate::models::{PacketInfo, Report, ReportType, Action, PacketType};
use crate::config::Config;
use log::{debug, info, warn, error};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use std::collections::HashMap;

/// Type d'attaque détecté par l'inspection des paquets
#[derive(Debug, Clone, Eq, Hash)]
pub enum AttackType {
    /// Attaque par flood SYN (TCP)
    SynFlood,
    /// Attaque par flood ICMP (ping)
    PingFlood,
    /// Attaque par amplification DNS
    DnsAmplification,
    /// Attaque par amplification NTP
    NtpAmplification,
    /// Attaque Slowloris (épuisement des connexions HTTP)
    Slowloris,
    /// Attaque HTTP Flood (GET/POST flood)
    HttpFlood,
    /// Attaque par fragmentation de paquets
    FragmentationAttack,
    /// Autre type d'attaque non catégorisé
    Other(String),
}

impl AttackType {
    pub fn to_string(&self) -> String {
        match self {
            Self::SynFlood => "SYN Flood".to_string(),
            Self::PingFlood => "ICMP Flood".to_string(),
            Self::DnsAmplification => "DNS Amplification".to_string(),
            Self::NtpAmplification => "NTP Amplification".to_string(),
            Self::Slowloris => "Slowloris".to_string(),
            Self::HttpFlood => "HTTP Flood".to_string(),
            Self::FragmentationAttack => "Fragmentation Attack".to_string(),
            Self::Other(desc) => format!("Other Attack: {}", desc),
        }
    }
}

impl PartialEq for AttackType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SynFlood, Self::SynFlood) => true,
            (Self::PingFlood, Self::PingFlood) => true,
            (Self::DnsAmplification, Self::DnsAmplification) => true,
            (Self::NtpAmplification, Self::NtpAmplification) => true,
            (Self::Slowloris, Self::Slowloris) => true,
            (Self::HttpFlood, Self::HttpFlood) => true,
            (Self::FragmentationAttack, Self::FragmentationAttack) => true,
            (Self::Other(a), Self::Other(b)) => a == b,
            _ => false,
        }
    }
}

/// Structure pour l'analyse approfondie des paquets
pub struct PacketInspector {
    /// Configuration du système
    config: Arc<RwLock<Config>>,
    /// Canal pour envoyer des rapports
    report_tx: mpsc::Sender<Report>,
    /// Signatures connues d'attaques
    attack_signatures: HashMap<AttackType, Vec<String>>,
    /// IPs connues des botnets
    botnet_ips: HashSet<IpAddr>,
    /// Compteurs de connexions TCP SYN par IP
    syn_counters: HashMap<IpAddr, (u32, SystemTime)>,
    /// Compteurs d'ICMP par IP
    icmp_counters: HashMap<IpAddr, (u32, SystemTime)>,
    /// Compteurs de requêtes DNS par IP
    dns_counters: HashMap<IpAddr, (u32, SystemTime)>,
    /// Fenêtre d'analyse en secondes
    analysis_window: u64,
}

impl PacketInspector {
    pub fn new(
        config: Arc<RwLock<Config>>,
        report_tx: mpsc::Sender<Report>,
    ) -> Self {
        let mut inspector = Self {
            config,
            report_tx,
            attack_signatures: HashMap::new(),
            botnet_ips: HashSet::new(),
            syn_counters: HashMap::new(),
            icmp_counters: HashMap::new(),
            dns_counters: HashMap::new(),
            analysis_window: 60, // Analyser sur une fenêtre de 60 secondes par défaut
        };
        
        // Initialiser les signatures d'attaques connues
        inspector.initialize_signatures();
        
        inspector
    }
    
    /// Initialise les signatures connues d'attaques
    fn initialize_signatures(&mut self) {
        // SYN Flood signatures
        self.attack_signatures.insert(
            AttackType::SynFlood, 
            vec![
                "TCP SYN without ACK".to_string(),
                "High rate of SYN packets".to_string(),
                "SYN packets with same source port".to_string(),
            ]
        );
        
        // ICMP Flood signatures
        self.attack_signatures.insert(
            AttackType::PingFlood, 
            vec![
                "High rate of ICMP Echo requests".to_string(),
                "ICMP packets with abnormal size".to_string(),
            ]
        );
        
        // DNS Amplification signatures
        self.attack_signatures.insert(
            AttackType::DnsAmplification, 
            vec![
                "DNS response without matching request".to_string(),
                "DNS response with large payload".to_string(),
                "Multiple identical DNS queries".to_string(),
            ]
        );
        
        // HTTP Flood signatures
        self.attack_signatures.insert(
            AttackType::HttpFlood, 
            vec![
                "Repeated HTTP GET/POST to same endpoint".to_string(),
                "HTTP requests with similar User-Agent".to_string(),
                "HTTP requests to nonexistent resources".to_string(),
            ]
        );
        
        // Load known botnet IPs (in a real implementation, this would come from a database)
        // For now, we just initialize an empty set
        info!("Signatures d'attaques initialisées");
    }
    
    /// Analyse un paquet pour détecter des signatures d'attaques connues
    pub async fn inspect_packet(&mut self, packet: &PacketInfo) -> Option<AttackType> {
        let now = SystemTime::now();
        let ip = packet.source_ip;
        
        // Vérifier si l'IP est connue comme étant un botnet
        if self.botnet_ips.contains(&ip) {
            self.report_botnet_activity(ip).await;
            return Some(AttackType::Other("Botnet Activity".to_string()));
        }
        
        // Analyser en fonction du type de paquet
        match packet.protocol {
            crate::models::PacketType::Tcp => {
                self.analyze_tcp_packet(packet, now).await
            },
            crate::models::PacketType::Icmp => {
                self.analyze_icmp_packet(packet, now).await
            },
            crate::models::PacketType::Udp => {
                self.analyze_udp_packet(packet, now).await
            },
            _ => None,
        }
    }
    
    /// Analyse un paquet TCP pour détecter des attaques
    async fn analyze_tcp_packet(&mut self, packet: &PacketInfo, now: SystemTime) -> Option<AttackType> {
        let ip = packet.source_ip;
        
        // Vérifier si c'est un paquet SYN (port de destination = 80, 443, etc.)
        if let Some(dst_port) = packet.dest_port {
            if dst_port == 80 || dst_port == 443 || dst_port == 8080 {
                // Incrémenter le compteur SYN pour cette IP
                let counter = self.syn_counters.entry(ip).or_insert((0, now));
                
                // Réinitialiser le compteur si la fenêtre d'analyse est passée
                if let Ok(elapsed) = now.duration_since(counter.1) {
                    if elapsed.as_secs() > self.analysis_window {
                        *counter = (1, now);
                    } else {
                        counter.0 += 1;
                    }
                } else {
                    // En cas d'erreur d'horloge, réinitialiser
                    *counter = (1, now);
                }
                
                // Vérifier si le seuil est dépassé
                if counter.0 > 100 { // Seuil arbitraire pour l'exemple
                    // Détecter une attaque SYN Flood
                    let count = counter.0; // Cloner la valeur pour éviter le double borrow
                    self.report_attack(ip, AttackType::SynFlood, count).await;
                    return Some(AttackType::SynFlood);
                }
            }
            
            // Détecter les tentatives d'attaque Slowloris
            if dst_port == 80 || dst_port == 443 {
                // L'analyse complète de Slowloris nécessiterait de suivre les connexions HTTP
                // et leur état, ce qui est au-delà de la portée de cet exemple
            }
        }
        
        None
    }
    
    /// Analyse un paquet ICMP pour détecter des attaques
    async fn analyze_icmp_packet(&mut self, packet: &PacketInfo, now: SystemTime) -> Option<AttackType> {
        let ip = packet.source_ip;
        
        // Incrémenter le compteur ICMP pour cette IP
        let counter = self.icmp_counters.entry(ip).or_insert((0, now));
        
        // Réinitialiser le compteur si la fenêtre d'analyse est passée
        if let Ok(elapsed) = now.duration_since(counter.1) {
            if elapsed.as_secs() > self.analysis_window {
                *counter = (1, now);
            } else {
                counter.0 += 1;
            }
        } else {
            // En cas d'erreur d'horloge, réinitialiser
            *counter = (1, now);
        }
        
        // Vérifier si le seuil est dépassé
        if counter.0 > 50 { // Seuil arbitraire pour l'exemple
            // Détecter une attaque ICMP Flood
            let count = counter.0; // Cloner la valeur pour éviter le double borrow
            self.report_attack(ip, AttackType::PingFlood, count).await;
            return Some(AttackType::PingFlood);
        }
        
        None
    }
    
    /// Analyse un paquet UDP pour détecter des attaques
    async fn analyze_udp_packet(&mut self, packet: &PacketInfo, now: SystemTime) -> Option<AttackType> {
        let ip = packet.source_ip;
        
        // Vérifier si c'est un paquet DNS (port = 53)
        if let Some(dst_port) = packet.dest_port {
            if dst_port == 53 {
                // Incrémenter le compteur DNS pour cette IP
                let counter = self.dns_counters.entry(ip).or_insert((0, now));
                
                // Réinitialiser le compteur si la fenêtre d'analyse est passée
                if let Ok(elapsed) = now.duration_since(counter.1) {
                    if elapsed.as_secs() > self.analysis_window {
                        *counter = (1, now);
                    } else {
                        counter.0 += 1;
                    }
                } else {
                    // En cas d'erreur d'horloge, réinitialiser
                    *counter = (1, now);
                }
                
                // Vérifier si le seuil est dépassé
                if counter.0 > 200 { // Seuil arbitraire pour l'exemple
                    // Détecter une possible attaque par amplification DNS
                    let count = counter.0; // Cloner la valeur pour éviter le double borrow
                    self.report_attack(ip, AttackType::DnsAmplification, count).await;
                    return Some(AttackType::DnsAmplification);
                }
            }
            
            // Vérifier si c'est un paquet NTP (port = 123)
            if dst_port == 123 {
                // Une analyse complète de l'amplification NTP nécessiterait d'inspecter
                // le contenu du paquet, ce qui est au-delà de la portée de cet exemple
            }
        }
        
        None
    }
    
    /// Signale une activité de botnet détectée
    async fn report_botnet_activity(&self, ip: IpAddr) {
        let message = format!("Activité de botnet détectée depuis l'IP {}", ip);
        
        // Récupérer la durée de blocage depuis la configuration
        let block_duration = {
            let config = self.config.read().await;
            // Pour les botnets, doubler la durée standard de blocage
            config.block_duration * 2
        };
        
        // Créer le rapport
        let report = Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Alert,
            source_ip: Some(ip),
            message,
            details: None,
            severity: 0,
            suggested_action: Some(Action::Block(ip, Duration::from_secs(block_duration))),
        };
        
        // Envoyer le rapport
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport de botnet: {}", e);
        }
    }
    
    /// Signale une attaque détectée
    async fn report_attack(&self, ip: IpAddr, attack_type: AttackType, count: u32) {
        let message = format!(
            "Attaque {} détectée depuis l'IP {} ({} paquets en {} secondes)",
            attack_type.to_string(), ip, count, self.analysis_window
        );
        
        // Récupérer la durée de blocage depuis la configuration
        let block_duration = {
            let config = self.config.read().await;
            config.block_duration
        };
        
        // Créer le rapport
        let report = Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Alert,
            source_ip: Some(ip),
            message,
            details: None,
            severity: 0,
            suggested_action: Some(Action::Block(ip, Duration::from_secs(block_duration))),
        };
        
        // Envoyer le rapport
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport d'attaque: {}", e);
        }
    }
    
    /// Nettoie les compteurs obsolètes pour économiser la mémoire
    pub async fn cleanup_counters(&mut self) {
        let now = SystemTime::now();
        
        // Nettoyer les compteurs SYN
        self.syn_counters.retain(|_, (_, timestamp)| {
            if let Ok(elapsed) = now.duration_since(*timestamp) {
                elapsed.as_secs() <= self.analysis_window * 2
            } else {
                false
            }
        });
        
        // Nettoyer les compteurs ICMP
        self.icmp_counters.retain(|_, (_, timestamp)| {
            if let Ok(elapsed) = now.duration_since(*timestamp) {
                elapsed.as_secs() <= self.analysis_window * 2
            } else {
                false
            }
        });
        
        // Nettoyer les compteurs DNS
        self.dns_counters.retain(|_, (_, timestamp)| {
            if let Ok(elapsed) = now.duration_since(*timestamp) {
                elapsed.as_secs() <= self.analysis_window * 2
            } else {
                false
            }
        });
        
        debug!("Nettoyage des compteurs terminé: SYN={}, ICMP={}, DNS={}", 
               self.syn_counters.len(), self.icmp_counters.len(), self.dns_counters.len());
    }
    
    /// Charge une liste d'IPs de botnets connus depuis un fichier
    pub async fn load_botnet_ips(&mut self, path: &str) -> Result<(), std::io::Error> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let mut count = 0;
        for line in reader.lines() {
            if let Ok(ip_str) = line {
                // Ignorer les lignes vides ou les commentaires
                if ip_str.trim().is_empty() || ip_str.starts_with('#') {
                    continue;
                }
                
                // Essayer de parser l'IP
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    self.botnet_ips.insert(ip);
                    count += 1;
                }
            }
        }
        
        info!("Chargé {} IPs de botnets connus", count);
        Ok(())
    }
    
    /// Clone l'inspecteur pour les besoins asynchrones
    pub fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            report_tx: self.report_tx.clone(),
            attack_signatures: self.attack_signatures.clone(),
            botnet_ips: self.botnet_ips.clone(),
            syn_counters: self.syn_counters.clone(),
            icmp_counters: self.icmp_counters.clone(),
            dns_counters: self.dns_counters.clone(),
            analysis_window: self.analysis_window,
        }
    }
}

/// Inspecte un paquet pour détecter des signes d'attaque DDoS
pub fn inspect_packet(packet: &PacketInfo) -> Option<Action> {
    // Vérifier les drapeaux TCP suspicieux
    if packet.protocol == PacketType::Tcp {
        // Vérifier les tentatives SYN flood
        if let Some(ref flags) = packet.flags {
            // Paquet SYN sans ACK (début de connexion potentiellement malveillant)
            if flags.contains(&"SYN".to_string()) && !flags.contains(&"ACK".to_string()) {
                // Vérifier si les ports de destination sont courants (HTTP, HTTPS)
                if let Some(port) = packet.dest_port {
                    if port == 80 || port == 443 || port == 8080 {
                        // Ne pas bloquer tout de suite, mais signaler pour surveillance
                        debug!("Paquet SYN détecté vers le port {}: {}", port, packet.source_ip);
                    }
                }
            }
            
            // Paquets avec combinaisons de drapeaux invalides (FIN+URG+PSH)
            if flags.contains(&"FIN".to_string()) && 
               flags.contains(&"URG".to_string()) && 
               flags.contains(&"PSH".to_string()) {
                // Cette combinaison est souvent utilisée pour les scans furtifs
                warn!("Tentative de scan Xmas détectée depuis {}", packet.source_ip);
                return Some(Action::Block(packet.source_ip, Duration::from_secs(1800)));
            }
        }
    }
    
    // Vérifier les paquets ICMP suspicieux
    if packet.protocol == PacketType::Icmp {
        // Paquets ICMP de taille anormale (potentielle attaque par amplification)
        if packet.size > 1000 {
            warn!("Paquet ICMP de grande taille détecté: {} octets depuis {}", 
                  packet.size, packet.source_ip);
            return Some(Action::Block(packet.source_ip, Duration::from_secs(900)));
        }
    }
    
    // Vérifier les paquets UDP suspicieux
    if packet.protocol == PacketType::Udp {
        // Paquets ciblant des ports courants d'amplification DDoS
        if let Some(port) = packet.dest_port {
            match port {
                53 => {
                    // DNS - surveillé pour les attaques par amplification DNS
                    if packet.size < 40 {
                        debug!("Petite requête DNS depuis {} (potentielle amplification)", 
                              packet.source_ip);
                    }
                },
                123 => {
                    // NTP - utilisé pour les attaques par amplification NTP
                    debug!("Trafic NTP détecté depuis {}", packet.source_ip);
                },
                389 => {
                    // LDAP - utilisé pour les attaques par amplification
                    warn!("Potentielle attaque d'amplification LDAP depuis {}", packet.source_ip);
                    return Some(Action::RateLimit(packet.source_ip));
                },
                1900 => {
                    // SSDP - souvent utilisé pour les attaques par amplification
                    warn!("Potentielle attaque d'amplification SSDP depuis {}", packet.source_ip);
                    return Some(Action::RateLimit(packet.source_ip));
                },
                11211 => {
                    // Memcached - utilisé pour des attaques d'amplification massives
                    warn!("Potentielle attaque d'amplification Memcached depuis {}", packet.source_ip);
                    return Some(Action::Block(packet.source_ip, Duration::from_secs(3600)));
                },
                _ => {}
            }
        }
    }
    
    // Vérifier la fragmentation IP
    if let Some(ttl) = packet.ttl {
        // TTL très faible peut indiquer des tentatives d'évasion
        if ttl < 5 {
            warn!("Paquet avec TTL très bas ({}) détecté depuis {}", ttl, packet.source_ip);
            return Some(Action::Block(packet.source_ip, Duration::from_secs(300)));
        }
    }
    
    None
} 
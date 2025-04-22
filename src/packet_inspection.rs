#![allow(dead_code)]
use crate::models::{PacketInfo, Report, ReportType, Action, PacketType};
use crate::config::Config;
use log::{debug, info, warn, error};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use std::collections::HashMap;

/// Types d'attaques DDoS détectés par le système d'inspection de paquets.
/// Chaque type correspond à une signature d'attaque spécifique avec des
/// caractéristiques, vecteurs et mécanismes de détection propres.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum AttackType {
    /// Attaque SYN Flood: surcharge de paquets TCP avec flag SYN sans compléter la poignée de main TCP.
    /// Épuise les ressources du serveur en laissant des connexions semi-ouvertes.
    SynFlood,
    /// Attaque par saturation ICMP (Ping Flood): envoi massif de requêtes echo (ping)
    /// pour consommer la bande passante du réseau cible.
    PingFlood,
    /// Attaque par amplification DNS: exploitation des serveurs DNS pour amplifier le trafic.
    /// Utilise de petites requêtes générant de grandes réponses avec usurpation d'adresse IP source.
    DnsAmplification,
    /// Attaque par amplification NTP: exploitation des serveurs NTP (Network Time Protocol)
    /// via la commande monlist pour générer un trafic amplifié jusqu'à 556 fois.
    NtpAmplification,
    /// Attaque Slowloris: maintien de nombreuses connexions HTTP partielles et lentes,
    /// épuisant les ressources du serveur web en maintenant des sockets ouvertes.
    Slowloris,
    /// Attaque HTTP Flood: saturation du serveur par un volume excessif de requêtes HTTP légitimes
    /// qui submergent les capacités de traitement du serveur web.
    HttpFlood,
    /// Attaque par fragmentation: exploitation de la fragmentation des paquets IP
    /// pour contourner les systèmes de détection ou saturer les ressources de réassemblage.
    FragmentationAttack,
    /// Type d'attaque non catégorisé ou personnalisé, avec description en paramètre.
    Other(String),
}

impl AttackType {
    /// Convertit le type d'attaque en chaîne de caractères lisible pour l'humain.
    /// Utilisé pour les rapports et les journaux du système.
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

/// Système d'inspection approfondie des paquets réseau (Deep Packet Inspection).
/// Analyse le trafic à plusieurs niveaux pour détecter des patterns d'attaques DDoS
/// basés sur des signatures connues et des comportements anormaux.
pub struct PacketInspector {
    /// Configuration globale du système, partagée entre composants
    config: Arc<RwLock<Config>>,
    /// Canal pour envoyer des rapports d'alertes au système central de traitement
    report_tx: mpsc::Sender<Report>,
    /// Dictionnaire des signatures connues d'attaques pour la détection par pattern matching
    attack_signatures: HashMap<AttackType, Vec<String>>,
    /// Ensemble des adresses IP connues comme appartenant à des botnets ou réseaux malveillants
    botnet_ips: HashSet<IpAddr>,
    /// Compteurs de connexions TCP SYN par IP (pour détecter les SYN floods)
    /// Structure: (nombre de paquets SYN, timestamp de début de la fenêtre d'analyse)
    syn_counters: HashMap<IpAddr, (u32, SystemTime)>,
    /// Compteurs de paquets ICMP par IP (pour détecter les ping floods)
    /// Structure: (nombre de paquets ICMP, timestamp de début de la fenêtre d'analyse)
    icmp_counters: HashMap<IpAddr, (u32, SystemTime)>,
    /// Compteurs de requêtes DNS par IP (pour détecter les amplifications DNS)
    /// Structure: (nombre de requêtes DNS, timestamp de début de la fenêtre d'analyse)
    dns_counters: HashMap<IpAddr, (u32, SystemTime)>,
    /// Durée de la fenêtre d'analyse en secondes pour les compteurs de paquets
    /// Définit la période pendant laquelle les compteurs sont accumulés avant réinitialisation
    analysis_window: u64,
}

impl PacketInspector {
    /// Crée une nouvelle instance de l'inspecteur de paquets avec la configuration
    /// et le canal de communication spécifiés.
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
            analysis_window: 60, // Fenêtre d'analyse de 60 secondes par défaut
        };
        
        // Initialiser les signatures d'attaques connues
        inspector.initialize_signatures();
        
        inspector
    }
    
    /// Initialise la base de données des signatures d'attaques connues.
    /// Ces signatures servent de référence pour l'identification des attaques
    /// par pattern matching au niveau des paquets et flux réseau.
    fn initialize_signatures(&mut self) {
        // Signatures d'attaques SYN Flood - caractéristiques principales:
        // - Nombre élevé de SYN sans ACK associés
        // - Délai entre SYN et SYN-ACK trop long
        // - Même port source pour de nombreux SYN
        self.attack_signatures.insert(
            AttackType::SynFlood, 
            vec![
                "TCP SYN without ACK".to_string(),
                "High rate of SYN packets".to_string(),
                "SYN packets with same source port".to_string(),
            ]
        );
        
        // Signatures d'attaques ICMP Flood - caractéristiques principales:
        // - Volume anormalement élevé de requêtes ICMP Echo
        // - Taille anormale des paquets ICMP (très grande ou très petite)
        self.attack_signatures.insert(
            AttackType::PingFlood, 
            vec![
                "High rate of ICMP Echo requests".to_string(),
                "ICMP packets with abnormal size".to_string(),
            ]
        );
        
        // Signatures d'attaques par amplification DNS - caractéristiques principales:
        // - Réponses DNS sans requêtes correspondantes (spoofing IP)
        // - Réponses DNS anormalement grandes (facteur d'amplification)
        // - Requêtes DNS répétitives depuis les mêmes IPs
        self.attack_signatures.insert(
            AttackType::DnsAmplification, 
            vec![
                "DNS response without matching request".to_string(),
                "DNS response with large payload".to_string(),
                "Multiple identical DNS queries".to_string(),
            ]
        );
        
        // Signatures d'attaques HTTP Flood - caractéristiques principales:
        // - Requêtes HTTP répétitives vers les mêmes URLs
        // - User-Agents identiques ou suspects
        // - Requêtes vers des ressources inexistantes
        self.attack_signatures.insert(
            AttackType::HttpFlood, 
            vec![
                "Repeated HTTP GET/POST to same endpoint".to_string(),
                "HTTP requests with similar User-Agent".to_string(),
                "HTTP requests to nonexistent resources".to_string(),
            ]
        );
        
        // Dans une implémentation réelle, les IPs des botnets seraient chargées
        // depuis une base de données ou API externe mise à jour régulièrement
        info!("Signatures d'attaques initialisées pour {} types d'attaques", self.attack_signatures.len());
    }
    
    /// Analyse un paquet réseau pour détecter des signes d'attaques DDoS.
    /// Cette fonction est le point d'entrée principal de l'inspection des paquets.
    /// Retourne le type d'attaque détecté, le cas échéant.
    pub async fn inspect_packet(&mut self, packet: &PacketInfo) -> Option<AttackType> {
        let now = SystemTime::now();
        let ip = packet.source_ip;
        
        // Vérifier si l'IP appartient à un botnet connu - blocage immédiat
        if self.botnet_ips.contains(&ip) {
            self.report_botnet_activity(ip).await;
            return Some(AttackType::Other("Botnet Activity".to_string()));
        }
        
        // Déléguer l'analyse en fonction du protocole du paquet
        // à des fonctions spécialisées par type de protocole
        match packet.protocol {
            PacketType::Tcp => {
                self.analyze_tcp_packet(packet, now).await
            },
            PacketType::Icmp => {
                self.analyze_icmp_packet(packet, now).await
            },
            PacketType::Udp => {
                self.analyze_udp_packet(packet, now).await
            },
            _ => None,
        }
    }
    
    /// Analyse un paquet TCP pour détecter des attaques spécifiques au protocole TCP.
    /// Se concentre sur la détection des attaques SYN flood et Slowloris
    /// en surveillant les ports web standard (80, 443, 8080).
    async fn analyze_tcp_packet(&mut self, packet: &PacketInfo, now: SystemTime) -> Option<AttackType> {
        let ip = packet.source_ip;
        
        // Vérifier si c'est un paquet vers les ports web courants (HTTP/HTTPS)
        if let Some(dst_port) = packet.dest_port {
            if dst_port == 80 || dst_port == 443 || dst_port == 8080 {
                // Incrémenter le compteur SYN pour cette IP dans la fenêtre d'analyse courante
                let counter = self.syn_counters.entry(ip).or_insert((0, now));
                
                // Réinitialiser le compteur si la fenêtre d'analyse est dépassée
                // pour éviter les faux positifs sur des connexions légitimes espacées
                if let Ok(elapsed) = now.duration_since(counter.1) {
                    if elapsed.as_secs() > self.analysis_window {
                        *counter = (1, now);
                    } else {
                        counter.0 += 1;
                    }
                } else {
                    // En cas d'erreur d'horloge système, réinitialiser par sécurité
                    *counter = (1, now);
                }
                
                // Vérifier si le seuil d'alerte est dépassé pour cette IP
                // Le seuil de 100 paquets SYN par minute est un exemple, idéalement configurable
                if counter.0 > 100 {
                    // Détecter une attaque SYN Flood potentielle et générer une alerte
                    let count = counter.0;
                    self.report_attack(ip, AttackType::SynFlood, count).await;
                    return Some(AttackType::SynFlood);
                }
            }
            
            // Détection des attaques Slowloris (connexions HTTP incomplètes)
            // Ces attaques sont plus difficiles à détecter au niveau paquet,
            // car elles nécessitent un suivi d'état des connexions HTTP
            if dst_port == 80 || dst_port == 443 {
                // Note: Une implémentation complète nécessiterait un suivi d'état
                // des connexions HTTP et leur progression, ce qui requiert une 
                // analyse au niveau applicatif et un maintien d'état des sessions
            }
        }
        
        None
    }
    
    /// Analyse un paquet ICMP pour détecter des attaques de type ping flood.
    /// Surveille le volume et le débit des requêtes ICMP pour identifier
    /// les tentatives de saturation par ICMP Echo (ping).
    async fn analyze_icmp_packet(&mut self, packet: &PacketInfo, now: SystemTime) -> Option<AttackType> {
        let ip = packet.source_ip;
        
        // Incrémenter le compteur ICMP pour cette IP dans la fenêtre d'analyse
        let counter = self.icmp_counters.entry(ip).or_insert((0, now));
        
        // Réinitialiser le compteur si la fenêtre d'analyse est dépassée
        // pour maintenir des statistiques pertinentes à la période actuelle
        if let Ok(elapsed) = now.duration_since(counter.1) {
            if elapsed.as_secs() > self.analysis_window {
                *counter = (1, now);
            } else {
                counter.0 += 1;
            }
        } else {
            // En cas d'erreur d'horloge système, réinitialiser par sécurité
            *counter = (1, now);
        }
        
        // Vérifier si le seuil d'alerte est dépassé pour les paquets ICMP
        // Le seuil de 50 paquets ICMP par minute est un exemple, devrait être ajustable
        if counter.0 > 50 {
            // Identifier une attaque ICMP Flood potentielle et générer une alerte
            let count = counter.0;
            self.report_attack(ip, AttackType::PingFlood, count).await;
            return Some(AttackType::PingFlood);
        }
        
        None
    }
    
    /// Analyse un paquet UDP pour détecter des attaques par amplification.
    /// Se concentre sur les ports utilisés pour les services amplifiables:
    /// DNS (53), NTP (123), SSDP (1900), etc.
    async fn analyze_udp_packet(&mut self, packet: &PacketInfo, now: SystemTime) -> Option<AttackType> {
        let ip = packet.source_ip;
        
        // Vérifier les requêtes vers des ports spécifiques utilisés pour l'amplification
        if let Some(dst_port) = packet.dest_port {
            // Traitement spécifique pour le port DNS (53)
            if dst_port == 53 {
                // Incrémenter le compteur DNS pour cette IP dans la fenêtre d'analyse
                let counter = self.dns_counters.entry(ip).or_insert((0, now));
                
                // Réinitialiser le compteur si la fenêtre d'analyse est dépassée
                if let Ok(elapsed) = now.duration_since(counter.1) {
                    if elapsed.as_secs() > self.analysis_window {
                        *counter = (1, now);
                    } else {
                        counter.0 += 1;
                    }
                } else {
                    // En cas d'erreur d'horloge système, réinitialiser
                    *counter = (1, now);
                }
                
                // Vérifier si le seuil d'alerte est dépassé pour les requêtes DNS
                // Le seuil de 200 requêtes DNS par minute est un exemple, à adapter selon l'environnement
                if counter.0 > 200 {
                    // Identifier une potentielle attaque d'amplification DNS et générer une alerte
                    let count = counter.0;
                    self.report_attack(ip, AttackType::DnsAmplification, count).await;
                    return Some(AttackType::DnsAmplification);
                }
            }
            
            // Vérifier les requêtes vers le port NTP (123) utilisé pour l'amplification NTP
            if dst_port == 123 {
                // Note: Une analyse complète des paquets NTP nécessiterait
                // l'inspection du contenu pour identifier les commandes monlist
                // qui peuvent être utilisées pour l'amplification (facteur jusqu'à 556x)
            }
        }
        
        None
    }
    
    /// Génère un rapport d'activité suspecte provenant d'une IP de botnet connue.
    /// Ces IPs sont considérées comme hautement malveillantes et font l'objet
    /// d'un blocage plus long que pour les attaques standards.
    async fn report_botnet_activity(&self, ip: IpAddr) {
        let message = format!("Activité de botnet détectée depuis l'IP {}", ip);
        
        // Récupérer la durée de blocage depuis la configuration globale
        let block_duration = {
            let config = self.config.read().await;
            // Pour les botnets, doubler la durée standard de blocage
            // car il s'agit d'IPs connues pour être compromises
            config.block_duration * 2
        };
        
        // Créer le rapport d'alerte avec niveau de sévérité élevé (9/10)
        let report = Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Alert,
            source_ip: Some(ip),
            message,
            details: None,
            severity: 9, // Haute sévérité pour les botnets confirmés
            suggested_action: Some(Action::Block(ip, Duration::from_secs(block_duration))),
        };
        
        // Envoyer le rapport au système central pour traitement
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport de botnet: {}", e);
        }
    }
    
    /// Génère un rapport d'attaque avec les détails pertinents et recommande
    /// une action de mitigation basée sur le type et l'intensité de l'attaque.
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
        
        // Déterminer la sévérité en fonction du type d'attaque et du volume
        // Plus le niveau est élevé, plus l'attaque est considérée dangereuse
        let severity = match attack_type {
            AttackType::SynFlood | AttackType::DnsAmplification | AttackType::NtpAmplification => {
                // Attaques à fort potentiel d'impact sur la disponibilité
                if count > 500 { 8 } else { 6 }
            },
            AttackType::PingFlood | AttackType::HttpFlood => {
                // Attaques à impact modéré, dépendant du volume
                if count > 1000 { 7 } else { 5 }
            },
            _ => 5, // Sévérité par défaut pour les autres types d'attaques
        };
        
        // Créer le rapport avec la sévérité appropriée et l'action recommandée
        let report = Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Alert,
            source_ip: Some(ip),
            message,
            details: None,
            severity,
            suggested_action: Some(Action::Block(ip, Duration::from_secs(block_duration))),
        };
        
        // Envoyer le rapport au système central pour traitement
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport d'attaque: {}", e);
        }
    }
    
    /// Nettoie périodiquement les compteurs obsolètes pour économiser la mémoire
    /// et éviter les fuites de mémoire pour les IPs non récurrentes.
    /// Cette méthode devrait être appelée régulièrement par un job planifié.
    pub async fn cleanup_counters(&mut self) {
        let now = SystemTime::now();
        
        // Supprimer les compteurs SYN inactifs depuis longtemps (2x la fenêtre d'analyse)
        // pour éviter l'accumulation de données pour des IPs transitoires
        self.syn_counters.retain(|_, (_, timestamp)| {
            if let Ok(elapsed) = now.duration_since(*timestamp) {
                elapsed.as_secs() <= self.analysis_window * 2
            } else {
                false
            }
        });
        
        // Supprimer les compteurs ICMP inactifs selon le même principe
        self.icmp_counters.retain(|_, (_, timestamp)| {
            if let Ok(elapsed) = now.duration_since(*timestamp) {
                elapsed.as_secs() <= self.analysis_window * 2
            } else {
                false
            }
        });
        
        // Supprimer les compteurs DNS inactifs selon le même principe
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
    
    /// Charge une liste d'adresses IP de botnets connus depuis un fichier externe.
    /// Format attendu: une adresse IP par ligne, commentaires avec # en début de ligne.
    /// Ces IPs seront automatiquement bloquées dès détection.
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
                
                // Parser l'adresse IP et l'ajouter à l'ensemble des botnets connus
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    self.botnet_ips.insert(ip);
                    count += 1;
                }
            }
        }
        
        info!("Chargé {} IPs de botnets connus depuis {}", count, path);
        Ok(())
    }
    
    /// Clone l'inspecteur pour utilisation dans des tâches asynchrones parallèles.
    /// Permet de partager l'inspecteur entre plusieurs threads de traitement.
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

/// Fonction utilitaire d'inspection rapide d'un paquet individuel.
/// Permet une analyse simple et immédiate sans contexte historique.
/// Utilisée comme première ligne de défense avant l'analyse approfondie.
pub fn inspect_packet(packet: &PacketInfo) -> Option<Action> {
    // Analyse des paquets TCP pour détecter les attaques SYN flood et scans de ports
    if packet.protocol == PacketType::Tcp {
        if let Some(ref flags) = packet.flags {
            // Détection de SYN flood: paquets SYN sans ACK vers ports web sensibles
            if flags.contains(&"SYN".to_string()) && !flags.contains(&"ACK".to_string()) {
                if let Some(port) = packet.dest_port {
                    if port == 80 || port == 443 || port == 8080 {
                        debug!("Paquet SYN détecté vers le port {}: {}", port, packet.source_ip);
                    }
                }
            }
            
            // Détection de scan Xmas: combinaison FIN+URG+PSH (technique de scan furtif)
            // Ce pattern est très rarement légitime et indique souvent une reconnaissance
            if flags.contains(&"FIN".to_string()) && 
               flags.contains(&"URG".to_string()) && 
               flags.contains(&"PSH".to_string()) {
                warn!("Tentative de scan Xmas détectée depuis {}", packet.source_ip);
                return Some(Action::Block(packet.source_ip, Duration::from_secs(1800)));
            }
        }
    }
    
    // Analyse des paquets ICMP pour détecter les attaques par saturation
    if packet.protocol == PacketType::Icmp {
        // Détection de paquets ICMP anormalement grands (tentative d'amplification)
        // Les paquets ICMP légitimes dépassent rarement 1000 octets
        if packet.size > 1000 {
            warn!("Paquet ICMP de grande taille détecté: {} octets depuis {}", 
                  packet.size, packet.source_ip);
            return Some(Action::Block(packet.source_ip, Duration::from_secs(900)));
        }
    }
    
    // Analyse des paquets UDP pour détecter les attaques d'amplification
    // sur différents services vulnérables aux techniques d'amplification
    if packet.protocol == PacketType::Udp {
        if let Some(port) = packet.dest_port {
            match port {
                53 => {
                    // Détection d'attaques par amplification DNS
                    // Les petites requêtes peuvent générer de grandes réponses (facteur > 50x)
                    if packet.size < 40 {
                        debug!("Petite requête DNS depuis {} (potentielle amplification)", 
                              packet.source_ip);
                    }
                },
                123 => {
                    // Détection d'attaques par amplification NTP
                    // La commande monlist peut amplifier le trafic jusqu'à 556x
                    debug!("Trafic NTP détecté depuis {}", packet.source_ip);
                },
                389 => {
                    // Détection d'attaques par amplification LDAP (facteur > 50x)
                    warn!("Potentielle attaque d'amplification LDAP depuis {}", packet.source_ip);
                    return Some(Action::RateLimit(packet.source_ip));
                },
                1900 => {
                    // Détection d'attaques par amplification SSDP (facteur 30x)
                    warn!("Potentielle attaque d'amplification SSDP depuis {}", packet.source_ip);
                    return Some(Action::RateLimit(packet.source_ip));
                },
                11211 => {
                    // Détection d'attaques par amplification Memcached (facteur >50000x)
                    // Cette technique est extrêmement puissante et destructrice
                    warn!("Potentielle attaque d'amplification Memcached depuis {}", packet.source_ip);
                    return Some(Action::Block(packet.source_ip, Duration::from_secs(3600)));
                },
                _ => {}
            }
        }
    }
    
    // Détection des tentatives d'évasion par TTL anormalement bas
    // Cette technique est utilisée pour éviter la détection par certains firewalls
    if let Some(ttl) = packet.ttl {
        if ttl < 5 {
            warn!("Paquet avec TTL très bas ({}) détecté depuis {}", ttl, packet.source_ip);
            return Some(Action::Block(packet.source_ip, Duration::from_secs(300)));
        }
    }
    
    None
} 
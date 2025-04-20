use crate::analyzer::Analyzer;
use crate::config::{Config, ServiceState};
use crate::defender::Defender;
use crate::logger::Logger;
use crate::models::{Action, GlobalStats, IpStats, PacketInfo, PacketType, Report, ReportType};
use log::{debug, error, info, warn};
use pcap::{Capture, Device};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use std::process::Command;
use futures::executor;

pub struct ZdefenderService {
    config: Arc<RwLock<Config>>,
    logger: Arc<Logger>,
    analyzer: Option<Arc<Analyzer>>,
    defender: Option<Arc<RwLock<Defender>>>,
    packet_tx: Option<mpsc::Sender<PacketInfo>>,
    report_tx: Option<mpsc::Sender<Report>>,
    tasks: Vec<JoinHandle<()>>,
    running: bool,
}

impl ZdefenderService {
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        // Récupérer les paramètres de configuration pour le logger
        let log_config = executor::block_on(async {
            let config_guard = config.read().await;
            (config_guard.log_file.clone(), config_guard.log_mode)
        });
        
        Self {
            config,
            logger: Arc::new(Logger::new_with_mode(log_config.0, log_config.1)),
            analyzer: None,
            defender: None,
            packet_tx: None,
            report_tx: None,
            tasks: Vec::new(),
            running: false,
        }
    }

    pub async fn start_active(&self) {
        self.start(true).await;
    }

    pub async fn start_passive(&self) {
        self.start(false).await;
    }

    async fn start(&self, active: bool) {
        // Vérifier si le service est déjà en cours d'exécution
        if self.running {
            info!("Le service est déjà en cours d'exécution");
            return;
        }

        // Mise à jour de la configuration
        {
            let mut config = self.config.write().await;
            config.service_state = if active {
                ServiceState::Active
            } else {
                ServiceState::Passive
            };
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
            }
        }

        // Initialiser les canaux de communication
        let (packet_tx, mut packet_rx) = mpsc::channel::<PacketInfo>(1000);
        let (report_tx, mut report_rx) = mpsc::channel::<Report>(100);

        // Créer l'analyseur
        let analyzer = Arc::new(Analyzer::new(self.config.clone(), report_tx.clone()));

        // Créer le défenseur si en mode actif
        let defender = if active {
            Some(Arc::new(RwLock::new(Defender::new(
                self.config.clone(),
                self.logger.clone(),
            ).await)))
        } else {
            None
        };

        // Démarrer la tâche d'analyse des paquets
        let analyzer_clone = analyzer.clone();
        let _packet_task = tokio::spawn(async move {
            while let Some(packet) = packet_rx.recv().await {
                analyzer_clone.analyze_packet(packet).await;
            }
        });

        // Démarrer la tâche de traitement des rapports si en mode actif
        let _report_task = if active {
            let defender_clone = defender.clone().unwrap();
            Some(tokio::spawn(async move {
                while let Some(report) = report_rx.recv().await {
                    let mut defender = defender_clone.write().await;
                    defender.handle_report(report).await;
                }
            }))
        } else {
            None
        };

        // Démarrer la tâche de nettoyage périodique
        let analyzer_clone = analyzer.clone();
        let _cleanup_task = tokio::spawn(async move {
            let interval = Duration::from_secs(60); // Nettoyer toutes les minutes
            loop {
                tokio::time::sleep(interval).await;
                analyzer_clone.clear_expired_blocks().await;
            }
        });

        // Démarrer la capture de paquets pour chaque interface
        let interfaces = {
            let config = self.config.read().await;
            config.interfaces.clone()
        };

        let mut capture_tasks = Vec::new();
        for interface_name in interfaces {
            let packet_tx = packet_tx.clone();
            let logger = self.logger.clone();
            
            let capture_task = tokio::spawn(async move {
                // Tenter d'ouvrir l'interface
                let devices = match Device::list() {
                    Ok(devices) => devices,
                    Err(e) => {
                        error!("Erreur lors de la liste des interfaces: {}", e);
                        return;
                    }
                };
                
                let device = match devices.into_iter().find(|d| d.name == interface_name) {
                    Some(device) => device,
                    None => {
                        error!("Interface {} non trouvée", interface_name);
                        return;
                    }
                };
                
                info!("Démarrage de la capture sur l'interface {}", interface_name);
                
                match Capture::from_device(device).unwrap()
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(1000)
                    .open()
                {
                    Ok(mut capture) => {
                        loop {
                            match capture.next_packet() {
                                Ok(packet) => {
                                    // Analyser et envoyer le paquet
                                    if let Some(packet_info) = parse_packet(packet.data) {
                                        logger.log_packet(&packet_info);
                                        if let Err(e) = packet_tx.send(packet_info).await {
                                            error!("Erreur lors de l'envoi du paquet pour analyse: {}", e);
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Ignorer les erreurs de timeout
                                    if !e.to_string().contains("timed out") {
                                        error!("Erreur lors de la capture de paquet: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Erreur lors de l'ouverture de l'interface {}: {}", interface_name, e);
                    }
                }
            });
            
            capture_tasks.push(capture_task);
        }

        // Stocker les références pour un arrêt ultérieur
        // Notez que nous ne pouvons pas modifier l'instance self directement car elle est immutable
        // Dans une implémentation réelle, vous auriez besoin d'une structure mutable ou d'un Arc<RwLock<>>
        
        info!("Service {} démarré", if active { "actif" } else { "passif" });
    }

    pub async fn stop(&self) {
        // Mise à jour de la configuration
        {
            let mut config = self.config.write().await;
            config.service_state = ServiceState::Stopped;
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
            }
        }

        // Ici, nous devrions annuler toutes les tâches en cours, mais cela nécessiterait
        // une conception différente avec des signaux d'arrêt ou des drapeaux d'annulation
        
        info!("Service arrêté");
    }

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
            ServiceState::Active => "Actif",
            ServiceState::Passive => "Passif",
            ServiceState::Stopped => "Arrêté",
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

    pub async fn enable_fortress(&self) {
        if let Some(defender) = &self.defender {
            let mut defender = defender.write().await;
            defender.enable_fortress_mode().await;
        } else {
            // Créer temporairement un défenseur pour activer le mode forteresse
            let mut defender = Defender::new(self.config.clone(), self.logger.clone()).await;
            defender.enable_fortress_mode().await;
        }
    }

    pub async fn disable_fortress(&self) {
        if let Some(defender) = &self.defender {
            let mut defender = defender.write().await;
            defender.disable_fortress_mode().await;
        } else {
            // Créer temporairement un défenseur pour désactiver le mode forteresse
            let mut defender = Defender::new(self.config.clone(), self.logger.clone()).await;
            defender.disable_fortress_mode().await;
        }
    }

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

    pub async fn reload_config(&self) {
        info!("Rechargement de la configuration...");
        
        // Charger la nouvelle configuration depuis le fichier
        match Config::load() {
            Ok(new_config) => {
                let mut config = self.config.write().await;
                *config = new_config;
                info!("Configuration rechargée avec succès");
                
                // Afficher un résumé des paramètres importants
                let state = match config.service_state {
                    ServiceState::Active => "Actif",
                    ServiceState::Passive => "Passif",
                    ServiceState::Stopped => "Arrêté",
                };
                
                let fortress_mode = if config.fortress_mode {
                    "Activé"
                } else {
                    "Désactivé"
                };
                
                info!("État actuel: {}", state);
                info!("Mode forteresse: {}", fortress_mode);
                info!("Interfaces surveillées: {}", config.interfaces.join(", "));
                info!("Seuil de paquets: {} paquets/sec", config.packet_threshold);
            },
            Err(e) => {
                error!("Erreur lors du rechargement de la configuration: {}", e);
            }
        }
    }
}

fn parse_packet(packet_data: &[u8]) -> Option<PacketInfo> {
    if let Some(ethernet) = EthernetPacket::new(packet_data) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    return parse_ip_packet(
                        IpAddr::V4(ipv4.get_source()),
                        IpAddr::V4(ipv4.get_destination()),
                        ipv4.get_next_level_protocol(),
                        ipv4.payload(),
                        ipv4.payload().len(),
                    );
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                    return parse_ip_packet(
                        IpAddr::V6(ipv6.get_source()),
                        IpAddr::V6(ipv6.get_destination()),
                        ipv6.get_next_header(),
                        ipv6.payload(),
                        ipv6.payload().len(),
                    );
                }
            }
            _ => {
                // Protocole non géré
            }
        }
    }
    None
}

fn parse_ip_packet(
    source_ip: IpAddr,
    destination_ip: IpAddr,
    protocol: IpNextHeaderProtocol,
    payload: &[u8],
    size: usize,
) -> Option<PacketInfo> {
    let (protocol_type, source_port, destination_port) = match protocol {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(payload) {
                (
                    PacketType::Tcp,
                    Some(tcp.get_source()),
                    Some(tcp.get_destination()),
                )
            } else {
                (PacketType::Tcp, None, None)
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(payload) {
                (
                    PacketType::Udp,
                    Some(udp.get_source()),
                    Some(udp.get_destination()),
                )
            } else {
                (PacketType::Udp, None, None)
            }
        }
        IpNextHeaderProtocols::Icmp => (PacketType::Icmp, None, None),
        _ => (PacketType::Other, None, None),
    };

    let timestamp = SystemTime::now();
    let dest_ip = destination_ip;
    let dest_port = destination_port;
    let _flags = 0;
    let _ttl = 64;

    Some(PacketInfo {
        timestamp,
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        protocol: protocol_type,
        size,
        flags: None,
        ttl: Some(64),
    })
} 
use crate::logger::Logger;
use crate::models::PacketInfo;
use crate::config::Config;
use log::{error, info};
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
use std::time::SystemTime;
use tokio::sync::{mpsc, RwLock};
use std::thread;
use tokio::task::JoinSet;

/// Démarre la capture de paquets sur les interfaces configurées
pub async fn start_packet_capture(
    config: Arc<RwLock<Config>>,
    packet_tx: mpsc::Sender<PacketInfo>,
    logger: Arc<Logger>,
) {
    // Lire la configuration
    let interfaces = {
        let config_guard = config.read().await;
        config_guard.interfaces.clone()
    };
    
    let mut tasks = JoinSet::new();

    for interface_name in interfaces {
        let packet_tx = packet_tx.clone();
        let logger = logger.clone();
        let config = config.clone();
        
        tasks.spawn(async move {
            capture_on_interface(interface_name, packet_tx, logger, config).await;
        });
    }
    
    // Les tâches s'exécuteront en arrière-plan
    info!("Capture de paquets démarrée sur toutes les interfaces");
}

// Fonction qui gère la capture sur une seule interface
async fn capture_on_interface(
    interface_name: String,
    packet_tx: mpsc::Sender<PacketInfo>,
    logger: Arc<Logger>,
    config: Arc<RwLock<Config>>,
) {
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
    
    // Récupérer le nombre de threads d'analyse
    let analyzer_threads = {
        let config_guard = config.read().await;
        config_guard.analyzer_threads
    };
    
    // Créer un canal broadcast pour distribuer les paquets bruts entre les threads d'analyse
    let (raw_packet_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(1000);
    let raw_packet_tx = Arc::new(raw_packet_tx);
    
    // Cloner interface_name pour le thread de capture
    let capture_interface_name = interface_name.clone();
    
    // Lancer la capture dans un thread séparé car la bibliothèque pcap bloque
    let raw_packet_tx_clone = raw_packet_tx.clone();
    let _capture_thread = thread::spawn(move || {
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
                            let data = packet.data.to_vec();
                            // Envoyer le paquet brut au channel broadcast
                            let _ = raw_packet_tx_clone.send(data);
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
                error!("Erreur lors de l'ouverture de l'interface {}: {}", capture_interface_name, e);
            }
        }
    });
    
    // Créer plusieurs tâches pour traiter les paquets
    for i in 0..analyzer_threads {
        let logger = logger.clone();
        let packet_tx = packet_tx.clone();
        let mut raw_packet_rx = raw_packet_tx.subscribe();
        let analyzer_interface_name = interface_name.clone();
        
        tokio::spawn(async move {
            info!("Démarrage de l'analyseur {} pour l'interface {}", i, analyzer_interface_name);
            while let Ok(packet_data) = raw_packet_rx.recv().await {
                if let Some(packet_info) = parse_packet(&packet_data) {
                    logger.log_packet(&packet_info);
                    if let Err(e) = packet_tx.send(packet_info).await {
                        error!("Erreur lors de l'envoi du paquet pour analyse: {}", e);
                        break;
                    }
                }
            }
        });
    }
}

/// Analyse un paquet réseau brut et retourne une structure PacketInfo
pub fn parse_packet(packet_data: &[u8]) -> Option<PacketInfo> {
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

/// Analyse un paquet IP et extrait les informations pertinentes
pub fn parse_ip_packet(
    source_ip: IpAddr,
    destination_ip: IpAddr,
    protocol: IpNextHeaderProtocol,
    payload: &[u8],
    size: usize,
) -> Option<PacketInfo> {
    use crate::models::PacketType;
    
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
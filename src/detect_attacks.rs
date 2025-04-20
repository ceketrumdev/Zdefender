use std::net::SocketAddr;
use std::time::Duration;
use log::{debug, info, warn};
use crate::models::{Action, PacketInfo, IpStats, PacketType};

/// Détecte des attaques potentielles basé sur les métriques de l'IP
pub fn detect_attacks(
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
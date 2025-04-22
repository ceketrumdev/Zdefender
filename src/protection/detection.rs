//! Module de détection de menaces
//!
//! Ce module contient les fonctions avancées pour détecter les menaces
//! et les attaques réseau comme SYN floods, DDoS, etc.

use super::ProtectionManager;
use crate::models::{Action, PacketInfo, PacketType};
use futures;
use log::{debug, info, warn};
use rand::Rng;
use std::time::Duration;

impl ProtectionManager {
    /// Traite un paquet et décide de l'action à prendre
    pub async fn process_packet(&mut self, packet: PacketInfo) -> Option<Action> {
        // Vérifier si nous sommes en mode forteresse
        if self.fortress_mode_active {
            return self.process_packet_fortress_mode(&packet).await;
        }
        
        // Vérifier si la protection DDoS est active
        if self.ddos_protection_active {
            if let Some(action) = self.process_packet_ddos_mode(&packet).await {
                return Some(action);
            }
        }
        
        // Vérifier si l'IP est déjà bloquée
        if let Some(blocked_ip) = {
            let blocked_ips = self.blocked_ips.read().await;
            if blocked_ips.contains(&packet.source_ip) {
                Some(packet.source_ip)
            } else {
                None
            }
        } {
            // Vérifier si le blocage est toujours actif
            let block_expiry = self.block_expiry.read().await;
            if let Some(expiry) = block_expiry.get(&blocked_ip) {
                if expiry > &std::time::SystemTime::now() {
                    return Some(Action::Drop);
                } else {
                    // Retirer l'IP de la liste des IPs bloquées
                    let mut blocked_ips = self.blocked_ips.write().await;
                    blocked_ips.remove(&blocked_ip);
                    
                    let mut block_expiry = self.block_expiry.write().await;
                    block_expiry.remove(&blocked_ip);
                }
            }
        }
        
        // Vérifier les règles spécifiques au protocole
        if let Some(action) = self.check_protocol_rules(&packet) {
            return Some(action);
        }
        
        // Si aucune règle n'a déclenché d'action, autoriser le paquet
        None
    }
    
    /// Traite un paquet en mode forteresse
    async fn process_packet_fortress_mode(&self, packet: &PacketInfo) -> Option<Action> {
        // En mode forteresse, nous sommes très restrictifs
        // 1. Vérifier si l'IP est en liste blanche
        let config = futures::executor::block_on(async { self.config.read().await.clone() });
        if config.whitelist.iter().any(|ip| ip == &packet.source_ip.to_string()) {
            // Autoriser les IPs en liste blanche
            return None;
        }
        
        // 2. Vérifier le type de protocole
        match packet.protocol {
            PacketType::Tcp => {
                // Vérifier si c'est une nouvelle connexion TCP (SYN sans ACK)
                if let Some(ref flags) = packet.flags {
                    if flags.contains(&"SYN".to_string()) && !flags.contains(&"ACK".to_string()) {
                        // Bloquer les nouvelles connexions en mode forteresse
                        return Some(Action::Block(
                            packet.source_ip,
                            Duration::from_secs(config.block_duration)
                        ));
                    }
                }
            },
            PacketType::Udp => {
                // Bloquer tout trafic UDP en mode forteresse sauf vers les ports essentiels
                if let Some(port) = packet.dest_port {
                    if !config.essential_ports.contains(&port) {
                        return Some(Action::Drop);
                    }
                } else {
                    return Some(Action::Drop);
                }
            },
            PacketType::Icmp => {
                // Autoriser l'ICMP en quantité limitée
                return Some(Action::RateLimit(packet.source_ip));
            },
            _ => {
                // Bloquer tous les autres protocoles en mode forteresse
                return Some(Action::Drop);
            }
        }
        
        None // Autoriser le paquet si aucune règle ne l'a bloqué
    }
    
    /// Traite un paquet en mode protection DDoS
    async fn process_packet_ddos_mode(&self, packet: &PacketInfo) -> Option<Action> {
        // Vérifier si l'IP est en liste blanche
        let config = futures::executor::block_on(async { self.config.read().await.clone() });
        if !config.whitelist.iter().any(|ip| ip == &packet.source_ip.to_string()) {
            // Pour les IPs non en liste blanche, appliquer un échantillonnage du trafic
            let mut rng = rand::rng();
            let sample = rng.random_bool(self.rate_limit_factor);
            
            if !sample {
                // Rejeter aléatoirement une partie du trafic en fonction du facteur de limitation
                return Some(Action::Drop);
            }
            
            // Pour le trafic qui passe, appliquer une limitation de débit par IP
            return Some(Action::RateLimit(packet.source_ip));
        }
        
        None // Autoriser le paquet si l'IP est en liste blanche
    }
    
    /// Vérifie les règles spécifiques au protocole
    fn check_protocol_rules(&mut self, packet: &PacketInfo) -> Option<Action> {
        match packet.protocol {
            PacketType::Tcp => {
                // Vérifier les connexions TCP suspectes (comme les SYN floods)
                if let Some(ref flags) = packet.flags {
                    if flags.contains(&"SYN".to_string()) && !flags.contains(&"ACK".to_string()) {
                        // Incrémenter le compteur de SYN
                        self.syn_count += 1;
                        self.total_count += 1;
                        
                        // Calculer le pourcentage de SYN par rapport au total
                        let syn_percentage = (self.syn_count as f64) / (self.total_count as f64);
                        
                        // Si le pourcentage dépasse le seuil, nous avons peut-être un SYN flood
                        if syn_percentage > self.threshold_syn_percentage && self.total_count > 100 {
                            let config = futures::executor::block_on(async { self.config.read().await.clone() });
                            
                            // Vérifier si l'IP est en liste blanche
                            if !config.whitelist.iter().any(|ip| ip == &packet.source_ip.to_string()) {
                                // Bloquer l'IP
                                let _ = futures::executor::block_on(async {
                                    self.block_ip(
                                        packet.source_ip,
                                        Duration::from_secs(config.block_duration),
                                        "SYN flood suspect détecté"
                                    ).await
                                });
                                
                                return Some(Action::Block(
                                    packet.source_ip,
                                    Duration::from_secs(config.block_duration)
                                ));
                            }
                        }
                    } else {
                        // Incrémenter seulement le total pour les non-SYN
                        self.total_count += 1;
                    }
                }
            },
            PacketType::Udp => {
                // Vérifier les attaques UDP flood
                // TODO: Implémenter une détection d'UDP flood
            },
            PacketType::Icmp => {
                // Vérifier les attaques ICMP flood
                // TODO: Implémenter une détection d'ICMP flood
            },
            _ => {}
        }
        
        None
    }
    
    /// Configure les seuils de détection
    pub fn set_thresholds(&mut self, packets_per_second: f64, syn_percentage: f64) {
        self.threshold_packets_per_second = packets_per_second;
        self.threshold_syn_percentage = syn_percentage;
        
        info!("Seuils de détection configurés: pps={}, syn_percentage={}", 
              packets_per_second, syn_percentage);
    }
} 
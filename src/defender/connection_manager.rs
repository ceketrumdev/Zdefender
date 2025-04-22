//! Gestion des connexions réseau établies
//!
//! Ce module est responsable de la gestion des connexions réseau,
//! du suivi des connexions établies et de la mise à jour des listes blanches.

use super::Defender;
use crate::models::EstablishedConnection;
use log::{debug, info};
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, SystemTime};

impl Defender {
    /// Enregistre une nouvelle connexion ou met à jour une connexion existante
    pub async fn register_connection(&self, ip: IpAddr, request_type: Option<String>) {
        let now = SystemTime::now();
        let mut entry = self.established_connections
            .entry(ip)
            .or_insert_with(|| EstablishedConnection::new(ip));
        
        entry.update_activity();
        
        // Calculer le score de confiance basé sur la durée de la connexion
        if let Ok(duration) = now.duration_since(entry.created_at) {
            // Augmenter progressivement le score de confiance avec le temps
            let duration_factor = (duration.as_secs() as f64 / 3600.0).min(1.0); // Plafonné à 1h
            entry.trust_score = (entry.trust_score + duration_factor * 0.1).min(1.0);
        }
        
        // Ajouter le type de requête s'il est fourni
        if let Some(req_type) = request_type {
            entry.add_request_type(req_type);
        }
        
        // Marquer la connexion comme établie si elle a envoyé plusieurs paquets
        if entry.packet_count >= 3 && !entry.is_established {
            entry.is_established = true;
            debug!("Connexion marquée comme établie pour l'IP: {}", ip);
        }
        
        // Vérifier si cette IP devrait être automatiquement mise en liste blanche
        let should_auto_whitelist = {
            let config = self.config.read().await;
            if let Ok(duration) = now.duration_since(entry.created_at) {
                config.should_auto_whitelist(entry.trust_score, duration.as_secs())
            } else {
                false
            }
        };
        
        if should_auto_whitelist {
            // Ajouter l'IP à la whitelist temporaire
            let mut whitelist = self.temp_whitelist.write().await;
            if !whitelist.contains(&ip) {
                whitelist.insert(ip);
                info!("IP {} automatiquement ajoutée à la whitelist temporaire (score: {:.2})", 
                     ip, entry.trust_score);
            }
        }
    }
    
    /// Nettoie les connexions inactives plus anciennes que max_inactivity
    pub async fn cleanup_old_connections(&self, max_inactivity: Duration) {
        let now = SystemTime::now();
        let mut ips_to_remove = Vec::new();
        
        // Identifier les connexions inactives
        for conn in self.established_connections.iter() {
            if let Ok(inactive_time) = now.duration_since(conn.last_activity) {
                if inactive_time > max_inactivity {
                    ips_to_remove.push(conn.ip);
                }
            }
        }
        
        // Supprimer les connexions inactives
        for ip in ips_to_remove {
            self.established_connections.remove(&ip);
            
            // Si l'IP est dans la whitelist temporaire, la supprimer
            {
                let mut whitelist = self.temp_whitelist.write().await;
                if whitelist.remove(&ip) && self.fortress_mode {
                    // Supprimer l'exception iptables
                    let _ = Command::new("iptables")
                        .args(["-D", "INPUT", "-s", &ip.to_string(), "-j", "ACCEPT"])
                        .output();
                    
                    info!("IP inactive retirée de la whitelist: {}", ip);
                }
            }
        }
    }
    
    /// Vérifie si une IP est dans la liste blanche temporaire
    pub async fn is_whitelisted(&self, ip: IpAddr) -> bool {
        let whitelist = self.temp_whitelist.read().await;
        whitelist.contains(&ip)
    }
    
    /// Récupère la liste des connexions établies
    pub async fn get_established_connections(&self) -> Vec<EstablishedConnection> {
        let mut connections = Vec::new();
        for entry in self.established_connections.iter() {
            connections.push(entry.value().clone());
        }
        connections
    }
    
    /// Bloque une adresse IP pour une durée spécifiée
    pub(crate) async fn block_ip(&self, ip: IpAddr, duration_secs: u64) {
        debug!("Tentative de blocage de l'IP {}", ip);
        
        // Vérifier si l'IP est dans la liste blanche
        let whitelist = {
            let config = self.config.read().await;
            config.whitelist.clone()
        };
        
        if whitelist.iter().any(|allowed| allowed == &ip.to_string()) {
            info!("Tentative de blocage d'une IP en liste blanche ignorée: {}", ip);
            return;
        }
        
        // Utiliser iptables pour bloquer l'IP
        let output = Command::new("iptables")
            .args([
                "-A", "INPUT", 
                "-s", &ip.to_string(),
                "-j", "DROP"
            ])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    info!("IP {} bloquée avec succès", ip);
                    self.logger.log_block(ip, duration_secs);
                    
                    // Programmer le déblocage si nécessaire
                    let defender_clone = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
                        defender_clone.unblock_ip(ip).await;
                    });
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    info!("Erreur lors du blocage de l'IP {}: {}", ip, stderr);
                }
            }
            Err(e) => {
                info!("Erreur lors de l'exécution de la commande iptables: {}", e);
            }
        }
    }

    /// Débloque une adresse IP précédemment bloquée
    pub(crate) async fn unblock_ip(&self, ip: IpAddr) {
        debug!("Tentative de déblocage de l'IP {}", ip);
        
        // Utiliser iptables pour débloquer l'IP
        let output = Command::new("iptables")
            .args([
                "-D", "INPUT", 
                "-s", &ip.to_string(),
                "-j", "DROP"
            ])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    info!("IP {} débloquée avec succès", ip);
                    self.logger.log_unblock(ip);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    info!("Erreur lors du déblocage de l'IP {}: {}", ip, stderr);
                }
            }
            Err(e) => {
                info!("Erreur lors de l'exécution de la commande iptables: {}", e);
            }
        }
    }
} 
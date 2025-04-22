//! Module de gestion des IPs bloquées
//!
//! Ce module gère le blocage et le déblocage des adresses IP, ainsi que
//! le suivi des expirations de blocage.

use super::ProtectionManager;
use crate::models::{ReportType, BlockedIp};
use log::{debug, error, info};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

impl ProtectionManager {
    /// Vérifie si une IP est actuellement bloquée
    pub async fn is_blocked(&self, ip: IpAddr) -> bool {
        let blocked_ips = self.blocked_ips.read().await;
        blocked_ips.contains(&ip)
    }
    
    /// Vérifie si une IP est actuellement bloquée (version synchrone)
    pub fn is_blocked_sync(&self, ip: IpAddr) -> bool {
        // Vérifier dans le vecteur des IPs bloquées
        self.blocked_ips_vec.iter().any(|blocked| blocked.ip == ip && !blocked.is_expired())
    }
    
    /// Bloque une adresse IP pour une durée spécifiée
    pub async fn block_ip(&self, ip: IpAddr, duration: Duration, reason: &str) {
        // Vérifier si l'IP est déjà bloquée
        let mut blocked_ips = self.blocked_ips.write().await;
        if blocked_ips.contains(&ip) {
            debug!("IP {} déjà bloquée, mise à jour de la durée", ip);
        } else {
            info!("Blocage de l'IP {} pour une durée de {:?} - Raison: {}", ip, duration, reason);
        }
        
        // Ajouter l'IP à la liste des bloquées
        blocked_ips.insert(ip);
        
        // Calculer le moment d'expiration
        let expiry = SystemTime::now() + duration;
        
        // Mettre à jour l'expiration
        let mut block_expiry = self.block_expiry.write().await;
        block_expiry.insert(ip, expiry);
        
        // Envoyer un rapport de blocage
        self.send_report(
            ReportType::Action,
            format!("IP {} bloquée pour {:?}", ip, duration),
            Some(ip),
            Some(format!("Raison: {}", reason)),
            8,
        );
    }
    
    /// Retire une IP de la liste des bloquées
    pub async fn unblock_ip(&self, ip: IpAddr) {
        // Retirer l'IP de la liste des bloquées
        {
            let mut blocked_ips = self.blocked_ips.write().await;
            blocked_ips.remove(&ip);
        }
        
        // Retirer l'expiration
        {
            let mut block_expiry = self.block_expiry.write().await;
            block_expiry.remove(&ip);
        }
        
        // Générer un rapport de déblocage
        let message = format!("IP {} débloquée", ip);
        
        let report = crate::models::Report {
            timestamp: SystemTime::now(),
            report_type: ReportType::Info,
            source_ip: Some(ip),
            message,
            details: None,
            severity: 0,
            suggested_action: None,
        };
        
        // Envoyer le rapport
        if let Err(e) = self.report_tx.send(report).await {
            error!("Erreur lors de l'envoi du rapport de déblocage: {}", e);
        }
    }
    
    /// Nettoie les blocages expirés
    pub async fn cleanup_expired_blocks(&self) {
        let now = SystemTime::now();
        let mut ips_to_unblock = Vec::new();
        
        // Identifier les IPs à débloquer
        {
            let block_expiry = self.block_expiry.read().await;
            for (ip, expiry) in block_expiry.iter() {
                if let Ok(_) = expiry.duration_since(now) {
                    // Pas encore expiré
                    continue;
                }
                
                // Expiré, ajouter à la liste à débloquer
                ips_to_unblock.push(*ip);
            }
        }
        
        // Débloquer les IPs expirées
        for ip in ips_to_unblock {
            self.unblock_ip(ip).await;
        }
    }
    
    /// Nettoie les blocages expirés (version synchrone)
    pub fn synchronous_cleanup_expired_blocks(&mut self) -> usize {
        let initial_count = self.blocked_ips_vec.len();
        self.blocked_ips_vec.retain(|blocked| !blocked.is_expired());
        let removed = initial_count - self.blocked_ips_vec.len();
        if removed > 0 {
            info!("{} IP(s) débloquée(s) après expiration", removed);
        }
        removed
    }
    
    /// Récupère la durée de blocage depuis la configuration
    pub async fn get_block_duration(&self) -> u64 {
        let config = self.config.read().await;
        config.block_duration
    }
} 
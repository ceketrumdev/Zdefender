//! Module de gestion du mode forteresse
//!
//! Ce module gère l'activation et la désactivation du mode forteresse
//! qui offre une protection maximale contre les attaques.

use super::ProtectionManager;
use log::{info, warn};
use std::sync::Arc;

impl ProtectionManager {
    /// Active le mode forteresse
    pub fn enable_fortress_mode(&mut self) {
        self.fortress_mode = true;
        self.fortress_mode_active = true;
        
        self.send_report(
            crate::models::ReportType::Info,
            "Mode forteresse activé".to_string(),
            None,
            Some("Protection maximale activée, toutes les connexions non établies seront rejetées".to_string()),
            8,
        );
        
        info!("Mode forteresse activé pour le gestionnaire de protection");
    }

    /// Désactive le mode forteresse
    pub fn disable_fortress_mode(&mut self) {
        if !self.fortress_mode {
            warn!("Tentative de désactivation du mode forteresse déjà désactivé");
            return;
        }
        
        self.fortress_mode = false;
        self.fortress_mode_active = false;
        
        self.send_report(
            crate::models::ReportType::Info,
            "Mode forteresse désactivé".to_string(),
            None,
            None,
            5,
        );
        
        info!("Mode forteresse désactivé pour le gestionnaire de protection");
    }
    
    /// Vérifie si le mode forteresse est actif
    pub fn is_fortress_mode_active(&self) -> bool {
        self.fortress_mode_active
    }
    
    /// Active le mode de protection contre les attaques DDoS distribuées
    pub async fn enable_ddos_protection(&mut self, intensity: f64) {
        // Créer une copie locale de self.config pour éviter les problèmes de borrowing
        let config_arc = Arc::clone(&self.config);
        let config = config_arc.read().await.clone();
        
        // Activer le mode forteresse si configuré
        if config.ddos_auto_fortress {
            if !self.fortress_mode_active {
                self.fortress_mode_active = true;
                
                // Envoyer un rapport d'activation du mode forteresse
                let report = crate::models::Report {
                    timestamp: std::time::SystemTime::now(),
                    report_type: crate::models::ReportType::Action,
                    source_ip: None,
                    message: "MODE FORTERESSE activé suite à une attaque DDoS distribuée".to_string(),
                    details: Some(format!("Intensité de l'attaque: {:.2}", intensity)),
                    severity: 9,
                    suggested_action: Some(crate::models::Action::EnableFortress),
                };
                
                if let Err(e) = self.report_tx.send(report).await {
                    warn!("Erreur lors de l'envoi du rapport d'activation du mode forteresse: {}", e);
                }
            }
        }
        
        // Selon l'intensité de l'attaque, adapter la protection
        let rate_limit_factor = if intensity > 0.8 {
            // Forte intensité
            0.1 // Limiter à 10% du trafic normal
        } else if intensity > 0.5 {
            // Intensité moyenne
            0.3 // Limiter à 30% du trafic normal
        } else {
            // Faible intensité
            0.5 // Limiter à 50% du trafic normal
        };
        
        self.ddos_protection_active = true;
        self.rate_limit_factor = rate_limit_factor;
        
        info!("Protection DDoS activée avec facteur de limitation: {}", rate_limit_factor);
    }

    /// Désactive le mode de protection contre les attaques DDoS distribuées
    pub async fn disable_ddos_protection(&mut self) {
        // Créer une copie locale de self.config pour éviter les problèmes de borrowing
        let config_arc = Arc::clone(&self.config);
        
        // Désactiver le mode forteresse si activé par la protection DDoS
        if self.ddos_protection_active && self.fortress_mode_active {
            // Vérifier si le mode forteresse doit être désactivé
            let config = config_arc.read().await.clone();
            if config.ddos_auto_fortress {
                self.fortress_mode_active = false;
                
                // Envoyer un rapport de désactivation du mode forteresse
                let report = crate::models::Report {
                    timestamp: std::time::SystemTime::now(),
                    report_type: crate::models::ReportType::Action,
                    source_ip: None,
                    message: "MODE FORTERESSE désactivé, fin de l'attaque DDoS distribuée".to_string(),
                    details: None,
                    severity: 6,
                    suggested_action: Some(crate::models::Action::DisableFortress),
                };
                
                if let Err(e) = self.report_tx.send(report).await {
                    warn!("Erreur lors de l'envoi du rapport de désactivation du mode forteresse: {}", e);
                }
            }
        }
        
        self.ddos_protection_active = false;
        self.rate_limit_factor = 1.0;
        
        info!("Protection DDoS désactivée");
    }
} 
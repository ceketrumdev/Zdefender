//! Module de protection contre les attaques DDoS
//!
//! Ce module fournit des mécanismes de défense contre les attaques par déni de service distribué (DDoS),
//! y compris la détection automatique, les mesures d'atténuation et les réponses adaptatives.

use super::Defender;
use crate::models::{Report, ReportType};
use log::{error, info};
use std::time::{Duration, SystemTime};

impl Defender {
    /// Gère une attaque DDoS détectée
    pub async fn handle_ddos_attack(&mut self, num_ips: u32, packets_per_sec: u64, intensity: f64) {
        // Enregistrer l'attaque dans les logs
        info!(
            "Attaque DDoS distribuée détectée: {} IPs, {} paquets/sec, intensité: {:.2}",
            num_ips, packets_per_sec, intensity
        );
        
        // Vérifier la configuration dans un bloc séparé pour éviter le problème de mutabilité
        let (fortress_needed, protection_duration, detection_enabled) = {
            let config = self.config.read().await;
            let fortress_needed = config.ddos_detection_enabled && config.ddos_auto_fortress && !self.fortress_mode;
            let protection_duration = config.ddos_protection_duration;
            let detection_enabled = config.ddos_detection_enabled;
            (fortress_needed, protection_duration, detection_enabled)
        };
        
        if detection_enabled {
            // Activer le mode forteresse si configuré
            if fortress_needed {
                self.fortress_mode = true;
                info!("Mode forteresse activé automatiquement suite à une attaque DDoS distribuée");
                
                // Envoi d'une notification
                let notification = Report {
                    timestamp: SystemTime::now(),
                    report_type: ReportType::Action,
                    source_ip: None,
                    message: format!("MODE FORTERESSE activé - Attaque DDoS distribuée avec {} IPs", num_ips),
                    details: Some(format!("Intensité: {:.2}, Paquets/s: {}", intensity, packets_per_sec)),
                    severity: 9,
                    suggested_action: None,
                };
                
                self.notify_admins(&notification).await;
            }
            
            // Appliquer des mesures de protection adaptées à l'intensité de l'attaque
            self.apply_protection_measures(intensity, protection_duration).await;
        }
    }
    
    /// Applique des mesures de protection adaptées à l'intensité de l'attaque
    async fn apply_protection_measures(&mut self, intensity: f64, duration_secs: u64) {
        // Déterminer le niveau de protection
        let protection_level = if intensity > 0.8 {
            "CRITIQUE"
        } else if intensity > 0.5 {
            "ÉLEVÉ"
        } else {
            "MODÉRÉ"
        };
        
        // Durée de la protection
        let protection_duration = Duration::from_secs(duration_secs);
        
        info!("Protection niveau {} activée pour une durée de {} minutes", 
              protection_level, 
              protection_duration.as_secs() / 60);
        
        // Activer le filtrage de trafic pour limiter la bande passante
        self.rate_limiting_active = true;
        self.rate_limiting_factor = if intensity > 0.8 {
            0.1 // 10% du trafic autorisé
        } else if intensity > 0.5 {
            0.3 // 30% du trafic autorisé
        } else {
            0.5 // 50% du trafic autorisé
        };
        
        // Cloner les données nécessaires pour la tâche asynchrone
        let config_clone = self.config.clone();
        let logger_clone = self.logger.clone();
        
        // Programmer la désactivation de la protection après la durée configurée
        tokio::spawn(async move {
            tokio::time::sleep(protection_duration).await;
            // Créer une nouvelle instance du défenseur
            let mut defender = Defender::new(config_clone, logger_clone).await;
            // Désactiver les protections
            defender.disable_ddos_protection().await;
        });
    }
    
    /// Désactive les protections contre les attaques DDoS
    pub async fn disable_ddos_protection(&mut self) {
        if self.rate_limiting_active {
            self.rate_limiting_active = false;
            self.rate_limiting_factor = 1.0;
            
            info!("Protection contre les attaques DDoS distribuées désactivée");
            
            // Si le mode forteresse a été activé automatiquement, le désactiver
            let config = self.config.read().await;
            if config.ddos_auto_fortress && self.fortress_mode {
                self.fortress_mode = false;
                
                // Envoi d'une notification
                let notification = Report {
                    timestamp: SystemTime::now(),
                    report_type: ReportType::Info,
                    source_ip: None,
                    message: "MODE FORTERESSE désactivé - Fin de l'attaque DDoS distribuée".to_string(),
                    details: None,
                    severity: 6,
                    suggested_action: None,
                };
                
                self.notify_admins(&notification).await;
            }
        }
    }
    
    /// Configure les seuils de détection d'attaques DDoS
    pub async fn configure_ddos_thresholds(&mut self, ratio: f64, min_ips: u32, packets_per_second: u64) {
        let mut config = self.config.write().await;
        
        config.ddos_ratio_threshold = ratio;
        config.ddos_min_ips_threshold = min_ips;
        config.ddos_pps_threshold = packets_per_second;
        
        // Sauvegarder la configuration
        if let Err(e) = config.save() {
            error!("Erreur lors de la sauvegarde de la configuration: {}", e);
        } else {
            info!("Seuils de détection DDoS configurés: ratio={}, min_ips={}, pps={}", 
                  ratio, min_ips, packets_per_second);
        }
    }
    
    /// Active ou désactive la détection des attaques DDoS
    pub async fn set_ddos_detection(&mut self, enabled: bool) {
        let mut config = self.config.write().await;
        
        config.ddos_detection_enabled = enabled;
        
        // Sauvegarder la configuration
        if let Err(e) = config.save() {
            error!("Erreur lors de la sauvegarde de la configuration: {}", e);
        } else {
            info!("Détection des attaques DDoS {}", if enabled { "activée" } else { "désactivée" });
        }
    }
    
    /// Configure le comportement automatique du mode forteresse
    pub async fn set_auto_fortress(&mut self, enabled: bool) {
        let mut config = self.config.write().await;
        
        config.ddos_auto_fortress = enabled;
        
        // Sauvegarder la configuration
        if let Err(e) = config.save() {
            error!("Erreur lors de la sauvegarde de la configuration: {}", e);
        } else {
            info!("Mode forteresse automatique {}", if enabled { "activé" } else { "désactivé" });
        }
    }
} 
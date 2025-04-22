//! Module de gestion du mode forteresse
//!
//! Le mode forteresse est un état de protection maximale où seules les connexions
//! établies et autorisées sont acceptées. Il s'active automatiquement en cas d'attaque
//! ou peut être activé manuellement par un administrateur.

use super::Defender;
use log::{debug, error, info, warn};
use std::process::Command;
use std::time::SystemTime;

impl Defender {
    /// Active le mode forteresse (protection maximale)
    pub async fn enable_fortress_mode(&mut self) {
        if self.fortress_mode {
            info!("Le mode forteresse est déjà activé");
            return;
        }
        
        info!("Activation du mode forteresse");
        
        // Récupérer les paramètres de configuration pour la mise en liste blanche
        let connection_time_threshold = {
            let config = self.config.read().await;
            config.connection_time_for_trust // En secondes
        };
        
        // Ajouter les connexions établies à la whitelist temporaire
        self.update_fortress_whitelist(connection_time_threshold).await;
        
        // Configurer les règles de pare-feu
        if let Err(e) = self.configure_fortress_firewall().await {
            error!("Erreur lors de la configuration du pare-feu: {}", e);
            return;
        }
        
        // Activer le mode forteresse
        self.fortress_mode = true;
        self.logger.log_fortress_mode(true);
        
        // Mettre à jour la configuration
        {
            let mut config = self.config.write().await;
            config.fortress_mode = true;
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
            } else {
                info!("Configuration mise à jour: mode forteresse activé");
            }
        }
        
        info!("Mode forteresse activé avec succès. Les nouvelles connexions seront bloquées.");
    }

    /// Met à jour la liste blanche pour le mode forteresse
    async fn update_fortress_whitelist(&self, connection_time_threshold: u64) {
        let now = SystemTime::now();
        
        let mut whitelist = self.temp_whitelist.write().await;
        whitelist.clear(); // Réinitialiser la liste blanche temporaire
        
        for entry in self.established_connections.iter() {
            let conn = entry.value();
            
            // Vérifier si la connexion est établie depuis suffisamment longtemps
            if let Ok(duration) = now.duration_since(conn.created_at) {
                if duration.as_secs() >= connection_time_threshold {
                    whitelist.insert(entry.key().clone());
                    info!("IP établie ajoutée à la whitelist temporaire: {} (connectée depuis {} secondes, score de confiance: {:.2})",
                        conn.ip, duration.as_secs(), conn.trust_score);
                } else {
                    debug!("IP non ajoutée à la whitelist: {} (connectée depuis seulement {} secondes)", 
                        conn.ip, duration.as_secs());
                }
            }
        }
        
        info!("{} IP(s) ajoutée(s) à la whitelist temporaire", whitelist.len());
    }

    /// Configure le pare-feu pour le mode forteresse
    async fn configure_fortress_firewall(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Sauvegarder les règles iptables actuelles
        let _ = Command::new("iptables-save").output();
        
        // Autoriser les connexions établies
        Command::new("iptables")
            .args(["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .output()?;
        
        // Autoriser les connexions locales
        Command::new("iptables")
            .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            .output()?;
        
        // Ajouter les exceptions pour les IPs en whitelist permanente
        {
            let config = self.config.read().await;
            for ip in &config.whitelist {
                Command::new("iptables")
                    .args(["-A", "INPUT", "-s", ip, "-j", "ACCEPT"])
                    .output()?;
                
                debug!("IP de la whitelist permanente autorisée: {}", ip);
            }
        }
        
        // Ajouter les exceptions pour les IPs en whitelist temporaire
        {
            let whitelist = self.temp_whitelist.read().await;
            for ip in whitelist.iter() {
                Command::new("iptables")
                    .args(["-A", "INPUT", "-s", &ip.to_string(), "-j", "ACCEPT"])
                    .output()?;
                
                debug!("IP de la whitelist temporaire autorisée: {}", ip);
            }
        }
        
        // Bloquer toutes les nouvelles connexions entrantes
        Command::new("iptables")
            .args(["-A", "INPUT", "-j", "DROP"])
            .output()?;
            
        Ok(())
    }

    /// Désactive le mode forteresse
    pub async fn disable_fortress_mode(&mut self) {
        // Si le mode forteresse est déjà désactivé, on vérifie quand même dans la configuration
        if !self.fortress_mode {
            // Vérifier si la configuration a fortress_mode à true
            let config_fortress_mode = {
                let config = self.config.read().await;
                config.fortress_mode
            };
            
            if !config_fortress_mode {
                info!("Le mode forteresse est déjà désactivé");
                return;
            } else {
                info!("Le mode forteresse est désactivé localement mais activé dans la configuration, mise à jour...");
            }
        }
        
        info!("Désactivation du mode forteresse");
        
        // Forcer la mise à jour de la configuration, même si iptables échoue
        {
            let mut config = self.config.write().await;
            config.fortress_mode = false;
            match config.save() {
                Ok(_) => {
                    info!("Configuration mise à jour : mode forteresse désactivé");
                }
                Err(e) => {
                    error!("ERREUR CRITIQUE lors de la sauvegarde de la configuration: {}", e);
                    error!("Chemin de la configuration: {}", crate::config::CONFIG_FILE);
                    error!("Le mode forteresse n'a pas pu être désactivé correctement");
                    // Tenter de déterminer le problème de permissions
                    if let Ok(metadata) = std::fs::metadata(crate::config::CONFIG_FILE) {
                        let permissions = metadata.permissions();
                        error!("Permissions du fichier: {:?}", permissions);
                    }
                }
            }
        }
        
        // Restaurer les règles iptables
        let output = Command::new("iptables")
            .args(["-F"])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    self.fortress_mode = false;
                    self.logger.log_fortress_mode(false);
                    info!("Mode forteresse désactivé avec succès");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("Erreur lors de la désactivation du mode forteresse: {}", stderr);
                    // Même en cas d'erreur, on a déjà mis à jour la configuration
                }
            }
            Err(e) => {
                error!("Erreur lors de l'exécution de la commande iptables: {}", e);
                // Même en cas d'erreur, on a déjà mis à jour la configuration
            }
        }
    }
    
    /// Vérifie si le mode forteresse est activé
    pub fn is_fortress_mode_enabled(&self) -> bool {
        self.fortress_mode
    }
} 
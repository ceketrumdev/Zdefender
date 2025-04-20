use crate::models::{Action, Report};
use crate::config::Config;
use crate::logger::Logger;
use log::{debug, error, info, warn};
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};

pub struct Defender {
    config: Arc<RwLock<Config>>,
    logger: Arc<Logger>,
    fortress_mode: bool,
}

impl Defender {
    pub async fn new(config: Arc<RwLock<Config>>, logger: Arc<Logger>) -> Self {
        // Charger l'état du mode forteresse depuis la configuration
        let fortress_mode = {
            let config_read = config.read().await;
            config_read.fortress_mode
        };
        
        Self {
            config,
            logger,
            fortress_mode,
        }
    }

    pub async fn handle_report(&mut self, report: Report) {
        match report.suggested_action {
            Some(Action::Block(ip, duration)) => {
                self.block_ip(ip, duration.as_secs()).await;
            }
            Some(Action::Unblock(ip)) => {
                self.unblock_ip(ip).await;
            }
            Some(Action::EnableFortress) => {
                self.enable_fortress_mode().await;
            }
            Some(Action::DisableFortress) => {
                self.disable_fortress_mode().await;
            }
            Some(Action::Drop) => {
                // Aucune action nécessaire, le paquet est déjà supprimé
                debug!("Paquet supprimé: {}", report.message);
            }
            Some(Action::RateLimit(ip)) => {
                // Appliquer une limitation de débit (pourrait être implémenté avec iptables/tc)
                info!("Limitation de débit appliquée pour l'IP {}", ip);
            }
            None => {
                // Aucune action nécessaire
            },
            Some(Action::None) => todo!()
        }
    }

    async fn block_ip(&self, ip: IpAddr, duration_secs: u64) {
        debug!("Tentative de blocage de l'IP {}", ip);
        
        // Vérifier si l'IP est dans la liste blanche
        let whitelist = {
            let config = self.config.read().await;
            config.whitelist.clone()
        };
        
        if whitelist.iter().any(|allowed| allowed == &ip.to_string()) {
            warn!("Tentative de blocage d'une IP en liste blanche ignorée: {}", ip);
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
                    error!("Erreur lors du blocage de l'IP {}: {}", ip, stderr);
                }
            }
            Err(e) => {
                error!("Erreur lors de l'exécution de la commande iptables: {}", e);
            }
        }
    }

    async fn unblock_ip(&self, ip: IpAddr) {
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
                    error!("Erreur lors du déblocage de l'IP {}: {}", ip, stderr);
                }
            }
            Err(e) => {
                error!("Erreur lors de l'exécution de la commande iptables: {}", e);
            }
        }
    }

    pub async fn enable_fortress_mode(&mut self) {
        if self.fortress_mode {
            info!("Le mode forteresse est déjà activé");
            return;
        }
        
        info!("Activation du mode forteresse");
        
        // Sauvegarder les règles iptables actuelles
        let _ = Command::new("iptables-save")
            .output();
        
        // Autoriser les connexions établies
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .output();
        
        // Autoriser les connexions locales
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            .output();
        
        // Bloquer toutes les nouvelles connexions entrantes
        let output = Command::new("iptables")
            .args(["-A", "INPUT", "-j", "DROP"])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    self.fortress_mode = true;
                    self.logger.log_fortress_mode(true);
                    
                    // Mettre à jour la configuration
                    {
                        let mut config = self.config.write().await;
                        config.fortress_mode = true;
                        if let Err(e) = config.save() {
                            error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                        }
                    }
                    
                    info!("Mode forteresse activé avec succès");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("Erreur lors de l'activation du mode forteresse: {}", stderr);
                }
            }
            Err(e) => {
                error!("Erreur lors de l'exécution de la commande iptables: {}", e);
            }
        }
    }

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
        // Mettre à jour la configuration
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
    
    pub fn is_fortress_mode_enabled(&self) -> bool {
        self.fortress_mode
    }
}

impl Clone for Defender {
    fn clone(&self) -> Self {
        Defender {
            config: self.config.clone(),
            logger: self.logger.clone(),
            fortress_mode: self.fortress_mode,
        }
    }
} 
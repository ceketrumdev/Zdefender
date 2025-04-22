use crate::services::ZdefenderService;
use log::{error, info};
use std::process::Command;

impl ZdefenderService {
    /// Sécurise le serveur en configurant les règles firewall iptables
    pub async fn secure_server(&self, allowed_ports: Vec<u16>) -> Result<String, Box<dyn std::error::Error>> {
        info!("Sécurisation du serveur...");
        let mut response = String::new();
        
        // Début de la réponse
        response.push_str("=== SÉCURISATION DU SERVEUR ===\n\n");
        response.push_str("Application des règles de sécurité de base...\n");
        
        // Sauvegarder les règles iptables actuelles
        let _ = Command::new("iptables-save")
            .output();
        
        // Règles de base pour la sécurité
        // 1. Effacer toutes les règles existantes
        let _ = Command::new("iptables")
            .args(["-F"])
            .output();
        
        // 2. Politique par défaut: tout bloquer
        let _ = Command::new("iptables")
            .args(["-P", "INPUT", "DROP"])
            .output();
        
        let _ = Command::new("iptables")
            .args(["-P", "FORWARD", "DROP"])
            .output();
        
        // 3. Autoriser le loopback
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            .output();
        
        // 4. Autoriser les connexions établies et apparentées
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .output();
        
        // 5. Autoriser les ports spécifiés
        for port in &allowed_ports {
            // TCP
            let _ = Command::new("iptables")
                .args(["-A", "INPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "ACCEPT"])
                .output();
            
            // UDP (pour certains services comme DNS)
            let _ = Command::new("iptables")
                .args(["-A", "INPUT", "-p", "udp", "--dport", &port.to_string(), "-j", "ACCEPT"])
                .output();
            
            response.push_str(&format!("Port {} ouvert (TCP/UDP)\n", port));
        }
        
        // 6. Protection contre les scans de port
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"])
            .output();
        
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN", "-j", "DROP"])
            .output();
        
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN,RST", "-j", "DROP"])
            .output();
        
        // 7. Limiter les tentatives de connexion SSH (protection contre le brute force)
        if allowed_ports.contains(&22) {
            let _ = Command::new("iptables")
                .args([
                    "-A", "INPUT", "-p", "tcp", "--dport", "22", 
                    "-m", "state", "--state", "NEW", 
                    "-m", "recent", "--set", "--name", "SSH"
                ])
                .output();
                
            let _ = Command::new("iptables")
                .args([
                    "-A", "INPUT", "-p", "tcp", "--dport", "22", 
                    "-m", "state", "--state", "NEW", 
                    "-m", "recent", "--update", "--seconds", "60", "--hitcount", "4", 
                    "--name", "SSH", "-j", "DROP"
                ])
                .output();
                
            response.push_str("Protection contre les attaques par force brute SSH activée\n");
        }
        
        // 8. Protection contre les attaques DDoS de base
        // Limiter le nombre de connexions simultanées par IP
        let _ = Command::new("iptables")
            .args([
                "-A", "INPUT", "-p", "tcp", 
                "-m", "connlimit", "--connlimit-above", "20", 
                "-j", "DROP"
            ])
            .output();
        
        response.push_str("Protection anti-DDoS de base activée\n");
        
        // Mettre à jour la configuration
        {
            let mut config = self.config.write().await;
            config.allowed_ports = allowed_ports.clone();
            if let Err(e) = config.save() {
                error!("Erreur lors de la sauvegarde de la configuration: {}", e);
                response.push_str(&format!("\nATTENTION: Erreur lors de la sauvegarde de la configuration: {}\n", e));
            }
        }
        
        response.push_str("\nSécurisation terminée!\n");
        response.push_str("\nIMPORTANT: Si vous devez ouvrir d'autres ports à l'avenir, utilisez:\n");
        response.push_str("- La commande 'zdefender secure --ports=X,Y,Z'\n");
        response.push_str("- Ou les commandes iptables directement:\n");
        response.push_str("  iptables -A INPUT -p tcp --dport PORT -j ACCEPT\n");
        
        Ok(response)
    }

    /// Active le mode forteresse
    pub async fn enable_fortress(&self) {
        if let Some(defender) = &self.defender {
            let mut defender = defender.write().await;
            defender.enable_fortress_mode().await;
        } else {
            // Créer temporairement un défenseur pour activer le mode forteresse
            let mut defender = crate::defender::Defender::new(self.config.clone(), self.logger.clone()).await;
            defender.enable_fortress_mode().await;
        }
    }

    /// Désactive le mode forteresse
    pub async fn disable_fortress(&self) {
        if let Some(defender) = &self.defender {
            let mut defender = defender.write().await;
            defender.disable_fortress_mode().await;
        } else {
            // Créer temporairement un défenseur pour désactiver le mode forteresse
            let mut defender = crate::defender::Defender::new(self.config.clone(), self.logger.clone()).await;
            defender.disable_fortress_mode().await;
        }
    }
} 
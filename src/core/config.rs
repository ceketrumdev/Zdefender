use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use log::{info, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub firewall: FirewallConfig,
    pub honeypot: HoneypotConfig,
    pub encryption: EncryptionConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub port: u16,
    pub max_clients: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub default_policy: String,
    pub ddos_threshold: u32,
    pub block_duration: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HoneypotConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub log_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub key_path: String,
    pub algorithm: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&config_str)?;
        info!("Configuration chargée depuis {}", path.display());
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let config_str = serde_json::to_string_pretty(self)?;
        fs::write(path, config_str)?;
        info!("Configuration sauvegardée dans {}", path.display());
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen_address: "0.0.0.0".to_string(),
                port: 8080,
                max_clients: 100,
            },
            firewall: FirewallConfig {
                default_policy: "DROP".to_string(),
                ddos_threshold: 1000,
                block_duration: 3600,
            },
            honeypot: HoneypotConfig {
                enabled: true,
                ports: vec![22, 23, 3389],
                log_path: "/var/log/zdefender/honeypot.log".to_string(),
            },
            encryption: EncryptionConfig {
                key_path: "/etc/zdefender/keys".to_string(),
                algorithm: "AES-GCM".to_string(),
            },
        }
    }
} 
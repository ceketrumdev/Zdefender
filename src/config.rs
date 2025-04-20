use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use log::{info, warn, error};
use std::error::Error;
use crate::log_mode::LogMode;

pub const CONFIG_FILE: &str = "/etc/zdefender/config.json";
const DEFAULT_CONFIG_FILE: &str = "/etc/zdefender/config.json.default";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Interfaces réseau à surveiller
    pub interfaces: Vec<String>,
    
    /// Seuil de paquets par seconde avant détection d'une attaque
    pub packet_threshold: u32,
    
    /// Intervalle de temps (en secondes) pour vérifier les attaques
    pub check_interval: u64,
    
    /// Temps de blocage (en secondes) pour les IPs malveillantes
    pub block_duration: u64,
    
    /// Chemin vers le fichier de log
    pub log_file: String,
    
    /// Niveau de log
    pub log_level: String,
    
    /// Mode de journalisation (fichier ou systemd-journal)
    pub log_mode: LogMode,
    
    /// État actuel du service (actif, passif, arrêté)
    pub service_state: ServiceState,
    
    /// Mode forteresse activé ou non
    pub fortress_mode: bool,
    
    /// Liste d'IPs en liste blanche (jamais bloquées)
    pub whitelist: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ServiceState {
    Active,
    Passive,
    Stopped,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            interfaces: vec!["eth0".to_string()],
            packet_threshold: 1000,
            check_interval: 5,
            block_duration: 300,
            log_file: "/var/log/zdefender/zdefender.log".to_string(),
            log_level: "info".to_string(),
            log_mode: LogMode::File,
            service_state: ServiceState::Stopped,
            fortress_mode: false,
            whitelist: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

impl Config {
    /// Charge la configuration depuis le fichier
    pub fn load() -> Result<Self, Box<dyn Error>> {
        // Si le fichier de configuration n'existe pas, on crée le fichier par défaut
        if !Path::new(CONFIG_FILE).exists() {
            Self::create_default_config()?;
        }
        
        // Lire le contenu du fichier
        let mut file = File::open(CONFIG_FILE)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        // Désérialiser le contenu JSON
        let config: Config = serde_json::from_str(&contents)?;
        Ok(config)
    }
    
    /// Sauvegarde la configuration dans le fichier
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        // Créer le répertoire si nécessaire
        if let Some(parent) = Path::new(CONFIG_FILE).parent() {
            match fs::create_dir_all(parent) {
                Ok(_) => {},
                Err(e) => {
                    error!("Erreur lors de la création du répertoire de configuration: {}", e);
                    error!("Répertoire: {:?}", parent);
                    return Err(Box::new(e));
                }
            }
        }
        
        // Sérialiser la configuration en JSON
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(e) => {
                error!("Erreur lors de la sérialisation de la configuration: {}", e);
                return Err(Box::new(e));
            }
        };
        
        // Écrire dans le fichier
        let file_result = File::create(CONFIG_FILE);
        let mut file = match file_result {
            Ok(f) => f,
            Err(e) => {
                error!("Erreur lors de la création du fichier de configuration: {}", e);
                error!("Chemin: {}", CONFIG_FILE);
                return Err(Box::new(e));
            }
        };
        
        match file.write_all(json.as_bytes()) {
            Ok(_) => {},
            Err(e) => {
                error!("Erreur lors de l'écriture dans le fichier de configuration: {}", e);
                return Err(Box::new(e));
            }
        }
        
        Ok(())
    }
    
    /// Crée la configuration par défaut
    fn create_default_config() -> Result<(), Box<dyn Error>> {
        let default_config = Config::default();
        
        // Créer le répertoire si nécessaire
        if let Some(parent) = Path::new(CONFIG_FILE).parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Sérialiser la configuration en JSON
        let json = serde_json::to_string_pretty(&default_config)?;
        
        // Écrire dans le fichier
        let mut file = File::create(CONFIG_FILE)?;
        file.write_all(json.as_bytes())?;
        
        info!("Configuration par défaut créée dans {}", CONFIG_FILE);
        Ok(())
    }
} 
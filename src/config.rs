#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::fs::{self};
use std::path::Path;
use std::error::Error;
use crate::log_mode::LogMode;
use std::collections::HashMap;

pub const CONFIG_FILE: &str = "/etc/zdefender/config.json";
const DEFAULT_CONFIG_FILE: &str = "/etc/zdefender/config.json.default";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Version actuelle du logiciel
    pub version: String,
    
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
    
    /// Activer les statistiques en temps réel
    pub realtime_stats: bool,
    
    /// Afficher les statistiques en temps réel dans le terminal
    pub display_realtime_stats: bool,
    
    /// Ports autorisés lors de la sécurisation du serveur
    pub allowed_ports: Vec<u16>,
    
    /// Nouveaux paramètres pour le score de confiance
    pub trust_threshold: f64,
    
    /// Scores de confiance par région (code pays -> score)
    pub region_trust_scores: HashMap<String, f64>,
    
    pub auto_block_threshold: f64,
    pub auto_whitelist_threshold: f64,
    pub connection_time_for_trust: u64,
    
    /// Configuration des ports pour la commande secure
    pub essential_ports: Vec<u16>,
    
    /// Configuration du multithreading
    pub analyzer_threads: usize,
    pub packet_queue_size: usize,
    pub report_queue_size: usize,
    pub parallel_processing: bool,
    
    /// Configuration de la détection d'attaques DDoS distribuées
    pub ddos_detection_enabled: bool,
    pub ddos_ratio_threshold: f64,         // Seuil de ratio paquets/IPs
    pub ddos_min_ips_threshold: u32,       // Nombre minimum d'IPs distinctes
    pub ddos_pps_threshold: u64,           // Seuil de paquets par seconde
    pub ddos_protection_duration: u64,     // Durée en secondes de la protection après détection
    pub ddos_auto_fortress: bool,          // Mode forteresse automatique en cas d'attaque
    
    /// Configuration des mises à jour automatiques
    pub auto_update: bool,                 // Activer les mises à jour automatiques
    pub update_check_interval: u64,        // Intervalle en heures pour vérifier les mises à jour
    pub update_channel: UpdateChannel,     // Canal de mise à jour (stable, beta, dev)
    pub last_update_check: Option<String>, // Date de la dernière vérification de mise à jour
    
    /// Configuration des mises à jour automatiques
    pub update_config: UpdateConfig,
}

/// Configuration pour les mises à jour automatiques
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateConfig {
    /// Activer les mises à jour automatiques
    pub enabled: bool,
    
    /// Canal de mise à jour (stable, beta, dev)
    pub channel: String,
    
    /// Intervalle de vérification des mises à jour (en heures)
    pub check_interval: u32,
    
    /// Dernière vérification de mise à jour (timestamp)
    pub last_check: Option<u64>,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channel: "stable".to_string(),
            check_interval: 24,
            last_check: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ServiceState {
    Active,
    Passive,
    Stopped,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum UpdateChannel {
    Stable,
    Beta,
    Dev,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: env!("CARGO_PKG_VERSION").to_string(),
            interfaces: vec!["eth0".to_string()],
            packet_threshold: 2000,
            check_interval: 5,
            block_duration: 3600,
            log_file: "/var/log/zdefender/zdefender.log".to_string(),
            log_level: "info".to_string(),
            log_mode: LogMode::File,
            service_state: ServiceState::Stopped,
            fortress_mode: false,
            whitelist: vec!["127.0.0.1".to_string(), "::1".to_string()],
            realtime_stats: false,
            display_realtime_stats: false,
            allowed_ports: vec![80, 443, 8080, 8443],
            
            // Valeurs par défaut pour le score de confiance
            trust_threshold: 0.7,
            region_trust_scores: HashMap::new(),
            auto_block_threshold: 0.2,
            auto_whitelist_threshold: 0.9,
            connection_time_for_trust: 300, // 5 minutes
            
            // Ports essentiels par défaut
            essential_ports: vec![22, 80, 443],
            
            // Configuration du multithreading
            analyzer_threads: num_cpus::get(),
            packet_queue_size: 10000,
            report_queue_size: 1000,
            parallel_processing: true,
            
            // Configuration de la détection d'attaques DDoS distribuées
            ddos_detection_enabled: false,
            ddos_ratio_threshold: 0.5,
            ddos_min_ips_threshold: 10,
            ddos_pps_threshold: 1000,
            ddos_protection_duration: 300,
            ddos_auto_fortress: false,
            
            // Configuration des mises à jour automatiques
            auto_update: true,
            update_check_interval: 24, // Vérifier les mises à jour une fois par jour
            update_channel: UpdateChannel::Stable,
            last_update_check: None,
            
            // Configuration des mises à jour automatiques
            update_config: UpdateConfig::default(),
        }
    }
}

impl Config {
    /// Charge la configuration depuis le fichier
    pub fn load() -> Result<Self, Box<dyn Error>> {
        let config_dir = "/etc/zdefender";
        let config_file = format!("{}/config.json", config_dir);

        if !Path::new(&config_file).exists() {
            // Créer la configuration par défaut si elle n'existe pas
            let default_config = Config::default();
            // Créer le répertoire si nécessaire
            if !Path::new(config_dir).exists() {
                fs::create_dir_all(config_dir)?;
            }
            default_config.save()?;
            return Ok(default_config);
        }

        let config_content = fs::read_to_string(&config_file)?;
        let config: Config = serde_json::from_str(&config_content)?;

        Ok(config)
    }
    
    /// Sauvegarde la configuration dans le fichier
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let config_dir = "/etc/zdefender";
        let config_file = format!("{}/config.json", config_dir);

        // Créer le répertoire si nécessaire
        if !Path::new(config_dir).exists() {
            fs::create_dir_all(config_dir)?;
        }

        let config_json = serde_json::to_string_pretty(self)?;
        fs::write(&config_file, config_json)?;

        Ok(())
    }
    
    pub fn get_region_trust(&self, region_code: &str) -> f64 {
        // Retourne le score de confiance régional ou une valeur par défaut si non configuré
        *self.region_trust_scores.get(region_code).unwrap_or(&0.5)
    }
    
    // Ajoute ou met à jour le score de confiance d'une région
    pub fn set_region_trust(&mut self, region_code: &str, trust_score: f64) {
        self.region_trust_scores.insert(region_code.to_string(), trust_score.max(0.0).min(1.0));
    }
    
    // Vérifie si une IP peut être automatiquement bloquée selon son score de confiance
    pub fn should_auto_block(&self, trust_score: f64) -> bool {
        trust_score <= self.auto_block_threshold
    }
    
    // Vérifie si une IP peut être automatiquement mise en liste blanche selon son score de confiance
    pub fn should_auto_whitelist(&self, trust_score: f64, connection_time_secs: u64) -> bool {
        trust_score >= self.auto_whitelist_threshold && 
        connection_time_secs >= self.connection_time_for_trust
    }
} 
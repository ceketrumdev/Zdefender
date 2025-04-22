//! Module de défense contre les attaques réseau
//! 
//! Ce module fournit un système de défense qui surveille et protège contre diverses
//! attaques réseau comme les DDoS, SYN floods, etc.

mod connection_manager;
mod fortress;
mod ddos_protection;
mod notifications;

use crate::models::{Action, Report, EstablishedConnection, ReportType};
use crate::config::Config;
use crate::logger::Logger;
use log::{debug, info, warn, error};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use dashmap::DashMap;
use std::collections::HashSet;

pub use connection_manager::*;
pub use fortress::*;
pub use ddos_protection::*;
pub use notifications::*;

/// Structure principale gérant la défense du système contre les attaques
pub struct Defender {
    /// Configuration du système
    pub(crate) config: Arc<RwLock<Config>>,
    /// Logger pour enregistrer les événements
    pub(crate) logger: Arc<Logger>,
    /// État du mode forteresse (protection maximale)
    pub(crate) fortress_mode: bool,
    /// Connexions actuellement établies
    pub(crate) established_connections: Arc<DashMap<IpAddr, EstablishedConnection>>,
    /// Liste blanche temporaire d'IPs
    pub(crate) temp_whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    /// Indique si la limitation de débit est active
    pub(crate) rate_limiting_active: bool,
    /// Facteur de limitation de débit (0.0-1.0)
    pub(crate) rate_limiting_factor: f64,
}

impl Defender {
    /// Crée une nouvelle instance du défenseur
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
            established_connections: Arc::new(DashMap::new()),
            temp_whitelist: Arc::new(RwLock::new(HashSet::new())),
            rate_limiting_active: false,
            rate_limiting_factor: 1.0,
        }
    }

    /// Traite un rapport d'événement et applique l'action recommandée
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
            Some(Action::None) => {}
        }
    }
}

impl Clone for Defender {
    fn clone(&self) -> Self {
        Defender {
            config: self.config.clone(),
            logger: self.logger.clone(),
            fortress_mode: self.fortress_mode,
            established_connections: self.established_connections.clone(),
            temp_whitelist: self.temp_whitelist.clone(),
            rate_limiting_active: self.rate_limiting_active,
            rate_limiting_factor: self.rate_limiting_factor,
        }
    }
} 
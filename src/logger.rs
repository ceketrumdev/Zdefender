use crate::models::{PacketInfo, Report, ReportType};
use crate::log_mode::LogMode;
use chrono::{DateTime, Local};
use log::{debug, error, info, warn};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

pub struct Logger {
    log_file: Mutex<Option<File>>,
    log_path: String,
    log_mode: LogMode,
}

impl Logger {
    pub fn new(log_path: String) -> Self {
        Self::new_with_mode(log_path, LogMode::File)
    }

    pub fn new_with_mode(log_path: String, log_mode: LogMode) -> Self {
        // Si le mode de journalisation est fichier, initialiser le fichier de log
        let file = if log_mode == LogMode::File {
            // Créer le répertoire si nécessaire
            if let Some(parent) = Path::new(&log_path).parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    error!("Erreur lors de la création du répertoire de logs: {}", e);
                }
            }

            // Essayer d'ouvrir le fichier de log
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                Ok(file) => Some(file),
                Err(e) => {
                    error!("Erreur lors de l'ouverture du fichier de log {}: {}", log_path, e);
                    None
                }
            }
        } else {
            // En mode systemd-journal, pas besoin de fichier
            None
        };

        Self {
            log_file: Mutex::new(file),
            log_path,
            log_mode,
        }
    }

    pub fn log_packet(&self, packet: &PacketInfo) {
        let timestamp: DateTime<Local> = packet.timestamp.into();
        let formatted_time = timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        
        let protocol = match packet.protocol {
            crate::models::PacketType::Tcp => "TCP",
            crate::models::PacketType::Udp => "UDP",
            crate::models::PacketType::Icmp => "ICMP",
            crate::models::PacketType::Other => "OTHER",
        };
        
        let log_entry = format!(
            "[{}] {} -> {} | Protocol: {} | Size: {} bytes | Src Port: {:?} | Dst Port: {:?}",
            formatted_time,
            packet.source_ip,
            packet.dest_ip,
            protocol,
            packet.size,
            packet.source_port,
            packet.dest_port
        );
        
        match self.log_mode {
            LogMode::File => {
                self.write_to_log(&format!("{}\n", log_entry));
            },
            LogMode::SystemdJournal => {
                // Pour systemd-journal, on utilise le crate log
                // qui sera redirigé vers systemd-journal
                debug!("{}", log_entry);
            }
        }
    }

    pub fn log_report(&self, report: &Report) {
        let timestamp: DateTime<Local> = report.timestamp.into();
        let formatted_time = timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        
        let report_type = match report.report_type {
            ReportType::Info => "INFO",
            ReportType::Alert => "ALERT",
            ReportType::Warning => "WARNING",
            ReportType::Attack => "ATTACK",
            ReportType::Action => "ACTION",
        };
        
        let source_ip = match report.source_ip {
            Some(ip) => ip.to_string(),
            None => "N/A".to_string(),
        };
        
        let log_entry = format!(
            "[{}] [{}] [IP: {}] {}",
            formatted_time,
            report_type,
            source_ip,
            report.message
        );
        
        match self.log_mode {
            LogMode::File => {
                self.write_to_log(&format!("{}\n", log_entry));
            },
            LogMode::SystemdJournal => {
                // Pour systemd-journal, on utilise le crate log approprié selon le type de rapport
                match report.report_type {
                    ReportType::Info => info!("{}", log_entry),
                    ReportType::Warning => warn!("{}", log_entry),
                    ReportType::Alert => error!("{}", log_entry),
                    ReportType::Attack => warn!("ATTACK: {}", log_entry),
                    ReportType::Action => info!("ACTION: {}", log_entry),
                }
            }
        }
    }
    
    pub fn log_block(&self, ip: IpAddr, duration_secs: u64) {
        let timestamp: DateTime<Local> = SystemTime::now().into();
        let formatted_time = timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        
        let log_entry = format!(
            "[{}] [BLOCK] IP {} bloquée pour {} secondes",
            formatted_time,
            ip,
            duration_secs
        );
        
        match self.log_mode {
            LogMode::File => {
                self.write_to_log(&format!("{}\n", log_entry));
            },
            LogMode::SystemdJournal => {
                warn!("{}", log_entry);
            }
        }
    }
    
    pub fn log_unblock(&self, ip: IpAddr) {
        let timestamp: DateTime<Local> = SystemTime::now().into();
        let formatted_time = timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        
        let log_entry = format!(
            "[{}] [UNBLOCK] IP {} débloquée",
            formatted_time,
            ip
        );
        
        match self.log_mode {
            LogMode::File => {
                self.write_to_log(&format!("{}\n", log_entry));
            },
            LogMode::SystemdJournal => {
                info!("{}", log_entry);
            }
        }
    }
    
    pub fn log_fortress_mode(&self, enabled: bool) {
        let timestamp: DateTime<Local> = SystemTime::now().into();
        let formatted_time = timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        
        let status = if enabled { "activé" } else { "désactivé" };
        let log_entry = format!(
            "[{}] [FORTRESS] Mode forteresse {}",
            formatted_time,
            status
        );
        
        match self.log_mode {
            LogMode::File => {
                self.write_to_log(&format!("{}\n", log_entry));
            },
            LogMode::SystemdJournal => {
                warn!("{}", log_entry);
            }
        }
    }

    fn write_to_log(&self, message: &str) {
        // Ne rien faire si on est en mode systemd-journal
        if self.log_mode == LogMode::SystemdJournal {
            return;
        }

        let mut log_file_guard = match self.log_file.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Erreur lors de l'acquisition du verrou pour le fichier de log: {}", e);
                return;
            }
        };

        if let Some(file) = log_file_guard.as_mut() {
            if let Err(e) = file.write_all(message.as_bytes()) {
                error!("Erreur lors de l'écriture dans le fichier de log: {}", e);
                
                // Essayer de réouvrir le fichier
                *log_file_guard = match OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.log_path)
                {
                    Ok(file) => Some(file),
                    Err(e) => {
                        error!("Erreur lors de la réouverture du fichier de log: {}", e);
                        None
                    }
                };
            }
        }
    }
} 
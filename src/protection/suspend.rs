use std::process::{Command, Child, Stdio};
use std::net::IpAddr;
use anyhow::{Result, Context};
use log::{info, error, warn};
use tokio::sync::Mutex;
use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use pnet::datalink;
use once_cell::sync::Lazy;
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};

const STATE_FILE: &str = "/var/lib/zdefender/suspended_ips.json";

#[derive(Serialize, Deserialize, Default)]
struct SuspendedState {
    ips: HashSet<String>,
    interfaces: HashMap<String, Vec<String>>, // IP -> Liste des interfaces
}

// État global partagé
static SUSPENDED_IPS: Lazy<Arc<Mutex<HashSet<IpAddr>>>> = Lazy::new(|| {
    let state = load_state().unwrap_or_default();
    Arc::new(Mutex::new(state.ips.into_iter()
        .filter_map(|ip| ip.parse().ok())
        .collect()))
});

static TCPKILL_PROCESSES: Lazy<Arc<Mutex<HashMap<IpAddr, Vec<Child>>>>> = Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

fn load_state() -> Result<SuspendedState> {
    if !Path::new(STATE_FILE).exists() {
        return Ok(SuspendedState::default());
    }

    let content = fs::read_to_string(STATE_FILE)
        .context("Impossible de lire le fichier d'état")?;
    
    serde_json::from_str(&content)
        .context("Impossible de désérialiser l'état")
}

fn save_state(ips: &HashSet<IpAddr>, interfaces: &HashMap<IpAddr, Vec<String>>) -> Result<()> {
    // Créer le répertoire parent si nécessaire
    if let Some(parent) = Path::new(STATE_FILE).parent() {
        fs::create_dir_all(parent)
            .context("Impossible de créer le répertoire pour le fichier d'état")?;
    }

    let state = SuspendedState {
        ips: ips.iter()
            .map(|ip| ip.to_string())
            .collect(),
        interfaces: interfaces.iter()
            .map(|(ip, ifaces)| (ip.to_string(), ifaces.clone()))
            .collect(),
    };

    let content = serde_json::to_string_pretty(&state)
        .context("Impossible de sérialiser l'état")?;

    fs::write(STATE_FILE, content)
        .context("Impossible d'écrire le fichier d'état")
}

pub struct IpSuspender {
    suspended_ips: Arc<Mutex<HashSet<IpAddr>>>,
    tcpkill_processes: Arc<Mutex<HashMap<IpAddr, Vec<Child>>>>,
    interfaces: Arc<Mutex<HashMap<IpAddr, Vec<String>>>>,
}

impl IpSuspender {
    pub fn new() -> Self {
        let state = load_state().unwrap_or_default();
        let interfaces: HashMap<IpAddr, Vec<String>> = state.interfaces.into_iter()
            .filter_map(|(ip, ifaces)| ip.parse().ok().map(|ip| (ip, ifaces)))
            .collect();

        let suspended_ips = SUSPENDED_IPS.clone();
        let tcpkill_processes = TCPKILL_PROCESSES.clone();
        let interfaces = Arc::new(Mutex::new(interfaces));

        // Cloner les références pour le spawn
        let suspended_ips_clone = suspended_ips.clone();
        let interfaces_clone = interfaces.clone();

        // Restaurer les processus tcpkill pour les IPs suspendues
        tokio::spawn(async move {
            let suspended = suspended_ips_clone.lock().await;
            let interfaces = interfaces_clone.lock().await;

            for ip in suspended.iter() {
                if let Some(ifaces) = interfaces.get(ip) {
                    for iface in ifaces {
                        if let Err(e) = Self::start_tcpkill(ip, iface) {
                            error!("Erreur lors de la restauration de tcpkill pour l'IP {} sur l'interface {}: {}", 
                                ip, iface, e);
                        } else {
                            info!("Processus tcpkill restauré pour l'IP {} sur l'interface {}", ip, iface);
                        }
                    }
                }
            }
        });

        Self {
            suspended_ips,
            tcpkill_processes,
            interfaces,
        }
    }

    /// Vérifie si tcpkill est installé
    fn is_tcpkill_installed() -> bool {
        Command::new("which")
            .arg("tcpkill")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Obtient la liste des interfaces réseau disponibles
    fn get_network_interfaces() -> Vec<String> {
        datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .map(|iface| iface.name)
            .collect()
    }

    /// Vérifie si une IP est bloquée par iptables
    fn is_ip_blocked_by_iptables(ip: &IpAddr) -> bool {
        let output = Command::new("sudo")
            .args(&["iptables", "-C", "INPUT", "-s", &ip.to_string(), "-j", "DROP"])
            .output();

        output.map(|o| o.status.success()).unwrap_or(false)
    }

    /// Ajoute une règle iptables pour bloquer une IP
    fn add_iptables_rule(ip: &IpAddr) -> Result<()> {
        // Vérifier si la règle existe déjà
        if Self::is_ip_blocked_by_iptables(ip) {
            return Ok(());
        }

        // Bloquer le trafic entrant
        Command::new("sudo")
            .args(&["iptables", "-A", "INPUT", "-s", &ip.to_string(), "-j", "DROP"])
            .output()
            .context("Échec de l'ajout de la règle iptables INPUT")?;

        // Bloquer le trafic sortant
        Command::new("sudo")
            .args(&["iptables", "-A", "OUTPUT", "-d", &ip.to_string(), "-j", "DROP"])
            .output()
            .context("Échec de l'ajout de la règle iptables OUTPUT")?;

        // Bloquer le trafic de connexions existantes
        Command::new("sudo")
            .args(&["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-s", &ip.to_string(), "-j", "DROP"])
            .output()
            .context("Échec de l'ajout de la règle iptables pour les connexions existantes")?;

        // Sauvegarder les règles iptables
        Command::new("sudo")
            .args(&["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
            .output()
            .context("Échec de la sauvegarde des règles iptables")?;

        Ok(())
    }

    /// Supprime les règles iptables pour une IP
    fn remove_iptables_rule(ip: &IpAddr) -> Result<()> {
        let ip_str = ip.to_string();
        
        // Supprimer toutes les règles pour cette IP
        let rules = vec![
            vec!["-D", "INPUT", "-s", &ip_str, "-j", "DROP"],
            vec!["-D", "OUTPUT", "-d", &ip_str, "-j", "DROP"],
            vec!["-D", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-s", &ip_str, "-j", "DROP"],
        ];

        for rule in rules {
            // Essayer de supprimer la règle, ignorer si elle n'existe pas
            let _ = Command::new("sudo")
                .args(&["iptables"])
                .args(&rule)
                .output();
        }

        // Sauvegarder les règles iptables
        Command::new("sudo")
            .args(&["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
            .output()
            .context("Échec de la sauvegarde des règles iptables")?;

        Ok(())
    }

    /// Démarre un processus tcpkill pour une interface spécifique
    fn start_tcpkill(ip: &IpAddr, interface: &str) -> Result<Child> {
        Command::new("sudo")
            .args(&["tcpkill", "-i", interface, "host", &ip.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context(format!("Échec du démarrage de tcpkill sur l'interface {}", interface))
    }

    /// Arrête tous les processus tcpkill pour une IP
    async fn stop_tcpkill_processes(&self, ip: &IpAddr) -> Result<()> {
        let mut processes = self.tcpkill_processes.lock().await;
        if let Some(ip_processes) = processes.remove(ip) {
            for mut process in ip_processes {
                if let Err(e) = process.kill() {
                    error!("Erreur lors de l'arrêt du processus tcpkill pour l'IP {}: {}", ip, e);
                }
            }
        }
        Ok(())
    }

    /// Vérifie si tcpkill est toujours actif pour une IP
    fn is_tcpkill_running(ip: &IpAddr) -> bool {
        let output = Command::new("ps")
            .args(&["aux"])
            .output();

        match output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.contains(&format!("tcpkill.*host {}", ip))
            },
            Err(e) => {
                error!("Erreur lors de la vérification des processus tcpkill : {}", e);
                false
            }
        }
    }

    pub async fn suspend_ip(&self, ip: IpAddr, interface: Option<String>) -> Result<()> {
        let mut suspended = self.suspended_ips.lock().await;
        
        if suspended.contains(&ip) {
            info!("L'IP {} est déjà suspendue", ip);
            return Ok(());
        }

        // Ajouter les règles iptables pour un blocage permanent
        if let Err(e) = Self::add_iptables_rule(&ip) {
            error!("Erreur lors de l'ajout des règles iptables: {}", e);
            return Err(e);
        }

        // Vérifier si tcpkill est installé
        if !Self::is_tcpkill_installed() {
            warn!("tcpkill n'est pas installé. Le blocage se fera uniquement via iptables.");
            suspended.insert(ip);
            let mut interfaces = self.interfaces.lock().await;
            interfaces.insert(ip, Vec::new());
            if let Err(e) = save_state(&suspended, &interfaces) {
                error!("Erreur lors de la sauvegarde de l'état: {}", e);
            }
            info!("IP {} suspendue avec succès via iptables", ip);
            return Ok(());
        }

        let interfaces = if let Some(iface) = interface {
            vec![iface]
        } else {
            Self::get_network_interfaces()
        };

        let mut tcpkill_processes = Vec::new();
        let mut error_messages = Vec::new();
        let mut successful_interfaces = Vec::new();

        for iface in interfaces {
            match Self::start_tcpkill(&ip, &iface) {
                Ok(process) => {
                    tcpkill_processes.push(process);
                    successful_interfaces.push(iface.clone());
                    info!("Processus tcpkill démarré en arrière-plan pour l'IP {} sur l'interface {}", ip, iface);
                },
                Err(e) => {
                    let error_msg = format!("Échec du démarrage de tcpkill pour l'IP {} sur l'interface {}: {}", 
                        ip, iface, e);
                    error!("{}", error_msg);
                    error_messages.push(error_msg);
                }
            }
        }

        if !tcpkill_processes.is_empty() {
            // Stocker les processus tcpkill
            let mut processes = self.tcpkill_processes.lock().await;
            processes.insert(ip, tcpkill_processes);
            
            // Sauvegarder les interfaces
            let mut interfaces = self.interfaces.lock().await;
            interfaces.insert(ip, successful_interfaces);
            
            suspended.insert(ip);
            if let Err(e) = save_state(&suspended, &interfaces) {
                error!("Erreur lors de la sauvegarde de l'état: {}", e);
            }
            info!("IP {} suspendue avec succès sur toutes les interfaces", ip);
            Ok(())
        } else {
            // En cas d'échec, supprimer les règles iptables
            let _ = Self::remove_iptables_rule(&ip);
            Err(anyhow::anyhow!("Erreurs lors du blocage de l'IP:\n{}", error_messages.join("\n")))
        }
    }

    pub async fn unsuspend_ip(&self, ip: &IpAddr) -> Result<()> {
        let mut suspended = self.suspended_ips.lock().await;
        let is_suspended = suspended.contains(ip);
        
        // Arrêter tous les processus tcpkill
        if let Err(e) = self.stop_tcpkill_processes(ip).await {
            error!("Erreur lors de l'arrêt des processus tcpkill: {}", e);
            return Err(e);
        }

        // Vérifier que tcpkill n'est plus actif
        if Self::is_tcpkill_running(ip) {
            warn!("Des processus tcpkill sont toujours actifs pour l'IP {}. Tentative de les arrêter avec killall...", ip);
            let _ = Command::new("sudo")
                .args(&["killall", "-9", "tcpkill"])
                .output();
            
            // Vérifier à nouveau
            if Self::is_tcpkill_running(ip) {
                error!("Impossible d'arrêter tous les processus tcpkill pour l'IP {}", ip);
                return Err(anyhow::anyhow!("Des processus tcpkill sont toujours actifs pour l'IP {}", ip));
            }
        }

        // Supprimer les règles iptables
        if let Err(e) = Self::remove_iptables_rule(ip) {
            error!("Erreur lors de la suppression des règles iptables: {}", e);
            return Err(e);
        }

        if is_suspended {
            suspended.remove(ip);
            let mut interfaces = self.interfaces.lock().await;
            interfaces.remove(ip);
            if let Err(e) = save_state(&suspended, &interfaces) {
                error!("Erreur lors de la sauvegarde de l'état: {}", e);
            }
            info!("IP {} désuspendue avec succès", ip);
        } else {
            info!("IP {} n'était pas dans la liste des IPs suspendues, mais les règles ont été nettoyées", ip);
        }

        Ok(())
    }

    pub async fn is_suspended(&self, ip: &IpAddr) -> bool {
        let suspended = self.suspended_ips.lock().await;
        suspended.contains(ip)
    }

    pub async fn get_suspended_ips(&self) -> Vec<IpAddr> {
        let suspended = self.suspended_ips.lock().await;
        suspended.iter().copied().collect()
    }
} 
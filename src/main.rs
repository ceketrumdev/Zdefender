mod core {
    pub mod audit;
    pub mod benchmark;
    pub mod encryption;
    pub mod firewall;
    pub mod honeypot;
    pub mod memory;
    pub mod network;
    pub mod threading;
}

mod cli;

use std::path::Path;
use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use cli::CLI;

fn main() -> Result<(), Box<dyn Error>> {
    // Vérification des privilèges root
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Erreur: ZDefender nécessite des privilèges root pour fonctionner");
        return Err("Privilèges insuffisants".into());
    }

    // Initialisation des chemins de logs
    let log_path = Path::new("/var/log/zdefender/zdefender.log");
    let audit_path = Path::new("/var/log/zdefender/audit.log");

    // Création des répertoires avec les bonnes permissions
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
    }
    if let Some(parent) = audit_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
    }

    // Démarrage de l'interface CLI
    let mut cli = CLI::new(log_path, audit_path)?;
    cli.run();

    Ok(())
} 
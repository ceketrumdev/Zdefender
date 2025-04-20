use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Change le mode de fonctionnement de ZDefender
    #[arg(short, long)]
    pub mode: Option<Mode>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Mode {
    /// Mode d'analyse uniquement, sans action de protection
    Passive,
    /// Mode de protection actif avec blocage automatique
    Active,
}

#[derive(Subcommand)]
pub enum Command {
    /// Démarre le service ZDefender
    Start {
        /// Exécute en arrière-plan (daemon)
        #[arg(short, long)]
        daemon: bool,
    },
    
    /// Arrête le service ZDefender
    Stop,
    
    /// Affiche le statut actuel du service
    Status,
    
    /// Configure le mode forteresse
    Fortress {
        /// Active le mode forteresse
        #[arg(short, long)]
        enable: bool,
        
        /// Désactive le mode forteresse (prioritaire sur --enable)
        #[arg(long)]
        disable: bool,
    },
    
    /// Affiche les statistiques de protection
    Stats,

    /// Recharge la configuration
    Reload,
} 
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
    
    /// Affiche les statistiques en temps réel (Ctrl+C pour quitter)
    Stats,
    
    /// Affiche un rapport statique des statistiques basiques
    Check,
    
    /// Affiche des statistiques détaillées avec scores de confiance
    DetailedStats,
    
    /// Active ou désactive les statistiques en temps réel (obsolète, utilisez Stats)
    Realtime {
        /// Mode à définir (on ou off)
        #[arg(default_value = "on")]
        mode: RealtimeMode,
    },
    
    /// Sécurise rapidement le serveur en bloquant tous les ports non essentiels
    Secure {
        /// Liste des ports qui doivent rester ouverts (séparés par des virgules)
        #[arg(short, long)]
        ports: Option<String>,
    },

    /// Recharge la configuration
    Reload,
    
    /// Configure les scores de confiance régionaux
    ConfigureRegion {
        /// Code de région à configurer (ex: US, EU, CN, etc.)
        region: String,
        
        /// Score de confiance à attribuer (entre 0.0 et 1.0)
        #[arg(default_value = "0.5")]
        score: f64,
    },
    
    /// Consulte les informations sur une IP spécifique
    IpInfo {
        /// Adresse IP à vérifier
        ip: String,
    },

    /// Affiche les logs du système en temps réel
    Logs {
        /// Nombre de lignes à afficher (si non précisé, affiche les logs en continu)
        #[arg(short, long)]
        lines: Option<usize>,
        
        /// Filtre par niveau de log (error, warn, info, debug, trace)
        #[arg(short, long)]
        level: Option<String>,
    },
    
    /// Lance un benchmark du système anti-DDoS
    Benchmark {
        /// Nombre de paquets à traiter (défaut: 10000)
        #[arg(short, long, default_value = "10000")]
        packets: u64,
        
        /// Ratio de trafic normal vs trafic d'attaque (défaut: 0.8)
        #[arg(short, long, default_value = "0.8")]
        normal_ratio: f64,
        
        /// Fichier de sortie pour les résultats CSV
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Configure la protection contre les attaques DDoS distribuées
    DDoSProtection {
        /// Active la détection automatique des attaques DDoS distribuées
        #[arg(short, long)]
        enable: bool,
        
        /// Désactive la détection automatique des attaques DDoS distribuées
        #[arg(long)]
        disable: bool,
        
        /// Configure le seuil de ratio paquets/IPs (valeur par défaut: 50.0)
        #[arg(long)]
        ratio: Option<f64>,
        
        /// Configure le nombre minimum d'IPs distinctes pour considérer une attaque DDoS (valeur par défaut: 50)
        #[arg(long)]
        min_ips: Option<u32>,
        
        /// Configure le seuil de paquets par seconde pour déclencher une alerte (valeur par défaut: 5000)
        #[arg(long)]
        packets_per_second: Option<u64>,
        
        /// Configure la durée de protection après détection (en secondes, valeur par défaut: 300)
        #[arg(long)]
        duration: Option<u64>,
        
        /// Active l'activation automatique du mode forteresse en cas d'attaque
        #[arg(long)]
        auto_fortress: bool,
        
        /// Désactive l'activation automatique du mode forteresse
        #[arg(long)]
        no_auto_fortress: bool,
    },
    
    /// Configure les paramètres de mise à jour
    UpdateSettings {
        /// Active les mises à jour automatiques
        #[arg(short, long)]
        enable: bool,
        
        /// Désactive les mises à jour automatiques
        #[arg(long)]
        disable: bool,
        
        /// Configure le canal de mise à jour
        #[arg(long)]
        channel: Option<UpdateChannel>,
        
        /// Configure l'intervalle de vérification des mises à jour (en heures)
        #[arg(long)]
        interval: Option<u64>,
        
        /// Force une vérification immédiate des mises à jour
        #[arg(long)]
        check_now: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RealtimeMode {
    /// Active les statistiques en temps réel
    On,
    /// Désactive les statistiques en temps réel
    Off,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum UpdateChannel {
    /// Canal stable (versions stables uniquement)
    Stable,
    /// Canal beta (versions bêta et stables)
    Beta,
    /// Canal de développement (versions expérimentales)
    Dev,
} 
use crate::analyzer;
use crate::config::Config;
use crate::models::{Action, IpStats, IpStatsMap, PacketInfo, PacketType, Report, ReportType};
use crate::defender::Defender;
use crate::protection::ProtectionManager;
use crate::logger::Logger;
use async_trait::async_trait;

use log::{info, warn, debug, error};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use std::fs::File;
use std::io::Write;
use rand::{Rng, rngs::ThreadRng, thread_rng};
use num_format::{Locale, ToFormattedString};

/// Structure principale de benchmark pour le système ZDefender
pub struct ZDefenderBenchmark {
    config: Arc<RwLock<Config>>,
    logger: Arc<Logger>,
    analyzer: Arc<analyzer::Analyzer>,
    defender: Option<Arc<RwLock<Defender>>>,
    report_tx: mpsc::Sender<Report>,
    report_rx: mpsc::Receiver<Report>,
    protection_manager: Arc<RwLock<ProtectionManager>>,
    
    // Statistiques du benchmark
    packets_processed: u64,
    packets_blocked: u64,
    start_time: Instant,
    times: Vec<u128>, // durées en nanosecondes
    attack_detection_times: Vec<u128>, // temps de détection d'attaque
    
    // Configuration du benchmark
    normal_traffic_ratio: f64,
    attack_traffic_ratio: f64,
    max_packets: u64,
    
    // Générateur aléatoire
    rng: ThreadRng,
    
    // Source d'IPs
    normal_ips: Vec<IpAddr>,
    attack_ips: Vec<IpAddr>,
}

/// Résultats du benchmark
#[derive(Debug)]
pub struct BenchmarkResults {
    pub packets_processed: u64,
    pub packets_blocked: u64,
    pub total_duration_ms: u128,
    pub avg_packet_processing_ns: u128,
    pub median_packet_processing_ns: u128,
    pub p95_packet_processing_ns: u128, // 95th percentile
    pub p99_packet_processing_ns: u128, // 99th percentile
    pub avg_attack_detection_ms: u128,
    pub attacks_detected: u64,
    pub packet_throughput: f64, // packets per second
}

impl ZDefenderBenchmark {
    /// Crée une nouvelle instance du benchmark
    pub async fn new(
        config: Arc<RwLock<Config>>,
        normal_traffic_ratio: f64,
        attack_traffic_ratio: f64,
        max_packets: u64,
    ) -> Self {
        // Configurer les canaux de communication
        let (report_tx, report_rx) = mpsc::channel::<Report>(1000);
        
        // Initialiser le logger
        let log_config = {
            let config_guard = config.read().await;
            (config_guard.log_file.clone(), config_guard.log_mode)
        };
        let logger = Arc::new(Logger::new_with_mode(log_config.0, log_config.1));
        
        // Initialiser l'analyseur
        let analyzer = Arc::new(analyzer::Analyzer::new(config.clone(), report_tx.clone()));
        
        // Initialiser le défenseur
        let defender = Some(Arc::new(RwLock::new(Defender::new(
            config.clone(),
            logger.clone(),
        ).await)));
        
        // Initialiser le gestionnaire de protection
        let protection_manager = ProtectionManager::new(config.clone(), report_tx.clone()).await;
        let protection_manager = Arc::new(RwLock::new(protection_manager));
        
        // Générer les IPs
        let mut rng = rand::thread_rng();
        let normal_ips = (0..100).map(|_| generate_random_ip(&mut rng)).collect();
        let attack_ips = (0..20).map(|_| generate_random_ip(&mut rng)).collect();
        
        Self {
            config,
            logger,
            analyzer,
            defender,
            report_tx,
            report_rx,
            protection_manager,
            packets_processed: 0,
            packets_blocked: 0,
            start_time: Instant::now(),
            times: Vec::with_capacity(max_packets as usize),
            attack_detection_times: Vec::new(),
            normal_traffic_ratio,
            attack_traffic_ratio,
            max_packets,
            rng,
            normal_ips,
            attack_ips,
        }
    }
    
    /// Exécute le benchmark complet
    pub async fn run(&mut self) -> BenchmarkResults {
        info!("Démarrage du benchmark ZDefender");
        self.start_time = Instant::now();
        
        // Démarrer le traitement des rapports
        self.process_reports().await;
        
        // Phase 1: Trafic normal pour établir une ligne de base
        info!("Phase 1: Génération de trafic normal pour établir une ligne de base");
        self.generate_normal_traffic(self.max_packets / 4).await;
        
        // Phase 2: Mélanger trafic normal et attaques
        info!("Phase 2: Mélange de trafic normal et d'attaques");
        self.generate_mixed_traffic(self.max_packets / 2).await;
        
        // Phase 3: Trafic intense d'attaque pour tester les limites
        info!("Phase 3: Simulation d'attaque DDoS intensive");
        self.generate_attack_traffic(self.max_packets / 4).await;
        
        // Attendre que tous les rapports soient traités
        time::sleep(Duration::from_millis(500)).await;
        
        // Générer et retourner les résultats
        self.generate_results()
    }
    
    /// Génère uniquement du trafic normal
    async fn generate_normal_traffic(&mut self, count: u64) {
        let progress_interval = count / 10;
        
        for i in 0..count {
            if i % progress_interval == 0 {
                debug!("Génération de trafic normal: {}%", (i * 100) / count);
            }
            
            let packet = self.generate_normal_packet();
            self.process_packet(packet).await;
            
            // Petit délai pour éviter de surcharger le système
            if i % 1000 == 0 {
                time::sleep(Duration::from_micros(10)).await;
            }
        }
    }
    
    /// Génère un mélange de trafic normal et d'attaques
    async fn generate_mixed_traffic(&mut self, count: u64) {
        let progress_interval = count / 10;
        
        for i in 0..count {
            if i % progress_interval == 0 {
                debug!("Génération de trafic mixte: {}%", (i * 100) / count);
            }
            
            let packet = if self.rng.gen_bool(self.normal_traffic_ratio) {
                self.generate_normal_packet()
            } else {
                self.generate_attack_packet()
            };
            
            self.process_packet(packet).await;
            
            // Petit délai pour éviter de surcharger le système
            if i % 1000 == 0 {
                time::sleep(Duration::from_micros(10)).await;
            }
        }
    }
    
    /// Génère du trafic d'attaque intensif
    async fn generate_attack_traffic(&mut self, count: u64) {
        let progress_interval = count / 10;
        let attack_detection_start = Instant::now();
        let mut attack_detected = false;
        
        for i in 0..count {
            if i % progress_interval == 0 {
                debug!("Génération d'attaque: {}%", (i * 100) / count);
            }
            
            let packet = self.generate_attack_packet();
            let action = self.process_packet(packet).await;
            
            // Détecter quand l'attaque est identifiée
            if !attack_detected && matches!(action, Some(Action::Block(_, _))) {
                let detection_time = attack_detection_start.elapsed().as_nanos();
                self.attack_detection_times.push(detection_time);
                attack_detected = true;
                info!("Attaque détectée après {} paquets et {} ns", i, detection_time);
            }
            
            // Petit délai pour éviter de surcharger le système
            if i % 1000 == 0 {
                time::sleep(Duration::from_micros(10)).await;
            }
        }
    }
    
    /// Génère un paquet de trafic normal
    fn generate_normal_packet(&mut self) -> PacketInfo {
        let source_ip = *self.normal_ips.choose(&mut self.rng).unwrap_or(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let dest_ip = *self.normal_ips.choose(&mut self.rng).unwrap_or(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        
        // Générer des ports aléatoires mais réalistes
        let source_port = Some(self.rng.gen_range(1024..=65535));
        let dest_port = Some(self.rng.gen_range(80..=8080));
        
        // Varier les protocoles
        let protocol = match self.rng.gen_range(0..=9) {
            0..=6 => PacketType::Tcp,   // 70% TCP
            7..=8 => PacketType::Udp,   // 20% UDP
            _ => PacketType::Icmp,     // 10% ICMP
        };
        
        // Taille de paquet variable mais réaliste
        let size = self.rng.gen_range(64..=1500);
        
        PacketInfo {
            timestamp: SystemTime::now(),
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            protocol,
            size,
            flags: None,
            ttl: Some(64),
        }
    }
    
    /// Génère un paquet d'attaque
    fn generate_attack_packet(&mut self) -> PacketInfo {
        // Pour une attaque, on utilise une IP spécifique de la liste d'attaques
        let source_ip = *self.attack_ips.choose(&mut self.rng).unwrap_or(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        
        // L'attaque cible souvent un port spécifique
        let dest_port = Some(self.rng.gen_range(1..=1024)); // Ports bien connus
        
        // Les attaques sont souvent sur un protocole spécifique
        let protocol = match self.rng.gen_range(0..=9) {
            0..=4 => PacketType::Tcp,   // 50% TCP SYN flood
            5..=8 => PacketType::Udp,   // 40% UDP flood
            _ => PacketType::Icmp,     // 10% ICMP flood
        };
        
        // Taille de paquet variable
        let size = self.rng.gen_range(40..=2000);
        
        PacketInfo {
            timestamp: SystemTime::now(),
            source_ip,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), // Cible fixe
            source_port: Some(self.rng.gen_range(1024..=65535)),
            dest_port,
            protocol,
            size,
            flags: None,
            ttl: Some(64),
        }
    }
    
    /// Traite un paquet et mesure le temps nécessaire
    async fn process_packet(&mut self, packet: PacketInfo) -> Option<Action> {
        self.packets_processed += 1;
        
        // Mesurer le temps de traitement
        let start = Instant::now();
        
        // Analyser le paquet avec l'analyseur
        self.analyzer.analyze_packet(packet.clone()).await;
        
        // Vérifier si le paquet doit être bloqué
        let mut action = None;
        if let Some(_) = &self.defender {
            // Vérifier avec le gestionnaire de protection
            let mut protection_manager = self.protection_manager.write().await;
            action = protection_manager.process_packet(packet.clone()).await;
            
            // Si une action de blocage est suggérée, incrémenter le compteur
            if matches!(action, Some(Action::Block(_, _))) || matches!(action, Some(Action::Drop)) {
                self.packets_blocked += 1;
            }
        }
        
        // Enregistrer le temps de traitement
        let elapsed = start.elapsed().as_nanos();
        self.times.push(elapsed);
        
        action
    }
    
    /// Démarre une tâche pour traiter les rapports générés
    async fn process_reports(&mut self) {
        // Créer un nouvel émetteur et récepteur pour la tâche asynchrone
        let (internal_tx, mut internal_rx) = mpsc::channel::<Report>(1000);
        let defender_clone = self.defender.clone();
        
        // Créer une tâche qui écoute le canal report_rx et transfert les rapports à internal_rx
        let mut report_rx = std::mem::replace(&mut self.report_rx, mpsc::channel::<Report>(1).1);
        let internal_tx_clone = internal_tx.clone();
        
        tokio::spawn(async move {
            while let Some(report) = report_rx.recv().await {
                let _ = internal_tx_clone.send(report).await;
            }
        });
        
        // Tâche qui traite les rapports
        tokio::spawn(async move {
            while let Some(report) = internal_rx.recv().await {
                // Traiter le rapport
                if let Some(defender) = &defender_clone {
                    let mut defender = defender.write().await;
                    defender.handle_report(report).await;
                }
            }
        });
    }
    
    /// Génère les résultats du benchmark
    fn generate_results(&self) -> BenchmarkResults {
        let total_duration = self.start_time.elapsed();
        let total_duration_ms = total_duration.as_millis();
        
        // Calculer les statistiques sur les temps de traitement
        let avg_packet_processing_ns = if !self.times.is_empty() {
            self.times.iter().sum::<u128>() / self.times.len() as u128
        } else {
            0
        };
        
        // Trier les temps pour calculer la médiane et les percentiles
        let mut sorted_times = self.times.clone();
        sorted_times.sort_unstable();
        
        let median_packet_processing_ns = if !sorted_times.is_empty() {
            sorted_times[sorted_times.len() / 2]
        } else {
            0
        };
        
        let p95_index = (sorted_times.len() as f64 * 0.95) as usize;
        let p95_packet_processing_ns = if !sorted_times.is_empty() && p95_index < sorted_times.len() {
            sorted_times[p95_index]
        } else {
            0
        };
        
        let p99_index = (sorted_times.len() as f64 * 0.99) as usize;
        let p99_packet_processing_ns = if !sorted_times.is_empty() && p99_index < sorted_times.len() {
            sorted_times[p99_index]
        } else {
            0
        };
        
        // Calculer le temps moyen de détection d'attaque
        let avg_attack_detection_ms = if !self.attack_detection_times.is_empty() {
            (self.attack_detection_times.iter().sum::<u128>() / self.attack_detection_times.len() as u128) / 1_000_000
        } else {
            0
        };
        
        // Calculer le débit
        let packet_throughput = if total_duration.as_secs() > 0 {
            self.packets_processed as f64 / total_duration.as_secs() as f64
        } else {
            self.packets_processed as f64 / (total_duration.as_millis() as f64 / 1000.0)
        };
        
        BenchmarkResults {
            packets_processed: self.packets_processed,
            packets_blocked: self.packets_blocked,
            total_duration_ms,
            avg_packet_processing_ns,
            median_packet_processing_ns,
            p95_packet_processing_ns,
            p99_packet_processing_ns,
            avg_attack_detection_ms,
            attacks_detected: self.attack_detection_times.len() as u64,
            packet_throughput,
        }
    }
    
    /// Génère un rapport CSV avec les résultats de benchmark
    pub fn save_results_to_csv(&self, results: &BenchmarkResults, file_path: &str) -> std::io::Result<()> {
        let mut file = File::create(file_path)?;
        
        // Entêtes
        writeln!(file, "Métrique,Valeur")?;
        
        // Données
        writeln!(file, "Paquets traités,{}", results.packets_processed.to_formatted_string(&Locale::fr))?;
        writeln!(file, "Paquets bloqués,{}", results.packets_blocked.to_formatted_string(&Locale::fr))?;
        writeln!(file, "Durée totale (ms),{}", results.total_duration_ms)?;
        writeln!(file, "Temps moyen de traitement (ns),{}", results.avg_packet_processing_ns)?;
        writeln!(file, "Temps médian de traitement (ns),{}", results.median_packet_processing_ns)?;
        writeln!(file, "95e percentile temps de traitement (ns),{}", results.p95_packet_processing_ns)?;
        writeln!(file, "99e percentile temps de traitement (ns),{}", results.p99_packet_processing_ns)?;
        writeln!(file, "Temps moyen de détection d'attaque (ms),{}", results.avg_attack_detection_ms)?;
        writeln!(file, "Nombre d'attaques détectées,{}", results.attacks_detected)?;
        writeln!(file, "Débit (paquets/seconde),{:.2}", results.packet_throughput)?;
        
        // Configuration du système
        let config_guard = futures::executor::block_on(async {
            self.config.read().await.clone()
        });
        
        writeln!(file, "\nConfiguration")?;
        writeln!(file, "Threads d'analyse,{}", config_guard.analyzer_threads)?;
        writeln!(file, "Seuil de paquets,{}", config_guard.packet_threshold)?;
        writeln!(file, "Intervalle de vérification,{}", config_guard.check_interval)?;
        writeln!(file, "Taille de la file de paquets,{}", config_guard.packet_queue_size)?;
        writeln!(file, "Traitement parallèle,{}", config_guard.parallel_processing)?;
        
        Ok(())
    }
    
    /// Affiche un résumé des résultats du benchmark
    pub fn print_results(&self, results: &BenchmarkResults) {
        println!("\n=== RÉSULTATS DU BENCHMARK ZDEFENDER ===");
        println!("Paquets traités: {}", results.packets_processed.to_formatted_string(&Locale::fr));
        println!("Paquets bloqués: {}", results.packets_blocked.to_formatted_string(&Locale::fr));
        println!("Pourcentage de blocage: {:.2}%", (results.packets_blocked as f64 / results.packets_processed as f64) * 100.0);
        println!("Durée totale: {} ms", results.total_duration_ms);
        println!("Temps moyen de traitement: {} ns", results.avg_packet_processing_ns);
        println!("Temps médian de traitement: {} ns", results.median_packet_processing_ns);
        println!("95e percentile: {} ns", results.p95_packet_processing_ns);
        println!("99e percentile: {} ns", results.p99_packet_processing_ns);
        println!("Temps moyen de détection d'attaque: {} ms", results.avg_attack_detection_ms);
        println!("Nombre d'attaques détectées: {}", results.attacks_detected);
        println!("Débit: {:.2} paquets/seconde", results.packet_throughput);
        println!("====================================");
    }
}

/// Génère une adresse IP aléatoire
fn generate_random_ip(rng: &mut ThreadRng) -> IpAddr {
    // 80% IPv4, 20% IPv6
    if rng.gen_bool(0.8) {
        let a = rng.gen_range(1..=254);
        let b = rng.gen_range(0..=255);
        let c = rng.gen_range(0..=255);
        let d = rng.gen_range(1..=254);
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    } else {
        // Génération simple d'IPv6
        let segments: [u16; 8] = [
            rng.gen(), rng.gen(), rng.gen(), rng.gen(),
            rng.gen(), rng.gen(), rng.gen(), rng.gen(),
        ];
        IpAddr::V6(segments.into())
    }
}

/// Extension du type Vec pour ajouter une méthode permettant de choisir un élément aléatoire
trait ChooseRandom<T> {
    fn choose(&self, rng: &mut ThreadRng) -> Option<&T>;
}

impl<T> ChooseRandom<T> for Vec<T> {
    fn choose(&self, rng: &mut ThreadRng) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            Some(&self[rng.gen_range(0..self.len())])
        }
    }
} 
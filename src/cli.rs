use std::io::{self, Write, BufRead};
use std::path::Path;
use crate::core::audit::{AuditSystem, LogLevel};
use crate::core::benchmark::BenchmarkSystem;

pub struct CLI {
    audit_system: AuditSystem,
    benchmark_system: BenchmarkSystem,
    running: bool,
}

impl CLI {
    pub fn new(log_path: &Path, audit_path: &Path) -> Result<Self, std::io::Error> {
        Ok(Self {
            audit_system: AuditSystem::new(log_path, audit_path)?,
            benchmark_system: BenchmarkSystem::new(),
            running: true,
        })
    }

    pub fn run(&mut self) {
        println!("ZDefender 2.0 CLI - Tapez 'help' pour la liste des commandes");
        
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        while self.running {
            print!("zdefender> ");
            stdout.flush().unwrap();

            let mut input = String::new();
            if stdin.lock().read_line(&mut input).is_err() {
                continue;
            }

            let command = input.trim();
            self.process_command(command);
        }
    }

    fn process_command(&mut self, command: &str) {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        match parts[0] {
            "help" => self.show_help(),
            "status" => self.show_status(),
            "logs" => self.show_logs(parts.get(1).map(|&n| n.parse().unwrap_or(10))),
            "benchmark" => self.run_benchmark(parts.get(1)),
            "clear" => self.clear_logs(),
            "exit" => self.running = false,
            _ => println!("Commande non reconnue. Tapez 'help' pour la liste des commandes."),
        }
    }

    fn show_help(&self) {
        println!("\nCommandes disponibles:");
        println!("  help     - Affiche cette aide");
        println!("  status   - Affiche le statut du système");
        println!("  logs [n] - Affiche les n derniers logs (défaut: 10)");
        println!("  benchmark [nom] - Lance un benchmark");
        println!("  clear    - Efface les logs");
        println!("  exit     - Quitte l'application\n");
    }

    fn show_status(&self) {
        let metrics = self.audit_system.get_metrics();
        println!("\nStatut du système:");
        println!("  Requêtes totales: {}", metrics.total_requests);
        println!("  Requêtes bloquées: {}", metrics.blocked_requests);
        println!("  Attaques DDoS: {}", metrics.ddos_attacks);
        println!("  Utilisation mémoire: {:.1}%", metrics.memory_usage);
        println!("  Utilisation CPU: {:.1}%\n");
    }

    fn show_logs(&self, count: Option<usize>) {
        let count = count.unwrap_or(10);
        let logs = self.audit_system.get_recent_logs(count);
        
        println!("\nDerniers logs:");
        for log in logs {
            println!(
                "[{}] [{}] [{}] {} {}",
                log.timestamp,
                format!("{:?}", log.level),
                log.module,
                log.message,
                log.metadata.unwrap_or_default()
            );
        }
        println!();
    }

    fn run_benchmark(&self, name: Option<&str>) {
        let name = name.unwrap_or("default");
        self.benchmark_system.start_benchmark(name);
        
        // Simuler une opération
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        if let Some(result) = self.benchmark_system.end_benchmark(1000) {
            println!("\nRésultats du benchmark '{}':", name);
            println!("  Durée: {:?}", result.duration);
            println!("  Opérations/seconde: {:.2}", result.operations_per_second);
            println!("  Utilisation mémoire: {} bytes", result.memory_usage);
            println!("  Utilisation CPU: {:.1}%\n", result.cpu_usage);
        }
    }

    fn clear_logs(&self) {
        self.audit_system.clear_logs();
        println!("Logs effacés.\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cli_creation() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let audit_path = dir.path().join("test.audit");

        let cli = CLI::new(&log_path, &audit_path);
        assert!(cli.is_ok());
    }
} 
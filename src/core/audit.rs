use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;
use std::os::unix::fs::OpenOptionsExt;

const MAX_LOG_ENTRIES: usize = 10000;
const LOG_BUFFER_SIZE: usize = 1024 * 1024; // 1 MB

#[derive(Debug, Clone)]
pub enum LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    timestamp: u64,
    level: LogLevel,
    module: String,
    message: String,
    metadata: Option<String>,
}

pub struct AuditSystem {
    log_writer: Arc<Mutex<BufWriter<File>>>,
    log_buffer: Arc<Mutex<VecDeque<LogEntry>>>,
    audit_writer: Arc<Mutex<BufWriter<File>>>,
    metrics: Arc<Mutex<Metrics>>,
}

#[derive(Debug, Default)]
struct Metrics {
    total_requests: u64,
    blocked_requests: u64,
    ddos_attacks: u64,
    memory_usage: f64,
    cpu_usage: f64,
    response_times: Vec<u64>,
}

impl AuditSystem {
    pub fn new(log_path: &Path, audit_path: &Path) -> Result<Self, std::io::Error> {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(log_path)?;

        let audit_file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(audit_path)?;

        Ok(Self {
            log_writer: Arc::new(Mutex::new(BufWriter::with_capacity(LOG_BUFFER_SIZE, log_file))),
            log_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES))),
            audit_writer: Arc::new(Mutex::new(BufWriter::with_capacity(LOG_BUFFER_SIZE, audit_file))),
            metrics: Arc::new(Mutex::new(Metrics::default())),
        })
    }

    pub fn log(&self, level: LogLevel, module: &str, message: &str, metadata: Option<&str>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = LogEntry {
            timestamp,
            level: level.clone(),
            module: module.to_string(),
            message: message.to_string(),
            metadata: metadata.map(String::from),
        };

        // Ajouter à la mémoire tampon
        {
            let mut buffer = self.log_buffer.lock().unwrap();
            if buffer.len() >= MAX_LOG_ENTRIES {
                buffer.pop_front();
            }
            buffer.push_back(entry.clone());
        }

        // Écrire dans le fichier
        if let Ok(mut writer) = self.log_writer.lock() {
            let log_line = format!(
                "[{}] [{}] [{}] {} {}\n",
                timestamp,
                format!("{:?}", level),
                module,
                message,
                metadata.unwrap_or("")
            );
            let _ = writer.write_all(log_line.as_bytes());
            let _ = writer.flush();
        }

        // Journalisation système pour les événements critiques
        if matches!(level, LogLevel::ERROR | LogLevel::CRITICAL) {
            let _ = std::process::Command::new("logger")
                .arg("-t")
                .arg("zdefender")
                .arg(&format!("[{}] {}", module, message))
                .output();
        }
    }

    pub fn audit(&self, action: &str, user: &str, details: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Ok(mut writer) = self.audit_writer.lock() {
            let audit_line = format!(
                "[{}] [AUDIT] User: {} Action: {} Details: {}\n",
                timestamp, user, action, details
            );
            let _ = writer.write_all(audit_line.as_bytes());
            let _ = writer.flush();
        }

        // Journalisation système pour l'audit
        let _ = std::process::Command::new("logger")
            .arg("-t")
            .arg("zdefender-audit")
            .arg(&format!("User: {} Action: {} Details: {}", user, action, details))
            .output();
    }

    pub fn update_metrics(&self, metrics: Metrics) {
        if let Ok(mut current_metrics) = self.metrics.lock() {
            *current_metrics = metrics;
        }
    }

    pub fn get_metrics(&self) -> Metrics {
        self.metrics.lock().unwrap().clone()
    }

    pub fn get_recent_logs(&self, count: usize) -> Vec<LogEntry> {
        self.log_buffer
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    pub fn clear_logs(&self) {
        if let Ok(mut buffer) = self.log_buffer.lock() {
            buffer.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_logging() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let audit_path = dir.path().join("test.audit");

        let audit_system = AuditSystem::new(&log_path, &audit_path).unwrap();
        audit_system.log(
            LogLevel::INFO,
            "test",
            "Test message",
            Some("metadata"),
        );

        let logs = audit_system.get_recent_logs(1);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "Test message");
    }

    #[test]
    fn test_metrics() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let audit_path = dir.path().join("test.audit");

        let audit_system = AuditSystem::new(&log_path, &audit_path).unwrap();
        let mut metrics = Metrics::default();
        metrics.total_requests = 100;
        metrics.blocked_requests = 10;
        audit_system.update_metrics(metrics);

        let current_metrics = audit_system.get_metrics();
        assert_eq!(current_metrics.total_requests, 100);
        assert_eq!(current_metrics.blocked_requests, 10);
    }
} 
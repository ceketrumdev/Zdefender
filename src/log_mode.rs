use serde::{Deserialize, Serialize};

/// Mode de journalisation utilisé par le système
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogMode {
    /// Journal dans un fichier local
    File,
    /// Journal via systemd-journal
    SystemdJournal,
}

impl Default for LogMode {
    fn default() -> Self {
        LogMode::File
    }
} 
pub mod models;
pub mod protection;
pub mod packet_inspection;
pub mod detect_attacks;
pub mod config;
pub mod intelligent_detection;
pub mod log_mode;
pub mod logger;

// Re-export des structures principales pour faciliter l'utilisation
pub use models::{PacketInfo, Report, ReportType, Action, IpStats, BlockedIp, GlobalStats};
pub use protection::ProtectionManager;
pub use log_mode::LogMode; 
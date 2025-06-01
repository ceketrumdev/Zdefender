use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log::{info, warn, error};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub packets: u32,
    pub bytes: u64,
    pub last_seen: Instant,
}

#[derive(Debug)]
pub struct Firewall {
    connection_stats: Arc<Mutex<HashMap<IpAddr, ConnectionStats>>>,
    blocked_ips: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    ddos_threshold: u32,
    block_duration: Duration,
}

impl Firewall {
    pub fn new(ddos_threshold: u32, block_duration_seconds: u32) -> Self {
        Self {
            connection_stats: Arc::new(Mutex::new(HashMap::new())),
            blocked_ips: Arc::new(Mutex::new(HashMap::new())),
            ddos_threshold,
            block_duration: Duration::from_secs(block_duration_seconds as u64),
        }
    }

    pub fn process_packet(&self, src_ip: IpAddr, packet_data: &[u8]) -> bool {
        // Vérifier si l'IP est bloquée
        if self.is_ip_blocked(src_ip) {
            return false;
        }

        // Mettre à jour les statistiques
        self.update_stats(src_ip, packet_data.len() as u64);

        // Vérifier les seuils DDoS
        if self.check_ddos_threshold(src_ip) {
            self.block_ip(src_ip);
            return false;
        }

        true
    }

    fn update_stats(&self, ip: IpAddr, bytes: u64) {
        let mut stats = self.connection_stats.lock().unwrap();
        let entry = stats.entry(ip).or_insert(ConnectionStats {
            packets: 0,
            bytes: 0,
            last_seen: Instant::now(),
        });

        entry.packets += 1;
        entry.bytes += bytes;
        entry.last_seen = Instant::now();
    }

    fn check_ddos_threshold(&self, ip: IpAddr) -> bool {
        let stats = self.connection_stats.lock().unwrap();
        if let Some(conn_stats) = stats.get(&ip) {
            if conn_stats.packets > self.ddos_threshold {
                warn!("DDoS détecté depuis {}: {} paquets", ip, conn_stats.packets);
                return true;
            }
        }
        false
    }

    fn block_ip(&self, ip: IpAddr) {
        let mut blocked = self.blocked_ips.lock().unwrap();
        blocked.insert(ip, Instant::now());
        info!("IP {} bloquée pour {} secondes", ip, self.block_duration.as_secs());
    }

    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        let mut blocked = self.blocked_ips.lock().unwrap();
        
        // Nettoyer les IPs expirées
        blocked.retain(|_, time| time.elapsed() < self.block_duration);
        
        blocked.contains_key(&ip)
    }

    pub fn cleanup_expired_blocks(&self) {
        let mut blocked = self.blocked_ips.lock().unwrap();
        blocked.retain(|ip, time| {
            if time.elapsed() >= self.block_duration {
                info!("Déblocage de l'IP {}", ip);
                false
            } else {
                true
            }
        });
    }

    pub fn get_connection_stats(&self) -> HashMap<IpAddr, ConnectionStats> {
        self.connection_stats.lock().unwrap().clone()
    }

    pub fn get_blocked_ips(&self) -> HashMap<IpAddr, Instant> {
        self.blocked_ips.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_firewall_creation() {
        let firewall = Firewall::new(1000, 3600);
        assert_eq!(firewall.ddos_threshold, 1000);
        assert_eq!(firewall.block_duration.as_secs(), 3600);
    }

    #[test]
    fn test_ip_blocking() {
        let firewall = Firewall::new(10, 1);
        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Simuler des paquets jusqu'au seuil
        for _ in 0..11 {
            firewall.process_packet(test_ip, &[0; 100]);
        }

        // Vérifier que l'IP est bloquée
        assert!(!firewall.process_packet(test_ip, &[0; 100]));
    }
} 
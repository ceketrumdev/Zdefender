use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::{SocketAddr, TcpListener, TcpStream};
use log::{info, error, warn};
use serde::{Serialize, Deserialize};
use std::error::Error;
use crate::core::encryption::EncryptionManager;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};
use nix::sys::socket::{bind, connect, recv, send, setsockopt, sockopt};
use nix::sys::socket::sockopt::ReuseAddr;
use std::os::unix::io::RawFd;
use std::thread;
use std::sync::mpsc::{channel, Sender, Receiver};

const MAX_PACKET_SIZE: usize = 65535;
const ENCRYPTION_THREADS: usize = 4;
const ROUTING_TABLE_SIZE: usize = 1000;

#[derive(Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    Heartbeat,
    Alert {
        source_ip: String,
        alert_type: String,
        details: String,
    },
    Command {
        command: String,
        parameters: Vec<String>,
    },
    Response {
        status: bool,
        message: String,
    },
}

#[derive(Debug, Clone)]
pub struct Packet {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: Vec<u8>,
    timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct Route {
    destination: IpAddr,
    next_hop: IpAddr,
    interface: String,
    metric: u32,
}

pub struct NetworkManager {
    encryption: EncryptionManager,
    listener: Option<TcpListener>,
    clients: Vec<SocketAddr>,
    routes: Arc<Mutex<HashMap<IpAddr, Route>>>,
    encryption_sender: Sender<Packet>,
    analysis_sender: Sender<Packet>,
    running: Arc<Mutex<bool>>,
    raw_socket: RawFd,
}

impl NetworkManager {
    pub fn new(encryption: EncryptionManager) -> Self {
        Self {
            encryption,
            listener: None,
            clients: Vec::new(),
            routes: Arc::new(Mutex::new(HashMap::with_capacity(ROUTING_TABLE_SIZE))),
            encryption_sender: Sender::new(),
            analysis_sender: Sender::new(),
            running: Arc::new(Mutex::new(true)),
            raw_socket: 0,
        }
    }

    pub async fn start_server(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(addr).await?;
        self.listener = Some(listener);
        info!("Serveur démarré sur {}", addr);

        self.accept_connections().await
    }

    async fn accept_connections(&mut self) -> Result<(), Box<dyn Error>> {
        let listener = self.listener.as_ref().unwrap();
        
        loop {
            let (socket, addr) = listener.accept().await?;
            info!("Nouvelle connexion depuis {}", addr);
            self.clients.push(addr);

            let encryption = self.encryption.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(socket, encryption).await {
                    error!("Erreur de gestion du client {}: {}", addr, e);
                }
            });
        }
    }

    async fn handle_client(
        mut socket: TcpStream,
        encryption: EncryptionManager,
    ) -> Result<(), Box<dyn Error>> {
        let mut buffer = vec![0; 4096];

        loop {
            let n = socket.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            let decrypted = encryption.decrypt(&buffer[..n])?;
            let message: NetworkMessage = serde_json::from_slice(&decrypted)?;

            match message {
                NetworkMessage::Heartbeat => {
                    let response = NetworkMessage::Response {
                        status: true,
                        message: "OK".to_string(),
                    };
                    let response_bytes = serde_json::to_vec(&response)?;
                    let encrypted = encryption.encrypt(&response_bytes)?;
                    socket.write_all(&encrypted).await?;
                }
                NetworkMessage::Alert { source_ip, alert_type, details } => {
                    warn!("Alerte de {}: {} - {}", source_ip, alert_type, details);
                }
                NetworkMessage::Command { command, parameters } => {
                    info!("Commande reçue: {} avec paramètres {:?}", command, parameters);
                }
                NetworkMessage::Response { status, message } => {
                    info!("Réponse reçue: {} - {}", status, message);
                }
            }
        }

        Ok(())
    }

    pub async fn connect_to_server(&self, addr: &str) -> Result<TcpStream, Box<dyn Error>> {
        let stream = TcpStream::connect(addr).await?;
        info!("Connecté au serveur {}", addr);
        Ok(stream)
    }

    pub async fn send_message(
        &self,
        stream: &mut TcpStream,
        message: NetworkMessage,
    ) -> Result<(), Box<dyn Error>> {
        let message_bytes = serde_json::to_vec(&message)?;
        let encrypted = self.encryption.encrypt(&message_bytes)?;
        stream.write_all(&encrypted).await?;
        Ok(())
    }

    pub fn start(&self) -> Result<(), String> {
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        
        while *self.running.lock().unwrap() {
            match recv(self.raw_socket, &mut buffer, 0) {
                Ok(size) => {
                    if size > 0 {
                        let packet = self.parse_packet(&buffer[..size])?;
                        
                        // Duplication du paquet pour l'analyse
                        self.analysis_sender.send(packet.clone())
                            .map_err(|e| format!("Erreur envoi analyse: {}", e))?;
                        
                        // Envoi pour chiffrement
                        self.encryption_sender.send(packet)
                            .map_err(|e| format!("Erreur envoi chiffrement: {}", e))?;
                    }
                }
                Err(e) => return Err(format!("Erreur réception paquet: {}", e)),
            }
        }
        Ok(())
    }

    fn parse_packet(&self, data: &[u8]) -> Result<Packet, String> {
        // Parsing basique des paquets IP
        if data.len() < 20 {
            return Err("Paquet trop court".to_string());
        }

        let source = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dest = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let protocol = data[9];

        Ok(Packet {
            source: IpAddr::V4(source),
            destination: IpAddr::V4(dest),
            protocol,
            payload: data[20..].to_vec(),
            timestamp: Instant::now(),
        })
    }

    fn encryption_worker(
        receiver: Receiver<Packet>,
        routes: Arc<Mutex<HashMap<IpAddr, Route>>>,
        running: Arc<Mutex<bool>>,
    ) {
        while *running.lock().unwrap() {
            if let Ok(packet) = receiver.recv() {
                // Chiffrement rapide du paquet
                let encrypted = Self::fast_encrypt(&packet.payload);
                
                // Recherche de la route
                if let Some(route) = routes.lock().unwrap().get(&packet.destination) {
                    // Envoi du paquet chiffré
                    Self::send_packet(&route, &encrypted);
                }
            }
        }
    }

    fn analysis_worker(
        receiver: Receiver<Packet>,
        running: Arc<Mutex<bool>>,
    ) {
        while *running.lock().unwrap() {
            if let Ok(packet) = receiver.recv() {
                // Analyse du paquet (à implémenter)
                // Cette partie sera développée dans un module séparé
            }
        }
    }

    fn fast_encrypt(data: &[u8]) -> Vec<u8> {
        // Chiffrement XOR simple pour la démonstration
        // À remplacer par un chiffrement plus robuste mais rapide
        let key: u8 = 0x42;
        data.iter().map(|&b| b ^ key).collect()
    }

    fn send_packet(route: &Route, data: &[u8]) {
        // Envoi du paquet vers la prochaine interface
        // À implémenter avec les appels système appropriés
    }

    pub fn add_route(&self, route: Route) {
        self.routes.lock().unwrap().insert(route.destination, route);
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }
}

impl Drop for NetworkManager {
    fn drop(&mut self) {
        self.stop();
        // Fermeture propre du socket
        let _ = nix::unistd::close(self.raw_socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_parsing() {
        let manager = NetworkManager::new(EncryptionManager::new()).unwrap();
        let test_data = vec![
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x01, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
        ];
        
        let packet = manager.parse_packet(&test_data).unwrap();
        assert_eq!(packet.source, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(packet.destination, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }
} 
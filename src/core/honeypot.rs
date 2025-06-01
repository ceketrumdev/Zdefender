use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, warn, error};
use serde::{Serialize, Deserialize};
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
pub struct HoneypotEvent {
    timestamp: u64,
    source_ip: String,
    source_port: u16,
    destination_port: u16,
    protocol: String,
    payload: Vec<u8>,
}

pub struct Honeypot {
    ports: Vec<u16>,
    log_writer: Arc<Mutex<BufWriter<std::fs::File>>>,
    running: Arc<Mutex<bool>>,
}

impl Honeypot {
    pub fn new(ports: Vec<u16>, log_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        
        let log_writer = Arc::new(Mutex::new(BufWriter::new(file)));
        
        Ok(Self {
            ports,
            log_writer,
            running: Arc::new(Mutex::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        drop(running);

        for &port in &self.ports {
            let log_writer = Arc::clone(&self.log_writer);
            let running = Arc::clone(&self.running);
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_port(port, log_writer, running).await {
                    error!("Erreur sur le port {}: {}", port, e);
                }
            });
        }

        Ok(())
    }

    async fn handle_port(
        port: u16,
        log_writer: Arc<Mutex<BufWriter<std::fs::File>>>,
        running: Arc<Mutex<bool>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
        info!("Honeypot en écoute sur le port {}", port);

        while *running.lock().unwrap() {
            if let Ok((stream, addr)) = listener.accept() {
                let log_writer = Arc::clone(&log_writer);
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(stream, addr, port, log_writer).await {
                        error!("Erreur de connexion: {}", e);
                    }
                });
            }
        }

        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        port: u16,
        log_writer: Arc<Mutex<BufWriter<std::fs::File>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer)?;
        
        let event = HoneypotEvent {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
            source_ip: addr.ip().to_string(),
            source_port: addr.port(),
            destination_port: port,
            protocol: "TCP".to_string(),
            payload: buffer[..n].to_vec(),
        };

        // Log l'événement
        let mut writer = log_writer.lock().unwrap();
        serde_json::to_writer(&mut *writer, &event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        // Simuler un service vulnérable
        stream.write_all(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")?;
        
        Ok(())
    }

    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_honeypot_creation() {
        let honeypot = Honeypot::new(vec![2222], "test_honeypot.log").unwrap();
        assert_eq!(honeypot.ports, vec![2222]);
    }
} 
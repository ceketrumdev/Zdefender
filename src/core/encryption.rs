use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const BLOCK_SIZE: usize = 16;
const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct EncryptionKey {
    key: [u8; KEY_SIZE],
    created_at: Instant,
}

pub struct EncryptionManager {
    current_key: Arc<Mutex<EncryptionKey>>,
    key_cache: Arc<Mutex<HashMap<[u8; 4], EncryptionKey>>>,
    last_rotation: Arc<Mutex<Instant>>,
}

impl EncryptionManager {
    pub fn new() -> Self {
        Self {
            current_key: Arc::new(Mutex::new(Self::generate_key())),
            key_cache: Arc::new(Mutex::new(HashMap::new())),
            last_rotation: Arc::new(Mutex::new(Instant::now())),
        }
    }

    fn generate_key() -> EncryptionKey {
        let mut key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            key[i] = rand::random();
        }
        EncryptionKey {
            key,
            created_at: Instant::now(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.check_key_rotation();
        let key = self.current_key.lock().unwrap();
        self.fast_encrypt(data, &key.key)
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.check_key_rotation();
        let key = self.current_key.lock().unwrap();
        self.fast_decrypt(data, &key.key)
    }

    fn fast_encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let key_len = key.len();
        
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key_len];
            result.push(byte ^ key_byte ^ (i as u8));
        }
        
        result
    }

    fn fast_decrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let key_len = key.len();
        
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key_len];
            result.push(byte ^ key_byte ^ (i as u8));
        }
        
        result
    }

    fn check_key_rotation(&self) {
        let mut last_rotation = self.last_rotation.lock().unwrap();
        if last_rotation.elapsed() >= KEY_ROTATION_INTERVAL {
            let new_key = Self::generate_key();
            *self.current_key.lock().unwrap() = new_key;
            *last_rotation = Instant::now();
        }
    }

    pub fn get_key_fingerprint(&self) -> [u8; 4] {
        let key = self.current_key.lock().unwrap();
        let mut fingerprint = [0u8; 4];
        for i in 0..4 {
            fingerprint[i] = key.key[i] ^ key.key[i + 4];
        }
        fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let manager = EncryptionManager::new();
        let test_data = b"Test message for encryption";
        
        let encrypted = manager.encrypt(test_data);
        let decrypted = manager.decrypt(&encrypted);
        
        assert_eq!(test_data, decrypted.as_slice());
    }

    #[test]
    fn test_key_rotation() {
        let manager = EncryptionManager::new();
        let initial_fingerprint = manager.get_key_fingerprint();
        
        // Forcer la rotation de la clé
        *manager.last_rotation.lock().unwrap() = Instant::now() - KEY_ROTATION_INTERVAL;
        manager.check_key_rotation();
        
        let new_fingerprint = manager.get_key_fingerprint();
        assert_ne!(initial_fingerprint, new_fingerprint);
    }
} 
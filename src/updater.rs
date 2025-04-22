use crate::config::Config;
use log::{info, warn, error};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::process::Command;
use std::time::Duration;
use std::path::Path;

const GITHUB_REPO_URL: &str = "https://github.com/ceketrumdev/Zdefender";
const GITHUB_API_RELEASES_URL: &str = "https://api.github.com/repos/ceketrumdev/Zdefender/releases/latest";

#[derive(Debug, Serialize, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: String,
    published_at: String,
    body: String,
    html_url: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// Structure gérant les mises à jour du système
pub struct UpdateManager {
    config: Arc<RwLock<Config>>,
    http_client: Client,
}

impl UpdateManager {
    /// Crée une nouvelle instance du gestionnaire de mises à jour
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        // Créer un client HTTP avec un timeout raisonnable
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("zdefender-updater")
            .build()
            .unwrap_or_else(|_| Client::new());
            
        Self {
            config,
            http_client: client,
        }
    }
    
    /// Vérifie si une mise à jour est disponible et la télécharge si nécessaire
    pub async fn check_for_updates(&self) -> Result<bool, Box<dyn std::error::Error>> {
        info!("Vérification des mises à jour depuis {}", GITHUB_REPO_URL);
        
        // Récupérer la version actuelle depuis la configuration
        let current_version = {
            let config = self.config.read().await;
            config.version.clone()
        };
        
        info!("Version actuelle: {}", current_version);
        
        // Récupérer les informations sur la dernière version depuis GitHub
        let latest_release = match self.fetch_latest_release().await {
            Ok(release) => release,
            Err(e) => {
                warn!("Impossible de récupérer la dernière version: {}", e);
                return Ok(false);
            }
        };
        
        let latest_version = latest_release.tag_name.trim_start_matches('v').to_string();
        info!("Dernière version disponible: {}", latest_version);
        
        // Comparer les versions
        if self.is_newer_version(&latest_version, &current_version) {
            info!("Une nouvelle version est disponible: {} -> {}", current_version, latest_version);
            
            // Vérifier si les mises à jour automatiques sont activées
            let auto_update_enabled = {
                let config = self.config.read().await;
                config.auto_update
            };
            
            if auto_update_enabled {
                info!("Téléchargement et installation de la mise à jour...");
                
                // Télécharger et installer la mise à jour
                match self.download_and_install_update(&latest_release).await {
                    Ok(_) => {
                        info!("Mise à jour vers la version {} réussie", latest_version);
                        
                        // Mettre à jour la version dans la configuration
                        let mut config = self.config.write().await;
                        config.version = latest_version.clone();
                        
                        if let Err(e) = config.save() {
                            error!("Erreur lors de la sauvegarde de la configuration après mise à jour: {}", e);
                        }
                        
                        return Ok(true);
                    },
                    Err(e) => {
                        error!("Échec de la mise à jour: {}", e);
                        return Err(e);
                    }
                }
            } else {
                info!("Une mise à jour est disponible, mais les mises à jour automatiques sont désactivées");
                info!("Vous pouvez mettre à jour manuellement depuis: {}", latest_release.html_url);
                return Ok(false);
            }
        } else {
            info!("Le système est à jour");
            return Ok(false);
        }
    }
    
    /// Récupère les informations sur la dernière version depuis GitHub
    async fn fetch_latest_release(&self) -> Result<GitHubRelease, Box<dyn std::error::Error>> {
        let response = self.http_client
            .get(GITHUB_API_RELEASES_URL)
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(format!("Erreur HTTP: {}", response.status()).into());
        }
        
        let release: GitHubRelease = response.json().await?;
        Ok(release)
    }
    
    /// Compare deux versions sémantiques
    fn is_newer_version(&self, latest: &str, current: &str) -> bool {
        // Fonction simple pour comparer des versions sémantiques (x.y.z)
        let parse_version = |v: &str| -> (u32, u32, u32) {
            let parts: Vec<&str> = v.split('.').collect();
            let major = parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(0);
            let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            (major, minor, patch)
        };
        
        let latest_parsed = parse_version(latest);
        let current_parsed = parse_version(current);
        
        latest_parsed > current_parsed
    }
    
    /// Télécharge et installe une mise à jour
    async fn download_and_install_update(&self, release: &GitHubRelease) -> Result<(), Box<dyn std::error::Error>> {
        // Vérifier s'il y a des fichiers à télécharger
        if release.assets.is_empty() {
            return Err("Aucun fichier de mise à jour disponible".into());
        }
        
        // Trouver le bon fichier d'installation pour la plateforme actuelle
        let asset = self.find_appropriate_asset(&release.assets)?;
        
        info!("Téléchargement de {} ({})", asset.name, self.format_size(asset.size));
        
        // Créer un répertoire temporaire pour le téléchargement
        let temp_dir = std::env::temp_dir().join("zdefender_update");
        std::fs::create_dir_all(&temp_dir)?;
        
        let asset_path = temp_dir.join(&asset.name);
        
        // Télécharger le fichier
        let response = self.http_client
            .get(&asset.browser_download_url)
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(format!("Erreur de téléchargement: {}", response.status()).into());
        }
        
        let content = response.bytes().await?;
        std::fs::write(&asset_path, content)?;
        
        info!("Téléchargement terminé, installation en cours...");
        
        // Exécuter l'installation en fonction du type de fichier
        match Path::new(&asset.name).extension().and_then(|e| e.to_str()) {
            Some("sh") => {
                // Rendre le script exécutable
                let mode_result = Command::new("chmod")
                    .args(["+x", asset_path.to_str().unwrap()])
                    .output();
                
                if let Err(e) = mode_result {
                    return Err(format!("Erreur lors de la modification des permissions: {}", e).into());
                }
                
                // Exécuter le script d'installation
                let install_result = Command::new("sh")
                    .arg(asset_path.to_str().unwrap())
                    .output()?;
                
                if !install_result.status.success() {
                    let error_msg = String::from_utf8_lossy(&install_result.stderr);
                    return Err(format!("Erreur lors de l'installation: {}", error_msg).into());
                }
            },
            Some("zip") => {
                // Décompresser l'archive
                let unzip_result = Command::new("unzip")
                    .args(["-o", asset_path.to_str().unwrap(), "-d", temp_dir.to_str().unwrap()])
                    .output()?;
                
                if !unzip_result.status.success() {
                    let error_msg = String::from_utf8_lossy(&unzip_result.stderr);
                    return Err(format!("Erreur lors de la décompression: {}", error_msg).into());
                }
                
                // Chercher un script d'installation
                let install_script = temp_dir.join("install.sh");
                if install_script.exists() {
                    // Rendre le script exécutable
                    let _ = Command::new("chmod")
                        .args(["+x", install_script.to_str().unwrap()])
                        .output();
                    
                    // Exécuter le script d'installation
                    let install_result = Command::new("sh")
                        .arg(install_script.to_str().unwrap())
                        .output()?;
                    
                    if !install_result.status.success() {
                        let error_msg = String::from_utf8_lossy(&install_result.stderr);
                        return Err(format!("Erreur lors de l'installation: {}", error_msg).into());
                    }
                } else {
                    // Copier les fichiers manuellement
                    info!("Aucun script d'installation trouvé, copie des fichiers...");
                    
                    // Copier le binaire si présent
                    let bin_path = temp_dir.join("zdefender");
                    if bin_path.exists() {
                        let dest_path = "/usr/local/bin/zdefender";
                        std::fs::copy(bin_path, dest_path)?;
                        
                        // Rendre le binaire exécutable
                        let _ = Command::new("chmod")
                            .args(["+x", dest_path])
                            .output();
                    }
                }
            },
            _ => {
                return Err(format!("Type de fichier non pris en charge: {}", asset.name).into());
            }
        }
        
        // Nettoyage des fichiers temporaires
        let _ = std::fs::remove_dir_all(temp_dir);
        
        info!("Installation terminée avec succès");
        Ok(())
    }
    
    /// Trouve le fichier d'installation approprié pour la plateforme actuelle
    fn find_appropriate_asset(&self, assets: &[GitHubAsset]) -> Result<&GitHubAsset, Box<dyn std::error::Error>> {
        // Détecter le système d'exploitation
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        
        info!("Recherche d'une version pour {}-{}", os, arch);
        
        // Chercher une correspondance spécifique au système
        for asset in assets {
            let name = asset.name.to_lowercase();
            
            // Correspondance précise OS-ARCH
            if name.contains(&format!("{}-{}", os, arch)) 
               || (name.contains(os) && name.contains(arch)) {
                return Ok(asset);
            }
            
            // Pour Linux, chercher les formats génériques
            if os == "linux" && (name.ends_with(".sh") || name.contains("install")) {
                return Ok(asset);
            }
        }
        
        // Si on ne trouve pas de correspondance précise, prendre le premier script d'installation ou fichier zip
        for asset in assets {
            let name = asset.name.to_lowercase();
            if name.ends_with(".sh") || name.ends_with(".zip") {
                return Ok(asset);
            }
        }
        
        // Si tout échoue, prendre le premier asset
        assets.first().ok_or_else(|| "Aucun fichier de mise à jour trouvé".into())
    }
    
    /// Formate une taille en octets en une chaîne lisible
    fn format_size(&self, size: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        
        if size >= GB {
            format!("{:.2} GB", size as f64 / GB as f64)
        } else if size >= MB {
            format!("{:.2} MB", size as f64 / MB as f64)
        } else if size >= KB {
            format!("{:.2} KB", size as f64 / KB as f64)
        } else {
            format!("{} bytes", size)
        }
    }
} 
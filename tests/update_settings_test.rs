use zdefender::config::{Config, UpdateChannel};
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_update_settings() {
    // Créer une configuration de test
    let mut config = Config::default();
    config.auto_update = true;
    config.update_channel = UpdateChannel::Stable;
    config.update_check_interval = 24;
    
    let config_arc = Arc::new(RwLock::new(config));
    
    // Test 1: Désactiver les mises à jour automatiques
    {
        let mut config = config_arc.write().await;
        config.auto_update = false;
        assert_eq!(config.auto_update, false);
    }
    
    // Test 2: Activer les mises à jour automatiques
    {
        let mut config = config_arc.write().await;
        config.auto_update = true;
        assert_eq!(config.auto_update, true);
    }
    
    // Test 3: Changer le canal de mise à jour
    {
        let mut config = config_arc.write().await;
        config.update_channel = UpdateChannel::Beta;
        assert_eq!(config.update_channel, UpdateChannel::Beta);
    }
    
    // Test 4: Changer l'intervalle de vérification
    {
        let mut config = config_arc.write().await;
        config.update_check_interval = 48;
        assert_eq!(config.update_check_interval, 48);
    }
    
    println!("Tous les tests ont réussi!");
} 
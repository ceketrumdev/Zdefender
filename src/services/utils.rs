use crate::services::ZdefenderService;
use std::time::SystemTime;

impl ZdefenderService {
    /// Formate une durée de temps pour l'affichage
    pub fn format_duration(time: SystemTime) -> String {
        match SystemTime::now().duration_since(time) {
            Ok(duration) => {
                let secs = duration.as_secs();
                if secs < 60 {
                    format!("il y a {} secondes", secs)
                } else if secs < 3600 {
                    format!("il y a {} minutes", secs / 60)
                } else if secs < 86400 {
                    format!("il y a {} heures", secs / 3600)
                } else {
                    format!("il y a {} jours", secs / 86400)
                }
            },
            Err(_) => "temps inconnu".to_string()
        }
    }
} 
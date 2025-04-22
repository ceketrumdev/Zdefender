use crate::services::ZdefenderService;
use crate::analyzer::AnalyzerInterface;

impl ZdefenderService {
    /// Gère les commandes utilisateur
    pub async fn handle_command(&mut self, command: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Ajouter le traitement de commandes pour les nouvelles fonctionnalités
        if command == "stats" || command == "statistics" {
            let stats = self.get_security_stats().await;
            let blocked_ips = if let Some(analyzer) = &self.analyzer {
                analyzer.get_blocked_ips().await
            } else {
                Vec::new()
            };
            let established_conns = if let Some(defender) = &self.defender {
                let defender_read = defender.read().await;
                defender_read.get_established_connections().await
            } else {
                Vec::new()
            };

            let mut response = String::new();
            response.push_str("=== Statistiques de sécurité ===\n");
            response.push_str(&format!("Score de sécurité global: {:.2}\n", stats.average_security_score));
            response.push_str(&format!("Paquets analysés: {}\n", stats.total_packets_analyzed));
            response.push_str(&format!("Trafic entrant: {}/s\n", stats.inbound_bps));
            response.push_str(&format!("Trafic sortant: {}/s\n", stats.outbound_bps));
            response.push_str(&format!("Attaques détectées: {}\n", stats.attacks_detected));
            response.push_str(&format!("IPs bloquées: {}\n", blocked_ips.len()));
            response.push_str(&format!("Connexions établies: {}\n", established_conns.len()));

            return Ok(response);
        } else if command == "detailed_stats" {
            // Statistiques détaillées avec scores de confiance
            let mut response = String::new();

            // Statistiques globales
            let stats = self.get_security_stats().await;
            response.push_str("=== STATISTIQUES DÉTAILLÉES ===\n\n");
            response.push_str(&format!("Score de sécurité global: {:.2}\n", stats.average_security_score));
            response.push_str(&format!("Paquets analysés: {}\n", stats.total_packets_analyzed));
            response.push_str(&format!("Trafic entrant: {} octets/s\n", stats.inbound_bps));
            response.push_str(&format!("Trafic sortant: {} octets/s\n", stats.outbound_bps));
            response.push_str(&format!("Attaques détectées: {}\n", stats.attacks_detected));

            // Statistiques des IPs
            if let Some(analyzer) = &self.analyzer {
                let (_, ip_stats) = analyzer.get_stats().await;
                let blocked_ips = analyzer.get_blocked_ips().await;

                response.push_str("\n=== STATISTIQUES DES IPs ===\n");
                response.push_str(&format!("Nombre total d'IPs suivies: {}\n", ip_stats.len()));
                response.push_str(&format!("IPs bloquées: {}\n\n", blocked_ips.len()));

                // Top IPs par nombre de paquets
                response.push_str("Top 5 IPs par nombre de paquets:\n");
                for (i, (ip, stats)) in ip_stats.iter().take(5).enumerate() {
                    response.push_str(&format!("{}. {} - {} paquets - {:.2} p/s - Score de confiance: {:.2} - {}\n",
                                               i + 1, ip, stats.packet_count, stats.packets_per_second,
                                               stats.trust_score, if stats.is_blocked { "BLOQUÉE" } else { "active" }));
                }

                // IPs avec les meilleurs scores de confiance
                response.push_str("\nTop 5 IPs par score de confiance:\n");
                let mut ip_trust_scores: Vec<_> = ip_stats
                    .iter()
                    .map(|(ip, stats)| (*ip, stats.trust_score))
                    .collect();

                ip_trust_scores.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

                for (i, (ip, trust)) in ip_trust_scores.iter().take(5).enumerate() {
                    if let Some((_, stats)) = ip_stats.iter().find(|(addr, _)| addr == ip) {
                        response.push_str(&format!("{}. {} - Score: {:.2} - {} paquets - Depuis: {}\n",
                                                   i + 1, ip, trust, stats.packet_count,
                                                   Self::format_duration(stats.first_seen)));
                    }
                }

                // IPs avec les scores de confiance les plus bas
                response.push_str("\nIPs avec les scores de confiance les plus bas:\n");
                let mut low_trust_scores = ip_trust_scores;
                low_trust_scores.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

                for (i, (ip, trust)) in low_trust_scores.iter().take(5).enumerate() {
                    if let Some((_, stats)) = ip_stats.iter().find(|(addr, _)| addr == ip) {
                        response.push_str(&format!("{}. {} - Score: {:.2} - {} paquets - Anomalie: {:.2}\n",
                                                   i + 1, ip, trust, stats.packet_count, stats.anomaly_score));
                    }
                }
            } else {
                response.push_str("\nAucune statistique d'IP disponible (service non démarré)\n");
            }

            // Statistiques des connexions établies
            if let Some(defender) = &self.defender {
                let defender_read = defender.read().await;
                let established_conns = defender_read.get_established_connections().await;

                response.push_str("\n=== CONNEXIONS ÉTABLIES ===\n");
                response.push_str(&format!("Nombre total de connexions: {}\n\n", established_conns.len()));

                // Connexions les plus anciennes
                let mut conns = established_conns.clone();
                conns.sort_by(|a, b| a.created_at.cmp(&b.created_at));

                response.push_str("Connexions les plus anciennes:\n");
                for (i, conn) in conns.iter().take(5).enumerate() {
                    response.push_str(&format!("{}. {} - Âge: {} - Score: {:.2} - Paquets: {}\n",
                                               i + 1, conn.ip, Self::format_duration(conn.created_at),
                                               conn.trust_score, conn.packet_count));
                }
            } else {
                response.push_str("\nAucune connexion établie (service non démarré)\n");
            }

            // Afficher les infos sur la configuration des scores de confiance
            let config_read = self.config.read().await;
            response.push_str("\n=== CONFIGURATION DE CONFIANCE ===\n");
            response.push_str(&format!("Seuil de confiance: {:.2}\n", config_read.trust_threshold));
            response.push_str(&format!("Seuil de blocage auto: {:.2}\n", config_read.auto_block_threshold));
            response.push_str(&format!("Seuil de whitelist auto: {:.2}\n", config_read.auto_whitelist_threshold));

            response.push_str("\nScores de confiance régionaux:\n");
            if config_read.region_trust_scores.is_empty() {
                response.push_str("Aucun score régional configuré\n");
            } else {
                for (region, score) in &config_read.region_trust_scores {
                    response.push_str(&format!("- {}: {:.2}\n", region, score));
                }
            }

            return Ok(response);
        } else if command.starts_with("ip_info ") {
            // Obtenir les informations détaillées sur une IP spécifique
            let parts: Vec<&str> = command.splitn(2, ' ').collect();
            if parts.len() < 2 {
                return Err("Format invalide: ip_info [adresse_ip]".into());
            }

            let ip_str = parts[1];
            match ip_str.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    let mut response = String::new();
                    response.push_str(&format!("=== INFORMATIONS SUR L'IP {} ===\n\n", ip));

                    // Vérifier si l'IP est dans la whitelist permanente
                    let is_whitelisted = {
                        let config = self.config.read().await;
                        config.whitelist.contains(&ip.to_string())
                    };

                    if is_whitelisted {
                        response.push_str("Cette IP est dans la liste blanche permanente.\n\n");
                    }

                    // Vérifier si l'IP est bloquée
                    let is_blocked = if let Some(analyzer) = &self.analyzer {
                        let blocked_ips = analyzer.get_blocked_ips().await;
                        blocked_ips.iter().any(|(blocked_ip, _)| *blocked_ip == ip)
                    } else {
                        false
                    };

                    if is_blocked {
                        response.push_str("STATUT: BLOQUÉE\n\n");
                    }

                    // Obtenir les statistiques détaillées
                    if let Some(analyzer) = &self.analyzer {
                        if let Some(stats) = analyzer.get_ip_stats(ip).await {
                            response.push_str("Statistiques détaillées:\n");
                            response.push_str(&format!("- Première observation: {}\n", Self::format_duration(stats.first_seen)));
                            response.push_str(&format!("- Dernière activité: {}\n", Self::format_duration(stats.last_seen)));
                            response.push_str(&format!("- Paquets total: {}\n", stats.packet_count));
                            response.push_str(&format!("- Octets total: {}\n", stats.total_bytes));
                            response.push_str(&format!("- Paquets/sec: {:.2}\n", stats.packets_per_second));
                            response.push_str(&format!("- Octets/sec: {:.2}\n", stats.bytes_per_second));

                            response.push_str("\nRépartition par protocole:\n");
                            response.push_str(&format!("- TCP: {}\n", stats.tcp_count));
                            response.push_str(&format!("- UDP: {}\n", stats.udp_count));
                            response.push_str(&format!("- ICMP: {}\n", stats.icmp_count));
                            response.push_str(&format!("- Autres: {}\n", stats.other_count));

                            response.push_str("\nScores de sécurité:\n");
                            response.push_str(&format!("- Score de confiance: {:.2}\n", stats.trust_score));
                            response.push_str(&format!("- Score d'anomalie: {:.2}\n", stats.anomaly_score));
                            response.push_str(&format!("- Stabilité de connexion: {:.2}\n", stats.connection_stability));
                            response.push_str(&format!("- Compteur d'actions suspectes: {}\n", stats.suspicious_count));
                        } else {
                            response.push_str("Aucune statistique disponible pour cette IP.\n");
                        }
                    } else {
                        response.push_str("Service d'analyse non disponible (service non démarré).\n");
                    }

                    // Vérifier si l'IP a une connexion établie
                    if let Some(defender) = &self.defender {
                        let defender_read = defender.read().await;
                        let conns = defender_read.get_established_connections().await;

                        if let Some(conn) = conns.iter().find(|c| c.ip == ip) {
                            response.push_str("\nInformations de connexion:\n");
                            response.push_str(&format!("- Connexion établie: {}\n", if conn.is_established { "Oui" } else { "Non" }));
                            response.push_str(&format!("- Créée le: {}\n", Self::format_duration(conn.created_at)));
                            response.push_str(&format!("- Dernière activité: {}\n", Self::format_duration(conn.last_activity)));
                            response.push_str(&format!("- Score de confiance: {:.2}\n", conn.trust_score));
                            response.push_str(&format!("- Paquets échangés: {}\n", conn.packet_count));

                            if !conn.request_types.is_empty() {
                                response.push_str("- Types de requêtes: ");
                                for (i, req_type) in conn.request_types.iter().enumerate() {
                                    if i > 0 {
                                        response.push_str(", ");
                                    }
                                    response.push_str(req_type);
                                }
                                response.push_str("\n");
                            }
                        } else {
                            response.push_str("\nAucune connexion établie pour cette IP.\n");
                        }
                    }

                    return Ok(response);
                },
                Err(_) => {
                    return Err(format!("Adresse IP invalide: {}", ip_str).into());
                }
            }
        } else if command.starts_with("secure") {
            // Sécuriser le serveur
            let parts: Vec<&str> = command.split(' ').collect();
            let mut ports = Vec::new();

            // Vérifier s'il y a des ports spécifiés
            if parts.len() > 1 {
                for part in &parts[1..] {
                    if part.starts_with("ports=") {
                        let port_str = part.trim_start_matches("ports=");
                        for port_val in port_str.split(',') {
                            if let Ok(port) = port_val.trim().parse::<u16>() {
                                ports.push(port);
                            }
                        }
                    }
                }
            }

            // Si aucun port n'est spécifié, utiliser les ports essentiels de la configuration
            if ports.is_empty() {
                let config = self.config.read().await;
                ports = config.essential_ports.clone();
            }

            return self.secure_server(ports).await;
        } else if command == "realtime on" {
            self.toggle_realtime_stats(true).await?;
            return Ok("Statistiques en temps réel activées".to_string());
        } else if command == "realtime off" {
            self.toggle_realtime_stats(false).await?;
            return Ok("Statistiques en temps réel désactivées".to_string());
        } else if command.starts_with("logs") {
            // Format: logs [lines=N] [level=LEVEL]
            let parts: Vec<&str> = command.split(' ').collect();
            let mut lines: Option<usize> = None;
            let mut level: Option<String> = None;

            // Analyser les paramètres
            for part in &parts[1..] {
                if part.starts_with("lines=") {
                    if let Ok(n) = part.trim_start_matches("lines=").parse::<usize>() {
                        lines = Some(n);
                    }
                } else if part.starts_with("level=") {
                    level = Some(part.trim_start_matches("level=").to_string());
                }
            }

            // Appeler la méthode read_logs
            return match self.read_logs(lines, level).await {
                Ok(logs) => Ok(logs),
                Err(e) => Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Erreur lors de la lecture des logs: {}", e),
                ))),
            };
        }
        
        Ok(String::new())
    }
} 
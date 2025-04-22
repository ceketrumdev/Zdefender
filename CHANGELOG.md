# 📋 Changelog de ZDefender

## 🚀 Version 0.1.3 (21/04/2025)

### ✨ Nouvelles fonctionnalités

#### 🏰 Mode Forteresse Amélioré
- **Whitelist automatique** pour les connexions établies depuis plus de 5 minutes
- **Blocage automatique** des nouvelles connexions en mode forteresse
- **Système d'exceptions** pour services critiques

#### 📊 Interface de statistiques en temps réel
- **Rafraîchissement automatique** toutes les 0.5 secondes
- **Métriques avancées** : paquets traités, débit entrant/sortant
- **Score de sécurité moyen** pour tous les paquets analysés
- **Visualisation des connexions** établies avec leurs scores de confiance

#### 🔍 Système de confiance des IPs
- **Score de confiance dynamique** basé sur plusieurs paramètres :
  - Historique de connexions
  - Régularité et cohérence des requêtes
  - Ancienneté de la connexion
  - Région d'origine de l'IP
- **Gestion automatique** des connexions de confiance en mode forteresse
- **Configuration régionale** avec scores de confiance par pays/région

#### 🔒 Commande de sécurisation automatique
- **Lockdown rapide** du serveur avec un seul paramètre
- **Protection des ports** avec fermeture des ports non essentiels
- **Configuration personnalisable** des ports à maintenir ouverts

#### 🔄 Nouvelles commandes
- **stats** : Affichage des statistiques en temps réel jusqu'à Ctrl+C
- **check** : Affichage statique des statistiques de base
- **detailed-stats** : Statistiques détaillées avec scores de confiance
- **ip-info** : Informations complètes sur une IP spécifique
- **secure** : Sécurisation rapide du serveur avec ports personnalisables
- **configure-region** : Configuration des scores de confiance par région
- **Mode forteresse amélioré** pour une meilleure protection contre les attaques DDoS sophistiquées
- **Interface de statistiques en temps réel** pour une meilleure visibilité sur les attaques
- **Système de confiance d'IP dynamique** qui ajuste les scores en fonction du comportement
- **Gestion automatique des mises à jour** avec configuration des canaux (stable, beta, dev)
- Nouvelles commandes:
  - `stats` pour afficher des statistiques détaillées sur les performances
  - `ip` pour obtenir des informations sur une adresse IP spécifique
  - `update-settings` pour configurer les paramètres de mise à jour automatique

### 🛠️ Améliorations

- **Interface en temps réel améliorée** avec actualisation toutes les 0.5 secondes
- **Support des paramètres régionaux** pour une meilleure gestion des connexions
- **Gestion précise des temps d'expiration** des IP bloquées
- **Système de seuils de confiance** configurables via fichier config
- **Amélioration de l'architecture** pour une meilleure cohérence

### 🐛 Corrections

- **Gestion des signaux** pour arrêter proprement les statistiques temps réel
- **Correction du format des statistiques** pour une meilleure lisibilité
- **Optimisation des performances** lors de l'actualisation des statistiques

---

## 🔄 Version 0.1.2 (Janvier 2023)

- Correction du bug "Cannot start a runtime from within a runtime"
- Ajout de la commande `fortress --disable` pour désactiver le mode forteresse
- Amélioration de la journalisation des erreurs
- Correction des problèmes de permissions lors de l'installation 
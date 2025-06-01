# Documentation de l'API REST ZDefender

L'API REST de ZDefender permet de gérer la suspension et la désuspension d'IPs à distance. Le serveur API écoute sur `http://localhost:3000` par défaut.

## Endpoints

### 1. Suspendre une IP
```http
POST /api/v1/suspend
Content-Type: application/json

{
    "ip": "192.168.1.100",
    "interface": "eth0"  // Optionnel
}
```

**Réponse :**
```json
{
    "success": true,
    "message": "IP 192.168.1.100 suspendue avec succès"
}
```

**Erreur :**
```json
{
    "success": false,
    "message": "Erreur lors de la suspension de l'IP 192.168.1.100: [détails de l'erreur]"
}
```

### 2. Désuspendre une IP
```http
POST /api/v1/unsuspend/192.168.1.100
```

**Réponse :**
```json
{
    "success": true,
    "message": "IP 192.168.1.100 désuspendue avec succès"
}
```

**Erreur :**
```json
{
    "success": false,
    "message": "Erreur lors de la désuspension de l'IP 192.168.1.100: [détails de l'erreur]"
}
```

### 3. Vérifier le statut d'une IP
```http
GET /api/v1/status/192.168.1.100
```

**Réponse :**
```json
{
    "success": true,
    "message": "IP 192.168.1.100 est suspendue"
}
```
ou
```json
{
    "success": true,
    "message": "IP 192.168.1.100 n'est pas suspendue"
}
```

### 4. Lister toutes les IPs suspendues
```http
GET /api/v1/list
```

**Réponse :**
```json
{
    "success": true,
    "message": "IPs suspendues: 192.168.1.100, 192.168.1.101, 192.168.1.102"
}
```

## Exemples d'utilisation

### Avec curl

1. Suspendre une IP :
```bash
curl -X POST http://localhost:3000/api/v1/suspend \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

2. Suspendre une IP sur une interface spécifique :
```bash
curl -X POST http://localhost:3000/api/v1/suspend \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "interface": "eth0"}'
```

3. Désuspendre une IP :
```bash
curl -X POST http://localhost:3000/api/v1/unsuspend/192.168.1.100
```

4. Vérifier le statut d'une IP :
```bash
curl http://localhost:3000/api/v1/status/192.168.1.100
```

5. Lister les IPs suspendues :
```bash
curl http://localhost:3000/api/v1/list
```

### Avec Python

```python
import requests

BASE_URL = "http://localhost:3000"

def suspend_ip(ip, interface=None):
    data = {"ip": ip}
    if interface:
        data["interface"] = interface
    
    response = requests.post(f"{BASE_URL}/api/v1/suspend", json=data)
    return response.json()

def unsuspend_ip(ip):
    response = requests.post(f"{BASE_URL}/api/v1/unsuspend/{ip}")
    return response.json()

def check_status(ip):
    response = requests.get(f"{BASE_URL}/api/v1/status/{ip}")
    return response.json()

def list_suspended():
    response = requests.get(f"{BASE_URL}/api/v1/list")
    return response.json()

# Exemples d'utilisation
print(suspend_ip("192.168.1.100"))
print(unsuspend_ip("192.168.1.100"))
print(check_status("192.168.1.100"))
print(list_suspended())
```

### Avec JavaScript/Node.js

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:3000';

async function suspendIp(ip, interface = null) {
    const data = { ip };
    if (interface) data.interface = interface;
    
    const response = await axios.post(`${BASE_URL}/api/v1/suspend`, data);
    return response.data;
}

async function unsuspendIp(ip) {
    const response = await axios.post(`${BASE_URL}/api/v1/unsuspend/${ip}`);
    return response.data;
}

async function checkStatus(ip) {
    const response = await axios.get(`${BASE_URL}/api/v1/status/${ip}`);
    return response.data;
}

async function listSuspended() {
    const response = await axios.get(`${BASE_URL}/api/v1/list`);
    return response.data;
}

// Exemples d'utilisation
async function main() {
    console.log(await suspendIp('192.168.1.100'));
    console.log(await unsuspendIp('192.168.1.100'));
    console.log(await checkStatus('192.168.1.100'));
    console.log(await listSuspended());
}

main().catch(console.error);
```

## Notes importantes

1. Le serveur API doit être démarré avec les privilèges root pour pouvoir exécuter les commandes iptables et tcpkill.
2. Les règles iptables sont persistantes et survivent aux redémarrages du serveur.
3. Les processus tcpkill sont automatiquement restaurés au redémarrage du serveur.
4. L'API est sécurisée par défaut et n'accepte que les connexions locales (localhost).
5. Toutes les réponses sont au format JSON avec un champ `success` et un champ `message`.

## Gestion des erreurs

L'API retourne toujours un code HTTP 200 avec un objet JSON contenant :
- `success`: booléen indiquant si l'opération a réussi
- `message`: description du résultat ou de l'erreur

Les erreurs courantes incluent :
- IP invalide
- Échec de l'ajout des règles iptables
- Échec du démarrage de tcpkill
- Interface réseau invalide 
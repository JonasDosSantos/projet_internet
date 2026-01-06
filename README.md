**Jonas Dos Santos (MIC) & Nathan Fauvelle-Aymar (MIC) **

# Système de Fichiers Distribué (P2P)

Ce projet implémente un système de partage de fichiers en lecture seule via un protocole hybride :
1.  **Serveur Central (HTTP)** : Pour s'enregistrer et trouver d'autres pairs[cite: 8].
2.  **Peer-to-Peer (UDP)** : Pour échanger les fichiers directement[cite: 9].

## Structure du code

Voici où trouver et placer le code pour chaque partie du projet :

```text
.
├── cmd/
│   └── peer/
│       └── main.go       # Le point d'entrée (Main). Lance le programme.
│
├── pkg/
│   ├── client/           # COMMUNICATION HTTP (Section 3 du sujet)
│   │   └── client.go     # Requêtes vers le serveur central (GET /peers, etc.).
│   │
│   ├── identity/         # CRYPTOGRAPHIE (Annexe A)
│   │   └── crypto.go     # Gestion des clés (ECDSA) et signatures.
│   │
│   ├── p2p/              # PROTOCOLE UDP (Section 4)
│   │   ├── messages.go   # Définition des paquets (Header, Type, Body).
│   │   └── server.go     # Envoi/Réception UDP, Handshake, Ping.
│   │
│   └── filesystem/       # FICHIERS & MERKLE TREE (Section 5)
│       └── merkle.go     # Découpage des fichiers en blocs (Chunks) et hashage.
```

## Télécharger les dépendances
go mod tidy

## Lancer le pair
go run cmd/peer/main.go

## Tests suggérés
Diagnostic :
go run cmd/peer/main.go -name "TestSolo" -port 8085

Alice & Bob :
go run cmd/peer/main.go -name "Alice" -port 8081 -share "secret.txt"
go run cmd/peer/main.go -name "Bob" -port 8082 -connect "127.0.0.1:8081"


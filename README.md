**Jonas Dos Santos (MIC) & Nathan Fauvelle-Aymar (MIC) **

# Système de Fichiers Distribué (P2P)

Ce projet implémente un système de partage de fichiers en lecture seule via un protocole hybride :
1.  **Serveur Central (HTTP)** : Pour s'enregistrer et trouver d'autres pairs[cite: 8].
2.  **Peer-to-Peer (UDP)** : Pour échanger les fichiers directement[cite: 9].

## Structure du code

Voici où trouver et placer le code pour chaque partie du projet :

```text
.
├── main.go                  # Le point d'entrée (Main). Lance le programme.       
│
├── pkg/
│   ├── client/              # COMMUNICATION HTTP (Section 3 du sujet)
│   │   └── client.go        # Requêtes vers le serveur central (GET /peers, etc.).
│   │
│   ├── identity/            # CRYPTOGRAPHIE (Annexe A) & Extension Diffie-Hellman
│   │   ├── key_storage.go   # Sauvegarde et consultation de notre clé privée de signature.
│   │   └── crypto.go        # Gestion des clés (ECDSA) et signatures. 
                             # Gestion du chiffrement et déchiffrement AES, et de la génération des clés publqiues & privées de Diffie-Hellman
│   │
│   ├── p2p/                 # PROTOCOLE UDP (Section 4)
│   │   ├── messages.go      # Définition des paquets (Header, Type, Body) ainsi que des constantes du pakgage p2p.
│   │   ├── peer.go          # Définition des obets nécessaires à la communcation entre peers.
│   │   ├── download.go      # Gestion des téléchargements à partir des roothash.
│   │   ├── keepAlive.go     # Gestion des keep-alives.
│   │   ├── handlers.go      # Gestion des requêtes reçues.
│   │   └── senders.go       # Gestion des requêtes envoyées.
│   │
│   └── filesystem/          # FICHIERS & MERKLE TREE (Section 5)
│       └── file.go          # Découpage des fichiers en blocs (Chunks) et hashage.
```

## Télécharger les dépendances
go mod tidy

## Lancer le pair
go run main.go

# Mode DEBUG (ou bavard)
go run main.go -b

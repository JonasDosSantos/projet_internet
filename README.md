**Jonas Dos Santos (MIC) & Nathan Fauvelle-Aymar (MIC) **

# Système de Fichiers Distribué (P2P)

Ce projet implémente un système de partage de fichiers en peer to peer. Il nécessite un serveur STUN pour l'obtention des adresses et clefs des pairs :
1.  **Serveur Central (HTTP)** : Pour s'enregistrer et trouver d'autres pairs.
2.  **Peer-to-Peer (UDP)** : Pour échanger les fichiers directement.

## Structure du code


```text
.
├── main.go                  # Lance le programme.    
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
```
go mod tidy
```

## Lancer le pair (en mode 'taiseux', attention quasiment rien n'est print)
```
go run main.go
```

# Mode DEBUG (ou 'bavard', attention c'est très bavard)
```
go run main.go -b
```

## Tests suggérés
3 scénarios à éxécuter pour tester la plupart des fonctionnalités du notre programme
Pour chacun des scénarios, commencez par vous créer un pair (immédiatement après avec 'go run'). Vous pouvez utiliser les valeurs par défaut de nom et de port, ne chargez aucun fichier.
Vous devriez alors voir s'afficher ces lignes dans votre terminal:

```text
Pour commencer, il faut se register auprès du serveur.
Pour être reconnu par le serveur comme un pair, il faut envoyer un 'hello' à son peer.
Pour connaître la liste des commandes disponibles, taper 'help'.
```

Commencez donc par taper:
```
register
```

Vous devez ensuite 'hello' le pair du prof, pour ça, il nous faut son adresse.
Pour obtenir son adresse, il nous faut son nom, on commence donc par lister les pairs connectés:
```
peers
```
Vous devriez voir 'jch.irif.fr' dans la liste, pour obtenir son addresse:
```
addr jch.irif.fr
```
On peut maintenant 'hello' ce pair en utilisant au choix l'adresse IPv4 ou IPv6 obtenues:
```
hello 81.194.30.229:8443
```

Remarque: on aurait pu sauter les 2 dernières étapes en tapant juste:
```
hello jch.irif.fr
```
car nous avons implémenté un mécanisme pour trouver l'adresse d'un pair automatiquement via son nom.

Vous êtes maintenant connectés et le serveur rend votre adresse et votre clef publique disponibles aux autres pairs, pour le vérifier:
```
peers
```
Vous devriez voir votre nom dans la liste. Tapez maintenant
```
addr <votre nom>
```
et/ou
```
key <votre nom>
```
pour vérifier que le register à fonctionné.

# Scénario 1:
On va tenter de 'percer' un NAT. Pour commencer, choisissez un pair (alice dans notre exemple) avec qui vous voulez parler et tentez de le 'hello'.
```
hello alice
```
Que vous soyez en mode bavard ou non, vous devriez être averti que ce 'hello' à échoué. 
Notre hello vient de créer un 'trou' dans notre propre nat, il faut maintenant demander à alice de nous ping en empruntant le trou qu'on vient de créer.
```
nattraversal alice
```
Remarque: on ne spécifie pas de second argument dans cette fonction lorsqu'on veut 
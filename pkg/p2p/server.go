package p2p

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"project/pkg/filesystem"
	"project/pkg/identity"
	"sync"
	"time"
)

type Me struct {
	// notre connexion UDP
	Conn *net.UDPConn
	// notre clef privee
	PrivateKey *ecdsa.PrivateKey
	// notre nom
	PeerName string
	// url du serveur (pour gagner du temps)
	ServerURL string
	// le roothash associé a notre database
	RootHash [32]byte
	// notre database
	Database map[[32]byte][]byte
	// un verrou posé sur la DB
	DbLock sync.Mutex

	// pipe: des requetes lancées dans certaines fonctions attendent des reponses qui seront lus par d'autres fonctions. Il nous faut alors des pipe
	PendingRequests map[[32]byte]chan []byte
	// le verrou qui l'accompagne
	PendingLock sync.Mutex

	// On stocke l'adresse UDP du serveur, celles des peers, et on crée un Mutex pour éviter les conflits entre suppression et màj
	// ainsi que les adresses IP et ports de chaque peer, associé à la dernière fois qu'on l'a "vu"
	ServerUDPAddr string
	Sessions      map[string]*PeerSession
	Mutex         sync.Mutex
}

// Structure pour suivre l'état d'un pair
type PeerSession struct {
	LastSeen  time.Time
	PublicKey *ecdsa.PublicKey
}

// fonction pour charger un fichier ou dossier local dans notre Database (pour le proposer aux autres pairs)
func (me *Me) Load__file__system(nodes []filesystem.Node) {

	// on prends le mutex sur la Database
	me.DbLock.Lock()

	// on le lache lorsque la fonction termine
	defer me.DbLock.Unlock()

	me.Database = make(map[[32]byte][]byte)

	// On remplit la map pour un accès rapide (O(1)) lors des requêtes
	for _, node := range nodes {
		me.Database[node.Hash] = node.Data
	}

	// la racine est le dernier noeud de l'arbre, je l'enregistre dans la variable correspondante de Me
	if len(nodes) > 0 {
		me.RootHash = nodes[len(nodes)-1].Hash
		fmt.Printf("système de fichiers chargé. RootHash = %x\n", me.RootHash)
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Nous avons fais le choix de dériver (très simplement) notre propre clef publique pour définir l'ID de nos messages
func (me *Me) Generate__id__from__key() uint32 {

	// On transforme notre clef en chaine d'octets
	pubBytes := identity.PublicKey__to__bytes(&me.PrivateKey.PublicKey)

	// Ce sera notre ID
	idBuffer := make([]byte, 4)

	// octets de poids faible de la coordonée X
	idBuffer[0] = pubBytes[30]
	idBuffer[1] = pubBytes[31]

	// Octets de poids faibles de la coordonée Y
	idBuffer[2] = pubBytes[62]
	idBuffer[3] = pubBytes[63]

	// On renvoie 4 octets (l'ID)
	return binary.BigEndian.Uint32(idBuffer)
}

// fonction pour établir une nouvelle connexion UDP
func New__communication(port int, priv *ecdsa.PrivateKey, name string, serverURL string) (*Me, error) {

	// on prépare l'adresse à laquelle on va recevoir et envoyer les messages UDP (adresse locale)
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	// on ouvre le port et écoute tout ce qui rentre
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	// Adresse UDP du serveur en dur
	serverUDP := "81.194.30.229:8443"

	// on renvoie nos infos dans la structure crée dans ce but
	return &Me{
		Conn:            conn,
		PrivateKey:      priv,
		PeerName:        name,
		ServerURL:       serverURL,
		PendingRequests: make(map[[32]byte]chan []byte),
		Database:        make(map[[32]byte][]byte),
		ServerUDPAddr:   serverUDP,
		Sessions:        make(map[string]*PeerSession),
	}, nil
}

// ENVOIE DES MESSAGES Hello ET Ping

// fonction qui envoie Hello à une destination (paramètre destAddr)
func (me *Me) Send__hello(destAddr string) error {

	// on prépare l'adresse de destination pour UDP
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	// le coprs du messages est Extensions + Name (d'où 4octets + taille de Name en octets)
	body := make([]byte, 4+len(me.PeerName))

	// on écrit le nom du Peer à la fin (les 4 premiers octets sont vides pour le moment)
	copy(body[4:], []byte(me.PeerName))

	// on génère l'ID avec notre fonction qui dérive notre clef publique
	msgId := me.Generate__id__from__key()

	msg := Message{
		Id:   msgId,
		Type: TypeHello,
		Body: body,
	}

	// on signe le message
	unsignedData := msg.Serialize()
	sig, err := identity.Sign(me.PrivateKey, unsignedData)
	if err != nil {
		return err
	}
	msg.Signature = sig

	// Envoie les octets finaux sur le réseau
	_, err = me.Conn.WriteToUDP(msg.Serialize(), udpAddr)
	return err
}

// fonction qui envoie un ping à une destination
func (me *Me) Send__ping(destAddr string) error {

	// on prépare l'adresse de destination pour UDP
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	msgID := me.Generate__id__from__key()

	// on cree la struct Message du ping
	msg := Message{
		Id:   msgID,
		Type: TypePing,
		Body: []byte{},
	}

	// on transforme la struct en chaine d'octets
	data := msg.Serialize()

	// on envoie au destinataire
	_, err = me.Conn.WriteToUDP(data, udpAddr)
	return err
}

// fonction qui envoie un rootRequest à une destination
func (me *Me) Send__RootRequest(destAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	// Ici le body envoyé est vide, il sera rempli par un handler
	msg := Message{
		Id:   me.Generate__id__from__key(),
		Type: TypeRootRequest,
		Body: []byte{},
	}

	// Pas de signature nécessaire pour la requête
	_, err = me.Conn.WriteToUDP(msg.Serialize(), udpAddr)
	return err
}

// fonction qui envoie une datumRequest à une destination
func (me *Me) Send__DatumRequest(destAddr string, hash [32]byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	// Le body doit contenir les 32 octets du hash demandé
	body := make([]byte, 32)
	copy(body, hash[:])

	msg := Message{
		Id:   me.Generate__id__from__key(),
		Type: TypeDatumRequest, // 3
		Body: body,
	}

	_, err = me.Conn.WriteToUDP(msg.Serialize(), udpAddr)
	return err
}

// GESTION KEEPALIVE ET TIMEOUT ENTRE PEER
// On ne veut pas qu'une adresse dont on met à jour le "LastSeen" soit supprimée simultanément, d'où l'usage d'un mutex

// Met à jour l'heure de dernier contact avec une adresse
func (me *Me) Update__last__seen(addrStr string) {
	me.Mutex.Lock()
	defer me.Mutex.Unlock()

	if session, exists := me.Sessions[addrStr]; exists {
		session.LastSeen = time.Now()
	} else {
		// Nouvelle session, on l'ajoute
		me.Sessions[addrStr] = &PeerSession{
			LastSeen: time.Now(),
		}
	}
}

func (me *Me) Start__maintenance__loop() {
	// On vérifie toutes les 30 secondes
	ticker := time.NewTicker(30 * time.Second)
	// Le timer s'arrêtera lorsque la maintenance_loop s'éteindra
	defer ticker.Stop()

	for range ticker.C {
		// On envoie un keepalive au serveur ttes les 30 secondes car il assure également le maintien du NAT
		fmt.Println("Keep-alive : Envoi Hello au serveur central.")
		me.Send__hello(me.ServerUDPAddr)

		me.Mutex.Lock()
		now := time.Now()

		for addr, session := range me.Sessions {
			diff := now.Sub(session.LastSeen)

			// Après 5 minutes : expiration
			if diff > 5*time.Minute {
				fmt.Printf("Timeout : Session expirée avec %s (inactif depuis %s)\n", addr, diff)
				delete(me.Sessions, addr)
				continue
			}

			// Après 4 minutes : keepalive
			if diff > 4*time.Minute {
				fmt.Printf("Keep-alive : Envoi Ping automatique à %s\n", addr)
				// On lance le ping via la fonction "send__ping" dans une goroutine pour ne pas bloquer le mutex
				go me.Send__ping(addr)
			}
		}
		me.Mutex.Unlock()
	}
}

// BOUCLE D'ECOUTE

// Boucle qui écoute les messages arrivant sur le port définit par la fonction New__communication
func (me *Me) Listen__loop() {

	// on prépare un buffer de 64000 octets
	buffer := make([]byte, 64000)

	fmt.Printf("on écoute sur le port %s\n", me.Conn.LocalAddr())

	// On lance la maintenant__loop qui gère les timeouts et keepalives
	go me.Start__maintenance__loop()

	// boucle infinie
	for {
		// n = taille
		// addr = emetteur
		n, addr, err := me.Conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("erreur lecture sur le port:", err)
			continue
		}

		// On met à jour la session dès qu'on reçoit n'importe quel octet valide
		me.Update__last__seen(addr.String())

		// on transforme les octets recus en struc Message
		msg, err := Deserialize(buffer[:n])
		if err != nil {
			fmt.Println("Erreur de désérialisation :", err)
			continue
		}

		// on agit différement selon le Type de message
		switch msg.Type {

		// si Ping on appelle notre handler prévu
		case TypePing:
			fmt.Printf("ping recu de %s\n", addr)
			me.Handle__ping(msg, addr)

		// Si Hello on appelle notre handler prévu
		case TypeHello:
			fmt.Printf("hello recu de %s\n", addr)
			me.Handle__hello(msg, addr)

		case Error:
			me.Handle__error(msg, addr)

		// Rien à faire, notre connexion UDP est valide
		case TypeHelloReply:
			fmt.Printf("helloreply recu de %s\n", addr)

		// rien à faire
		case TypeOk:
			fmt.Printf("Ok recu de %s pour l'Id %d\n", addr, msg.Id)

		case TypeRootRequest:
			me.Handle__RootRequest(msg, addr)

		case TypeDatumRequest:
			me.Handle__DatumRequest(msg, addr)

		case TypeRootReply: // 131
			if len(msg.Body) >= 32 {
				copy(me.RootHash[:], msg.Body[:32])
				fmt.Printf("RootHash mis à jour : %x\n", me.RootHash)
			}

		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		case TypeDatum: // 132
			if len(msg.Body) <= 32 {
				continue
			}

			// Extraction : [Hash 32o] + [Data...]
			var receivedHash [32]byte
			copy(receivedHash[:], msg.Body[:32])
			dataContent := msg.Body[32:]

			// On regarde si Download_tree attend ce hash via un channel
			me.PendingLock.Lock()
			ch, exists := me.PendingRequests[receivedHash]

			if exists {
				// On envoie la donnée dans le channel (non bloquant)
				select {
				case ch <- dataContent:
				default:
				}
				// On nettoie la map
				delete(me.PendingRequests, receivedHash)
			}
			me.PendingLock.Unlock()

		case TypeNoDatum: // 133
			//me.handleNoDatum(msg, addr)

		// mauvais type
		default:
			fmt.Printf("type de message non géré : %d\n", msg.Type)
			me.Handle__if__error(msg, addr, fmt.Sprintf("unknown message type: %d", msg.Type))
		}
	}
}

func (me *Me) Download_tree(destAddr string, rootHash [32]byte) {

	// on initialise un waitgroup
	// un WaitGroup est comme un sem_barrier (il attends que tout le monde ait finit pour lacher)
	var wg sync.WaitGroup

	// on cree la semaphore qui va reguler notre trafic (c'est le pipe dont on parlait plus haut)
	semaphore := make(chan struct{}, 32)

	// on incremente le WaitGroup de 1 (sinon il est déjà "fini")
	wg.Add(1)

	// on appelle notre fonction de téléchargement
	me.Download_recursively(destAddr, rootHash, &wg, semaphore)

	// on attends que notre WaitGroup termine
	wg.Wait()
	fmt.Println("téléchargement terminé")
}

func (me *Me) Download_recursively(destAddr string, hash [32]byte, wg *sync.WaitGroup, semaphore chan struct{}) {
	// on lache le WaitGroup à la fin de la fonction
	defer wg.Done()

	// on vérifie si on a pas déjà ce fichier
	// on prends le verrou sur la database pour gérer la concurrence
	me.DbLock.Lock()
	_, have := me.Database[hash]
	me.DbLock.Unlock()

	// si on l'a, on finit
	if have {
		return
	}

	// on prend 1 "ticket" pour notre semaphore, si c'est plein, on attend
	semaphore <- struct{}{}

	// on rend le "ticket" à la fin de la fonction
	defer func() { <-semaphore }()

	// on prépare le channel (pipe) pour notre réponse
	respChan := make(chan []byte, 1)

	// on prend le verrou sur les channel
	me.PendingLock.Lock()
	// on en prend un
	me.PendingRequests[hash] = respChan
	me.PendingLock.Unlock()

	// on demande les data sur le hash voulu
	err := me.Send__DatumRequest(destAddr, hash)
	if err != nil {
		// si echec, on delete notre pipe
		me.PendingLock.Lock()
		delete(me.PendingRequests, hash)
		me.PendingLock.Unlock()
		return
	}

	// attente de la réponse
	select {

	// si on a recu ce qu'on voualit
	case receivedData := <-respChan:

		// on prends le verrou sur la Database et on y écrit les data
		me.DbLock.Lock()
		me.Database[hash] = receivedData
		me.DbLock.Unlock()

		// analyse du noeud reçu

		// recupération du type
		nodeType := receivedData[0]

		// switch/case sur le type
		switch nodeType {

		// si c'est un Directory
		case filesystem.TypeDirectory:

			// on coupe le type
			entriesData := receivedData[1:]

			// on va parcourir les entrees du dossier
			count := len(entriesData) / 64

			for i := 0; i < count; i++ {
				// on copie chaque hash des enfants
				var childHash [32]byte
				copy(childHash[:], entriesData[i*64+32:(i+1)*64])

				// on va lancer récursivement un télechargement sur cet enfant donc on incremente notre WaitGroup
				wg.Add(1)

				// on appelle notre fonction de telechargement
				go me.Download_recursively(destAddr, childHash, wg, semaphore)
			}

		// si c'est un BigNode ou un BigDirectory (meme principe)
		case filesystem.TypeBig, filesystem.TypeBigDirectory:

			// on coupe le type
			hashesData := receivedData[1:]

			// on va parcourir les enfants
			count := len(hashesData) / 32

			for i := 0; i < count; i++ {
				// on copie chaque hash des enfants
				var childHash [32]byte
				copy(childHash[:], hashesData[i*32:(i+1)*32])

				// on va lancer récursivement un télechargement sur cet enfant donc on incremente notre WaitGroup
				wg.Add(1)

				// on appelle notre fonction de telechargement
				go me.Download_recursively(destAddr, childHash, wg, semaphore)
			}
		}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	case <-time.After(10 * time.Second): // Timeout
		fmt.Printf("❌ Timeout hash %x\n", hash[:4])
		me.PendingLock.Lock()
		delete(me.PendingRequests, hash)
		me.PendingLock.Unlock()
	}
}

// fonction qui reconstruit tout un système de fichier à partir de notre Database
// cette fonction ne crée que l'architecture du file system et délègue le reste (écriture des chunks) à un autre fonction
// nodeHash est le noeud qu'on traite actuellement
// currentPath est le lieu où on se trouve dans l'arborescence
func (me *Me) Rebuild__file__system(nodeHash [32]byte, currentPath string) error {

	// on prends un verrou sur la DB pour copier les data du node souhaité
	me.DbLock.Lock()
	data, exists := me.Database[nodeHash]
	me.DbLock.Unlock()

	// si le neoud n'existe pas
	if !exists {
		return fmt.Errorf("noeud manquant dans la base de données : %x", nodeHash[:4])
	}

	// on récupère le type du noeud
	nodeType := data[0]

	// switch/case sur le type
	switch nodeType {

	// SI c'est un Directory
	case filesystem.TypeDirectory:

		// on crée le dossier sur le disque en local
		if err := os.MkdirAll(currentPath, 0755); err != nil {
			return fmt.Errorf("erreur création dossier %s: %v", currentPath, err)
		}

		// lecture de toutes les entrées : [Nom (32o)] + [Hash (32o)]

		// on coupe le type
		entriesData := data[1:]

		// on parcourt toutes les entrées
		entrySize := 64
		count := len(entriesData) / entrySize

		for i := 0; i < count; i++ {
			start := i * entrySize

			// suppréssion du padding sur le nom
			nameBytes := entriesData[start : start+32]
			name := string(bytes.Trim(nameBytes, "\x00"))

			// on récupère le hash
			var childHash [32]byte
			copy(childHash[:], entriesData[start+32:start+64])

			// on concaténe le nom de l'enfant a la fin du filepath
			childPath := filepath.Join(currentPath, name)

			// appel récursif pour continuer à construire
			if err := me.Rebuild__file__system(childHash, childPath); err != nil {
				return err
			}
		}

	// Si c'est un BigDirectory
	case filesystem.TypeBigDirectory:

		// on coupe le type
		hashesData := data[1:]

		// on va parcourir les entrees
		count := len(hashesData) / 32

		for i := 0; i < count; i++ {
			// on récupère le hash de l'enfant
			var childHash [32]byte
			copy(childHash[:], hashesData[i*32:(i+1)*32])

			// appel récursif sans changer le path car on ne s'est pas "déplacer" dans l'arborescence
			if err := me.Rebuild__file__system(childHash, currentPath); err != nil {
				return err
			}
		}

	// si c'est un fichier (chunk ou BigNode, même logique)
	case filesystem.TypeChunk, filesystem.TypeBig:

		// on crée le fichier en local (ou on l'écrase)
		file, err := os.Create(currentPath)
		if err != nil {
			return fmt.Errorf("erreur création fichier %s: %v", currentPath, err)
		}
		defer file.Close()

		// on appelle notre fonction dédiée au remplissage des fichiers
		if err := me.rebuild__file__content(nodeHash, file); err != nil {
			return err
		}

	default:
		return fmt.Errorf("type de noeud inconnu : %d", nodeType)
	}

	return nil
}

// fonction pour remplir les fichiers (appelée par Rebuild__file__system)
func (me *Me) rebuild__file__content(hash [32]byte, file *os.File) error {

	// on prend le verrou sur la DB
	me.DbLock.Lock()
	data, exists := me.Database[hash]
	me.DbLock.Unlock()

	// si le chunk qu'on cherche n'existe pas (peu de chance d'arriver au vu de notre implémentation)
	if !exists {
		return fmt.Errorf("chunk manquant : %x", hash[:4])
	}

	// on récupère le type du node (soit chunk soit BigNode)
	nodeType := data[0]

	// si c'est un chunk
	switch nodeType {

	// si on est sur une feuille
	case filesystem.TypeChunk:
		// on écrit tout sauf le premier octet (le type)
		_, err := file.Write(data[1:])
		return err

	// si c'est un BigNode
	case filesystem.TypeBig:

		// on coupe le type
		hashesData := data[1:]

		// on va parcourir tout les enfants
		count := len(hashesData) / 32

		for i := 0; i < count; i++ {
			// on récupère le hash de l'enfant
			var childHash [32]byte
			copy(childHash[:], hashesData[i*32:(i+1)*32])

			// appel récursif pour continuer à écrire à la suite
			if err := me.rebuild__file__content(childHash, file); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("type de noeud inconnu (pas forcément inconnu mais problématique) : %d", nodeType)
	}

	return nil
}

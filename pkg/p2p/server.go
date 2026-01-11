package p2p

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"sync"
	"bytes"
	"time"
	"net"
	"os"
	"path/filepath"
	"project/pkg/filesystem"
	"project/pkg/identity"
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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

	// on renvoie nos infos dans la structure crée dans ce but
	return &Me{
		Conn: conn,
		PrivateKey: priv,
		PeerName: name,
		ServerURL: serverURL,
		PendingRequests: make(map[[32]byte]chan []byte),
       	Database: make(map[[32]byte][]byte),
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

// BOUCLE D'ECOUTE

// Boucle qui écoute les messages arrivant sur le port définit par la fonction New__communication
func (me *Me) Listen__loop() {

	// on prépare un buffer de 64000 octets
	buffer := make([]byte, 64000)

	fmt.Printf("on écoute sur le port %s\n", me.Conn.LocalAddr())

	// boucle infinie
	for {
		// n = taille
		// addr = emetteur
		n, addr, err := me.Conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("erreur lecture sur le port:", err)
			continue
		}

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
	fmt.Println("téléchargement terminé\n")
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
				copy(childHash[:], entriesData[i*64+32 : (i+1)*64])
				
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
				copy(childHash[:], hashesData[i*32 : (i+1)*32])
				
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

/*

// fonction pour print une arborescence de fichier (celle actuellement dans notre variable Database)
func (me *Me) PrintTree(rootHash [32]byte) {

	// on vérifie que la DB n'est pas vide ie qu'il y a bien quelque chose a print
	if len(me.Database) == 0 {
		fmt.Println("notre DB est vide")
		return
	}

	// on appelle notre fonction d'affichage
	me.recursivePrint(rootHash, "")
}

func (me *Me) recursivePrint(nodeHash [32]byte, prefix string) {

	// on récupère toutes les data du hash voulu dans notre DB
	data, exists := me.Database[nodeHash]

	// s'il n'existe pas 
	if !exists {
		fmt.Printf("%s❌ [MANQUANT] Hash: %x...\n", prefix, nodeHash[:4])
		return
	}

	// 2. Identification du type
	nodeType := data[0]

	switch nodeType {

	case filesystem.TypeDirectory:
		// TYPE 1 : Dossier standard
		// Structure : [Type 1o] + [ [Nom 32o] + [Hash 32o] ] * N
		
		entriesData := data[1:]
		entrySize := 64
		count := len(entriesData) / entrySize

		for i := 0; i < count; i++ {
			start := i * entrySize
			
			// Extraction et nettoyage du nom (on enlève les 0x00 inutiles)
			nameBytes := entriesData[start : start+32]
			name := string(bytes.Trim(nameBytes, "\x00"))

			// Extraction du hash de l'enfant
			var childHash [32]byte
			copy(childHash[:], entriesData[start+32:start+64])

			// On regarde ce qu'est cet enfant pour savoir comment l'afficher
			childData, childExists := me.Database[childHash]

			if !childExists {
				// On affiche le nom mais on signale que le contenu est absent
				fmt.Printf("%s├── ❓ %s (Contenu non téléchargé)\n", prefix, name)
				continue
			}

			childType := childData[0]

			// Si l'enfant est un dossier (ou un gros dossier), on l'affiche comme tel et on descend
			if childType == filesystem.TypeDirectory || childType == filesystem.TypeBigDirectory {
				fmt.Printf("%s├── 📁 %s/\n", prefix, name)
				me.recursivePrint(childHash, prefix+"│   ")
			} else {
				// Sinon c'est un fichier (Chunk ou BigFile), on l'affiche juste
				fmt.Printf("%s├── 📄 %s\n", prefix, name)
			}
		}

	case filesystem.TypeBigDirectory:
		// TYPE 3 : Gros Dossier (Liste de hashs)
		// Structure : [Type 1o] + [Hash 32o] * N
		// Ce n'est pas un sous-dossier visuel, c'est la suite du contenu du dossier parent.
		// On garde donc le MÊME préfixe.
		
		hashesData := data[1:]
		hashSize := 32
		count := len(hashesData) / hashSize

		for i := 0; i < count; i++ {
			var childHash [32]byte
			copy(childHash[:], hashesData[i*hashSize:(i+1)*hashSize])
			
			// Appel récursif avec le même niveau d'indentation
			me.recursivePrint(childHash, prefix)
		}

	// Les types 0 (Chunk) et 2 (BigFile) ne sont pas traités ici 
	// car ils sont affichés lors du parcours de leur parent (TypeDirectory).
	}
}

*/

// fonction qui reconstruit tout un système de fichier à partir de notre Database
func (me *Me) Rebuild__file__system(nodeHash [32]byte, currentPath string) error {
	
	// on prends un verrou sur la DB pour copié les data du node souhaité
	me.DbLock.Lock()
	data, exists := me.Database[nodeHash]
	me.DbLock.Unlock()

	// si le neoud n'existe pas 
	if !exists {
		return fmt.Errorf("noeud manquant dans la base de données : %x", nodeHash[:4])
	}

	// 2. Identification du type de noeud
	nodeType := data[0]

	switch nodeType {

	// --- CAS DOSSIER (Type 1) ---
	case filesystem.TypeDirectory:
		// On crée le dossier physique sur le disque
		// MkdirAll ne renvoie pas d'erreur si le dossier existe déjà
		if err := os.MkdirAll(currentPath, 0755); err != nil {
			return fmt.Errorf("erreur création dossier %s: %v", currentPath, err)
		}

		// Lecture des entrées : [Nom (32o)] + [Hash (32o)]
		entriesData := data[1:]
		entrySize := 64
		count := len(entriesData) / entrySize

		for i := 0; i < count; i++ {
			start := i * entrySize
			
			// Extraction et nettoyage du nom (suppression des 0x00)
			nameBytes := entriesData[start : start+32]
			name := string(bytes.Trim(nameBytes, "\x00"))

			// Extraction du hash de l'enfant
			var childHash [32]byte
			copy(childHash[:], entriesData[start+32:start+64])

			// Construction du chemin complet pour l'enfant (ex: "downloads/images/vacances.jpg")
			childPath := filepath.Join(currentPath, name)

			// Appel récursif
			if err := me.Rebuild__file__system(childHash, childPath); err != nil {
				return err
			}
		}

	// --- CAS GROS DOSSIER (Type 3) ---
	case filesystem.TypeBigDirectory:
		// Ce noeud contient une liste de hashs qui pointent vers la suite du contenu du dossier.
		// IMPORTANT : On garde 'currentPath' tel quel, on ne descend pas dans un sous-dossier.
		
		hashesData := data[1:]
		count := len(hashesData) / 32

		for i := 0; i < count; i++ {
			var childHash [32]byte
			copy(childHash[:], hashesData[i*32:(i+1)*32])
			
			// Récursion avec le MÊME chemin courant
			if err := me.Rebuild__file__system(childHash, currentPath); err != nil {
				return err
			}
		}

	// --- CAS FICHIER (Type 0 ou 2) ---
	case filesystem.TypeChunk, filesystem.TypeBig:
		// On crée le fichier sur le disque
		// os.Create écrase le fichier s'il existe déjà
		f, err := os.Create(currentPath)
		if err != nil {
			return fmt.Errorf("erreur création fichier %s: %v", currentPath, err)
		}
		defer f.Close()

		// On appelle la fonction helper pour remplir le contenu
		// On passe le descripteur de fichier 'f' pour écrire dedans au fur et à mesure
		if err := me.rebuild__file__content(nodeHash, f); err != nil {
			return err
		}
	
	default:
		return fmt.Errorf("type de noeud inconnu : %d", nodeType)
	}

	return nil
}

// Fonction auxiliaire pour écrire le contenu d'un fichier (récursif pour TypeBig)
func (me *Me) rebuild__file__content(hash [32]byte, f *os.File) error {
	
	me.DbLock.Lock()
	data, exists := me.Database[hash]
	me.DbLock.Unlock()

	if !exists {
		return fmt.Errorf("chunk manquant : %x", hash[:4])
	}

	nodeType := data[0]

	if nodeType == filesystem.TypeChunk {
		// FEUILLE : C'est de la donnée brute
		// On écrit tout sauf le premier octet (qui est le Type)
		_, err := f.Write(data[1:])
		return err

	} else if nodeType == filesystem.TypeBig {
		// NOEUD INTERMÉDIAIRE : Liste de hashs d'enfants
		hashesData := data[1:]
		count := len(hashesData) / 32
		
		for i := 0; i < count; i++ {
			var childHash [32]byte
			copy(childHash[:], hashesData[i*32:(i+1)*32])
			
			// Récursion : on écrit la suite dans le même fichier ouvert 'f'
			if err := me.rebuild__file__content(childHash, f); err != nil {
				return err
			}
		}
	}
	
	return nil
}
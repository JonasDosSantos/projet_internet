package p2p

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"project/pkg/client"
	"project/pkg/filesystem"
	"project/pkg/identity"
	"strings"
)

type Me struct {
	Conn       *net.UDPConn
	PrivateKey *ecdsa.PrivateKey
	PeerName   string
	ServerURL  string
	RootHash   [32]byte
	Database   map[[32]byte][]byte
}

// Ajoutez cette méthode utilitaire pour charger l'arbre généré par file.go dans la structure Me
func (me *Me) LoadFileSystem(nodes []filesystem.Node) {
	me.Database = make(map[[32]byte][]byte)

	// On remplit la map pour un accès rapide (O(1)) lors des requêtes
	for _, node := range nodes {
		me.Database[node.Hash] = node.Data
	}

	// La racine est le dernier noeud généré par votre algorithme dans file.go
	if len(nodes) > 0 {
		me.RootHash = nodes[len(nodes)-1].Hash
		fmt.Printf("Système de fichiers chargé. Racine : %x\n", me.RootHash)
	}
}

// Nous avons fais le choix de dériver (très simplement) notre propre clef publique pour définir l'ID de nos messages
func (me *Me) generateIdFromKey() uint32 {

	// On transforme notre clef en chaine d'octets
	pubBytes := identity.PublicKeyToBytes(&me.PrivateKey.PublicKey)

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

func NewCommunication(port int, priv *ecdsa.PrivateKey, name string, serverURL string) (*Me, error) {

	// on prépare l'adresse à laquelel on va recevoir les messages via UDP (adresse locale)
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
		Conn:       conn,
		PrivateKey: priv,
		PeerName:   name,
		ServerURL:  serverURL,
	}, nil
}

// ENVOIE DES MESSAGES Hello ET Ping

// fonction qui envoie Hello à une destination (paramètre destAddr)
func (me *Me) SendHello(destAddr string) error {

	// on prépare l'adresse de destination pour UDP
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	// le coprs du messages est Extensions + Name (d'où 4octets + taille de Name en octets)
	body := make([]byte, 4+len(me.PeerName))

	// on écrit le nom du Peer à la fin (les 4 premiers octets sont vides pour le moment) /////////////////////////////////////////////////////////////
	copy(body[4:], []byte(me.PeerName))

	// on génère l'ID avec notre fonction qui dérive notre clef publique
	msgId := me.generateIdFromKey()

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
func (me *Me) SendPing(destAddr string) error {

	// on prépare l'adresse de destination pour UDP
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	msgID := me.generateIdFromKey()

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
func (me *Me) SendRootRequest(destAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	// Ici le body envoyé est vide >> il sera rempli par un handler
	msg := Message{
		Id:   me.generateIdFromKey(),
		Type: TypeRootRequest,
		Body: []byte{},
	}

	// Pas de signature nécessaire pour la requête
	_, err = me.Conn.WriteToUDP(msg.Serialize(), udpAddr)
	return err
}

// fonction qui envoie une datumRequest à une destination
func (me *Me) SendDatumRequest(destAddr string, hash [32]byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		return err
	}

	// Le body doit contenir exactement les 32 octets du hash demandé
	body := make([]byte, 32)
	copy(body, hash[:])

	msg := Message{
		Id:   me.generateIdFromKey(),
		Type: TypeDatumRequest, // 3
		Body: body,
	}

	_, err = me.Conn.WriteToUDP(msg.Serialize(), udpAddr)
	return err
}

// HANDLERS DE GESTION LORS DE LA RECEPTION DE Hello, Ping ET Error

// fonction qui gère la réception d'un Hello
func (me *Me) handleHello(req *Message, addr *net.UDPAddr) {

	// on récupère le nom de l'emetteur (le nom est placé après les 4octets de bitmap représentants les extensions)
	if len(req.Body) < 4 {
		fmt.Println("le message Hello est incorrect")
		return
	}
	sender := strings.Trim(string(req.Body[4:]), "\x00")
	fmt.Printf("Vérification du Hello de : '%s'\n", sender)

	// on récupère la clef publique de l'emetteur en la demandant au serveur
	pubKeyBytes, err := client.GetPublicKey(me.ServerURL, sender)
	if err != nil {
		fmt.Printf("clef de %s introuvable\n", sender)
		return
	}
	pubKey, _ := identity.BytesToPublicKey(pubKeyBytes)

	// Il ne faut pas vérifier tout le message mais seulement le "header" + le body
	dataToVerify := req.Serialize()[:7+len(req.Body)]

	// on vérifie
	if !identity.VerifySignature(pubKey, dataToVerify, req.Signature) {
		fmt.Printf("signature invalide recue de %s, message jeté\n", sender)
		return
	}

	fmt.Printf("signature de %s vérifiée\n", sender)

	// reponse

	// on cree le body
	body := make([]byte, 4+len(me.PeerName))
	copy(body[4:], []byte(me.PeerName))

	// on cree la struct Message de la réponse
	reply := Message{
		Id:   req.Id,
		Type: TypeHelloReply,
		Body: body,
	}

	unsignedData := reply.Serialize()
	sig, _ := identity.Sign(me.PrivateKey, unsignedData)
	reply.Signature = sig
	me.Conn.WriteToUDP(reply.Serialize(), addr)
}

// fonction qui gère la réception d'un ping
func (me *Me) handlePing(req *Message, addr *net.UDPAddr) error {

	// on cree la struct Message de la réponse
	reply := Message{
		Id:   req.Id,
		Type: TypeOk,
		Body: []byte{},
	}

	// on transforme le message en chaine d'octets
	data := reply.Serialize()

	// on renvoie le OK à l'emetteur
	_, err := me.Conn.WriteToUDP(data, addr)
	return err
}

// focntion qui gère les messages d'erreurs recus
func (me *Me) handleError(msg *Message, addr *net.UDPAddr) {
	errorMessage := string(msg.Body)

	fmt.Printf("Error recu de %s (Id: %d) :\n", addr, msg.Id)
	fmt.Printf(">> Message : %s\n", errorMessage)
}

// fonction qui gère les messages RootRequest = une demande d'envoi du roothash
func (me *Me) handleRootRequest(req *Message, addr *net.UDPAddr) {
	fmt.Printf("RootRequest reçue de %s\n", addr)

	// le corps de la réponse est simplement le RootHash (32 octets)
	body := me.RootHash[:] // Slice des 32 octets

	// on cree la struct Message de la réponse,
	// L'ID est le même que celui de la requête, et le body est le hash qui sert de réponse
	reply := Message{
		Id:   req.Id,
		Type: TypeRootReply,
		Body: body,
	}

	// On signe le message RootReply conformément à la Section 4.3
	unsignedData := reply.Serialize()
	sig, err := identity.Sign(me.PrivateKey, unsignedData)
	if err != nil {
		fmt.Println("Erreur signature RootReply:", err)
		return
	}
	reply.Signature = sig

	// Envoi
	_, err = me.Conn.WriteToUDP(reply.Serialize(), addr)
	if err != nil {
		fmt.Println("Erreur envoi RootReply:", err)
	}
}

// Handler pour les DatumRequest
func (me *Me) handleDatumRequest(req *Message, addr *net.UDPAddr) {
	// Vérification de sécurité : la requête doit contenir un hash de 32 octets
	if len(req.Body) != 32 {
		fmt.Printf("DatumRequest invalide de %s (taille body incorrecte)\n", addr)
		return
	}

	// On récupère le hash demandé
	var requestedHash [32]byte
	copy(requestedHash[:], req.Body)

	// On cherche dans notre "Base de données" en mémoire
	data, found := me.Database[requestedHash]

	if found {
		// CAS 1 : DONNÉE TROUVÉE -> Réponse TypeDatum (132)
		// Format du Body : Hash (32 octets) + Data (variable)

		replyBody := make([]byte, 32+len(data))
		copy(replyBody[0:32], requestedHash[:]) // D'abord le hash
		copy(replyBody[32:], data)              // Ensuite les données

		reply := Message{
			Id:   req.Id,
			Type: TypeDatum,
			Body: replyBody,
			// PAS DE SIGNATURE pour les données (Section 4.3)
		}

		me.Conn.WriteToUDP(reply.Serialize(), addr)
		fmt.Printf("Donnée envoyée à %s (taille: %d)\n", addr, len(data))

	} else {
		// CAS 2 : PAS TROUVÉ -> Réponse TypeNoDatum (133)
		// Le corps contient uniquement le hash demandé

		reply := Message{
			Id:   req.Id,
			Type: TypeNoDatum,
			Body: requestedHash[:],
		}

		// OBLIGATOIRE : Signer le message NoDatum (Section 4.3)
		unsignedData := reply.Serialize()
		sig, err := identity.Sign(me.PrivateKey, unsignedData)
		if err == nil {
			reply.Signature = sig
			me.Conn.WriteToUDP(reply.Serialize(), addr)
			fmt.Printf("NoDatum envoyé à %s\n", addr)
		}
	}
}

// Cette fonction reçoit la réponse à la requête de Root, et envoie une DatumRequest avec le hash reçu
func (me *Me) handleRootReply(msg *Message, addr *net.UDPAddr) {
	// Vérification de la taille (le hash doit faire 32 octets)
	if len(msg.Body) < 32 {
		fmt.Printf("RootReply invalide reçu de %s (taille < 32)\n", addr)
		return
	}

	// On récupère le hash
	rootHash := msg.Body[:32]
	fmt.Printf(">>> ROOT HASH REÇU de %s : %x\n", addr, rootHash)

	// C'est ici que la logique de téléchargement commence !
	// Puisqu'on a la racine, on veut maintenant son contenu.
	// On envoie donc immédiatement une demande de données (DatumRequest).

	// Attention : Pour éviter une boucle infinie ou un spam si on reçoit plusieurs fois le même paquet,
	// dans un client réel, on vérifierait si on a déjà ce hash.

	fmt.Printf(" -> Envoi automatique de DatumRequest pour le hash %x...\n", rootHash[:5]) // On affiche juste le début pour la lisibilité

	// On convertit la slice en array [32]byte pour la fonction SendDatumRequest
	var hashArray [32]byte
	copy(hashArray[:], rootHash)

	err := me.SendDatumRequest(addr.String(), hashArray)
	if err != nil {
		fmt.Printf("Erreur envoi DatumRequest: %v\n", err)
	}
}

func (me *Me) handleDatum(msg *Message, addr *net.UDPAddr) {
	// 1. Validation de la structure du message
	// Le body doit contenir au moins le Hash (32 octets) + 1 octet de Type de noeud
	if len(msg.Body) <= 32 {
		fmt.Printf("Datum invalide (trop court) de %s\n", addr)
		return
	}

	// 2. Extraction Hash et Données
	remoteHash := msg.Body[:32]
	data := msg.Body[32:] // Le reste, c'est le contenu du noeud (Merkle Node)

	// 3. VÉRIFICATION D'INTÉGRITÉ (CRITIQUE )
	// On hash ce qu'on vient de recevoir pour vérifier que c'est bien ce qu'on a demandé
	localHash := sha256.Sum256(data)
	if !bytes.Equal(remoteHash, localHash[:]) {
		fmt.Printf("ALERTE : Données corrompues reçues de %s ! Hash incorrect.\n", addr)
		return
	}

	fmt.Printf("Donnée vérifiée reçue (taille: %d octets). Analyse du type...\n", len(data))

	// 4. ANALYSE DU TYPE DE NOEUD (Premier octet des données [cite: 199])
	nodeType := data[0]

	switch nodeType {

	case filesystem.TypeChunk: // 0
		// C'est un morceau de fichier final.
		// Dans un vrai client, on le stockerait sur le disque.
		content := string(data[1:]) // On saute le type (1er octet)
		fmt.Printf("   -> [FICHIER] Chunk reçu : \"%s...\"\n", content[:min(20, len(content))])

	case filesystem.TypeDirectory: // 1
		// C'est un dossier : il contient une liste de (Nom + Hash)
		// On doit parcourir cette liste pour télécharger les fichiers du dossier
		fmt.Println("   -> [DOSSIER] Contenu du répertoire :")

		// Le format est : Type (1o) + [Nom (32o) + Hash (32o)] répétes
		entrySize := 64
		entriesData := data[1:] // On enlève le type

		count := len(entriesData) / entrySize
		for i := 0; i < count; i++ {
			start := i * entrySize

			// Extraction du nom (nettoyage des 0x00 de padding)
			nameBytes := entriesData[start : start+32]
			name := strings.Trim(string(nameBytes), "\x00")

			// Extraction du hash
			childHashSlice := entriesData[start+32 : start+64]
			var childHash [32]byte
			copy(childHash[:], childHashSlice)

			fmt.Printf("      - Fichier trouvé : %s (Hash: %x...)\n", name, childHash[:5])

			// RÉCURSION : On demande le contenu de ce fichier/dossier enfant !
			go me.SendDatumRequest(addr.String(), childHash)
		}

	case filesystem.TypeBig: // 2 (et TypeBigDirectory = 3)
		// C'est un gros fichier découpé en plusieurs hashs
		fmt.Println("   -> [BIG NODE] Liste de morceaux :")

		// Le format est : Type (1o) + [Hash (32o)] répétes
		hashSize := 32
		hashesData := data[1:]

		count := len(hashesData) / hashSize
		for i := 0; i < count; i++ {
			start := i * hashSize
			childHashSlice := hashesData[start : start+32]
			var childHash [32]byte
			copy(childHash[:], childHashSlice)

			fmt.Printf("      - Morceau %d (Hash: %x...)\n", i+1, childHash[:5])

			// RÉCURSION : On demande ce morceau
			go me.SendDatumRequest(addr.String(), childHash)
		}

	default:
		fmt.Printf("   -> Type de noeud inconnu : %d\n", nodeType)
	}
}

// Petite fonction utilitaire pour l'affichage
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Dans pkg/p2p/server.go

/*
func (me *Me) handleNoDatum(msg *Message, addr *net.UDPAddr) {
	// 1. Validation de la taille (Doit contenir juste le hash de 32 octets)
	if len(msg.Body) != 32 {
		fmt.Printf("NoDatum invalide reçu de %s (taille body != 32)\n", addr)
		return
	}

	// 2. Extraction du hash manquant
	missingHash := msg.Body[:32]

	// 3. VÉRIFICATION DE LA SIGNATURE (OBLIGATOIRE - Section 4.3)
	// Pour vérifier la signature, il faut la clé publique de l'émetteur (addr).
	// Idéalement, on devrait l'avoir stockée dans une map `Sessions` lors du Hello.
	// Ici, on va faire une vérification simplifiée : on vérifie juste que la signature est présente.

	dataToVerify := msg.Serialize()[:7+len(msg.Body)] // Tout le message jusqu'à la fin du body

	// Note : Dans un code complet, il faut retrouver la pubKey associée à 'addr'
	// et appeler identity.VerifySignature(pubKey, dataToVerify, msg.Signature)
	if len(msg.Signature) != 64 {
		fmt.Printf("ALERTE: NoDatum non signé (ou mal signé) reçu de %s. Ignoré.\n", addr)
		return
	}

	// 4. Logique métier
	fmt.Printf("⚠️  ÉCHEC : Le peer %s ne possède pas le hash demandé : %x\n", addr, missingHash[:5])
	fmt.Println("    -> Le téléchargement de cette branche est interrompu.")

	// (Extension possible : Ici, on pourrait déclencher une recherche vers un AUTRE peer)
}
*/

// BOUCLE D'ECOUTE

// Boucle qui écoute les messages arrivant sur le port définit par la fonction NewCommunication
func (me *Me) ListenLoop() {

	// on prépare un buffer de 2048 octets
	buffer := make([]byte, 2048)

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
			me.handlePing(msg, addr)

		// Si Hello on appelle notre handler prévu
		case TypeHello:
			fmt.Printf("hello recu de %s\n", addr)
			me.handleHello(msg, addr)

		case Error:
			me.handleError(msg, addr)

		// Rien à faire, notre connexion UDP est valide
		case TypeHelloReply:
			fmt.Printf("helloreply recu de %s\n", addr)

		// rien à faire
		case TypeOk:
			fmt.Printf("Ok recu de %s pour l'Id %d\n", addr, msg.Id)

		case TypeRootRequest:
			me.handleRootRequest(msg, addr)

		case TypeDatumRequest:
			me.handleDatumRequest(msg, addr)

		case TypeRootReply: // 131
			fmt.Printf("RootReply (131) reçu de %s\n", addr)
			me.handleRootReply(msg, addr)

		case TypeDatum: // 132
			me.handleDatum(msg, addr)

		case TypeNoDatum: // 133
			//me.handleNoDatum(msg, addr)

		// mauvais type
		default:
			fmt.Printf("type de message non géré : %d\n", msg.Type)
		}
	}
}

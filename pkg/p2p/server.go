package p2p

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"net"
	"project/pkg/filesystem"
	"project/pkg/identity"
)

// EN PLUS DU TIMEOUT IL FAUT FAIRE UN FONCTION QUI VERIFIE SI LE PEER QUI VIENT DE NOUS ENVOYER UN MESSAGE ETAIT DANS NOTRE LISTE DE " CONNEXION COURANTE" ////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FAIRE UN TIMEOUT AVEC LE SERVEUR AUSSI ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
func (me *Me) Send__hello(destAddr string) error {

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
			fmt.Printf("RootReply (131) reçu de %s\n", addr)
			me.Handle__RootReply(msg, addr)

		case TypeDatum: // 132
			me.Handle__Datum(msg, addr)

		case TypeNoDatum: // 133
			//me.handleNoDatum(msg, addr)

		// mauvais type
		default:
			fmt.Printf("type de message non géré : %d\n", msg.Type)
			me.Handle__if__error(msg, addr, fmt.Sprintf("unknown message type: %d", msg.Type))
		}
	}
}

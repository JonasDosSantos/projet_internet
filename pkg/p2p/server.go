package p2p

import (
	"encoding/binary"
	"crypto/ecdsa"
	"strings"
	"fmt"
	"net"
	"project/pkg/identity"
	"project/pkg/client"
)

type Me struct {
	Conn       *net.UDPConn
	PrivateKey *ecdsa.PrivateKey
	PeerName   string
	ServerURL  string
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
		Conn: conn,
		PrivateKey: priv,
		PeerName: name,
		ServerURL: serverURL,
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
		Id:     msgID,
		Type:   TypePing,
		Body:   []byte{},
	}

	// on transforme la struct en chaine d'octets
	data := msg.Serialize()

	// on envoie au destinataire
	_, err = me.Conn.WriteToUDP(data, udpAddr)
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
		Id:     req.Id,
		Type:   TypeOk,
		Body:   []byte{},
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
			me.handleError(msg,addr)

		// Rien à faire, notre connexion UDP est valide
		case TypeHelloReply:
			fmt.Printf("helloreply recu de %s\n", addr)

		// rien à faire
		case TypeOk: 
			fmt.Printf("Ok recu de %s pour l'Id %d\n", addr, msg.Id)

		// mauvais type
		default:
			fmt.Printf("type de message non géré : %d\n", msg.Type)
		}
	}
}
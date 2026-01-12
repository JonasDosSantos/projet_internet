package p2p

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"project/pkg/client"

	//"project/pkg/filesystem"
	"project/pkg/identity"
	"strings"
	"time"
)

// HANDLERS DE GESTION LORS DE LA RECEPTION DE Hello, Ping ET Error

// fonction qui gère la réception d'un Hello
func (me *Me) Handle__hello(req *Message, addr *net.UDPAddr) {

	// on récupère le nom de l'emetteur (le nom est placé après les 4octets de bitmap représentants les extensions)
	if len(req.Body) < 4 {
		fmt.Println("le message Hello est incorrect")

		me.Handle__if__error(req, addr, "invalid hello format")
		return
	}
	sender := strings.Trim(string(req.Body[4:]), "\x00")

	// on récupère la clef publique de l'emetteur en la demandant au serveur
	pubKeyBytes, err := client.Get__publicKey(me.ServerURL, sender)
	if err != nil {
		fmt.Printf("clef de %s introuvable\n", sender)

		me.Handle__if__error(req, addr, "sender's key is nowhere to be found")
		return
	}
	pubKey, _ := identity.Bytes__to__PublicKey(pubKeyBytes)

	// Il ne faut pas vérifier tout le message mais seulement le "header" + le body
	dataToVerify := req.Serialize()[:7+len(req.Body)]

	// on vérifie
	if !identity.Verify__signature(pubKey, dataToVerify, req.Signature) {
		fmt.Printf("signature invalide recue de %s, message jeté\n", sender)

		// on avertit l'emetteur qu'il y a eu une erreur
		me.Handle__if__error(req, addr, "bad signature")
		return
	}

	Log("signature de %s vérifiée\n", sender)

	// Sauvegarde de la clé publique liée à cette IP pour plus tard (nodatum)
	me.Mutex.Lock()

	// on regarde si ce pair existe dans notre liste de pairs actifs
	session, exists := me.Sessions[addr.String()]

	// s'il existe (forcément) ET qu'on connait déjà sa clef
	if exists && session.PublicKey != nil {
		// alors c'est un KeepAlive
		Log("KeepAlive : Hello reçu de %s", sender)
	} else {
		// c'est un nouveau pair
		fmt.Printf("\nHello reçu de %s %s\n ", sender, addr)

		// on enregistre sa clef publique
		if exists {
			session.PublicKey = pubKey
		} else {
			// Sécurité au cas où
			me.Sessions[addr.String()] = &PeerSession{
				LastSeen:  time.Now(),
				PublicKey: pubKey,
			}
		}
	}
	me.Mutex.Unlock()

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
func (me *Me) Handle__ping(req *Message, addr *net.UDPAddr) {

	// on cree la struct Message de la réponse
	reply := Message{
		Id:   req.Id,
		Type: TypeOk,
		Body: []byte{},
	}

	// on transforme le message en chaine d'octets
	data := reply.Serialize()

	// on renvoie le OK à l'emetteur
	me.Conn.WriteToUDP(data, addr)
}

// fonction qui envoie une erreur à une destination, en paramètre: la destination et le message Human-Readable
func (me *Me) Handle__if__error(req *Message, addr *net.UDPAddr, errorMsg string) {

	// on cree la struct Message de la réponse
	reply := Message{
		Id:   req.Id,
		Type: Error,
		Body: []byte(errorMsg),
	}

	// on transforme le message en chaine d'octets
	data := reply.Serialize()

	// on renvoie l'erreur à l'emetteur
	me.Conn.WriteToUDP(data, addr)
}

// focntion qui gère les messages d'erreurs recus
func (me *Me) Handle__error(req *Message, addr *net.UDPAddr) {
	errorMessage := string(req.Body)

	fmt.Printf("Error recu de %s (Id: %d) :\n", addr, req.Id)
	fmt.Printf(" Message : %s\n", errorMessage)
}

// fonction qui gère les messages RootRequest = une demande d'envoi du roothash
func (me *Me) Handle__RootRequest(req *Message, addr *net.UDPAddr) {

	// le corps de la réponse est simplement le RootHash (32 octets)
	body := me.RootHash[:]

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
	me.Conn.WriteToUDP(reply.Serialize(), addr)
}

// Handler pour les DatumRequest
func (me *Me) Handle__DatumRequest(req *Message, addr *net.UDPAddr) {

	// par sécurité, on vérifie que la reponse contient bien un hash de 32 octets
	if len(req.Body) != 32 {
		fmt.Printf("DatumRequest invalide de %s (taille body incorrecte)\n", addr)

		me.Handle__if__error(req, addr, "invalid hash size (must be 32 bytes) in DatumRequest")
		return
	}

	// On récupère le hash demandé
	var requestedHash [32]byte
	copy(requestedHash[:], req.Body)

	// On cherche dans notre "Base de données" en mémoire
	data, found := me.Database[requestedHash]

	if found {
		// on vérifie que les data qu'on a dans notre "Base de Données" correspond bien au hash demandé
		verificationHash := sha256.Sum256(data)

		if !bytes.Equal(verificationHash[:], requestedHash[:]) {
			fmt.Printf("donnée corrompue en mémoire interne %x\n", requestedHash[:5])

			// on considère qu'on a pas trouvé la donnée
			found = false
		}
	}

	if found {
		// si on a ce hash dans notre "Base de Données" alors on renvoie un message "Datum"

		// Format du body : Hash (32 octets) + Data
		replyBody := make([]byte, 32+len(data))
		copy(replyBody[0:32], requestedHash[:])
		copy(replyBody[32:], data)

		reply := Message{
			Id:   req.Id,
			Type: TypeDatum,
			Body: replyBody,
		}

		me.Conn.WriteToUDP(reply.Serialize(), addr)

	} else {
		// si on a pas trouvé ce hash

		reply := Message{
			Id:   req.Id,
			Type: TypeNoDatum,
			Body: requestedHash[:],
		}

		// on signe le message
		unsignedData := reply.Serialize()
		sig, err := identity.Sign(me.PrivateKey, unsignedData)

		if err == nil {
			reply.Signature = sig
			me.Conn.WriteToUDP(reply.Serialize(), addr)
		}
	}
}

// handler à la reception d'un RootReply
func (me *Me) Handle__RootReply(req *Message, addr *net.UDPAddr) {
	// par sécurité, on vérifie que la reponse contient bien un hash de 32 octets
	if len(req.Body) != 32 {
		fmt.Printf("RootReply invalide de %s (taille body incorrecte)\n", addr)

		me.Handle__if__error(req, addr, "invalid hash size (must be 32 bytes) in RootReply")
		return
	}

	// mise à jour du RootHash de notre DataBase
	copy(me.RootHash[:], req.Body[:32])
	fmt.Printf("roothash mis à jour: %x\n", me.RootHash)
}

// handler pour les Datum : je redirige vers le pipe qui l'attend
func (me *Me) Handle__Datum(req *Message, addr *net.UDPAddr) {

	// par sécurité, on vérifie que la reponse contient bien un hash de 32 octets
	if len(req.Body) <= 32 {
		fmt.Printf("Datum invalide de %s (taille body incorrecte)\n", addr)

		me.Handle__if__error(req, addr, "invalid hash size (must be 32 bytes) in Datum")
		return
	}

	// recuperation du hash
	var receivedHash [32]byte
	copy(receivedHash[:], req.Body[:32])

	// recuperation des data
	dataContent := req.Body[32:]

	// on prend le verrou sur notre map de pipe et on verifie si l'un d'eux attend ce hash
	me.PendingLock.Lock()
	respChan, exists := me.PendingRequests[receivedHash]

	// Si OUI
	if exists {

		// on essaye d'écrire la donnée dans le pipe
		select {

		case respChan <- dataContent:

		default:

		}
		// on nettoie la map
		delete(me.PendingRequests, receivedHash)
	}
	// on lache le verrou
	me.PendingLock.Unlock()
}

func (me *Me) Handle__NoDatum(req *Message, addr *net.UDPAddr) {
	// Validation de la taille
	if len(req.Body) != 32 {
		fmt.Printf("NoDatum invalide reçu de %s (taille != 32)\n", addr)
		me.Handle__if__error(req, addr, "invalid NoDatum size")
		return
	}

	missingHash := req.Body[:32]

	// récupération de la clé publique via la Session
	me.Mutex.Lock()
	session, exists := me.Sessions[addr.String()]
	me.Mutex.Unlock()

	if !exists || session.PublicKey == nil {
		fmt.Printf("NoDatum reçu de %s, mais pair connu. Ignoré.\n", addr)
		return
	}

	// Vérification de la signature
	dataToVerify := req.Serialize()[:7+len(req.Body)]

	if !identity.Verify__signature(session.PublicKey, dataToVerify, req.Signature) {
		fmt.Printf("Signature invalide pour NoDatum de %s\n", addr)
		me.Handle__if__error(req, addr, "bad signature on NoDatum")
		return
	}

	// 4. LOGIQUE MÉTIER (ADAPTÉE AUX CHANNELS)
	fmt.Printf("Le peer %s ne possède pas le hash : %x\n", addr, missingHash[:5])

	// On prépare la clé pour la chercher dans la map
	var hashArray [32]byte
	copy(hashArray[:], missingHash)

	// On touche à la map partagée, donc on lock
	me.PendingLock.Lock()
	ch, waiting := me.PendingRequests[hashArray]

	if waiting {
		// Quelqu'un attendait ce fichier via un channel
		// On supprime l'entrée de la map
		delete(me.PendingRequests, hashArray)

		// On ferme le channel
		// Cela va envoyer une valeur "vide" (nil) instantanément à Download_recursively.
		// Cela évite d'attendre le timeout de 10s pour rien
		close(ch)
		fmt.Printf("échec envoyé au processus de téléchargement.\n")
	}
	me.PendingLock.Unlock()
}

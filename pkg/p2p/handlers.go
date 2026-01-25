package p2p

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"project/pkg/client"

	//"project/pkg/filesystem"
	"project/pkg/identity"
	"strings"
	"time"
)

// fonction à qui les handler délègue les vérifications de base
func (me *Me) msg__verifier(req *Message, addr *net.UDPAddr, is_rootRequest bool, is_length_32 bool, verif_needed bool) (*PeerSession, bool) {

	// on prend le verrou sur les session et on récupère les infos sur la session
	me.Mutex.Lock()
	session, exists := me.Sessions[addr.String()]

	// si la session n'existe pas
	if !exists {
		me.Mutex.Unlock()
		fmt.Printf("Message (Type %d) reçu de %s, mais pair inconnu. Ignoré.\n", req.Type, addr)
		me.Handle__if__error(req, addr, "please hello first")
		return nil, false
	}

	// si on ne connait pas encore la clef du peer
	if session.PublicKey == nil {
		me.Mutex.Unlock()
		fmt.Printf("Message (Type %d) reçu de %s, mais clé publique inconnue. Ignoré.\n", req.Type, addr)
		me.Handle__if__error(req, addr, "your key is nowhere to be found (could be our fault), please Handshake (Hello)")
		return nil, false
	}

	if !is_rootRequest {
		if is_length_32 {
			if len(req.Body) < 32 {
				fmt.Printf("Message (Type %d) invalide de %s (taille body incorrecte)\n", req.Type, addr)

				me.Handle__if__error(req, addr, "invalid hash size (must be 32 bytes)")
				return nil, false
			}
		} else {
			if len(req.Body) != 6 && len(req.Body) != 18 {
				fmt.Printf("Message (Type %d) invalide de %s (taille body incorrecte)\n", req.Type, addr)

				me.Handle__if__error(req, addr, "invalid addr size (must be 6 or 18 bytes)")
				return nil, false
			}
		}
	}

	if verif_needed {

		serializedMsg := req.Serialize()
		dataToVerify := serializedMsg[:7+len(req.Body)]

		if !identity.Verify__signature(session.PublicKey, dataToVerify, req.Signature) {
			me.Mutex.Unlock()
			fmt.Printf(" Signature invalide pour le message (Type %d) de %s\n", req.Type, addr)
			me.Handle__if__error(req, addr, "bad signature")
			return nil, false
		}
	}

	// on met à jour le lastseen
	session.LastSeen = time.Now()

	me.Mutex.Unlock()

	return session, true
}

// HANDLERS DE GESTION LORS DE LA RECEPTION DE Hello, Ping, Error etc

// Handler pour les messages de type OK
func (me *Me) Handle__Ok(req *Message, addr *net.UDPAddr) {

	// je prend le verrou sur la map de pipe
	me.PendingLock.Lock()
	// je regarde s'il existe bien un pipe qui attend cette réponse
	respChan, exists := me.PendingRequests[Key__from__Id(req.Id)]

	// si OUI
	if exists {

		select {

		// on essaye d'écrire la donnée dans le pipe
		case respChan <- req.Body:

		// sinon, on delete le pipe
		default:
		}

		// on nettoie notre map de pipe car l'ID est unique
		delete(me.PendingRequests, Key__from__Id(req.Id))
	}
	// on lache le verrou
	me.PendingLock.Unlock()

	Verbose_log("Ok reçu de %s", addr)
}

// handler pour les hellos (hello et helloReply)
func (me *Me) Handle__hellos(req *Message, addr *net.UDPAddr) {

	isReply := false
	if req.Type == TypeHelloReply {
		isReply = true
	}

	// on récupère le nom de l'emetteur (le nom est placé après les 4octets de bitmap représentants les extensions)
	if len(req.Body) < 4 {
		fmt.Println("le message Hello est incorrect")

		if isReply {
			me.Handle__if__error(req, addr, "invalid helloReply format")
		} else {
			me.Handle__if__error(req, addr, "invalid hello format")
		}
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
		if isReply {
			me.Handle__if__error(req, addr, "bad signature on helloReply ")
		} else {
			me.Handle__if__error(req, addr, "bad signature on hello")
		}
		return
	}

	me.Mutex.Lock()

	// on regarde si ce pair existe dans notre liste de pairs actifs
	session, exists := me.Sessions[addr.String()]

	// s'il existe ET qu'on connait déjà sa clef
	if exists && session.PublicKey != nil {
		// alors c'est un KeepAlive
		if isReply {
			Verbose_log("KeepAlive : HelloReply reçu de %s", sender)
		} else {
			Verbose_log("KeepAlive : Hello reçu de %s", sender)
		}
		session.LastSeen = time.Now()
	} else {
		// c'est un nouveau pair
		if isReply {
			fmt.Printf("\nHelloReply reçu de %s\n", sender)
		} else {
			fmt.Printf("\nHello reçu de %s\n", sender)
		}

		// on enregistre sa clef publique
		if exists {
			session.PublicKey = pubKey
			session.LastSeen = time.Now()
		} else {
			// Sécurité au cas où
			me.Sessions[addr.String()] = &PeerSession{
				LastSeen:  time.Now(),
				PublicKey: pubKey,
			}
		}
	}
	me.Mutex.Unlock()

	if isReply {

		// je prend le verrou sur la map de pipe
		me.PendingLock.Lock()
		// je regarde s'il existe bien un pipe qui attend cette réponse
		respChan, exists := me.PendingRequests[Key__from__Id((req.Id))]

		// si OUI
		if exists {

			select {

			// on essaye d'écrire la donnée dans le pipe
			case respChan <- req.Body:

			// sinon, on delete le pipe
			default:
			}

			// on nettoie notre map de pipe car l'ID est unique
			delete(me.PendingRequests, Key__from__Id((req.Id)))
		}
		// on lache le verrou
		me.PendingLock.Unlock()

	} else {
		//reponse

		// on cree le body
		body := make([]byte, 4+len(me.PeerName))

		var extensions uint32 = 0
		extensions |= ExtensionNAT
		extensions |= ExtensionEncryption
		binary.BigEndian.PutUint32(body[0:4], extensions)

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
		me.Send__UDP(reply, addr)
	}

	// On lit les extensions du message reçu
	extensions := binary.BigEndian.Uint32(req.Body[0:4])

	// On vérifie si le bit Encryption est activé
	if (extensions & ExtensionEncryption) != 0 {
		fmt.Printf("%s supporte le chiffrement !\n", sender)

		// On lance l'échange de clés (dans une goroutine pour ne pas bloquer)
		go me.Send__KeyExchange(addr.String())
	}
}

// fonction qui gère la réception d'un ping
func (me *Me) Handle__ping(req *Message, addr *net.UDPAddr) {

	me.Mutex.Lock()
	session, exists := me.Sessions[addr.String()]

	if !exists {
		me.Mutex.Unlock()
		fmt.Printf("Ping reçu de %s, mais pair inconnu. Ignoré.\n", addr)

		me.Handle__if__error(req, addr, " please hello first")
		return
	}

	// puisqu'on a reçu un message valide d'une session connue, on met à jour le LastSeen
	session.LastSeen = time.Now()

	me.Mutex.Unlock()

	// on cree la struct Message de la réponse
	reply := Message{
		Id:   req.Id,
		Type: TypeOk,
		Body: []byte{},
	}

	Verbose_log("Ping reçu de %s", addr)
	me.Send__UDP(reply, addr)
}

// fonction qui envoie une erreur à une destination, en paramètre: la destination et le message Human-Readable
func (me *Me) Handle__if__error(req *Message, addr *net.UDPAddr, errorMsg string) {

	// on cree la struct Message de la réponse
	reply := Message{
		Id:   req.Id,
		Type: Error,
		Body: []byte(errorMsg),
	}

	me.Send__UDP(reply, addr)
}

// focntion qui gère les messages d'erreurs recus
func (me *Me) Handle__error(req *Message, addr *net.UDPAddr) {
	errorMessage := string(req.Body)

	fmt.Printf("Error recu de %s (Id: %d) :\n", addr, req.Id)
	fmt.Printf("Message : %s\n", errorMessage)

	// je prend le verrou sur la map de pipe
	me.PendingLock.Lock()
	// je regarde s'il existe bien un pipe qui attend cette réponse
	respChan, exists := me.PendingRequests[Key__from__Id((req.Id))]

	// si OUI
	if exists {

		select {

		// on essaye d'écrire la donnée dans le pipe
		case respChan <- req.Body:

		// sinon, on delete le pipe
		default:
		}

		// on nettoie notre map de pipe car l'ID est unique
		delete(me.PendingRequests, Key__from__Id((req.Id)))
	}
	// on lache le verrou
	me.PendingLock.Unlock()
}

// fonction qui gère les messages RootRequest = une demande d'envoi du roothash (pourrait se nommer Send__RootReply)
func (me *Me) Handle__RootRequest(req *Message, addr *net.UDPAddr) {

	_, success := me.msg__verifier(req, addr, true, false, false)
	if !success {
		return
	}

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

	me.Send__UDP(reply, addr)

	Verbose_log("RootRequest reçu de %s", addr)
}

// Handler pour les DatumRequest
func (me *Me) Handle__DatumRequest(req *Message, addr *net.UDPAddr) {

	session, success := me.msg__verifier(req, addr, false, true, false)
	if !success {
		return
	}

	Verbose_log("DatumRequest reçu de %s", addr)

	// On récupère le hash demandé
	var requestedHash [32]byte
	copy(requestedHash[:], req.Body)

	// On cherche dans notre "Base de données" en mémoire
	me.DbLock.Lock()
	data, found := me.Database[requestedHash]
	me.DbLock.Unlock()

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

		if session.IsEncrypted {
			// On chiffre le tout
			encryptedBody, err := identity.Encrypt_AES(session.SharedKey, replyBody)
			if err == nil {
				// On remplace le body à envoyer par le body chiffré
				replyBody = encryptedBody
				Verbose_log("Le Datum que l'on va envoyer à %s est chiffré.", addr)
			}
		}

		//sinon on envoi en normal

		reply := Message{
			Id:   req.Id,
			Type: TypeDatum,
			Body: replyBody,
		}

		me.Send__UDP(reply, addr)
		Verbose_log("Envoi d'un Datum à %s", addr)

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
			me.Send__UDP(reply, addr)
			Verbose_log("Envoi d'un NoDatum à %s", addr)
		}
	}
}

// handler à la reception d'un RootReply
func (me *Me) Handle__RootReply(req *Message, addr *net.UDPAddr) {

	_, success := me.msg__verifier(req, addr, false, true, true)
	if !success {
		return
	}

	Verbose_log("RootReply reçu de %s", addr)

	// mise à jour du RootHash de notre DataBase
	copy(me.RootHash[:], req.Body[:32])
	Verbose_log("roothash mis à jour: %x\n", me.RootHash)

	// je prend le verrou sur la map de pipe
	me.PendingLock.Lock()
	// je regarde s'il existe bien un pipe qui attend cette réponse
	respChan, exists := me.PendingRequests[Key__from__Id(req.Id)]

	// si OUI
	if exists {

		select {

		// on essaye d'écrire la donnée dans le pipe
		case respChan <- req.Body:

		// sinon, on delete le pipe
		default:
		}

		// on nettoie notre map de pipe car l'ID est unique
		delete(me.PendingRequests, Key__from__Id(req.Id))
	}
	// on lache le verrou
	me.PendingLock.Unlock()
}

// handler pour les Datum : je redirige vers le pipe qui l'attend
func (me *Me) Handle__Datum(req *Message, addr *net.UDPAddr) {

	session, success := me.msg__verifier(req, addr, false, true, false)
	if !success {
		return
	}

	if session.IsEncrypted {
		Verbose_log("Le datum reçu de %s est chiffré.", addr)
		// Déchiffrement
		decryptedBody, err := identity.Decrypt_AES(session.SharedKey, req.Body)
		if err != nil {
			fmt.Printf("Erreur déchiffrement de %s : %v\n", addr, err)
			return
		}

		Verbose_log("Datum déchiffré avec succès de %s", addr)

		// On "triche" : on modifie le message pour faire croire qu'il était en clair
		req.Body = decryptedBody
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

	_, success := me.msg__verifier(req, addr, false, true, true)
	if !success {
		return
	}

	missingHash := req.Body[:32]

	Verbose_log("NoDatum reçu de %s, le peer ne possède pas le hash : %x\n", addr, missingHash[:5])

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
		close(ch)
		fmt.Printf("échec envoyé au processus de téléchargement.\n")
	}
	me.PendingLock.Unlock()
}

// handlr pour les NatTraversalRequest(1) : A nous demande d'être l'intermédiaire entre lui et B (équivalent à Send__NatTraversalRequest2)
func (me *Me) Handle__NatTraversalRequest(req *Message, addr *net.UDPAddr) {

	_, success := me.msg__verifier(req, addr, false, false, true)
	if !success {
		return
	}

	Verbose_log("NatTraversalRequest reçu de %s", addr)

	// on récupère l'ip et le port cible
	var targetIP net.IP
	var targetPort uint16

	// selon si c'est IPv4 ou IPv6
	if len(req.Body) == 6 {
		targetIP = net.IP(req.Body[0:4])
		targetPort = binary.BigEndian.Uint16(req.Body[4:6])
	} else {
		targetIP = net.IP(req.Body[0:16])
		targetPort = binary.BigEndian.Uint16(req.Body[16:18])
	}

	// on assemble l'ip et le port
	targetAddrStr := fmt.Sprintf("%s:%d", targetIP.String(), targetPort)
	targetUDP, err := net.ResolveUDPAddr("udp", targetAddrStr)
	if err != nil {
		return
	}

	// on prépare le ebody du message à envoeyr
	var body []byte
	srcIP := addr.IP.To4()

	if srcIP != nil {
		// IPv4
		body = make([]byte, 6)
		copy(body[0:4], srcIP)
		binary.BigEndian.PutUint16(body[4:6], uint16(addr.Port))
	} else {
		// IPv6
		srcIP = addr.IP
		body = make([]byte, 18)
		copy(body[0:16], srcIP)
		binary.BigEndian.PutUint16(body[16:18], uint16(addr.Port))
	}
	// on répond OK à l'emetteur
	Verbose_log("Envoi d'un Ok à l'intermédiaire\n")
	me.Handle__ping(req, addr)

	Verbose_log("Envoi d'un NatTraversalRequest2 à %s\n", targetAddrStr)
	go func() {
		err := me.Send__NatTraversalRequest2(targetUDP, body)
		if err != nil {
			fmt.Printf("échec du relai vers %s : %v\n", targetAddrStr, err)
		}
	}()
}

// Handler pour les requetes de NatTraversalRequest2 : si on reèoit cette requête, on envoie un ping à l'adresse cible
func (me *Me) Handle__NatTraversalRequest2(req *Message, addr *net.UDPAddr) {

	_, success := me.msg__verifier(req, addr, false, false, true)
	if !success {
		return
	}

	Verbose_log("NatTraversalRequest2 reçu de %s", addr)

	fmt.Printf(" DEBUG :Body du Nat2 (Bytes): %v\n", req.Body)

	// on récupère l'ip et le port
	var targetIP net.IP
	var targetPort uint16

	if len(req.Body) == 6 {
		// si IPv4
		targetIP = net.IP(req.Body[0:4])
		targetPort = binary.BigEndian.Uint16(req.Body[4:6])
	} else {
		// si IPv6
		targetIP = net.IP(req.Body[0:16])
		targetPort = binary.BigEndian.Uint16(req.Body[16:18])
	}

	// on assemble Ip et port
	targetAddrStr := fmt.Sprintf("%s:%d", targetIP.String(), targetPort)

	// il faut envoyer un Ok à l'envoyeur du NatTraversalRequest2, on appelle notre fonction Handle__Ping qui fait exactement ca
	Verbose_log("Envoi d'un Ok à l'intermédiaire")
	me.Handle__ping(req, addr)

	Verbose_log("Tentative de ping à la cible")
	go me.Send__ping(targetAddrStr)
}

func (me *Me) Handle__KeyExchange(req *Message, addr *net.UDPAddr) {
	// On verrouille pour lire la map des sessions de manière thread-safe
	me.Mutex.Lock()
	session, exists := me.Sessions[addr.String()]
	me.Mutex.Unlock()

	// Cette variable permet de savoir si la clé a déjà été généré.
	// Si c'est le cas, on a déjà envoyé notre clé, donc on n'en aura plus besoin après cette fonction.
	// > La même variable existe dans "Send_KeyExchange" dans senders.go
	isAlreadyDefinedEphemeralPrivKey := false

	if !exists || session.PublicKey == nil {
		return
	}

	// On vérifie d'abord la signature du message envoyé
	dataToVerify := req.Serialize()[:7+len(req.Body)]
	if !identity.Verify__signature(session.PublicKey, dataToVerify, req.Signature) {
		fmt.Printf("ALERTE: Signature invalide pour KeyExchange de %s\n", addr)
		return
	}

	me.Mutex.Lock()
	defer me.Mutex.Unlock()

	// Si on reçoit la clé de l'autre AVANT d'avoir décidé d'envoyer la nôtre,
	// on doit quand même générer notre moitié du secret pour faire le calcul.
	if session.EphemeralPriv == nil {
		// On génère la clé, MAIS ON NE L'ENVOIE PAS ICI.
		// C'est le rôle de Hello/HelloReply de gérer l'envoi.
		priv, _, err := identity.Generate_Ephemeral_Key()
		if err != nil {
			return
		}
		session.EphemeralPriv = priv
	} else {
		isAlreadyDefinedEphemeralPrivKey = true
	}

	// Calcul du secret
	sharedKey, err := identity.Compute_Shared_Secret(session.EphemeralPriv, req.Body)
	if err != nil {
		fmt.Printf("Erreur crypto : %v\n", err)
		return
	}

	// On enregistre les informations pour la session
	session.SharedKey = sharedKey
	session.IsEncrypted = true

	// On garde EphemeralPriv tant que la session est active ou on le supprime
	// Pour l'instant, on peut le laisser à nil pour dire "c'est fini"

	if isAlreadyDefinedEphemeralPrivKey {
		session.EphemeralPriv = nil
	}

	if Verbose {
		fmt.Printf("SECRET ÉTABLI AVEC %s (Passivement)\n", addr)
	}
}

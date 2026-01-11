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
	fmt.Printf("Vérification du Hello de : '%s'\n", sender)

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

	//TIMEOUT DE 5 MINUTES ////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

	// MAJ DU TIMEOUT DE 5 MINUTES ////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
	fmt.Printf(">> Message : %s\n", errorMessage)
}

// fonction qui gère les messages RootRequest = une demande d'envoi du roothash
func (me *Me) Handle__RootRequest(req *Message, addr *net.UDPAddr) {
	fmt.Printf("RootRequest reçue de %s\n", addr)

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

	// par sécurité, on vérifie que la requête contient bien un hash de 32 octets
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
		fmt.Printf("data envoyés à %s \n", addr)

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
			fmt.Printf("NoDatum envoyé à %s\n", addr)
		}
	}
}


/*

// handler pour les RootReply
func (me *Me) Handle__RootReply(req *Message, addr *net.UDPAddr) {

	// vérification de sécurité (taille du hash)
	if len(req.Body) < 32 {
		fmt.Printf("RootReply invalide reçu de %s (taille < 32)\n", addr)
		
		me.Handle__if__error(req, addr, "invalid hash size (must be 32 bytes) in Rootreply")
    	return
	}

	// on récupère le hash
	rootHash := req.Body[:32]
	fmt.Printf(" root hash recu de %s : %x\n", addr, rootHash)

	// on vient de récupérer le root hash, on av donc maintenant demander les data des étages inférieurs de l'arbre

	fmt.Printf("envoi d'un DatumRequest pour le root hash\n")

	// on convertit le hash en tableau d'octets pour le faire passer en paramètre de la fonction DatumRequest
	var hashArray [32]byte
	copy(hashArray[:], rootHash)

	me.Send__DatumRequest(addr.String(), hashArray)
}

func (me *Me) Handle__Datum(req *Message, addr *net.UDPAddr) {
	// vérification de la structure du message recu, il doit y avoir au moins 32 octets de hash
	if len(req.Body) <= 32 {
		fmt.Printf("Datum invalide (trop court) de %s\n", addr)
		return
	}

	// on récupère le hash
	remoteHash := req.Body[:32]

	// on récupère la suite du message (le contenu du noeud de l'arbre)
	data := req.Body[32:]

	// on vérifie que ce qu'on a reçu est bien ce qu'on a demandé (normalement, l'envoyeur à aussi vérifié ça de son côté, nous on le fait)
	localHash := sha256.Sum256(data)
	if !bytes.Equal(remoteHash, localHash[:]) {
		fmt.Printf("données corrompues reçues de %s, hash incorrect.\n", addr)
		
		// on renvoie un message d'erreur human-readable
		me.Handle__if__error(req, addr, "hash mismatch (data corrupted) in Datum")
    	return
	}

	// on récupère le type du noeud. c'est le premier octets des data
	nodeType := data[0]

	// on fait un switch/case sur ce type
	switch nodeType {

	case filesystem.TypeChunk:
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		///////////////////////////////////////////////////TELECHARGEMENT ICI///////////////////////////////////////////////////
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// C'est un morceau de fichier final.
		// Dans un vrai client, on le stockerait sur le disque.
		//content := string(data[1:]) // On saute le type (1er octet)
		//fmt.Printf("   -> [FICHIER] Chunk reçu : \"%s...\"\n", content[:min(20, len(content))])

	case filesystem.TypeDirectory:
		// c'est un directory, il y a donc une liste de couples (nom, hash)
		fmt.Println("dossier trouvé, contenu :")

		// 64 = 32 + 32 = len(nom) + len(hash)
		entrySize := 64

		// on enleve l'octet de type
		entriesData := data[1:]

		// c'est le nombre d'entree dans le repertoire
		count := len(entriesData) / entrySize

		// boucle sur chaque entree
		for i := 0; i < count; i++ {
			// debut de "l'offset"
			start := i * entrySize

			// on récupère le nom en enlevant le padding
			nameBytes := entriesData[start : start+32]
			name := strings.Trim(string(nameBytes), "\x00")

			// on récupère le hash
			childHashSlice := entriesData[start+32 : start+64]
			var childHash [32]byte
			copy(childHash[:], childHashSlice)

			fmt.Printf(" fichier ou dossier trouvé : %s\n", name)

			// on va chercher récursivement chaque enfant
			go me.Send__DatumRequest(addr.String(), childHash)
		}

		case filesystem.TypeBig, filesystem.TypeBigDirectory:
			// c'est un BigDIrectory ou un BigNode, on traite de la même façon

			// on enlève le type du départ
			hashesData := data[1:]

			// nombre d'enfants
			count := len(hashesData) / 32

			// on boucle sur chacun d'eux
			for i := 0; i < count; i++ {

				// debut de "l'offset"
				start := i * 32
				childHashSlice := hashesData[start : start+32]
				var childHash [32]byte
				copy(childHash[:], childHashSlice)

				// on demande ce morceau
				go me.Send__DatumRequest(addr.String(), childHash)
			}

		// si le type du noeud est inconnu, on avertit l'emetteur
		default:
			fmt.Printf("type de noeud inconnu %d\n", nodeType)
			me.Handle__if__error(req, addr, "node type unknown in Datum")
		}
}



*/







// Petite fonction utilitaire pour l'affichage
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}










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
	// et appeler identity.Verify__signature(pubKey, dataToVerify, msg.Signature)
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
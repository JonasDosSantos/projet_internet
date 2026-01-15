package p2p

import (
	"encoding/binary"
	"fmt"
	"net"
	"project/pkg/identity"
	"time"
)

// fonction qui sert à envoyer un message et vérifie si le timeout est atteint, auquel cas réessaye jusqu'à 3 fois.
// les paramètres sont: la destiantion, une "clef" pour le pipe (hash pour les Datum, Id sinon), la fonction Sender (Send__hello, ...)
func (me *Me) Send__with__timeout(destAddr string, key [32]byte, sendFunc func() error, failureMsg string) ([]byte, error) {

	// on commence avec un timeout de 2 secondes. A chaque timeoeut on double. Si le 3eme essai (16secondes) échoue, on stop
	currentTimeout := 2 * time.Second
	maxTimeout := 8 * time.Second

	for {
		// on prépare le pipe pour la réponse
		respChan := make(chan []byte, 1)

		// on prends le verrou sur notre map de pipe et on y place celui qu'on vient de créer
		me.PendingLock.Lock()
		me.PendingRequests[key] = respChan
		me.PendingLock.Unlock()

		// execution de notre fonction d'envoi (notre action)
		err := sendFunc()
		if err != nil {
			fmt.Printf("erreur envoi UDP %v\n", err)

			// on a eu une erreur "système", on delete notre pipe
			me.PendingLock.Lock()
			delete(me.PendingRequests, key)
			me.PendingLock.Unlock()
			return nil, fmt.Errorf("échec critique de l'envoi (adresse invalide ?) : %v", err)
		}

		// attente
		select {
		case data := <-respChan:
			// si notre pipe contient des data c'est un succès
			return data, nil

		case <-time.After(currentTimeout):
			// timeout

			// on prend le verrou sur notre map et on delete le pipe
			me.PendingLock.Lock()
			delete(me.PendingRequests, key)
			me.PendingLock.Unlock()

			// si on a atteint le max de timeout définit, on renvoi une erreur
			if currentTimeout >= maxTimeout {
				fmt.Println("echec de l'envoi du message, aucune réponse après 4 tentatives et 30s")
				if failureMsg != "" {
					fmt.Println(failureMsg)
				}

				return nil, fmt.Errorf("timeout définitif après %v", currentTimeout)
			}

			// on double le timeout et on reesaye
			fmt.Printf("timeout de %v. nouvel essai\n", currentTimeout)
			currentTimeout *= 2
		}
	}
}

// fonction qui envoie Hello à une destination (paramètre destAddr)
func (me *Me) Send__hello(destAddr string) error {

	// on genere l'ID de ce message
	msgId := me.Generate__random__id()

	// on derive l'ID en une key
	waitKey := Key__from__Id(msgId)

	// on crée une "action", c'est ce qui est transmis à Send__with__timeout
	sendFunc := func() error {

		// on prépare l'adresse de destination pour UDP
		udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
		if err != nil {
			return err
		}

		// le coprs du message est Extensions + Name (d'où 4octets + taille de Name en octets)
		body := make([]byte, 4+len(me.PeerName))

		// on écrit le nom du Peer à la fin (les 4 premiers octets sont vides pour le moment)
		copy(body[4:], []byte(me.PeerName))

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

	customMsg := fmt.Sprintln(" Echec d'un Hello, veuillez réessayer avec l'option de NAT Traversal")

	// on appelle notre fonction qui gère le timeout avec reply
	_, err := me.Send__with__timeout(destAddr, waitKey, sendFunc, customMsg)
	if err == nil {
		return nil
	}
	////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////

	// 3. EN CAS D'ÉCHEC : AUTOMATISATION DU NAT TRAVERSAL
	fmt.Println("Echec direct. Tentative via NAT Traversal...")

	// A. On prévient le serveur (Signal)
	// C'est ici que A dit à C : "Dis à B de m'écrire"
	errNat := me.Send__NatTraversalRequest(destAddr, me.ServerUDPAddr)
	if errNat != nil {
		return fmt.Errorf("échec total (Direct + Serveur injoignable): %v", errNat)
	}

	// B. On RELANCE l'envoi vers B immédiatement (Hole Punching)
	// C'est l'étape cruciale qui manquait dans ta proposition.
	// On réutilise la même fonction d'envoi.
	_, errRetry := me.Send__with__timeout(destAddr, waitKey, sendFunc, "Abandon après échec NAT Traversal")

	return errRetry
}

// fonction qui envoie un ping à une destination
func (me *Me) Send__ping(destAddr string) error {

	// on genere l'ID de ce message
	msgId := me.Generate__random__id()

	// on derive l'ID en une key
	waitKey := Key__from__Id(msgId)

	// on crée une "action", c'est ce qui est transmis à Send__with__timeout
	sendFunc := func() error {
		// on prépare l'adresse de destination pour UDP
		udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
		if err != nil {
			return err
		}

		// on cree la struct Message du ping
		msg := Message{
			Id:   msgId,
			Type: TypePing,
			Body: []byte{},
		}

		// on transforme la struct en chaine d'octets
		data := msg.Serialize()

		// on envoie au destinataire
		_, err = me.Conn.WriteToUDP(data, udpAddr)
		return err
	}

	// on appelle notre fonction qui gère le timeout avec reply
	_, err := me.Send__with__timeout(destAddr, waitKey, sendFunc, "")
	return err
}

// fonction qui envoie un rootRequest à une destination
func (me *Me) Send__RootRequest(destAddr string) error {

	// on genere l'ID de ce message
	msgId := me.Generate__random__id()

	// on derive l'ID en une key
	waitKey := Key__from__Id(msgId)

	// on crée une "action", c'est ce qui est transmis à Send__with__timeout
	sendFunc := func() error {
		udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
		if err != nil {
			return err
		}

		// Ici le body envoyé est vide, il sera rempli par un handler
		msg := Message{
			Id:   msgId,
			Type: TypeRootRequest,
			Body: []byte{},
		}

		// Pas de signature nécessaire pour la requête
		_, err = me.Conn.WriteToUDP(msg.Serialize(), udpAddr)
		return err
	}

	// on appelle notre fonction qui gère le timeout avec reply
	_, err := me.Send__with__timeout(destAddr, waitKey, sendFunc, "")
	return err
}

// fonction qui envoie une datumRequest à une destination
func (me *Me) Send__DatumRequest(destAddr string, hash [32]byte) ([]byte, error) {

	// on crée une "action", c'est ce qui est transmis à Send__with__timeout
	sendFunc := func() error {

		udpAddr, err := net.ResolveUDPAddr("udp", destAddr)
		if err != nil {
			return err
		}

		// Le body doit contenir les 32 octets du hash demandé
		body := make([]byte, 32)
		copy(body, hash[:])

		msg := Message{
			Id:   me.Generate__random__id(),
			Type: TypeDatumRequest, // 3
			Body: body,
		}

		_, err = me.Conn.WriteToUDP(msg.Serialize(), udpAddr)
		return err
	}

	return me.Send__with__timeout(destAddr, hash, sendFunc, "")
}

// fonction pour envoyer un NatTraversalRequest(1) au serveur
func (me *Me) Send__NatTraversalRequest(targetAddr string, destAddr string) error {

	msgId := me.Generate__random__id()
	waitKey := Key__from__Id(msgId)

	// on prépare l'"action" pour Send__with__timeout
	sendFunc := func() error {

		// on prépapre l'adresse pour l'envoi
		udpaddr, err := net.ResolveUDPAddr("udp", destAddr)
		if err != nil {
			return err
		}

		// on prépare aussi "target", on va l'écrire dans le body
		targetUDP, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return err
		}

		// on prépare le body
		var body []byte

		// on récupère l'ip (si l'ip est une IPv6, To4 renvoie nil)
		ip := targetUDP.IP.To4()

		if ip != nil {
			// c'est une IPv4
			body = make([]byte, 6)

			// on écrit l'ip dans les 4 premirs octets
			copy(body[0:4], ip)

			// on écrit le port à la suite
			binary.BigEndian.PutUint16(body[4:6], uint16(targetUDP.Port))
		} else {
			// c'est une IPv6

			// on récupère l'ip (sur 16 octets)
			ip = targetUDP.IP
			body = make([]byte, 18)

			// on écrit l'ip au début
			copy(body[0:16], ip)

			// on écrit le port à la fin
			binary.BigEndian.PutUint16(body[16:18], uint16(targetUDP.Port))
		}

		// création d'un message avec notre struct mssage
		msg := Message{
			Id:   msgId,
			Type: TypeNatTraversalRequest,
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
		_, err = me.Conn.WriteToUDP(msg.Serialize(), udpaddr)
		return err
	}

	/// on envoie avec notre fonction d'envoi
	_, err := me.Send__with__timeout(destAddr, waitKey, sendFunc, "")
	return err
}

// fonction sender de natrequest2
func (me *Me) Send__NatTraversalRequest2(destAddr *net.UDPAddr, body []byte) error {

	// on récupère l'adreesse dest
	destStr := destAddr.String()

	// on prépare l'id du message et la key pour notre map de pipe
	msgId := me.Generate__random__id()
	waitKey := Key__from__Id(msgId)

	// on prépare l'"action" pour Send__with__timeout
	sendFunc := func() error {

		msg := Message{
			Id:   msgId,
			Type: TypeNatTraversalRequest2,
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
		_, err = me.Conn.WriteToUDP(msg.Serialize(), destAddr)
		return err
	}

	_, err := me.Send__with__timeout(destStr, waitKey, sendFunc, "")
	return err
}

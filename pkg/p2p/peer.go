package p2p

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// variable pour le mode bavard (par défaut sur false)
var Verbose bool = false

// fonction de log liée à la variable Verbose
func Log(format string, a ...interface{}) {
	if Verbose {
		fmt.Printf(format+"\n", a...)
	}
}

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

func (me *Me) Generate__random__id() uint32 {

	// on crée la variable
	b := make([]byte, 4)

	// on appelle la bibliothèque rand de crypto
	_, err := rand.Read(b)

	// si erreur
	if err != nil {
		fmt.Println("erreur génération aléatoire:", err)
		return 0
	}

	// on revoie notre nombre random
	return binary.BigEndian.Uint32(b)
}

// convertit une ID (4 octets) en une Key (32 octets) : utile pour notre gestion des timeout message
func Key__from__Id(id uint32) [32]byte {

	// on crée la variable
	var key [32]byte

	// on y écrit l'id dans les octets de poids fort
	binary.BigEndian.PutUint32(key[:4], id)
	return key
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

// Boucle qui écoute les messages arrivant sur le port définit par la fonction New__communication
func (me *Me) Listen__loop() {

	// on prépare un buffer de 64000 octets
	buffer := make([]byte, 64000)

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

		routingKey := [32]byte{}
		dataContent := make([]byte, 0)
		shouldRoute := false

		// on agit différement selon le Type de message
		switch msg.Type {

		////////////////
		// REQUETES
		////////////////

		case TypePing:
			Log("ping recu de %s\n", addr)
			me.Handle__ping(msg, addr)

		case TypeHello:
			me.Handle__hello(msg, addr)

		case TypeRootRequest:
			Log("RootRequest recu de %s\n", addr)
			me.Handle__RootRequest(msg, addr)

		case TypeDatumRequest:
			Log("DatumRequest recu de %s\n", addr)
			me.Handle__DatumRequest(msg, addr)

		case TypeNatTraversalRequest2:
			me.Handle__NatTraversalRequest2(msg, addr)

		/////////////
		// REPONSES
		/////////////

		case Error:
			me.Handle__error(msg, addr)

		case TypeHelloReply:
			Log("helloreply recu de %s\n", addr)

			routingKey = Key__from__Id(msg.Id)
			dataContent = msg.Body
			shouldRoute = true

		case TypeOk:
			Log("Ok recu de %s \n", addr)

			routingKey = Key__from__Id(msg.Id)
			dataContent = msg.Body
			shouldRoute = true

		case TypeRootReply:
			Log("RootReply recu de %s pour l'Id %d\n", addr, msg.Id)
			me.Handle__RootReply(msg, nil)

			routingKey = Key__from__Id(msg.Id)
			dataContent = msg.Body
			shouldRoute = true

		case TypeNoDatum:
			Log("noDatum recu de %s\n", addr)
			me.Handle__NoDatum(msg, addr)

		case TypeDatum:
			me.Handle__Datum(msg, addr)

		// mauvais type
		default:
			fmt.Printf("type de message non géré : %d\n", msg.Type)
			me.Handle__if__error(msg, addr, fmt.Sprintf("unknown message type: %d", msg.Type))
		}

		// routage (dans le cas des réponses) : il y a actuellemnt un pipe qui attend cette réponse
		if shouldRoute {

			// je prend le verrou sur la map de pipe
			me.PendingLock.Lock()
			// je regarde s'il existe bien un pipe qui attend cette réponse
			respChan, exists := me.PendingRequests[routingKey]

			// si OUI
			if exists {

				select {

				// on essaye d'écrire la donnée dans le pipe
				case respChan <- dataContent:

				// sinon, on delete le pipe
				default:
				}

				// on nettoie notre map de pipe car l'ID est unique
				delete(me.PendingRequests, routingKey)
			}
			// on lache le verrou
			me.PendingLock.Unlock()
		}
	}
}

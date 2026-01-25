package p2p

import (
	"crypto/ecdh"
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
func Verbose_log(format string, a ...interface{}) {
	if Verbose {
		LogMsg(format+"\n", a...)
	}
}

// fonction utilitaire pour afficher HH:MM:SS au début de chaque print
func LogMsg(format string, a ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf(timestamp+" "+format, a...)
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
	// Des informations nécessaires pour le timeout
	LastSeen  time.Time
	PublicKey *ecdsa.PublicKey

	// Des informations nécessaires pour le handshake Diffie Hellman
	// La clé AES calculée
	SharedKey []byte

	// La clé privée temporaire pour cet échange
	EphemeralPriv *ecdh.PrivateKey // Ma clé privée temporaire pour cet échange

	// Pour savoir si le handshake est fini
	IsEncrypted bool
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

		// on transforme les octets recus en struct Message
		msg, err := Deserialize(buffer[:n])
		if err != nil {
			fmt.Println("Erreur de désérialisation :", err)
			continue
		}
		if msg.Type != TypeDatum {
			Verbose_log("[DEBUG] Received : type: %s, id: %d, addr: %s", msg__type__to__string(msg.Type), msg.Id, addr)
		}

		// on agit différement selon le Type de message
		switch msg.Type {

		////////////////
		// REQUETES
		////////////////

		case TypePing:
			me.Handle__ping(msg, addr)

		case TypeHello:
			me.Handle__hellos(msg, addr)

		case TypeRootRequest:
			me.Handle__RootRequest(msg, addr)

		case TypeDatumRequest:
			me.Handle__DatumRequest(msg, addr)

		case TypeNatTraversalRequest2:
			me.Handle__NatTraversalRequest2(msg, addr)

		case TypeNatTraversalRequest:
			me.Handle__NatTraversalRequest(msg, addr)

		/////////////
		// REPONSES
		/////////////

		case Error:
			me.Handle__error(msg, addr)

		case TypeHelloReply:
			me.Handle__hellos(msg, addr)

		case TypeOk:
			me.Handle__Ok(msg, addr)

		case TypeRootReply:
			me.Handle__RootReply(msg, addr)

		case TypeNoDatum:
			me.Handle__NoDatum(msg, addr)

		case TypeDatum:
			me.Handle__Datum(msg, addr)

		case TypeKeyExchange:
			me.Handle__KeyExchange(msg, addr)

		// mauvais type
		default:
			fmt.Printf("type de message non géré : %d\n", msg.Type)
			me.Handle__if__error(msg, addr, fmt.Sprintf("unknown message type: %d", msg.Type))
		}
	}
}

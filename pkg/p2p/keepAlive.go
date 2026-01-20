package p2p

import (
	"fmt"
	"net"
	"project/pkg/identity"
	"time"
)

func (me *Me) Start__maintenance__loop() {
	// On vérifie toutes les 30 secondes
	ticker := time.NewTicker(1 * time.Minute)
	// Le timer s'arrêtera lorsque la maintenance_loop s'éteindra
	defer ticker.Stop()

	for range ticker.C {
		me.Mutex.Lock()

		// boolean
		ping_server := false

		sAddr, err := net.ResolveUDPAddr("udp", me.ServerUDPAddr)
		if err == nil {
			// s'il existe deja une session avec le serveur alors il faut le prendre en compte dans les keep alive
			if _, exists := me.Sessions[sAddr.String()]; exists {
				ping_server = true
			}
		}

		now := time.Now()

		for addr, session := range me.Sessions {
			diff := now.Sub(session.LastSeen)

			// Après 5 minutes : expiration
			if diff > 5*time.Minute {
				fmt.Printf("Timeout : Session expirée avec %s (inactif depuis %s)", addr, diff)
				delete(me.Sessions, addr)
				continue
			}

			// Après 3 minutes : keepalive
			if diff > 3*time.Minute {
				Verbose_log("Keep-alive : Envoi Ping automatique à %s", addr)
				// On lance le ping via la fonction "send__ping" dans une goroutine pour ne pas bloquer le mutex
				go me.Send__ping(addr)
			}
		}
		me.Mutex.Unlock()

		if ping_server {
			Verbose_log("Keep-alive : Envoi Hello au serveur")
			go me.Send__hello(me.ServerUDPAddr)
		}
	}
}

// fonction qui retourne la liste des peers avec qui je suis actullement en contact
func (me *Me) List__active__peers() []string {

	// je prends le verrou sur la map de mes connexions
	me.Mutex.Lock()

	// on le lacherais à la fin de la fonction
	defer me.Mutex.Unlock()

	// on prepare un tableau
	var activeList []string

	for addr, session := range me.Sessions {

		key := "no key"

		if session.PublicKey != nil {

			pubBytes := identity.PublicKey__to__bytes(session.PublicKey)

			key = fmt.Sprintf("clef publique (signatures) %x...", pubBytes[:32])
		}

		encryptionStatus := ""
		if session.IsEncrypted {
			encryptionStatus = "Chiffrement via échange de clef DH"
		}

		entry := fmt.Sprintf("- %-25s : %-25s + %s", addr, key, encryptionStatus)
		activeList = append(activeList, entry)
	}

	return activeList
}

package p2p

import (
	"fmt"
	"time"
)

// Met à jour l'heure de dernier contact avec une adresse
func (me *Me) Update__last__seen(addrStr string) {
	me.Mutex.Lock()
	defer me.Mutex.Unlock()

	if session, exists := me.Sessions[addrStr]; exists {
		session.LastSeen = time.Now()
	} else {
		// Nouvelle session, on l'ajoute
		me.Sessions[addrStr] = &PeerSession{
			LastSeen: time.Now(),
		}
	}
}

func (me *Me) Start__maintenance__loop() {
	// On vérifie toutes les 30 secondes
	ticker := time.NewTicker(30 * time.Second)
	// Le timer s'arrêtera lorsque la maintenance_loop s'éteindra
	defer ticker.Stop()

	for range ticker.C {
		// On envoie un keepalive au serveur ttes les 30 secondes car il assure également le maintien du NAT
		Log("Keep-alive : Envoi Hello au serveur central.")
		me.Send__hello(me.ServerUDPAddr)

		me.Mutex.Lock()
		now := time.Now()

		for addr, session := range me.Sessions {
			diff := now.Sub(session.LastSeen)

			// Après 5 minutes : expiration
			if diff > 5*time.Minute {
				fmt.Printf("Timeout : Session expirée avec %s (inactif depuis %s)\n", addr, diff)
				delete(me.Sessions, addr)
				continue
			}

			// Après 4 minutes : keepalive
			if diff > 4*time.Minute {
				Log("Keep-alive : Envoi Ping automatique à %s\n", addr)
				// On lance le ping via la fonction "send__ping" dans une goroutine pour ne pas bloquer le mutex
				go me.Send__ping(addr)
			}
		}
		me.Mutex.Unlock()
	}
}

// fonction qui retourne la liste des peers avec qui je suis actullement en contact
func (me *Me) List__active__peers() []string {

	// je prends le verrou sur la map de mes connexions
	me.Mutex.Lock()

	// je le lacherais à la fin de la fonction
	defer me.Mutex.Unlock()

	// je prepare un tableau
	var activeList []string

	// on parcout la map
	for addr := range me.Sessions {
		activeList = append(activeList, addr)
	}

	return activeList
}

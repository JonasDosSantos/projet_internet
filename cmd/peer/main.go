package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"time"

	"project/pkg/client"
	"project/pkg/filesystem"
	"project/pkg/identity"
	"project/pkg/p2p"
)

func main() {
	// --- 1. CONFIGURATION (ARGUMENTS & CONSTANTES) ---
	serverURL := "https://jch.irif.fr:8443"
	// Adresse UDP du serveur pour l'enregistrement (IP du sujet)
	serverUDPAddr := "81.194.30.229:8443"

	// Drapeaux (flags)
	namePtr := flag.String("name", "peer-test", "Nom unique du peer")
	portPtr := flag.Int("port", 8080, "Port UDP d'écoute")
	sharePtr := flag.String("share", "", "Chemin du fichier ou dossier à partager")
	connectPtr := flag.String("connect", "", "Adresse IP:Port d'un autre peer à contacter")

	flag.Parse()

	myPeerName := *namePtr
	myUDPPort := *portPtr

	fmt.Printf("\n=== LANCEMENT DU PEER '%s' SUR LE PORT %d ===\n", myPeerName, myUDPPort)

	// --- 2. IDENTITÉ (CLÉ PERSISTANTE UNIQUEMENT) ---
	fmt.Println("[1/6] Chargement de l'identité...")

	var privateKey *ecdsa.PrivateKey

	// A. Chargement de la clé (PEM)
	loadedKey, err := identity.LoadIdentity()

	if err == nil {
		fmt.Println(" -> Clé privée chargée (identity.pem).")
		privateKey = loadedKey
	} else {
		fmt.Println(" -> Aucune clé trouvée. Génération...")
		privateKey, err = identity.KeyGen()
		if err != nil {
			log.Fatal("Erreur génération clé : ", err)
		}

		// Sauvegarde immédiate
		if err := identity.SaveIdentity(privateKey); err != nil {
			fmt.Printf("ATTENTION : Echec sauvegarde clé : %v\n", err)
		} else {
			fmt.Println(" -> Nouvelle clé sauvegardée.")
		}
	}

	// Calcul de la clé publique pour la suite
	pubKeyBytes := identity.PublicKey__to__bytes(&privateKey.PublicKey)

	// --- 3. DIAGNOSTICS SERVEUR ---
	fmt.Println("[2/6] Diagnostics connexion Serveur REST...")

	// A. Enregistrement
	fmt.Print(" -> Tentative d'enregistrement... ")
	err = client.Register(serverURL, myPeerName, pubKeyBytes)
	if err != nil {
		fmt.Printf("Warning (%v) - On continue.\n", err)
	} else {
		fmt.Println("Succès.")
	}

	// B. Liste des peers
	fmt.Print(" -> Récupération de la liste des peers... ")
	peers, err := client.Get__peer__list(serverURL)
	if err != nil {
		fmt.Printf("Erreur (%v)\n", err)
	} else {
		fmt.Printf("%d peers trouvés.\n", len(peers))
	}

	// C. Vérification clé du serveur
	fmt.Print(" -> Récupération clé serveur (jch.irif.fr)... ")
	_, err = client.Get__publicKey(serverURL, "jch.irif.fr")
	if err != nil {
		fmt.Printf("Erreur (%v)\n", err)
	} else {
		fmt.Println("OK.")
	}

	// --- 4. DÉMARRAGE DU MOTEUR P2P (UDP) ---
	fmt.Println("[3/6] Démarrage du serveur UDP...")
	me, err := p2p.New__communication(myUDPPort, privateKey, myPeerName, serverURL)
	if err != nil {
		log.Fatal("Erreur critique (UDP) : ", err)
	}

	// --- 5. CHARGEMENT DES FICHIERS (SI MODE PARTAGE) ---
	if *sharePtr != "" {
		fmt.Printf("[4/6] Mode 'Seeder' activé. Traitement de : %s\n", *sharePtr)
		nodes, err := filesystem.Build__merkle__from__path(*sharePtr)
		if err != nil {
			log.Fatal("Erreur Merkle : ", err)
		}
		me.Load__file__system(nodes)
		fmt.Printf(" -> Fichier chargé. RootHash: %x\n", me.RootHash)
	} else {
		fmt.Println("[4/6] Mode 'Leecher' (pas de fichiers partagés).")
	}

	// --- 6. LANCEMENT DE L'ÉCOUTE ---
	go me.Listen__loop()
	fmt.Println(" -> Listen__loop active.")

	// --- 7. ACTIONS RÉSEAU ---
	fmt.Println("[5/6] Initialisation des contacts...")

	// ACTION A : Enregistrement IP auprès du serveur (Hole Punching)
	fmt.Printf(" -> Envoi Hello au serveur (%s) pour enregistrer l'IP...\n", serverUDPAddr)
	err = me.Send__hello(serverUDPAddr)
	if err != nil {
		fmt.Printf("    Erreur envoi serveur: %v\n", err)
	}

	// ACTION B : Connexion P2P ciblée (Si argument --connect fourni)
	if *connectPtr != "" {
		targetAddr := *connectPtr
		fmt.Printf("\n--- SCÉNARIO DE TÉLÉCHARGEMENT VERS %s ---\n", targetAddr)

		// 1. Handshake
		fmt.Print(" 1. Envoi du HELLO au pair... ")
		err = me.Send__hello(targetAddr)
		if err != nil {
			fmt.Printf("ERREUR: %v\n", err)
		} else {
			fmt.Println("OK.")
		}

		// Attente pour traversée NAT
		time.Sleep(1 * time.Second)

		// 2. Request Root
		fmt.Print(" 2. Envoi du ROOT REQUEST... ")
		err = me.Send__RootRequest(targetAddr)
		if err != nil {
			fmt.Printf("ERREUR: %v\n", err)
		} else {
			fmt.Println("OK.")
		}

		// 3. Attente active de la réponse (RootHash)
		fmt.Println(" ⏳ Attente de la réception du RootHash...")

		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		rootReceived := false

		for {
			select {
			case <-timeout:
				fmt.Println(" ❌ Timeout : Le RootHash n'a pas été reçu après 5 secondes.")
				goto FinScenario
			case <-ticker.C:
				if me.RootHash != [32]byte{} {
					rootReceived = true
					goto Suite
				}
			}
		}

	Suite:
		if rootReceived {
			fmt.Printf(" ✅ Racine reçue : %x\n", me.RootHash)

			// 4. Téléchargement des données (remplit la Database)
			fmt.Println("\n--- DÉBUT DU TÉLÉCHARGEMENT DE L'ARBRE ---")
			me.Download_tree(targetAddr, me.RootHash)

			// 5. Affichage de l'arbre reconstruit
			fmt.Println("\n--- ARBORESCENCE RECONSTRUITE (DEPUIS DATABASE) ---")
			fmt.Println("---------------------------------------------------")

			// 6. Écriture physique sur le disque (NOUVEAU)
			fmt.Println("\n--- ÉCRITURE SUR LE DISQUE ---")
			outputDir := "./downloads" // Tu peux changer le dossier ici
			fmt.Printf(" -> Création des fichiers dans '%s'...\n", outputDir)

			err := me.Rebuild__file__system(me.RootHash, outputDir)
			if err != nil {
				fmt.Printf("❌ Erreur lors de la reconstruction : %v\n", err)
			} else {
				fmt.Println("✅ SUCCÈS ! Système de fichiers reconstruit.")
			}
		}

	FinScenario:
	} else {
		fmt.Println("\n[INFO] Pas de cible P2P spécifiée. Le peer attend les connexions.")
	}

	// --- MAINTIEN EN VIE ---
	fmt.Println("\n===================================================")
	fmt.Println("  Le peer est actif. CTRL+C pour quitter.")
	fmt.Println("===================================================")
	select {}
}

package main

import (
	"fmt"
	"log"
	"project/pkg/client"
	"project/pkg/identity"
	"project/pkg/p2p"
)

func main() {
	// --- CONFIGURATION ---
	serverURL := "https://jch.irif.fr:8443"
	serverUDPAddr := "81.194.30.229:8443"
	myPeerName := "test1" // Utilise un nouveau nom pour éviter l'erreur 500
	myUDPPort := 1234

	fmt.Println("=== INITIALISATION DU PEER ===")

	// --- ÉTAPE 1 : GÉNÉRATION DE L'IDENTITÉ ---
	fmt.Println("1. Génération de la clé ECDSA...")
	privateKey, err := identity.KeyGen()
	if err != nil {
		log.Fatal("Erreur lors de la génération de clé : ", err)
	}
	pubKeyBytes := identity.PublicKeyToBytes(&privateKey.PublicKey)

	// --- ÉTAPE 2 : ENREGISTREMENT HTTP ---
	fmt.Printf("2. Enregistrement de '%s' sur le serveur REST...\n", myPeerName)
	err = client.Register(serverURL, myPeerName, pubKeyBytes)
	if err != nil {
		fmt.Printf("Erreur d'enregistrement HTTP : %v\n", err)
	} else {
		fmt.Println("Enregistrement HTTP réussi (Code 204).")
	}

	// --- NOUVELLE ÉTAPE : RÉCUPÉRATION DES INFOS DU RÉSEAU ---
	fmt.Println("\n--- INTERROGATION DU SERVEUR REST ---")

	// 1. Récupérer la liste des peers
	peers, err := client.GetPeerList(serverURL)
	if err != nil {
		fmt.Printf("Erreur GetPeerList : %v\n", err)
	} else {
		fmt.Printf("Liste des peers récupérée (%d peers trouvés) :\n", len(peers))
		
		// BOUCLE À RAJOUTER :
		for _, name := range peers {
			if name != "" { // On évite d'afficher les lignes vides
				fmt.Printf("  -> %s\n", name)
			}
		}
	}

	// 2. Récupérer la clé publique de jch.irif.fr
	serverPeerName := "jch.irif.fr"
	fmt.Printf("Récupération de la clé pour '%s'...\n", serverPeerName)
	serverKey, err := client.GetPublicKey(serverURL, serverPeerName)
	if err != nil {
		fmt.Printf("Erreur GetPublicKey : %v\n", err)
	} else {
		fmt.Printf("Clé de %s récupérée (%d octets).\n", serverPeerName, len(serverKey))
	}

	// 3. Récupérer les adresses UDP de jch.irif.fr
	fmt.Printf("Récupération des adresses UDP pour '%s'...\n", serverPeerName)
	addrs, err := client.GetPeerAddresses(serverURL, serverPeerName)
	if err != nil {
		fmt.Printf("Erreur GetPeerAddresses : %v\n", err)
	} else {
		fmt.Printf("Adresses de %s : %v\n", serverPeerName, addrs)
	}
	fmt.Println("-------------------------------------\n")

	// --- ÉTAPE 3 : DÉMARRAGE DU SERVEUR UDP ---
	fmt.Printf("3. Ouverture du port UDP %d...\n", myUDPPort)
	me, err := p2p.NewCommunication(myUDPPort, privateKey, myPeerName, serverURL)
	if err != nil {
		log.Fatal("Erreur lors de l'ouverture du port UDP : ", err)
	}

	go me.ListenLoop()

	// --- ÉTAPE 4 : CONTACT UDP INITIAL ---
	fmt.Printf("4. Envoi du message Hello à %s...\n", serverUDPAddr)
	err = me.SendHello(serverUDPAddr)
	if err != nil {
		fmt.Printf("Erreur lors de l'envoi du Hello UDP : %v\n", err)
	} else {
		fmt.Println("Hello UDP envoyé !")
	}

	// --- ÉTAPE 5 : MAINTIEN EN VIE ---
	fmt.Println("\n============================================")
	fmt.Println("Le peer est actif et écoute le réseau.")
	fmt.Println("Appuyez sur 'Entrée' pour fermer le programme.")
	fmt.Println("============================================")

	var input string
	fmt.Scanln(&input)
	fmt.Println("Fermeture du peer.")
}
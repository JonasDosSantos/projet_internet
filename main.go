package main

import (
	"bufio"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"project/pkg/client"
	"project/pkg/filesystem"
	"project/pkg/identity"
	"project/pkg/p2p"
)

func main() {

	// gestion du mode bavard
	verbosePtr := flag.Bool("b", false, "activer le mode bavard")
	flag.Parse()

	// on active le mode bavard si demandé par -b
	p2p.Verbose = *verbosePtr
	if p2p.Verbose {
		fmt.Println("Verbose mode activated")
	}

	/////////////
	// USER INFO
	/////////////

	// URL du serveur
	serverURL := "https://jch.irif.fr:8443"

	// on crée un scnanner qui va lire tout ce que l'user tape dans le terminal
	scanner := bufio.NewScanner(os.Stdin)

	// on demande le nom
	fmt.Print("\n entrez votre nom (default: 'bob') : ")

	// on attend que la touche entree soit pressée
	scanner.Scan()

	// on récupère juste le nom (on enlève les espaces)
	my_name := strings.TrimSpace(scanner.Text())

	// gestion de la valeur par défautl
	if my_name == "" {
		my_name = "bob"
	}

	// on demande le port UDP que veut utiliser l'user
	fmt.Print(" entrez votre port UDP (default: 8082) : ")
	scanner.Scan()

	// on enleve les espaces
	portStr := strings.TrimSpace(scanner.Text())

	// par defaut 8082
	my_UDP_port := 8082

	// on lit ce que l'user a écrit
	// si non vide
	if portStr != "" {

		// conversion en int
		portInt, err := strconv.Atoi(portStr)

		// si ca marche on utilise cet entier comme port
		if err == nil {
			my_UDP_port = portInt
		} else {
			fmt.Println("port invalide. usage du port par dedfaut (8082)")
		}
	}

	// on demande si l'user veut partager un dossier (il peut le faire plus tard aussi)
	fmt.Print(" entrez le nom du dossier à partager (default : rien): ")
	scanner.Scan()
	sharePath := strings.TrimSpace(scanner.Text())

	/////////////
	// IDENTITE
	/////////////

	// on prépare une variable pour notre clef privée
	var my_privKey *ecdsa.PrivateKey
	var err error

	// on essaie de charger une clef depuis le fichier identity.pem
	my_privKey, err = identity.Load_Identity()

	// si erreur
	if err != nil {
		// alors on génère une nouvelle clef privée
		my_privKey, _ = identity.KeyGen()

		// et on l'écrit dans le fichier pour la prochaine connexion
		identity.Save__Identity(my_privKey)
	}

	// on dérive notre clef privée pour générer une clef publique
	pubKey, err := identity.Extract__PubKey(my_privKey)
	if err != nil {
		log.Fatalf("erreur extraction clef publique : %v", err)
	}

	// on convertit notre clef publique en bytes pour l'envoi sur le réseau
	pubKeyBytes := identity.PublicKey__to__bytes(pubKey)

	// On commence une nouvelle communication
	me, err := p2p.New__communication(my_UDP_port, my_privKey, my_name, serverURL)
	if err != nil {
		// si on échoue on arrête tout
		log.Fatalf("erreur à l'ouverture de la communication UDP (est-ce que le numéro de port est utilisable ?): %v", err)
	}

	// on charge le dossier voulu
	if sharePath != "" {

		// on construit l'arbre de merkle de notre dossier
		merkle_tree, err := filesystem.Build__merkle__from__path(sharePath)

		// s'il n'y a pas d'erreurs
		if err == nil {
			// alors on charge le tout dans notre DataBase
			me.Load__file__system(merkle_tree)
		} else {
			p2p.LogMsg("erreur chargement du dossier voulu : %v\n", err)
		}
	}

	// on lance la boucle d'écoute sur notre port UDP
	// on utilise une autre routine pour ne pas rester bloquer ici
	go me.Listen__loop()

	////////////////////////////////////////////////////////////////
	// DEBUT DE LA BOUCLE INTERACTIVE ENTRE L'USER ET LE PROGRMAME
	////////////////////////////////////////////////////////////////

	fmt.Println("\nPour commencer, il faut se register auprès du serveur.")
	fmt.Println("Pour être reconnu par le serveur comme un pair, il faut envoyer un 'Hello' à son peer.")
	fmt.Println("Pour connaître la liste des commandes disponibles, taper 'help'.")

	// boucle infinie
	for {
		// UI
		fmt.Print("\n >>>> ")

		// on attend que l'user écrive
		if !scanner.Scan() {
			// si le scanner renvoie FALSE c'est que l'user à CTRL+D
			break
		}

		// on récupère ce que l'user à écrit
		line := scanner.Text()

		// on récupère les mots écrits (on sépare par les espaces)
		words := strings.Fields(line)

		// s'il n'y a rien, on continue (recommence la boucle for)
		if len(words) == 0 {
			continue
		}

		// le premier mot est la commande
		cmd := words[0]

		// les mots suivants sont ls arguments
		args := words[1:]

		// on fait un switch/case sur la cmd
		switch cmd {

		case "help":
			printHelp()

		case "info":
			fmt.Printf("MES INFOS: \n")
			fmt.Printf("Nom : %s\n", my_name)
			myAddr, err := find__name__from__addr(my_name, serverURL)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
				continue
			}
			fmt.Printf("Adresse : %s\n", myAddr)
			if me.RootHash == [32]byte{} {
				fmt.Println("RootHash : no roothash")
			} else {
				fmt.Printf("RootHash : %x\n", me.RootHash)
			}

		case "register":
			err = client.Register(serverURL, my_name, pubKeyBytes)
			if err != nil {
				p2p.LogMsg("erreur Register (%v)\n", err)
			} else {
				p2p.LogMsg("enregistrement (HTTP) auprès du serveur réussi")
			}

		case "active":
			// on recupere la liste des pairs actifs
			active_list := me.List__active__peers()

			if len(active_list) == 0 {
				p2p.LogMsg("aucune session active\n")
			} else {
				p2p.LogMsg("Seessions actives: \n")

				for i := 0; i < len(active_list); i++ {
					fmt.Printf("- %s\n", active_list[i])
				}
			}

		case "peers":
			// appel au serveur pour demander la liste de pair qu'il a
			list, err := client.Get__peer__list(serverURL)
			if err != nil {
				p2p.LogMsg("Erreur get__peer_list :", err)
			} else {
				p2p.LogMsg("peers dans l'annuaire du serveur: \n")
				for i := 0; i < len(list); i++ {
					p := list[i]
					fmt.Printf("- %s\n", p)
				}
			}

		case "key":
			if len(args) < 1 {
				fmt.Println("usage: key <nom_du_peer>")
				continue
			}
			peerName := args[0]

			// appel au serveur pour obtenir la clef publique d'un pair
			key, err := client.Get__publicKey(serverURL, peerName)
			if err != nil {
				p2p.LogMsg(" erreur get_pubKey: %v\n", err)
			} else {
				p2p.LogMsg("clef publique de %s :\n%x\n", peerName, key)
			}

		case "addr":
			if len(args) < 1 {
				fmt.Println("usage: addr <nom_du_peer>")
				continue
			}
			peerName := args[0]

			// appel au serveur poir obtenir les adresses d'un pair
			addrs, err := client.Get__peer__adresses(serverURL, peerName)
			if err != nil {
				p2p.LogMsg(" erreur get__peer__adresses : %v\n", err)
			} else {
				p2p.LogMsg(" adresses de %s :\n", peerName)

				for i := 0; i < len(addrs); i++ {
					addr := addrs[i]
					fmt.Printf(" - %s\n", addr)
				}
			}

		case "hello":
			if len(args) < 1 {
				fmt.Println("usage: hello <ip:port>")
				continue
			}

			destAddr, err := find__name__from__addr(args[0], serverURL)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
				continue
			}

			p2p.LogMsg("envoi d'un hello à %s\n", destAddr)
			// on appelle notre fonction dédiée
			me.Send__hello(destAddr)

		case "ping":
			if len(args) < 1 {
				fmt.Println("usage: ping <ip:port>")
				continue
			}

			destAddr, err := find__name__from__addr(args[0], serverURL)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
				continue
			}

			p2p.LogMsg("envoi d'un ping à %s\n", destAddr)

			// on appelle notre fonction dédiée
			me.Send__ping(destAddr)

		case "root":
			if len(args) < 1 {
				fmt.Println("usage: root <ip:port>")
				continue
			}

			destAddr, err := find__name__from__addr(args[0], serverURL)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
				continue
			}

			p2p.LogMsg("RootRequest envoyé à %s ", destAddr)

			// on utilise notre fonction dédiée
			me.Send__RootRequest(destAddr)

		case "load":
			if len(args) < 1 {
				fmt.Println("usage: load <chemin_du_dossier>")
				continue
			}
			// Oon retire les espaces
			path := strings.Join(args, " ")

			// on construit l'arbre de merkle de notre dossier
			merkle_tree, err := filesystem.Build__merkle__from__path(path)

			// s'il n'y a pas d'erreurs
			if err == nil {
				// alors on charge le tout dans notre DataBase
				me.Load__file__system(merkle_tree)
			} else {
				fmt.Printf("erreur chargement du dossier voulu : %v\n", err)
			}

		case "download":
			if len(args) < 1 {
				fmt.Println("usage: download <ip:port> [path_file]")
				continue
			}

			destAddr, err := find__name__from__addr(args[0], serverURL)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
				continue
			}

			targetPath := ""
			if len(args) > 1 {
				targetPath = args[1]
			}

			rootBytes, err := me.Send__RootRequest(destAddr)
			if err != nil {
				fmt.Printf("Impossible de récupérer la racine de %s : %v\n", destAddr, err)
				continue
			}

			var rootHash [32]byte
			copy(rootHash[:], rootBytes)
			var targetHash [32]byte

			if targetPath == "" {
				targetHash = rootHash
			} else {
				foundHash, err := me.Get__hash__from__path(destAddr, rootHash, targetPath)
				if err != nil {
					fmt.Printf("Erreur : %v\n", err)
					continue
				}
				targetHash = foundHash
			}

			// on lance un chrono
			start := time.Now()

			// on appelle notre fonction de téléchargement
			me.Download_tree(destAddr, targetHash)

			var outName string
			if targetPath != "" {
				outName = filepath.Base(targetPath)
			} else {
				outName = fmt.Sprintf("root_%x", targetHash[:4])
			}

			// on écrit le dossier téléchargé en local
			outDir := filepath.Join("downloads", outName)

			// on reconstruit ce qui est dans la RAM actuellement
			err = me.Rebuild__file__system(targetHash, outDir)
			if err != nil {
				fmt.Printf("erreur téléchargement, erreur %v:\n", err)
				continue
			}

			p2p.LogMsg("téléchargement terminé en %v.\n", time.Since(start))

		case "nattraversal":
			if len(args) < 1 {
				fmt.Println("usage: nattraversal <ip:port_cible> [ip:port_intermediaire, default=server]")
				continue
			}

			targetAddr, err := find__name__from__addr(args[0], serverURL)
			if err != nil {
				fmt.Printf("Erreur : %v\n", err)
				continue
			}

			// par defaut, l'intermediaire est le serveur
			relayAddr := me.ServerUDPAddr

			// on utilise celui fourni par l'user (s'il en fourni un)
			if len(args) >= 2 {
				relayAddr = args[1]
			}

			// appel à notre fonction
			err = me.Send__NatTraversalRequest(targetAddr, relayAddr)
			if err != nil {
				fmt.Printf(" errer demande NatTraversal : %v\n", err)
			}

		case "print":
			destAddr := ""

			if len(args) > 0 {
				destAddr, err = find__name__from__addr(args[0], serverURL)
				if err != nil {
					fmt.Printf("Erreur : %v\n", err)
					continue
				}
			}

			go me.Print__Tree(destAddr)

		case "exit":
			p2p.LogMsg("fin du peer\n")
			return

		default:
			fmt.Println("Commande inconnue. Tapez 'help'.")
		}
	}
}

// affiche la fonction d'aide
func printHelp() {
	fmt.Println("\nCOMMANDES DISPONIBLES:")
	fmt.Println(" info                  	: mes informations")
	fmt.Println(" register              	: enregistrement (HTTP) auprès du serveur")
	fmt.Println(" active                	: lister les pairs actifs")
	fmt.Println(" peers                 	: liste les pairs reconnus par le serveur")
	fmt.Println(" key <nom>             	: obtenir la clef d'un peer")
	fmt.Println(" addr <nom>            	: obtenir les adresses IP d'un peer")
	fmt.Println(" load <path>           	: charge un fichier local dans le peer (pour le proposer aux autres peers)")
	fmt.Println(" hello <addr>          	: envoyer un hello")
	fmt.Println(" ping <addr>           	: envoyer un ping")
	fmt.Println(" root <addr>           	: demander le RootHash")
	fmt.Println(" download <addr> [file]	: télécharger les données d'un peer (default = whole tree)")
	fmt.Println(" print [addr] 				: affiche l'arbre d'un pair (default: local)")
	fmt.Println(" nattraversal <cible> [intermediaire]  	: demander à un intermediaire d'aider (default = server)")
	fmt.Println(" exit                  	: quitter")
}

// fonction qui transforme un nom en adresse (ou adresse en adresse)
func find__name__from__addr(input string, serverURL string) (string, error) {

	// si l'entree contient ":" c'est une adresse (on le suppose)
	if strings.Contains(input, ":") {
		return input, nil
	}

	// on suppose alors que c'est un nom
	addrs, err := client.Get__peer__adresses(serverURL, input)
	if err != nil {
		return "", fmt.Errorf("impossible de trouver lee peer '%s' : %v", input, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("aucune adresse trouvée pour le peer '%s'", input)
	}

	for _, addr := range addrs {
		// lees addr ipv4 n'ont qu'1 seeul ':'
		if strings.Count(addr, ":") == 1 {
			return addr, nil
		}
	}

	// sinon on renvoie ce qu'on trouve (càd une ipv6)
	return addrs[0], nil
}

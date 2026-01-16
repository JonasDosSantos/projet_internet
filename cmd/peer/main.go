package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
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
		fmt.Println("mode bavard activé")
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
			LogMsg("erreur chargement du dossier voulu : %v\n", err)
		}
	}

	// on lance la boucle d'écoute sur notre port UDP
	// on utilise une autre routine pour ne pas rester bloquer ici
	go me.Listen__loop()

	////////////////////////////////////////////////////////////////
	// DEBUT DE LA BOUCLE INTERACTIVE ENTRE L'USER ET LE PROGRMAME
	////////////////////////////////////////////////////////////////

	// on print la liste des commandes dispos
	printHelp()

	fmt.Println("\nPour commencer, il faut se regsiter auprès du serveur.")
	fmt.Println("Pour être reconnu par le serveur comme un pair, il faut envoyer un 'Hello' à son peer.")

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
			fmt.Printf("Port : %d\n", my_UDP_port)
			if me.RootHash == [32]byte{} {
				fmt.Println("RootHash : no roothash")
			} else {
				fmt.Printf("RootHash : %x\n", me.RootHash)
			}

		case "register":
			err = client.Register(serverURL, my_name, pubKeyBytes)
			if err != nil {
				LogMsg("erreur Register (%v)\n", err)
			} else {
				LogMsg("enregistrement (HTTP) auprès du serveur réussi")
			}

		case "active":
			// on recupere la liste des pairs actifs
			active_list := me.List__active__peers()

			if len(active_list) == 0 {
				LogMsg("aucune session active\n")
			} else {
				LogMsg("Seessions actives: \n")

				for i := 0; i < len(active_list); i++ {
					fmt.Printf("- %s\n", active_list[i])
				}
			}

		case "peers":
			// appel au serveur pour demander la liste de pair qu'il a
			list, err := client.Get__peer__list(serverURL)
			if err != nil {
				LogMsg("Erreur get__peer_list :", err)
			} else {
				LogMsg("peers dans l'annuaire du serveur: \n")
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
				LogMsg(" erreur get_pubKey: %v\n", err)
			} else {
				LogMsg("clef publique de %s :\n%x\n", peerName, key)
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
				LogMsg(" erreur get__peer__adresses : %v\n", err)
			} else {
				LogMsg(" adresses de %s :\n", peerName)

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
			LogMsg("envoi d'un hello à %s\n", args[0])
			// on appelle notre fonction dédiée
			me.Send__hello(args[0])

		case "ping":
			if len(args) < 1 {
				fmt.Println("usage: ping <ip:port>")
				continue
			}

			LogMsg("envoi d'un ping à %s\n", args[0])

			// on appelle notre fonction dédiée
			me.Send__ping(args[0])

		case "root":
			if len(args) < 1 {
				fmt.Println("usage: root <ip:port>")
				continue
			}
			LogMsg("RootRequest envoyé à %s ", args[0])

			// on utilise notre fonction dédiée
			me.Send__RootRequest(args[0])

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
			if len(args) < 2 {
				fmt.Println("usage: download <ip:port> <root_hash_hex>")
				continue
			}
			// la destination est le premier argument
			addr_dest := args[0]

			// le hash est le second argument, on appelle notre fonction dessus pour vérifier sa conformité (et le transformer en chaine d'octets)
			hashBytes, err := parse__hash(args[1])
			if err != nil {
				fmt.Println("hash invalide :", err)
				continue
			}

			// on lance un chrono
			start := time.Now()

			// on appelle notre fonction de téléchargement
			me.Download_tree(addr_dest, hashBytes)

			// on écrit le dossier téléchargé en local
			outDir := "./downloads"
			err = me.Rebuild__file__system(hashBytes, outDir)
			if err != nil {
				fmt.Println("erreur téléchargement")
				continue
			}

			LogMsg("téléchargement terminée en %v.\n", time.Since(start))

		case "nattraversal":
			if len(args) < 1 {
				fmt.Println("usage: nattraversal <ip:port_cible> [ip:port_intermediaire, default=server]")
				continue
			}

			// la cible est l'arg 0
			targetAddr := args[0]

			// par defaut, l'intermediaire est le serveur
			relayAddr := me.ServerUDPAddr

			// on utilise celui fourni par l'user (s'il en fourni un)
			if len(args) >= 2 {
				relayAddr = args[1]
			}

			// appel à notre fonction
			err := me.Send__NatTraversalRequest(targetAddr, relayAddr)

			if err != nil {
				fmt.Printf(" errer demande NatTraversal : %v\n", err)
			}

		case "exit":
			LogMsg("fin du peer")
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
	fmt.Println(" download <addr> <hash>	: télécharger les données associées au hash fourni")
	fmt.Println(" nattraversal <cible> [intermediaaire]  	: demander au un intermediaire d'aider à contacter une cible derriere un NAT")
	fmt.Println(" exit                  	: quitter")
}

// fonction pour convertir une chaine de caractère (hexadecimale) en octets
// utilse car les hash sont écrit en hexadecimal dans le terminal et il faut les "traduire" en octets pour les utilisr
func parse__hash(hexStr string) ([32]byte, error) {

	//on prépare notre tableau d'octets
	hash := [32]byte{}

	// on convertit la chaine d'hexa en octets
	b, err := hex.DecodeString(hexStr)

	// s'il y a une erreur, on return
	if err != nil {
		return hash, err
	}

	// verification de la taille
	if len(b) != 32 {
		return hash, fmt.Errorf("taille incorrecte (%d)", len(b))
	}

	// on copie dans notre variable puis return
	copy(hash[:], b)
	return hash, nil
}

// fonction utilitaire pour afficher HH:MM:SS au début de chaque print
func LogMsg(format string, a ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf(timestamp+" "+format, a...)
}

package p2p

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"project/pkg/filesystem"
	"strings"
	"sync"
)

// fonction pour charger un fichier ou dossier local dans notre Database (pour le proposer aux autres pairs)
func (me *Me) Load__file__system(nodes []filesystem.Node) {

	// on prends le mutex sur la Database
	me.DbLock.Lock()

	// on le lache lorsque la fonction termine
	defer me.DbLock.Unlock()

	me.Database = make(map[[32]byte][]byte)

	// On remplit la map pour un accès rapide (O(1)) lors des requêtes
	for _, node := range nodes {
		me.Database[node.Hash] = node.Data
	}

	// la racine est le dernier noeud de l'arbre, je l'enregistre dans la variable correspondante de Me
	if len(nodes) > 0 {
		me.RootHash = nodes[len(nodes)-1].Hash
		fmt.Printf("\nsystème de fichiers chargé. RootHash = %x\n", me.RootHash)
	}
}

// fonction utile pour transformer un path en un hash pour ensuite télécharger seulement 1 fichier d'un arbre d'un pair
func (me *Me) Get__hash__from__path(destAddr string, rootHash [32]byte, pathStr string) ([32]byte, error) {

	pathStr = strings.Trim(pathStr, "/")

	if pathStr == "" {
		return rootHash, nil
	}

	// on découpe à chaque "/"
	parts := strings.Split(pathStr, "/")

	currentHash := rootHash

	for _, nextHash := range parts {

		// on cherche le hash suivant dans le dossier courant
		nextHash, found, err := me.find__hash__in__dir(destAddr, currentHash, nextHash)

		if err != nil {
			return [32]byte{}, fmt.Errorf("erreur réseau/lecture sur %s : %v", nextHash, err)
		}

		if !found {
			return [32]byte{}, fmt.Errorf("'%s' introuvable dans le dossier parent", nextHash)
		}

		currentHash = nextHash
	}

	return currentHash, nil
}

// fonction qui cherche un nom dans un dossier Directory et renvoie le hash associé
func (me *Me) find__hash__in__dir(destAddr string, dirHash [32]byte, nameToFind string) ([32]byte, bool, error) {

	// on récupère le contenu du noeud
	data, err := me.ensureDatum(dirHash, destAddr)
	if err != nil {
		return [32]byte{}, false, err
	}

	nodeType := data[0]

	switch nodeType {

	case 1: // TypeDirectory
		entriesData := data[1:]
		count := len(entriesData) / 64

		for i := 0; i < count; i++ {
			// on extrait le nom
			nameBytes := entriesData[i*64 : i*64+32]
			name := string(bytes.Trim(nameBytes, "\x00"))

			// si c'est le bon nom
			if name == nameToFind {
				var foundHash [32]byte
				copy(foundHash[:], entriesData[i*64+32:(i+1)*64])
				return foundHash, true, nil
			}
		}

	case 3: // TypeBigDirectory
		hashesData := data[1:]
		count := len(hashesData) / 32

		for i := 0; i < count; i++ {
			var nextDirectory [32]byte
			copy(nextDirectory[:], hashesData[i*32:(i+1)*32])

			// Appel récursif : on cherche le nom dans ce sous-bloc
			foundHash, found, err := me.find__hash__in__dir(destAddr, nextDirectory, nameToFind)

			if err != nil {
				return [32]byte{}, false, err
			}
			if found {
				return foundHash, true, nil
			}
		}

	default:
		return [32]byte{}, false, fmt.Errorf("le chemin traverse un fichier qui n'est pas un dossier (Type %d)", nodeType)
	}

	return [32]byte{}, false, nil
}

// fonction appelée pour "télécharger" l'arbre d'un pair dans notre DataBase
func (me *Me) Download_tree(destAddr string, rootHash [32]byte) {

	// on initialise un waitgroup
	// un WaitGroup est comme un sem_barrier (il attends que tout le monde ait finit pour lacher)
	var wg sync.WaitGroup

	// on cree la semaphore qui va reguler notre trafic (c'est le pipe dont on parlait plus haut)
	semaphore := make(chan struct{}, 24)

	// on incremente le WaitGroup de 1 (sinon il est déjà "fini")
	wg.Add(1)

	// on appelle notre fonction de téléchargement
	me.Download_recursively(destAddr, rootHash, &wg, semaphore)

	// on attends que notre WaitGroup termine
	wg.Wait()
}

func (me *Me) Download_recursively(destAddr string, hash [32]byte, wg *sync.WaitGroup, semaphore chan struct{}) {
	// on lache le WaitGroup à la fin de la fonction
	defer wg.Done()

	// on vérifie si on a pas déjà ce fichier
	// on prends le verrou sur la database pour gérer la concurrence
	me.DbLock.Lock()
	_, have := me.Database[hash]
	me.DbLock.Unlock()

	// si on l'a, on finit
	if have {
		return
	}

	// on prend 1 "ticket" pour notre semaphore, si c'est plein, on attend
	semaphore <- struct{}{}

	// on rend le "ticket" à la fin de la fonction
	defer func() { <-semaphore }()

	// on demande les data sur le hash voulu
	receivedData, err := me.Send__DatumRequest(destAddr, hash)

	if err != nil {
		fmt.Printf("echec récupération data du hash %x : %v\n", hash[:5], err)
		return
	}

	// Si le channel a été fermé (par Handle__NoDatum), on reçoit une donnée vide.
	// On arrête le traitement pour ce noeud.
	if len(receivedData) == 0 {
		fmt.Printf("Abandon branche (NoDatum) pour le hash %x\n", hash[:4])
		return
	}

	// on prends le verrou sur la Database et on y écrit les data
	me.DbLock.Lock()
	me.Database[hash] = receivedData
	me.DbLock.Unlock()

	// analyse du noeud reçu

	// recupération du type
	nodeType := receivedData[0]

	// switch/case sur le type
	switch nodeType {

	// si c'est un Directory
	case filesystem.TypeDirectory:

		// on coupe le type
		entriesData := receivedData[1:]

		// on va parcourir les entrees du dossier
		count := len(entriesData) / 64

		for i := 0; i < count; i++ {
			// on copie chaque hash des enfants
			var childHash [32]byte
			copy(childHash[:], entriesData[i*64+32:(i+1)*64])

			// on va lancer récursivement un télechargement sur cet enfant donc on incremente notre WaitGroup
			wg.Add(1)

			// on appelle notre fonction de telechargement
			go me.Download_recursively(destAddr, childHash, wg, semaphore)
		}

	// si c'est un BigNode ou un BigDirectory (meme principe)
	case filesystem.TypeBig, filesystem.TypeBigDirectory:

		// on coupe le type
		hashesData := receivedData[1:]

		// on va parcourir les enfants
		count := len(hashesData) / 32

		for i := 0; i < count; i++ {
			// on copie chaque hash des enfants
			var childHash [32]byte
			copy(childHash[:], hashesData[i*32:(i+1)*32])

			// on va lancer récursivement un télechargement sur cet enfant donc on incremente notre WaitGroup
			wg.Add(1)

			// on appelle notre fonction de telechargement
			go me.Download_recursively(destAddr, childHash, wg, semaphore)
		}
	}
}

// fonction qui reconstruit tout un système de fichier à partir de notre Database
// cette fonction ne crée que l'architecture du file system et délègue le reste (écriture des chunks) à un autre fonction
// nodeHash est le noeud qu'on traite actuellement
// currentPath est le lieu où on se trouve dans l'arborescence
func (me *Me) Rebuild__file__system(nodeHash [32]byte, currentPath string) error {

	// on prend un verrou sur la DB pour copier les data du node souhaité
	me.DbLock.Lock()
	data, exists := me.Database[nodeHash]
	me.DbLock.Unlock()

	// si le neoud n'existe pas
	if !exists {
		return fmt.Errorf("noeud manquant dans la base de données : %x", nodeHash[:4])
	}

	// on récupère le type du noeud
	nodeType := data[0]

	// switch/case sur le type
	switch nodeType {

	// SI c'est un Directory
	case filesystem.TypeDirectory:

		// on crée le dossier sur le disque en local
		if err := os.MkdirAll(currentPath, 0755); err != nil {
			return fmt.Errorf("erreur création dossier %s: %v", currentPath, err)
		}

		// lecture de toutes les entrées : [Nom (32o)] + [Hash (32o)]

		// on coupe le type
		entriesData := data[1:]

		// on parcourt toutes les entrées
		entrySize := 64
		count := len(entriesData) / entrySize

		for i := 0; i < count; i++ {
			start := i * entrySize

			// suppréssion du padding sur le nom
			nameBytes := entriesData[start : start+32]
			name := string(bytes.Trim(nameBytes, "\x00"))

			// on récupère le hash
			var childHash [32]byte
			copy(childHash[:], entriesData[start+32:start+64])

			// on concaténe le nom de l'enfant a la fin du filepath
			childPath := filepath.Join(currentPath, name)

			// appel récursif pour continuer à construire
			if err := me.Rebuild__file__system(childHash, childPath); err != nil {
				return err
			}
		}

	// Si c'est un BigDirectory
	case filesystem.TypeBigDirectory:

		// on coupe le type
		hashesData := data[1:]

		// on va parcourir les entrees
		count := len(hashesData) / 32

		for i := 0; i < count; i++ {
			// on récupère le hash de l'enfant
			var childHash [32]byte
			copy(childHash[:], hashesData[i*32:(i+1)*32])

			// appel récursif sans changer le path car on ne s'est pas "déplacer" dans l'arborescence
			if err := me.Rebuild__file__system(childHash, currentPath); err != nil {
				return err
			}
		}

	// si c'est un fichier (chunk ou BigNode, même logique)
	case filesystem.TypeChunk, filesystem.TypeBig:

		// on crée le fichier en local (ou on l'écrase)
		file, err := os.Create(currentPath)
		if err != nil {
			return fmt.Errorf("erreur création fichier %s: %v", currentPath, err)
		}
		defer file.Close()

		// on appelle notre fonction dédiée au remplissage des fichiers
		if err := me.rebuild__file__content(nodeHash, file); err != nil {
			return err
		}

	default:
		return fmt.Errorf("type de noeud inconnu : %d", nodeType)
	}

	return nil
}

// fonction pour remplir les fichiers (appelée par Rebuild__file__system)
func (me *Me) rebuild__file__content(hash [32]byte, file *os.File) error {

	// on prend le verrou sur la DB
	me.DbLock.Lock()
	data, exists := me.Database[hash]
	me.DbLock.Unlock()

	// si le chunk qu'on cherche n'existe pas (peu de chance d'arriver au vu de notre implémentation)
	if !exists {
		return fmt.Errorf("chunk manquant : %x", hash[:4])
	}

	// on récupère le type du node (soit chunk soit BigNode)
	nodeType := data[0]

	// si c'est un chunk
	switch nodeType {

	// si on est sur une feuille
	case filesystem.TypeChunk:
		// on écrit tout sauf le premier octet (le type)
		_, err := file.Write(data[1:])
		return err

	// si c'est un BigNode
	case filesystem.TypeBig:

		// on coupe le type
		hashesData := data[1:]

		// on va parcourir tout les enfants
		count := len(hashesData) / 32

		for i := 0; i < count; i++ {
			// on récupère le hash de l'enfant
			var childHash [32]byte
			copy(childHash[:], hashesData[i*32:(i+1)*32])

			// appel récursif pour continuer à écrire à la suite
			if err := me.rebuild__file__content(childHash, file); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("type de noeud inconnu (pas forcément inconnu mais problématique) : %d", nodeType)
	}

	return nil
}

// fonctions pour print un arbre

// fonction mère pour print un arbre (le sien ou celui d'un pair)
func (me *Me) Print__Tree(targetAddr string) {

	var currentRootHash [32]byte

	// pour print notre propore systeme de fichier
	if targetAddr == "" {

		// On vérifie que la DB n'est pas vide
		if len(me.Database) == 0 {
			fmt.Println("La Database est vide, il faut load un dossier avant d'utiliser printTree")
			return
		}
		currentRootHash = me.RootHash

	} else {

		// on demande le roothash au pair spécifié
		hashBytes, err := me.Send__RootRequest(targetAddr)
		if err != nil {
			fmt.Printf("Erreur : Impossible de contacter %s : %v\n", targetAddr, err)
			return
		}

		copy(currentRootHash[:], hashBytes)
	}

	me.recursive__print__tree(currentRootHash, "", targetAddr)
}

// fonction "fille" pour print le systeme de fichier
func (me *Me) recursive__print__tree(nodeHash [32]byte, prefix string, targetAddr string) {

	// on utilise notre fonction qui récupère les data d'un noeud (auprès d'un pair ou dans notre propre DB)
	data, err := me.ensureDatum(nodeHash, targetAddr)

	if err != nil {
		if targetAddr == "" {
			fmt.Printf("%s manquant en local, on arrête\n", prefix)
		} else {
			fmt.Printf("%s manquant, on arrête\n", prefix)
		}
		return
	}

	nodeType := data[0]

	switch nodeType {

	case 1: // TypeDirectory
		entriesData := data[1:]
		entrySize := 64
		count := len(entriesData) / entrySize

		for i := 0; i < count; i++ {
			start := i * entrySize

			nameBytes := entriesData[start : start+32]
			name := string(bytes.Trim(nameBytes, "\x00"))

			var childHash [32]byte
			copy(childHash[:], entriesData[start+32:start+64])

			// on récupère les data sur l'enfant i
			childData, err := me.ensureDatum(childHash, targetAddr)

			if err != nil {
				fmt.Printf("erreur récupération de %s|%s, on arrête \n", prefix, name)
				return
			}

			childType := childData[0]

			// si l'enfant un DIrectory ou un BigDirectory, on continue récursivement
			if childType == 1 || childType == 3 {
				fmt.Printf("%s├── %s/\n", prefix, name)
				me.recursive__print__tree(childHash, prefix+"│   ", targetAddr)
			} else {
				// si c'est un fichieer, on met juste son nom.
				// on a atteint une feuille de l'arbre (ou un BigNode qui est en quelques sorte une feuille) donc on arrête
				fmt.Printf("%s├── %s\n", prefix, name)
			}
		}

	case 3: // TypeBigDirectory
		hashesData := data[1:]
		hashSize := 32
		count := len(hashesData) / hashSize

		for i := 0; i < count; i++ {
			var childHash [32]byte
			copy(childHash[:], hashesData[i*hashSize:(i+1)*hashSize])

			me.recursive__print__tree(childHash, prefix, targetAddr)
		}
	}
}

// fonction qui récupère les data d'un noeud qu'il soit en local ou pas (que ce soit notre propre systeme de fichier ou celui d'un peer)
func (me *Me) ensureDatum(hash [32]byte, targetAddr string) ([]byte, error) {

	// on vérifie si on l'a pas déjà localement
	me.DbLock.Lock()
	data, exists := me.Database[hash]
	me.DbLock.Unlock()

	if exists {
		return data, nil
	}

	// si on ne l'a pas

	// si on est en mode printTree local, c'est une erreur
	if targetAddr == "" {
		return nil, fmt.Errorf("donnée manquante localement")
	}

	// sinon, on demande la data au peer
	askedData, err := me.Send__DatumRequest(targetAddr, hash)
	if err != nil {
		return nil, err
	}

	return askedData, nil
}

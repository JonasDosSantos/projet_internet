package filesystem

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	TypeChunk = 0
	TypeDirectory = 1
	TypeBig = 2
	TypeBigDirectory = 3
)

// definition d'une structure qui représente 1 noeud de l'arbre de Merkle. C'est ce qui sera envoyé entre pairs
type Node struct {
	Hash [32]byte
	Data []byte
}
// Noeud de type 0 (chunk) ressemble à : Hash || 0x00 || Data
// noeud de type 1 (dir) ressemble à : Hash || 0x01 || NomEntree1 || HashEntree1 || ... || NomEntree16 || HashEntree16
// noeud de type 2 (bigNode) ressemble à : Hash || 0x02 || HashEnfant1 || HashEnfant2 || ... || HashEnfant32
// noeud de type 3 (bigDir) ressemble à : Hash || 0x03 || HashEnfant1 || HashEnfant2 || ... || HashEnfant32

// structure intermédiaire définie pour aider à la construction d'un arbre de Merkle
type DirEntry struct {
	Name string
	Hash [32]byte
}

// la fonction principale, prends en argument un chemin vers un fichier ou dossier et construit tout l'arbre de merkle associé
func Build__merkle__from__path(path string) ([]Node, error) {

	// on recupere les infos sur le path donné en paramètre
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// si ce n'est pas un repertoire (c'est un fichier), on appelle build__merkle__from__file
	if !info.IsDir() {
		return build__merkle__from__file(path)
	}

	// si c'est un repertoire, on va le "déplier" récursivement
	// on lit les entrées de ce répertoire
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	// liste qui contient tous les noeuds qu'on trouvera, c'est notre arbre mais représenté en forme de liste
	var allNodes []Node

	// liste qui contiendra le contenu d'un directory lorsque je suis en train de le traiter
	var currentDirEntries []DirEntry

	// boucle sur les entrees du dossier originel (on a déjà vérifier que path correspondait à un directory et pas un file)
	for i := 0; i < len(entries); i++ {

		// on s'occupe de l'entree i
		entry := entries[i]
		
		// le chemin complet de cette entree est path||entry
		newPath := filepath.Join(path, entry.Name())
		
		// appel récursif à build__merkle__from__path
		childNodes, err := Build__merkle__from__path(newPath)
		if err != nil {
			return nil, err
		}

		// on ajoute la sortie à la liste de tous les neouds
		allNodes = append(allNodes, childNodes...)

		// on récupère la racine de l'enfant
		childRoot := childNodes[len(childNodes)-1]

		// ajout à la liste représentant le dossier en cours de traitement
		currentDirEntries = append(currentDirEntries, DirEntry{Name: entry.Name(), Hash: childRoot.Hash,})
	}

	// a ce stade, on a traité toutes les entrées de "path". Tous les neouds de l'arbre représentant path sont dans la liste allNodes

	// on applique maintenant la fonction build__merkle__from__directory à cette liste pour construire tous les noeuds de type 1 (dir) et 3 (bigDir) nécessaires
	dirNodes, err := build__merkle__from__directory(currentDirEntries)
	if err != nil {
		return nil, err
	}

	// on ajoute les noeuds crées à la liste allNodes, notre arbre est terminé !
	allNodes = append(allNodes, dirNodes...)
	return allNodes, nil
}

// fonction qui transforme un fichier local en arbre de merkle (représenté en liste)
func build__merkle__from__file(filePath string) ([]Node, error) {

	// ouverture d'un fichier avec la bibliothèque os
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// liste de tous les noeuds qu'on créera
	var allNodes []Node

	// liste des hash à chaque "niveau" de l'arbre
	var currentLevelHashes [][32]byte

	// buffer de 1023 octets pour les data (c'est le maximum imposé par le sujet). On limite à 1023 octets car il faut prendre en compte 1 octets pour le type de noeud, du moins, on a compris le sujet comme ça
	buffer := make([]byte, 1024)
	for {
		// on lit le fichier dans notre buffer
		n, err := file.Read(buffer)
		
		// si on a lu quelque chose:
		if n > 0 {

			// création d'un noeud et copie des données dedans + ajout du type
			nodeData := make([]byte, 1+n)
			nodeData[0] = TypeChunk
			copy(nodeData[1:], buffer[:n])

			hash := sha256.Sum256(nodeData)

			// ajout du noeud à la liste et ajout du hash à la liste
			allNodes = append(allNodes, Node{Hash: hash, Data: nodeData})
			currentLevelHashes = append(currentLevelHashes, hash)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	// si fichier vide
	if len(allNodes) == 0 {
		emptyData := []byte{TypeChunk}
		hash := sha256.Sum256(emptyData)
		return []Node{{Hash: hash, Data: emptyData}}, nil
	}

	// on créee les étages supérieurs avec une autre fonction
	upperNodes := build__upper__layers(currentLevelHashes, TypeBig)
	allNodes = append(allNodes, upperNodes...)

	return allNodes, nil
}

// fonction qui construit l'arbre de merkle associé à un directory
// prends en paramètre la liste des entrées d'un directory
func build__merkle__from__directory(entries []DirEntry) ([]Node, error) {

	// liste qui contient tous les noeuds de ce directory 
	var allNodes []Node

	// liste des hash à chaque "niveau" de l'arbre
	var currentLevelHashes [][32]byte

	// on découpe les entrées en paquets de 16 (consigne du sujet)
	for start := 0; start < len(entries); start += 16 {

		// verification que "end" ne depasse pas 
		end := start + 16
		if end > len(entries) {
			end = len(entries)
		}

		// le paquet d'entrée qu'on traite actuellement est entre start et end (meme logique que dans build__upper__layers).
		entry_group := entries[start:end]

		// on utilise notre fonction pour construire les noeuds de type1 (dir)
		node, err := build__node__from__directory(entry_group)
		if err != nil {
			return nil, err
		}

		// on ajoute ce noeud à la liste
		allNodes = append(allNodes, node)
	
		// on ajoute le hash de ce noeud à la liste des hash à ce niveau (feuilles)
		currentLevelHashes = append(currentLevelHashes, node.Hash)
	}

	// si dossier vide
	if len(allNodes) == 0 {
		node, _ := build__node__from__directory([]DirEntry{})
		return []Node{node}, nil
	}

	// meme logique que pour build__merkle__from_file
	// on a pour le moment construit que les feuilles, on appelle build__upper_layers pour construire les étages de l'arbre (jusqu'à la racine)
	upperNodes := build__upper__layers(currentLevelHashes, TypeBigDirectory)

	// on ajoute les étages à la liste de tout nos noeuds
	allNodes = append(allNodes, upperNodes...)

	return allNodes, nil
}


func build__node__from__directory(entries []DirEntry) (Node, error) {
	// voir exemple ligne 23 de ce fichier
	// le champ contient 1 octet de type puis 64 octets par entrees (32 pour le nom + 32 pour le hash)
	size := 1 + len(entries)*64
	
	// on crée le champ data du noeud
	data := make([]byte, size)
	data[0] = TypeDirectory

	// boucle sur chaque entree
	for i := 0; i < len(entries); i++ {
        
        // on s'occupe de l'entree i
        entry := entries[i]

        // calcul de l'offset
        offset := 1 + i*64
        
        // verifications de la taille du nom, on a décidé de retourner une erreur si celui-ci est trop long (on aurait pu couper)
        if len(entry.Name) > 32 {
            return Node{}, fmt.Errorf("nom de fichier trop long : %s", entry.Name)
        }

		// par défaut, data à été initialisé avec 32 0x00 donc il n'y a pas besoin de padder si le nom est inférieur à 32 octets

        // ecriture du nom au bon endroit (offsett)
        copy(data[offset:], []byte(entry.Name))
        
        // ecriture du hash associé à la suite
        copy(data[offset+32:], entry.Hash[:])
    }

	// on calcule le hash de ce noeud
	hash := sha256.Sum256(data)

	// on renvoie le noeud ainsi crée
	return Node{Hash: hash, Data: data}, nil
}


// fonction appelée par build__merkle__from__file et build__merkle__from__directory pour construire les arbres de merkle
// ces 2 fonctions ne crée que les feuilles de chaque arbre, la fonction qui suit s'occupe des créer les étages supérieurs (jusqu'à la racine)
// cette fonction prends en paramètre une liste de hashes (les feuilles) et le type de noeud à traiter (chunks ou dir)
func build__upper__layers(hashes [][32]byte, nodeType byte) []Node {

	// c'est l'arbre qu'on renverra (c'est une liste)
	var allNodes []Node

	// on va itérer par "niveau" de l'arbre, on commence donc par les feuilles
	currentLevel := hashes

	// tant qu'il n'y a pas qu'1 seul noeud au current level (on serait dans ce cas à la racine), on continue
	for len(currentLevel) > 1 {

		// liste des noeuds de l'étage supérieur, on va remplir cette liste puis faire la même opération dessus
		var nextLevel [][32]byte

		// on boucle par paquet de 32 hash (contrainte imposée par le sujet, que ce soit pour les BigNodes ou les BigDir)
		for start := 0; start < len(currentLevel); start += 32 {
			// les hash qu'on traite à cette étape de la boucle sont ceux entre start et end
			end := start + 32

			// si end est + grand que le nombre de hash à cet étage, on "coupe" ce qui est en trop
			if end > len(currentLevel) {
				end = len(currentLevel)
			}

			// à cette itération, les enfants sont donc les hash entre start et end
			children := currentLevel[start:end]

			// création de la liste "data" du noeud parent (contient la concaténation des hash des enfants)
			data := make([]byte, 1+len(children)*32)

			// le type du parent dépend du type de fichier sur lequel on travaille (c'est en paramètre de la fonction)
			data[0] = nodeType
			
			// boucle pour copier le hash de chaque enfant
			offset := 1
			for i := 0; i < len(children); i++ {
				
				h := children[i]

				// on colle le hash à la fin (concaténation)
				copy(data[offset:], h[:])

				// on deplace l'offset
				offset += 32
			}

			// on calcule le hash du noeud qu'on vient de créer
			hash := sha256.Sum256(data)
			
			// on crée le noeud parent avec les valeurs hash et data qu'on vient de calculer
			node := Node{Hash: hash, Data: data}
			
			// on ajoute ce parent à la liste de tout nos noeuds
			allNodes = append(allNodes, node)

			// on ajoute ce parent à la liste les neouds de l'étage supérieur
			nextLevel = append(nextLevel, hash)
		}
		// lorsqu'on a fini un étage, on passe au supérieur

		currentLevel = nextLevel
	}

	return allNodes
}
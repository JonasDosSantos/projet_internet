package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// fonction pour s'enregistrer auprès du serveur
func Register(serverURL string, name string, key []byte) error {

	// on construit l'URL à laquelle on enverra la requête
	url := fmt.Sprintf("%s/peers/%s/key", serverURL, name)

	// on prépare la requête PUT
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(key))
	if err != nil {
		return err
	}

	// on crée un client http (connexion TCP), on va surement continuer à communiquer avec le serveur donc mieux vaut n'avoir qu'une connexion
	client := &http.Client{}

	// on execute la requête
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// on vérifie que la reponse est bien 204 : StatusNoContent (et pourquoi pas 200 : StatusOK)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("impossible de s'enregister, erreur serveur: code %d", resp.StatusCode)
	}

	return nil
}

// fonction pour obtenir une liste de 200 peers auprès du serveur
func Get__peer__list(serverURL string) ([]string, error) {

	// on construit l'URL à laquelle on enverra la requête
	url := fmt.Sprintf("%s/peers/", serverURL)

	// on execute la requête
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// on lit toute la réponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// le serveur renvoie une liste de peers avec 1 peer par ligne, on découpe donc le body à chaque "\n" et on met le tout dans une liste
	list := strings.Split(string(body), "\n")

	// on envoie la dite liste
	return list, nil
}

// focntion pour obtenir la clef privée d'un certain peer (paramètre peerName)
func Get__publicKey(serverURL string, peerName string) ([]byte, error) {

	// on construit l'URL
	url := fmt.Sprintf("%s/peers/%s/key", serverURL, peerName)

	// on execute la requête
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// on vérifie que la réponse du serveur est 200 : StatusOK
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("impossible de trouver la clef de %s : code %d", peerName, resp.StatusCode)
	}

	// le body de cette réponse contient la clef publique voulue
	key, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// on vérifie la taille
	if len(key) != 64 {
		return nil, fmt.Errorf("clef reçue non valide")
	}

	return key, nil
}

// fonction pour obtenir les adresses UDP d'un peer
func Get__peer__adresses(serverURL string, peerName string) ([]string, error) {

	// on construit l'URL
	url := fmt.Sprintf("%s/peers/%s/addresses", serverURL, peerName)

	// on execute la requête
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// on vérifie que la réponse est 200: StatusOK
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("impossible de trouver les adresses pour %s", peerName)
	}

	// on lit tout le body, il y a 1 adresse par ligne
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	//on découpe le body à chaque "\n" et on met le tout dans une liste
	addresses := strings.Split(string(body), "\n")

	return addresses, nil
}

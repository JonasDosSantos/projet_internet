package identity

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const my_file = "identity.pem"

// fonction qui sauvegarde notre clef privee dans un fichier local (pour aider à la connexion ultérieurement)
func SaveIdentity(key *ecdsa.PrivateKey) error {
	
	// on construit le fichier
	file, err := os.Create(my_file)
	if err != nil {
		return fmt.Errorf("création fichier impossible: %v", err)
	}
	defer file.Close()

	// écriture de la clef à la suite. on a choisi le format PEM en se basant sur:
	// https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go
	x509Encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	}

	return pem.Encode(file, pemBlock)
}

// fonction "inverse", on lit le contenu du fichier
func LoadIdentity() (*ecdsa.PrivateKey, error) {
	
	// on lit le fichier
	body, err := os.ReadFile(my_file)
	if err != nil {
		return nil, err
	}

	// on récupère le bloc avec la clef
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("fichier sans clef")
	}

	// on en extrait la clef
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// fonction de génération de key de la bibliotheque crypto
func KeyGen() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// fonction pour extraire une clef publique depuis une clef privée
func Extract__PubKey(priv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {

	publicKey, ok := priv.Public().(*ecdsa.PublicKey)

	if !ok {
		return nil, fmt.Errorf("impossible d'extraire la clé publique")
	}

	return publicKey, nil
}

// PASSAGE DE (CLEF CRYPTOGRAPHIQUE) A (CHAINE D'OCTETS) ET INVERSEMENT
// en crypto on manipule des clefs mais pour faciliter les échanges il nous faut pouvoir transformer ces clefs en octets

// transforme une clef en une chaine d'octets.
func PublicKey__to__bytes(pub *ecdsa.PublicKey) []byte {

	// on creer une notre chaine d'octets de longueur 64
	formatted := make([]byte, 64)

	// on remplit notre chaine d'octets avec les coordonnées des points X et Y de la clef publique
	pub.X.FillBytes(formatted[:32])
	pub.Y.FillBytes(formatted[32:])

	return formatted
}

// transforme une chaine d'octets en clef
func Bytes__to__PublicKey(data []byte) (*ecdsa.PublicKey, error) {
	// erreur si mauvaise taille de chaine d'octets
	if len(data) != 64 {
		return nil, fmt.Errorf("la clé doit comporter exactement 64 octets")
	}

	// recuperation des coordonnees de X et Y
	var x, y big.Int
	x.SetBytes(data[:32])
	y.SetBytes(data[32:])

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: &x, Y: &y}, nil
}

// FONCTION DE SIGNATURE ET VERIFICATION

// fonction qui signe des data et renvoie la signature
func Sign(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	// on hash des la data
	hashed := sha256.Sum256(data)

	// on appelle la fonction de signature de la bibliotheque pour obtenir le couple (r,s) = signature
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		return nil, err
	}

	// on met les 64 octets de signature dans une chaien d'octets de taille 64
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, nil
}

// fonction qui prend des data et une sigature et qui verifie si la signature est correcte
func Verify__signature(pub *ecdsa.PublicKey, data []byte, signature []byte) bool {

	// erreur si mauvaise taille de signature
	if len(signature) != 64 {
		return false
	}

	// on récupère les valeurs de r et s reçues
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	// on recalcule la signature pour pouvoir vérifier
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(pub, hashed[:], &r, &s)
}

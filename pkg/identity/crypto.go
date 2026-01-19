package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
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

////////////////////////////////////////////
/// FONCTIONS RELATIVES A LA CONFIDENTIALITE
////////////////////////////////////////////

/// ECHANGE DE CLE : DIFFIE-HELLMAN

// GENERATION DE CLE EPHEMERE (X25519)
// Renvoie la clé privée (à garder en mémoire le temps du handshake) et la publique (à envoyer)
func Generate_Ephemeral_Key() (*ecdh.PrivateKey, []byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := priv.PublicKey().Bytes()
	return priv, pubKey, nil
}

// CALCUL DU SECRET PARTAGÉ
// Prend ma clé privée et la clé publique reçue (en bytes) pour sortir la clé AES (hashée)
func Compute_Shared_Secret(myPrivKey *ecdh.PrivateKey, receivedPubBytes []byte) ([]byte, error) {
	// On utilise la courbe X25519 recommandée pour la sécurité par le NIST : RFC 7748
	curve := ecdh.X25519()

	// On transforme les bytes reçus en clé publique utilisable
	receivedPubKey, err := curve.NewPublicKey(receivedPubBytes)
	if err != nil {
		return nil, fmt.Errorf("clé publique distante invalide: %v", err)
	}

	// On utilise la fonction fournie par crypto/ecdh pour calcuelr le secret partagé à partir de notre clé privée,
	// et de la clé publique temporaire du peer avec lequel on communique
	secret, err := myPrivKey.ECDH(receivedPubKey)
	if err != nil {
		return nil, fmt.Errorf("echec calcul ECDH: %v", err)
	}

	// On hash le secret pour avoir une clé AES propre de 32 octets
	hash := sha256.Sum256(secret)
	return hash[:], nil
}

// CHIFFREMENT (AES-GCM)
// AES-GCM est le standard de chiffrement symétrique suggéré par le NIST (cf NIST SP 800-38D, 2007)
// On utilise donc le pacakge aes fourni par go crypto/aes
func Encrypt_AES(key []byte, plaintext []byte) ([]byte, error) {
	// Création du bloc AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// On utilise le mode GCM (Galois/Counter Mode) pour la confidentialité et l'intégrité
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Création d'un Nonce (Number used ONCE) aléatoire afin d'éviter les attaques par répétition
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Chiffrement : Le résultat contient [Nonce + Ciphertext + Tag]
	// rappel de la signature de la fonction : Seal(dst, nonce, plaintext, additionalData)
	// Cette fonction chiffre le plaintext avec nonce, et l'append à la dst, puis append additionalData.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DECHIFFREMENT (AES-GCM)
// On suit la logique du chiffrement pour déchiffrer
func Decrypt_AES(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext trop court")
	}

	// On sépare le nonce du reste
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Déchiffrement et vérification du tag d'intégrité
	plaintext, err := aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("echec déchiffrement (mauvaise clé ou message altéré): %v", err)
	}

	return plaintext, nil
}

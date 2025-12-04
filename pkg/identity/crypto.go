package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// GenerateKey crée une nouvelle paire de clés ECDSA P-256.
// Voir PDF Annexe A.1
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EncodePublicKey transforme une clé publique en tableau de 64 octets (32 pour X, 32 pour Y).
// Voir PDF Annexe A.1
func EncodePublicKey(pub *ecdsa.PublicKey) []byte {
	formatted := make([]byte, 64)
	// FillBytes est plus sûr que Bytes() car il garantit le padding à 32 octets
	pub.X.FillBytes(formatted[:32])
	pub.Y.FillBytes(formatted[32:])
	return formatted
}

// DecodePublicKey reconstruit une clé publique à partir de 64 octets.
// Voir PDF Annexe A.1
func DecodePublicKey(data []byte) *ecdsa.PublicKey {
	if len(data) != 64 {
		return nil
	}
	var x, y big.Int
	x.SetBytes(data[:32])
	y.SetBytes(data[32:])

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
}

// Sign hache les données (SHA-256) et génère une signature (R, S) de 64 octets.
// Voir PDF Annexe A.1
func Sign(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		return nil, err
	}

	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, nil
}

// Verify vérifie si une signature (64 octets) correspond aux données et à la clé publique.
// Voir PDF Annexe A.1
func Verify(pub *ecdsa.PublicKey, data []byte, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}

	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	hashed := sha256.Sum256(data)
	// ecdsa.Verify prend les pointeurs de r et s
	return ecdsa.Verify(pub, hashed[:], &r, &s)
}

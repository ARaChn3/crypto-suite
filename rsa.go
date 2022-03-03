package crsuite

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
    "crypto/sha256"
)
// RSAEncrypt encrypts plaintext using the RSA (Rivest–Shamir–Adleman)
// encryption algorithm.
func RSAEncrypt(plaintext []byte, keySize int) (ciphertext []byte, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, err error) {
    privateKey, err = GenerateKeyPairs(keySize)
	if err != nil {
		return
	}

	publicKey = &(privateKey.PublicKey)
	ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)

	return
}

// RSADecrypt decrypts ciphertext using privateKey and returns the plaintext
// thus obtained.
func RSADecrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
    return privateKey.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
}

// GenerateKeyPairs generates private and public keys for RSA encryption.
// the returned type: *rsa.PrivateKey contains the public key under the field
// named: PublicKey
func GenerateKeyPairs(bits int) (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

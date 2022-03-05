package crsuite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// just some random bytes, 128bits.
var bytes []byte = make([]byte, 16)

// to check if the bytes have been initialised.
var checkIfInit bool = false

// InitAESBytes initialises the bytes used for encryption in AES encryption.
func InitAESBytes() {
	var err error
	_, err = rand.Read(bytes)
	if err != nil {
		panic(err)
	}

	checkIfInit = true
}

// AESEcnrypt encrypts plaintext using the AES encryption algorithm.
func AESEcnrypt(plaintext []byte, secret []byte) ([]byte, error) {
	if !checkIfInit {
		panic("Error in Encryption, use InitAESBytes to initialise the bytes first")
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, bytes)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	return Base64Encrypt(ciphertext), nil
}

// AESDecrypt decrypts ciphertext using the key: secret and returns the
// plaintext thus obtained.
func AESDecrypt(ciphertext []byte, secret []byte) ([]byte, error) {
	if !checkIfInit {
		panic("Error in Decryption, use InitAESBytes to initialise the bytes first")
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	decoded, err := Base64Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBDecrypter(block, bytes)
	plaintext := make([]byte, len(decoded))
	cfb.XORKeyStream(plaintext, decoded)

	return plaintext, nil
}

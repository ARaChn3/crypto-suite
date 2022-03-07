package crsuite

import (
	"crypto/rsa"
	cr "github.com/ARaChn3/crypto-suite"
	"testing"
)

func TestRSAOperations(t *testing.T) {
	var ciphertext []byte
	var encErr error
	var plaintext = "Hello World!"
	var privateKey *rsa.PrivateKey

	t.Log("Testing RSAEncrypt...")
	ciphertext, _, privateKey, encErr = cr.RSAEncrypt([]byte(plaintext), 2048)
	if encErr != nil {
		t.Errorf("Error while encrypting: %v\n", encErr)
	}

	t.Log("Testing RSADecrypt...")
	test, decErr := cr.RSADecrypt(ciphertext, privateKey)
	if decErr != nil {
		t.Errorf("Error while decrypting: %v\n", decErr)
	}

	if string(test) != plaintext {
		t.Errorf("Incorrect decryption.\n\"%s\" should be equal to \"%s\"", test, plaintext)
	}
}

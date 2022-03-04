package crsuite

import (
	"encoding/base64"
)

/*
Base64 data encoding is specified in RFC 4648

Reference: https://datatracker.ietf.org/doc/html/rfc4648
*/

// Base64Encrypt performs base64 encoding on plaintext and returns it
func Base64Encrypt(plaintext []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(plaintext))
}

// Base64Decrypt decodes a base64 encoded string and returns result.
func Base64Decrypt(ciphertext []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(ciphertext))
	return []byte(decoded), err
}

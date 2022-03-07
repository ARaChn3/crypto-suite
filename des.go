package crsuite

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
)

// DESEncrypt performs DES encryption on plaintext using key and iv, and returns
// the ciphertext.
func DESEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {

	block, blkErr := des.NewCipher(key)
	if blkErr != nil {
		return nil, blkErr
	}

	blockSize := block.BlockSize()
	originalData := PKCS5Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(originalData))
	blockMode.CryptBlocks(ciphertext, originalData)
	return ciphertext, nil
}

// DESDecrypt performs DES decryption on ciphertext using key and iv, and
// returns the decrypted plaintext thus obtained.
func DESDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	originalData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(originalData, ciphertext)
	originalData = PKCS5UnPadding(originalData)
	return originalData, nil
}

// PKCS5Padding adds padding to src using the PKCS5 padding schema described in
// RFC 2898.
//
// Reference: https://www.ietf.org/rfc/rfc2898.txt
func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS5Padding removes padding from src according to the PKCS5 padding schema
// described in RFC 2898.
//
// Reference: https://www.ietf.org/rfc/rfc2898.txt
func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

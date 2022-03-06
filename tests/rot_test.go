package crsuite

import (
    cr "github.com/ARaChn3/crypto-suite"
    "testing"
)

func TestROTEncrypt(t *testing.T) {
    plaintext := "Hello World!"
    rot13Check := "Uryyb Jbeyq!"

    // Testing ROT-13 encryption on string: "Hello World!"
    ciphertext := cr.ROTEncrypt(plaintext, 13)
    if ciphertext != rot13Check {
        t.Errorf("Incorrect Rotation of characters.\nRot13: %s should be equal to %s", ciphertext, rot13Check)
    }

    rot47Check := "Czggj Rjmgy!"

    ciphertext = cr.ROTEncrypt(plaintext, 47)
    if ciphertext != rot47Check {
        t.Errorf("Incorrect Rotation of characters.\nROT47: %s should be equal to %s", ciphertext, rot13Check)
    }
}

func TestROTDecrypt(t *testing.T) {
    rot13Ciphertext := "Uryyb Jbeyq!"
    rot47Ciphertext := "Czggj Rjmgy!"

    checker := "Hello World!"

    if res := cr.ROTDecrypt(rot13Ciphertext, 13); res != checker {
        t.Errorf("Incorrect Rotation of characters.\nRot13: %s should be equal to %s", res, checker)
    }

    if res := cr.ROTDecrypt(rot47Ciphertext, 47); res != checker {
        t.Errorf("Incorrect Rotation of characters.\nRot47: %s should be equal to %s", res, checker)
    }
}

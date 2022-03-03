package crsuite

import (
    "fmt"
    "strings"
)


// ROTEncrypt performs a ROTn encryption on [plaintext] using
// [offset] and returns it.
// It is important to note that the ROT encryption performed on
// plaintext is using right-hand rotation of the text.
func ROTEncrypt(plaintext string, offset uint) string {
    rotMapping := func(r rune) rune {
        switch {
    	case r >= 'A' && r <= 'Z':
    		return 'A' + (r-'A'+rune(offset))%26
    	case r >= 'a' && r <= 'z':
    		return 'a' + (r-'a'+rune(offset))%26
    	}
        return r
    }
    return strings.Map(rotMapping, plaintext)
}

// ROTDecrypt performs ROTn decryption on plaintext and returns it.
// The offset specified is taken as a negative value by the function, using
// which, ROTn operation is performed.
func ROTDecrypt(ciphertext string, offset uint) string {
    rotMapping := func(r rune) rune {
        switch {
        case r >= 'A' && r <= 'Z':
            return 'A' + (r-'A'-rune(offset))%26
        case r >= 'a' && r <= 'z':
            return 'a' + (r-'a'-rune(offset))%26
        }
        return r
    }

    return strings.Map(rotMapping, ciphertext)
}

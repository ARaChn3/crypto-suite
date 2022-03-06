package crsuite

// ROTEncrypt performs a ROTn encryption on [plaintext] using
// [offset] and returns it.
// It is important to note that the ROT encryption performed on
// plaintext is using right-hand rotation of the text.
func ROTEncrypt(plaintext string, offset uint) (res string) {
	rotMap, _ := generateRotationMaps(offset)

	var ciphertext []rune

	for _, c := range plaintext {
		if _, ok := rotMap[c]; ok {
			ciphertext = append(ciphertext, rotMap[c])
		} else {
			ciphertext = append(ciphertext, c)
		}
	}

	return string(ciphertext)
}

// ROTDecrypt performs ROTn decryption on plaintext and returns it.
// The offset specified is taken as a negative value by the function, using
// which, ROTn operation is performed.
func ROTDecrypt(ciphertext string, offset uint) string {
	_, rotMap := generateRotationMaps(offset)

	var plaintext []rune

	for _, c := range ciphertext {
		if _, ok := rotMap[c]; ok {
			plaintext = append(plaintext, rotMap[c])
		} else {
			plaintext = append(plaintext, c)
		}
	}

	return string(plaintext)
}

// generates rotation maps for encryption and decryption
func generateRotationMaps(offset uint) (map[rune]rune, map[rune]rune) {
	var rotMap = make(map[rune]rune)
	var revRotMap = make(map[rune]rune)

	upperCase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerCase := "abcdefghijklmnopqrstuvwxyz"

	rotatedUpper := upperCase[offset%26:] + upperCase[:offset%26]
	rotatedLower := lowerCase[offset%26:] + lowerCase[:offset%26]

	for i := 0; i < len(upperCase); i++ {
		rotMap[rune(upperCase[i])] = rune(rotatedUpper[i])
		rotMap[rune(lowerCase[i])] = rune(rotatedLower[i])

		revRotMap[rune(rotatedLower[i])] = rune(lowerCase[i])
		revRotMap[rune(rotatedUpper[i])] = rune(upperCase[i])
	}

	return rotMap, revRotMap
}

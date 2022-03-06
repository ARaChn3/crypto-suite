package crsuite

import (
    "testing"
)

func TestAESEncrypt(t *testing.T) {
    initErr := InitAESBytes()
    if initErr != nil {
        t.Logf("Could not initialise bytes for aes encryption\nE: %v\n", initErr)
        t.Fail()
    }

    result, encErr := AESEcnrypt("Hello World!", 123123)
    if encErr != nil {
        t.Error(encErr)
    }

    if result != []byte{57, 234, 207, 164, 75, 94, 26, 179, 164, 181, 149, 232, 12, 101, 0, 19}
}

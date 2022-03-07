package crsuite

import (
    "testing"
    cr "github.com/ARaChn3/crypto-suite"
)

func TestBase64Encrypt(t *testing.T) {
    var ok bool = true

    checks := map[string]string{
        "Hello World": "SGVsbG8gV29ybGQ=",
        "foo bar foo bar": "Zm9vIGJhciBmb28gYmFy",
        "the fast fox... I don't really know the rest of the thing ;-;": "dGhlIGZhc3QgZm94Li4uIEkgZG9uJ3QgcmVhbGx5IGtub3cgdGhlIHJlc3Qgb2YgdGhlIHRoaW5nIDstOw==",
        "Discord is sooo good omg, idk how people still use other platforms to communicate?!": "RGlzY29yZCBpcyBzb29vIGdvb2Qgb21nLCBpZGsgaG93IHBlb3BsZSBzdGlsbCB1c2Ugb3RoZXIgcGxhdGZvcm1zIHRvIGNvbW11bmljYXRlPyE=",
    }

    for pt, tct := range checks {
        ct := cr.Base64Encrypt([]byte(pt))
        if string(ct) != tct {
            ok = false
            t.Logf("Incorrect encryption for test case: \"%s\"\n%s should be %s\n", pt, ct, tct)
        }
    }

    if !ok { t.Fail() }
}


func TestBase64Decrypt(t *testing.T) {
    var ok bool = true

    checks := map[string]string{
        "SGVsbG8gV29ybGQ=": "Hello World",
        "Zm9vIGJhciBmb28gYmFy": "foo bar foo bar",
        "dGhlIGZhc3QgZm94Li4uIEkgZG9uJ3QgcmVhbGx5IGtub3cgdGhlIHJlc3Qgb2YgdGhlIHRoaW5nIDstOw==": "the fast fox... I don't really know the rest of the thing ;-;",
        "RGlzY29yZCBpcyBzb29vIGdvb2Qgb21nLCBpZGsgaG93IHBlb3BsZSBzdGlsbCB1c2Ugb3RoZXIgcGxhdGZvcm1zIHRvIGNvbW11bmljYXRlPyE=": "Discord is sooo good omg, idk how people still use other platforms to communicate?!",
    }

    for ct, tpt := range checks {
        pt, err := cr.Base64Decrypt([]byte(ct))
        if err != nil {
            t.Errorf("Error While decrypting for test case: %s\nE: %v", ct, err)
        }
        if string(pt) != tpt {
            ok = false
            t.Logf("Incorrect decryption for test case: \"%s\"\n%s should be %s\n", ct, pt, tpt)
        }
    }

    if !ok { t.Fail() }
}

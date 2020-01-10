package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io/ioutil"
)

// RSAEncryptFile encrypts file with RSA public key (probably not secure)
func RSAEncryptFile(path string, pub *rsa.PublicKey) ([]byte, error) {

	// Read file to be encrypted
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Encrypt
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, []byte(""))
	if err != nil {
		return nil, err
	}

	return enc, nil
}

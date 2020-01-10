package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
)

// PublicKeyFromFile reads and parses a public key from file
func PublicKeyFromFile(path string) *rsa.PublicKey {

	// Read public key from file
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	// Decode PEM
	pubPem, _ := pem.Decode(pemData)
	if pubPem == nil || pubPem.Type != "RSA PUBLIC KEY" {
		log.Fatal("Failed to decode PEM containing public key.")
	}

	// Decode x509
	pubX509, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	var pubKey *rsa.PublicKey
	pubKey, _ = pubX509.(*rsa.PublicKey)

	return pubKey
}

func PrivateKeyFromFile(path string) *rsa.PrivateKey {

	// Read key from file
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	// Decode PEM
	privPem, _ := pem.Decode(pemData)
	if privPem == nil || privPem.Type != "RSA PRIVATE KEY" {
		log.Fatal("Failed to decode PEM containing private key.")
	}

	key, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return key
}

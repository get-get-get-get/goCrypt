package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
)

// KeyGenerator assists in key generation
type KeyGenerator struct {
	KeyFile       string
	PublicKeyFile string
	KeySize       int
}

// Save creates an RSA keypair and saves to file
func (kg KeyGenerator) Save() {
	reader := rand.Reader

	// Generate keypair
	key, err := rsa.GenerateKey(reader, kg.KeySize)
	if err != nil {
		log.Fatal(err)
	}
	pub := &key.PublicKey

	// Save keys
	savePEMKey(kg.KeyFile, key)
	savePEMPubKey(kg.PublicKeyFile, pub)
}

// NewKeyGenerator creates new KeyGenerator
func NewKeyGenerator(basepath string, keysize int) *KeyGenerator {

	kg := new(KeyGenerator)

	if !isValidKeySize(keysize) {
		return nil
	}
	kg.KeySize = keysize

	// Normalize path
	priv, err := filepath.Abs(basepath)
	if err != nil {
		log.Fatal(err)
	}
	pub := filepath.Join(priv, ".pub")
	kg.KeyFile = priv
	kg.PublicKeyFile = pub

	return kg
}

func isValidKeySize(n int) bool {
	if n < 1096 {
		return false
	}

	if (n & (n - 1)) == 0 {
		return true
	}

	return false
}

func savePEMKey(path string, key *rsa.PrivateKey) {

	// Format key as PEM
	var privatePem = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// Open file safely
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Write PEM to file
	err = pem.Encode(f, privatePem)
	if err != nil {
		log.Fatal(err)
	}
}

func savePEMPubKey(path string, pubkey *rsa.PublicKey) {
	// Not sure
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		log.Fatal(err)
	}

	// Format as PEM
	var publicPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	// Open file safely
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	err = pem.Encode(f, publicPem)
	if err != nil {
		log.Fatal(err)
	}
}

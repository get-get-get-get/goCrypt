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
	savePrivateKey(kg.KeyFile, key)
	savePublicKey(kg.PublicKeyFile, pub)
}

// NewKeyGenerator creates new KeyGenerator
func NewKeyGenerator(basepath string, keysize int) *KeyGenerator {

	kg := new(KeyGenerator)

	if !isValidKeySize(keysize) {
		return nil
	}
	kg.KeySize = keysize

	// Normalize path
	abspath, err := filepath.Abs(basepath)
	if err != nil {
		log.Fatal(err)
	}
	priv := abspath + ".key"
	pub := abspath + ".pub"
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

func savePrivateKey(path string, key *rsa.PrivateKey) {

	// Not sure
	pkcs1Bytes := x509.MarshalPKCS1PrivateKey(key)

	// Format key as PEM
	var privatePem = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1Bytes,
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

func savePublicKey(path string, pubkey *rsa.PublicKey) {
	// Not sure
	pkixBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		log.Fatal(err)
	}

	// Format as PEM
	var publicPem = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkixBytes,
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

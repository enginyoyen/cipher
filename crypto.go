package main

import (
	"crypto/rsa"
	"encoding/pem"
	"crypto/x509"
	"errors"
	"crypto/sha256"
	"fmt"
	"os"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"io"
)

const rsaKeyBitSize int = 2048

func GenerateRsaKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeyBitSize)
}

func EncodePublicKey(pub interface{}) ([]byte, error) {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	encodedPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkix,
	})
	return encodedPem, nil
}

func DecodePublicKey(pemBlock string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemBlock))
	if block == nil {
		return nil, errors.New("failed to parse given key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if v, ok := pub.(*rsa.PublicKey); ok {
		return v, nil
	} else {
		return nil, errors.New("given key is not type of RSA, is either DSA or ECDSA")
	}
}

func EncryptMessage(msg []byte, key *rsa.PublicKey) ([]byte, error) {
	result, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, msg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return nil, err
	}
	return result, nil
}

func DecryptMessage(msg []byte, key *rsa.PrivateKey) ([]byte, error) {
	result, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, msg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return nil, err
	}
	return result, nil
}

func GenerateAesKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func DecryptFileWithAes(key []byte, inputReader io.Reader, dest string) error {

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	reader := &cipher.StreamReader{S: stream, R: inputReader}
	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		return err
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.
	return nil
}


func EncryptFileWithAes(key []byte, src string, dest string) error {
	inFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		return err
	}
	return nil
}

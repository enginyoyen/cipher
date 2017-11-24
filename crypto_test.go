package main

import (
	"testing"
	"os"
	"io/ioutil"
	"bytes"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRsaKey(t *testing.T) {
	key, _ := GenerateRsaKey()
	if key == nil {
		t.Error("Could not generate the RSA key")
	}
}

func TestEncodePublicKey(t *testing.T) {
	key, _ := GenerateRsaKey()
	pem, _ := EncodePublicKey(&key.PublicKey)
	if pem == nil {
		t.Error("Could not generate the PEM file content")
	}
}

func TestDecodePublicKey(t *testing.T) {
	key, _ := GenerateRsaKey()
	pem, _ := EncodePublicKey(&key.PublicKey)
	decodedKey, _ := DecodePublicKey(string(pem))
	if decodedKey.E != key.PublicKey.E ||
		decodedKey.N.String() != key.PublicKey.N.String() {
		t.Error("Public key conversation failed. Decoded pem does not match the original key")
	}
}

func TestEncryptDecryptMessage(t *testing.T) {
	rsaKey, _ := GenerateRsaKey()
	msg := "This is a secret message"
	encryptedMsg, err := EncryptMessage([]byte(msg), &rsaKey.PublicKey)
	if err != nil {
		t.Errorf("Could not encrypt the message %s", err)
	}

	if string(encryptedMsg) == msg {
		t.Error("Encryption failure, result of the encryption should be same as input")
	}
	result, err := DecryptMessage(encryptedMsg, rsaKey)

	if string(result) != msg {
		t.Errorf("Result of the decryption (%s) does not match the input value (%s)", result, msg)
	}
}

func TestGenerateAesKey(t *testing.T) {
	key, err := GenerateAesKey()

	if err != nil {
		t.Errorf("Could not generate an AES key %s", err)
	}

	if len(key) != 32 {
		t.Errorf("Byte size should be 32, but it is : %d", len(key))
	}
}

func TestFileEncryptionDecryption(t *testing.T) {
	//aesKey := ""
	//EncryptFile()
	key, _ := GenerateAesKey()

	//generate temporary input file
	tempInput, _ := ioutil.TempFile(os.TempDir(), "")
	defer os.Remove(tempInput.Name())
	tempInput.WriteString("this is a sample \n content")
	tempInput.Close()

	//generate file that to be encrypted
	fileToBeEncrypted, _ := ioutil.TempFile(os.TempDir(), "")
	fileToBeEncrypted.Close()
	defer os.Remove(fileToBeEncrypted.Name())

	//encrypt test file
	EncryptFileWithAes(key, tempInput.Name(), fileToBeEncrypted.Name())
	assert.False(t, filesEqual(tempInput.Name(), fileToBeEncrypted.Name()), "Content of the file should be different")

	//revert back decryption
	fileToBeDecrypted, _ := ioutil.TempFile(os.TempDir(), "")
	fileToBeDecrypted.Close()
	defer os.Remove(fileToBeDecrypted.Name())

	encryptedFileReader, _ := os.Open(fileToBeEncrypted.Name())
	DecryptFileWithAes(key, encryptedFileReader, fileToBeDecrypted.Name())

	assert.True(t, filesEqual(tempInput.Name(), fileToBeDecrypted.Name()), "Content of original file and decrypted file should be same")

}

func filesEqual(a string, b string) bool {
	f1, _ := ioutil.ReadFile(a)
	f2, _ := ioutil.ReadFile(b)
	return bytes.Equal(f1, f2)
}



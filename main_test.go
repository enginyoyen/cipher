package main

import (
	"testing"
	"os"
	"fmt"
	"os/exec"
	"net/http"
	"time"
	"encoding/json"
	"bytes"
	"io/ioutil"
	"crypto/rsa"
	"encoding/hex"
)

func TestMain(m *testing.M) {

	build := exec.Command("/usr/local/bin/go", "build")
	err := build.Run()
	if err != nil {
		fmt.Printf("could not generate the binary file for test %v", err)
		os.Exit(1)
	}

	app := exec.Command("./cipher")
	go func() {
		err := app.Run()
		if err != nil {
			fmt.Printf("could not run the binary file for test %v", err)

		}
	}()
	//wait for 3 seconds to application to initilize
	time.Sleep(time.Second * 3)
	// run all tests
	exitCode := m.Run()

	//kill the app and exit
	app.Process.Kill()
	os.Exit(exitCode)
}

func TestAll(t *testing.T) {

	sessionId := getSessionId(t)
	publicKey := getThePublicKey(t, &sessionId)
	//TODO ask-client to accept a file
	//TODO wait for client to approved list of files to be transferred
	postFile(t, &sessionId, publicKey)

}

func postFile(t *testing.T, sessionId *SessionInfo, pk *rsa.PublicKey) {

	aesKey, _ := GenerateAesKey()
	encyptedAesKey, _ := EncryptMessage(aesKey, pk)

	//create temporary test file
	tempInput, _ := ioutil.TempFile(os.TempDir(), "")
	defer os.Remove(tempInput.Name())
	tempInput.WriteString("this is a sample \n content")
	tempInput.Close()

	//generate file that to be encrypted
	fileToBeEncrypted, _ := ioutil.TempFile(os.TempDir(), "")
	fileToBeEncrypted.Close()
	defer os.Remove(fileToBeEncrypted.Name())

	//encrypt test file
	EncryptFileWithAes(aesKey, tempInput.Name(), fileToBeEncrypted.Name())

	file, err := os.Open(fileToBeEncrypted.Name())
	if err != nil {
		panic(err)
	}
	defer file.Close()
	req, err := http.NewRequest("POST", "http://127.0.0.1:8080/file/"+sessionId.SessionId, file)

	client := &http.Client{}
	encodedAesKey := hex.EncodeToString(encyptedAesKey)
	req.Header.Add("X-AesKey", encodedAesKey)
	req.Header.Add("Content-Disposition", "inline; filename=\"myfile.txt\"")
	resp, err := client.Do(req)

	if err != nil {
		fmt.Println(err)
	}
	assertStatusCode(t, resp, http.StatusOK)
}

func getThePublicKey(t *testing.T, sessionId *SessionInfo) *rsa.PublicKey {
	resp, err := http.Get("http://127.0.0.1:8080/getPublicKey/" + sessionId.SessionId)
	checkTestError(t, err)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	publicKey, _ := DecodePublicKey(string(body))
	return publicKey
}

func getSessionId(t *testing.T) SessionInfo {
	sessionRequest := SessionRequest{Ip: "127.0.0.1", Port: 8081, Name: "TestClient"}
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(sessionRequest)
	resp, err := http.Post("http://127.0.0.1:8080/initSession", "application/json; charset=utf-8", b)
	checkTestError(t, err)
	defer resp.Body.Close()

	var sessionId = SessionInfo{}
	json.NewDecoder(resp.Body).Decode(&sessionId)
	return sessionId
}

func checkTestError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

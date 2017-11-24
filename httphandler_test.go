package main

import (
	"testing"
	"net/http/httptest"
	"io/ioutil"
	"github.com/stretchr/testify/assert"
	"strings"
	"net/http"
	"encoding/json"
	"fmt"
)

func TestInitSessionWithEmptyMethod(t *testing.T) {

	req := httptest.NewRequest("POST", "http://example.com/", nil)
	w := httptest.NewRecorder()
	InitSession(w, req)

	resp := w.Result()
	assertStatusCode(t, resp, http.StatusBadRequest)
}

func TestInitSessionWithWrongInput(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.com/", strings.NewReader("{\"some\":\"input\"}"))
	w := httptest.NewRecorder()
	InitSession(w, req)

	resp := w.Result()
	assertStatusCode(t, resp, http.StatusBadRequest)
}

func TestInitSession(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.com/foo", strings.NewReader("{\"ip\":\"localhost\", \"port\":8080,\"name\":\"testClient\"}"))
	w := httptest.NewRecorder()
	InitSession(w, req)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	assertStatusCode(t, resp, http.StatusOK)
	assertContentType(t, resp)
	assert.Contains(t, string(body), "sessionId", "Result does not contain sessionId")
}

func TestGetPublicKey(t *testing.T) {
	//retrieve sessionId
	req := httptest.NewRequest("POST", "http://example.com/foo", strings.NewReader("{\"ip\":\"localhost\", \"port\":8080,\"name\":\"testClient\"}"))
	w := httptest.NewRecorder()
	InitSession(w, req)
	resp := w.Result()
	var sessionId = SessionInfo{}
	json.NewDecoder(resp.Body).Decode(&sessionId)
	resp.Body.Close()

	//retrieve public key
	req = httptest.NewRequest("GET", "http://example.com/getPublicKey/"+sessionId.SessionId, nil)
	w = httptest.NewRecorder()
	GetPublicKey(w, req)
	resp = w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	assertStatusCode(t, resp, http.StatusOK)
	assert.Equal(t, resp.Header.Get("Content-Type"), "text/html", "wrong content type")
	assert.Contains(t, string(body), "BEGIN RSA PUBLIC KEY", "Result does not contain PUBLIC KEY")
	fmt.Println(string(body))
}

func TestGetPublicKeyWithWrongSessionId(t *testing.T) {
	//retrieve public key
	req := httptest.NewRequest("GET", "http://example.com/getPublicKey/123", nil)
	w := httptest.NewRecorder()
	GetPublicKey(w, req)
	resp := w.Result()

	assertStatusCode(t, resp, http.StatusNotFound)
}

func assertContentType(t *testing.T, r *http.Response) {
	assert.Equal(t, r.Header.Get("Content-Type"), "application/json", "wrong content type")
}

func assertStatusCode(t *testing.T, r *http.Response, statusCode int) {
	assert.Equal(t, statusCode, r.StatusCode, "wrong status code")
}

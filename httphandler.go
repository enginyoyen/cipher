package main

import (
	"encoding/json"
	"github.com/satori/go.uuid"
	"net/http"
	"io"
	"strings"
	"log"
)

type SessionInfo struct {
	SessionId string `json:"sessionId"`
}

func InitSession(w http.ResponseWriter, r *http.Request) {
	var t SessionRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	defer r.Body.Close()

	switch {
	case err == io.EOF:
		http.Error(w, "To create a session, valid session Request need to be posted that contains ip, port and name", 400)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if t.Port == 0 || t.Ip == "" || t.Name == "" {
		http.Error(w, "Invalid input, ip, port and name are required parameters", http.StatusBadRequest)
		return
	}

	uuid := uuid.NewV4()
	key, err := GenerateRsaKey()

	var obj = sessionDetail{PrivateKey: *key, PublicKey: key.PublicKey}
	sessions[uuid.String()] = obj

	sessionInfo, err := json.Marshal(SessionInfo{SessionId: uuid.String()})

	if err != nil {
		http.Error(w, "Serialization error", http.StatusInternalServerError)
		return
	}

	writeJsonContentType(w)
	w.Write(sessionInfo)
}

func GetPublicKey(w http.ResponseWriter, r *http.Request) {
	sessionId := strings.TrimPrefix(r.URL.Path, "/getPublicKey/")

	if val, ok := sessions[sessionId]; ok {
		buf, _ := EncodePublicKey(&val.PublicKey)
		w.Header().Set("Content-Type", "text/html")
		w.Write(buf)
		return
	}

	log.Println("session id does not exist")
	http.Error(w, "Session id could not be found", http.StatusNotFound)
}

func writeJsonContentType(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

package main

import (
	"fmt"
	"os"
	"github.com/hashicorp/mdns"
	"net"
	"time"
	"net/http"
	"encoding/json"
	"bytes"
	"crypto/rsa"
)

type sessionDetail struct {
	PrivateKey rsa.PrivateKey
	PublicKey  rsa.PublicKey
}

type SessionRequest struct {
	Ip   string
	Port int
	Name string
}

var sessions = make(map[string]sessionDetail)

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

//move method to httphandler.go
func ListClients(w http.ResponseWriter, r *http.Request) {

	// Make a channel for results and start listening
	entriesCh := make(chan *mdns.ServiceEntry, 4)

	q := mdns.QueryParam{Entries: entriesCh, Service: "_foobar._tcp", Timeout: time.Second * 1}

	mdns.Query(&q)

	close(entriesCh)
	buf := new(bytes.Buffer)
	buf.WriteString("[")
	enc := json.NewEncoder(buf)
	i := 0

	for entry := range entriesCh {
		if i != 0 {
			buf.WriteString(",")
		}
		enc.Encode(entry)
		i++
	}

	buf.WriteString("]")

	w.Header().Set("Content-Type", "application/json")
	w.Write(buf.Bytes())
}

func main() {

	go func() {
		http.HandleFunc("/getPublicKey/", GetPublicKey)
		http.HandleFunc("/listClients", ListClients)
		http.HandleFunc("/initSession", InitSession)
		http.ListenAndServe(":8080", nil)
	}()

	select {} // block forever

}

func setupMdnsServer() {
	// Setup our service export
	host, _ := os.Hostname()

	info := []string{"Application-Name", "value2", "value3", "id"}
	ips := []net.IP{{127, 0, 0, 1}}

	service, _ := mdns.NewMDNSService(host, "_foobar._tcp", "", "", 8000, ips, info)
	// Create the mDNS server, defer shutdown
	mdns.NewServer(&mdns.Config{Zone: service})

	//defer server.Shutdown()
}

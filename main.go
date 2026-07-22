package main

import (
	"fmt"
	"go_packet/analyzer"
	"go_packet/config"
	"log"
	"net/http"
	"os"
	"time"
)

var conf = config.ReadConfigFile("config/config.json")
var startCapture = true

func helloHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/hello" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method is not supported.", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprintf(w, "Hello, World!")
}

func pcapHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(conf.PcapName); os.IsNotExist(err) {
		http.Error(w, "Pcap dosn't exist", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", "attachment; filename=\"captured_traffic.pcap\"")

	http.ServeFile(w, r, conf.PcapName)
}

func main() {
	http.HandleFunc("/hello", helloHandler)
	http.HandleFunc("/pcap", pcapHandler)
	go func() {
		fmt.Println("Starting server at port 8080...")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal(err)
		}
	}()

	pr := analyzer.CreatePacketRead(conf)
	for {
		if startCapture {
			res := pr.Run()
			if !res {
				startCapture = false
			}
		} else {
			time.Sleep(100 * time.Second)
		}
	}
}

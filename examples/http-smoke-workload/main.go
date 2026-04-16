package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	time.Sleep(2 * time.Second)

	if _, err := os.ReadFile("/etc/hosts"); err != nil {
		log.Fatal(err)
	}

	resp, err := http.Get("http://127.0.0.1:18080/hello")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("status=%s body=%q", resp.Status, body)
}

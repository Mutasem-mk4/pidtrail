package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "hello from pidtrail fixture")
	})

	log.Println("listening on 127.0.0.1:18080")
	log.Fatal(http.ListenAndServe("127.0.0.1:18080", nil))
}

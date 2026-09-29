package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/Rukafuu/Mimir/internal/httpapi"
	"github.com/Rukafuu/Mimir/internal/kernel"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8787", "local HTTP listen address")
	flag.Parse()

	service := kernel.NewService(kernel.NewMemoryStore())
	server := &http.Server{Addr: *addr, Handler: httpapi.New(service)}
	log.Printf("mimird listening on http://%s", *addr)
	log.Fatal(server.ListenAndServe())
}

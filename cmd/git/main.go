package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jonjohnsonjr/dagdotdev/internal/git"
)

func main() {
	flag.Parse()

	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on %s", port)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), git.New(flag.Args())))
}

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/gcrane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/apk"
	"github.com/jonjohnsonjr/dagdotdev/internal/explore"
)

var auth = flag.Bool("auth", false, "use docker credentials")
var verbose = flag.Bool("v", false, "verbose logs")

func main() {
	flag.Parse()

	if *verbose {
		logs.Debug.SetOutput(os.Stderr)
	}

	if err := run(flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage %s apk | %s oci", os.Args[0], os.Args[0])
	}

	switch args[0] {
	case "apk":
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		log.Printf("listening on %s", port)

		opt := []apk.Option{apk.WithUserAgent("dagdotdev")}
		if *auth || os.Getenv("AUTH") == "keychain" {
			opt = append(opt, apk.WithKeychain(gcrane.Keychain))
		}

		return http.ListenAndServe(fmt.Sprintf(":%s", port), apk.New(args[1:], opt...))
	case "oci":
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		log.Printf("listening on %s", port)

		opt := []explore.Option{explore.WithUserAgent("dagdotdev")}
		if *auth || os.Getenv("AUTH") == "keychain" {
			opt = append(opt, explore.WithKeychain(gcrane.Keychain))
		}

		return http.ListenAndServe(fmt.Sprintf(":%s", port), explore.New(opt...))
	default:
		return fmt.Errorf("usage %s apk | %s oci", os.Args[0], os.Args[0])
	}
}

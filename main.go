package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/gcrane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/apk"
	"github.com/jonjohnsonjr/dagdotdev/internal/explore"
	"github.com/jonjohnsonjr/dagdotdev/internal/git"
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
		if cgid := os.Getenv("CHAINGUARD_IDENTITY"); cgid != "" {
			cgauth := apk.NewChainguardIdentityAuth(cgid, "https://issuer.enforce.dev", "https://apk.cgr.dev")
			opt = append(opt, apk.WithAuth(cgauth))
		}

		return http.ListenAndServe(fmt.Sprintf(":%s", port), apk.New(args[1:], opt...))
	case "oci":
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		log.Printf("listening on %s", port)

		opt := []explore.Option{explore.WithUserAgent("dagdotdev")}
		kcs := []authn.Keychain{}
		if cgid := os.Getenv("CHAINGUARD_IDENTITY"); cgid != "" {
			cgauth := explore.NewChainguardIdentityAuth(cgid, "https://issuer.enforce.dev", "https://cgr.dev")
			kcs = append(kcs, cgauth)
		}
		if *auth || os.Getenv("AUTH") == "keychain" {
			kcs = append(kcs, gcrane.Keychain)
		}

		if len(kcs) != 0 {
			opt = append(opt, explore.WithKeychain(authn.NewMultiKeychain(kcs...)))
		}

		return http.ListenAndServe(fmt.Sprintf(":%s", port), explore.New(opt...))
	case "git":
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		log.Printf("listening on %s", port)

		opt := []git.Option{git.WithUserAgent("dagdotdev")}

		return http.ListenAndServe(fmt.Sprintf(":%s", port), git.New(args[1:], opt...))
	default:
		return fmt.Errorf("usage %s apk | %s oci", os.Args[0], os.Args[0])
	}
}

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/authn"
	"github.com/jonjohnsonjr/dagdotdev/pkg/ggcr/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/apk"
	"github.com/jonjohnsonjr/dagdotdev/pkg/explore"
	"github.com/jonjohnsonjr/dagdotdev/pkg/git"
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
			opt = append(opt, apk.WithKeychain(authn.DefaultKeychain))
		}
		if eg := os.Getenv("EXAMPLES"); eg != "" {
			opt = append(opt, apk.WithExamples(strings.Split(eg, ",")))
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
		if *auth || os.Getenv("AUTH") == "keychain" {
			kcs = append(kcs, authn.DefaultKeychain)
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

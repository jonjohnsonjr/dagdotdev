package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/gcrane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/apk"

	sha256simd "github.com/minio/sha256-simd"
)

var auth = flag.Bool("auth", false, "use docker credentials")
var verbose = flag.Bool("v", false, "verbose logs")

func init() {
	crypto.RegisterHash(crypto.SHA256, sha256simd.New)
}

func main() {
	flag.Parse()

	logs.Trace.SetOutput(os.Stderr)
	logs.Trace.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	if *verbose {
		logs.Debug.SetOutput(os.Stderr)
		logs.Debug.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	}

	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	userAgent := os.Getenv("USERAGENT")
	if userAgent == "" {
		log.Print("please oh please set USERAGENT to something useful so registry operators can debug the weird things we do")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on %s", port)

	// TODO: Auth.
	opt := []apk.Option{apk.WithUserAgent(userAgent)}
	if *auth || os.Getenv("AUTH") == "keychain" {
		opt = append(opt, apk.WithKeychain(gcrane.Keychain))
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), apk.New(flag.Args(), opt...)))
}

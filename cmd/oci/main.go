package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/authn"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/gcrane"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/name"
	"github.com/jonjohnsonjr/dagdotdev/internal/explore"

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

	opt := []explore.Option{explore.WithUserAgent(userAgent)}
	kcs := []authn.Keychain{}
	if cgid := os.Getenv("CHAINGUARD_IDENTITY"); cgid != "" {
		cgauth := explore.NewChainguardIdentityAuth(cgid, "https://issuer.enforce.dev", "cgr.dev")
		kcs = append(kcs, cgauth)
	}
	if *auth || os.Getenv("AUTH") == "keychain" {
		kcs = append(kcs, gcrane.Keychain)
	}

	if dh := os.Getenv("DOCKERHUB_AUTH"); dh != "" {
		kc, err := newHubKeychain(dh)
		if err != nil {
			log.Fatal(err)
		}
		kcs = append(kcs, kc)
	}

	if len(kcs) != 0 {
		opt = append(opt, explore.WithKeychain(authn.NewMultiKeychain(kcs...)))
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), explore.New(opt...)))
}

func newHubKeychain(env string) (*keychain, error) {
	user, pass, ok := strings.Cut(env, ":")
	if !ok {
		return nil, fmt.Errorf("invalid DOCKERHUB_AUTH, expected user:pass")
	}

	return &keychain{
		user: user,
		pass: pass,
	}, nil
}

type keychain struct {
	user string
	pass string
}

func (k *keychain) Resolve(r authn.Resource) (authn.Authenticator, error) {
	if r.RegistryStr() != name.DefaultRegistry {
		return authn.Anonymous, nil
	}

	return authn.FromConfig(authn.AuthConfig{
		Username: k.user,
		Password: k.pass,
	}), nil
}

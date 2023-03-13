// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/internal/explore"
	"github.com/google/go-containerregistry/pkg/gcrane"
	"github.com/google/go-containerregistry/pkg/logs"

	sha256simd "github.com/minio/sha256-simd"
)

var auth = flag.Bool("auth", false, "use docker credentials")
var verbose = flag.Bool("v", false, "verbose logs")

const ua = "explore.ggcr.dev (jonjohnson at google dot com, if this is breaking you)"

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
	log.Print("starting explore.ggcr.dev")
	//logs.Debug.SetOutput(os.Stderr)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	opt := []explore.Option{}
	if *auth || os.Getenv("AUTH") == "keychain" {
		opt = append(opt, explore.WithKeychain(gcrane.Keychain))
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), explore.New(opt...)))
}

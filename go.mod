module github.com/jonjohnsonjr/dagdotdev

go 1.18

require (
	cloud.google.com/go/storage v1.29.0
	github.com/digitorus/timestamp v0.0.0-20230220124323-d542479a2425
	github.com/dustin/go-humanize v1.0.1
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/google/go-cmp v0.5.9
	github.com/google/go-containerregistry v0.13.0
	github.com/klauspost/compress v1.15.11
	github.com/minio/sha256-simd v1.0.0
	github.com/nanmu42/gzip v1.2.0
	github.com/spf13/cobra v1.6.0
	golang.org/x/crypto v0.0.0-20210915214749-c084706c2272
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
	golang.org/x/oauth2 v0.1.0
	golang.org/x/sync v0.1.0
)

require (
	cloud.google.com/go v0.107.0 // indirect
	cloud.google.com/go/compute v1.14.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.8.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.12.1 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20221019075359-21b8b40e6bb4 // indirect
	github.com/docker/cli v20.10.20+incompatible // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/docker v20.10.20+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.7.4 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.9.0 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.1 // indirect
	github.com/googleapis/gax-go/v2 v2.7.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.0.4 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/signalsciences/ac v1.2.0 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/ugorji/go/codec v1.2.6 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/net v0.1.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.5.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/api v0.106.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	google.golang.org/grpc v1.51.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace (
	github.com/google/go-containerregistry => ./internal/forks/github.com/google/go-containerregistry
	github.com/klauspost/compress => ./internal/forks/github.com/klauspost/compress
)

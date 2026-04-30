package explore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadFixture reads a fixture file from testdata/ relative to this package.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return b
}

// fixedCertDER is a deterministic test ECDSA cert (CN=test, O=dagdotdev-tests,
// serial 0xdeadbeef). Used so x509-rendering goldens stay byte-stable across runs.
const fixedCertDER = "MIIBmzCCAUCgAwIBAgIFAN6tvu8wCgYIKoZIzj0EAwIwKTENMAsGA1UEAwwEdGVzdDEYMBYGA1UECgwPZGFnZG90ZGV2LXRlc3RzMCAXDTI2MDQzMDIwMzEwN1oYDzIxMjYwNDA2MjAzMTA3WjApMQ0wCwYDVQQDDAR0ZXN0MRgwFgYDVQQKDA9kYWdkb3RkZXYtdGVzdHMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARBWw8tma6djbeyC0YSCOElugy3sty5LsLefzXMRTp8rJUWV4baIFdaXGWsyW24VSfDpGNp/t+3MU9KApbAtPwio1MwUTAdBgNVHQ4EFgQUOsotQq7n31xZlZQLAQvE9gLhhRUwHwYDVR0jBBgwFoAUOsotQq7n31xZlZQLAQvE9gLhhRUwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAiLXlEJtHWSnIGcD45BMpydUu4Wxwu8dyu9DhStWjBj0CIQCukkaqdM/UonCDB9wduhDWKzrMVHRbIKwqsfQU8pUIAA=="

func certDER(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(fixedCertDER)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func certPEM(t *testing.T) []byte {
	t.Helper()
	der := certDER(t)
	out := []byte("-----BEGIN CERTIFICATE-----\n")
	enc := base64.StdEncoding.EncodeToString(der)
	for i := 0; i < len(enc); i += 64 {
		end := i + 64
		if end > len(enc) {
			end = len(enc)
		}
		out = append(out, enc[i:end]...)
		out = append(out, '\n')
	}
	out = append(out, "-----END CERTIFICATE-----\n"...)
	return out
}

func TestGolden(t *testing.T) {
	cases := []goldenCase{
		{
			name: "manifest_by_digest",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				digest := fr.addImage("alpha/widget", "v1", nil)
				return "/?image=" + fr.Host() + "/alpha/widget@" + digest
			},
		},
		{
			name: "manifest_by_tag",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				fr.addImage("alpha/widget", "v1", nil)
				return "/?image=" + fr.Host() + "/alpha/widget:v1"
			},
		},
		{
			name: "manifest_with_layer",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				layer := []byte("fake-layer-bytes")
				layerDigest := fr.addBlob("alpha/widget", layer)
				cfg := map[string]any{
					"architecture": "amd64",
					"os":           "linux",
					"config":       map[string]any{"Cmd": []string{"/bin/sh"}},
					"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{layerDigest}},
				}
				cfgBody, _ := json.Marshal(cfg)
				cfgDigest := fr.addBlob("alpha/widget", cfgBody)
				manifest := map[string]any{
					"schemaVersion": 2,
					"mediaType":     "application/vnd.oci.image.manifest.v1+json",
					"config": map[string]any{
						"mediaType": "application/vnd.oci.image.config.v1+json",
						"digest":    cfgDigest,
						"size":      len(cfgBody),
					},
					"layers": []map[string]any{{
						"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
						"digest":    layerDigest,
						"size":      len(layer),
					}},
				}
				mfBody, _ := json.Marshal(manifest)
				digest := fr.addManifest("alpha/widget", "v1", mfBody, "application/vnd.oci.image.manifest.v1+json")
				return "/?image=" + fr.Host() + "/alpha/widget@" + digest
			},
		},
		{
			name: "image_index",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				amd := fr.addImage("alpha/multi", "", map[string]any{
					"architecture": "amd64", "os": "linux",
					"config": map[string]any{}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{}},
				})
				arm := fr.addImage("alpha/multi", "", map[string]any{
					"architecture": "arm64", "os": "linux",
					"config": map[string]any{}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{}},
				})
				index := map[string]any{
					"schemaVersion": 2,
					"mediaType":     "application/vnd.oci.image.index.v1+json",
					"manifests": []map[string]any{
						{
							"mediaType": "application/vnd.oci.image.manifest.v1+json",
							"digest":    amd, "size": 248,
							"platform": map[string]string{"architecture": "amd64", "os": "linux"},
						},
						{
							"mediaType": "application/vnd.oci.image.manifest.v1+json",
							"digest":    arm, "size": 248,
							"platform": map[string]string{"architecture": "arm64", "os": "linux"},
						},
					},
				}
				body, _ := json.Marshal(index)
				digest := fr.addManifest("alpha/multi", "v1", body, "application/vnd.oci.image.index.v1+json")
				return "/?image=" + fr.Host() + "/alpha/multi@" + digest
			},
		},
		{
			name: "blob_json_config",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				cfg := map[string]any{
					"architecture": "amd64",
					"os":           "linux",
					"config":       map[string]any{"Cmd": []string{"/bin/sh"}, "Env": []string{"PATH=/usr/bin"}},
					"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{}},
				}
				cfgBody, _ := json.Marshal(cfg)
				cfgDigest := fr.addBlob("alpha/widget", cfgBody)
				return "/?blob=" + fr.Host() + "/alpha/widget@" + cfgDigest +
					"&mt=application/vnd.oci.image.config.v1%2Bjson"
			},
		},
		{
			name: "repo_listing",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				fr.addImage("alpha/widget", "v1", nil)
				fr.addImage("alpha/widget", "v2", nil)
				return "/?repo=" + fr.Host() + "/alpha/widget"
			},
		},
		{
			name: "referrers_empty",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				digest := fr.addImage("alpha/widget", "v1", nil)
				return "/?referrers=" + fr.Host() + "/alpha/widget@" + digest
			},
		},
		{
			name: "render_raw",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				digest := fr.addImage("alpha/widget", "v1", nil)
				return "/?image=" + fr.Host() + "/alpha/widget@" + digest + "&render=raw"
			},
		},
		{
			name: "landing_page",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				return "/"
			},
		},
		{
			name: "manifest_not_found",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				return "/?image=" + fr.Host() + "/missing/repo@sha256:0000000000000000000000000000000000000000000000000000000000000000"
			},
		},
		{
			name: "manifest_with_subject",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				subjectDigest := fr.addImage("alpha/widget", "v1", nil)
				cfg := map[string]any{}
				cfgBody, _ := json.Marshal(cfg)
				cfgDigest := fr.addBlob("alpha/widget", cfgBody)
				sigBlob := []byte(`{"signature":"fake"}`)
				sigDigest := fr.addBlob("alpha/widget", sigBlob)
				manifest := map[string]any{
					"schemaVersion": 2,
					"mediaType":     "application/vnd.oci.image.manifest.v1+json",
					"config": map[string]any{
						"mediaType": "application/vnd.oci.empty.v1+json",
						"digest":    cfgDigest,
						"size":      len(cfgBody),
					},
					"layers": []map[string]any{{
						"mediaType":   "application/vnd.dev.cosign.simplesigning.v1+json",
						"digest":      sigDigest,
						"size":        len(sigBlob),
						"annotations": map[string]string{"dev.cosignproject.cosign/signature": "MEUCIQ=="},
					}},
					"subject": map[string]any{
						"mediaType": "application/vnd.oci.image.manifest.v1+json",
						"digest":    subjectDigest,
						"size":      248,
					},
					"annotations": map[string]string{"org.opencontainers.image.created": "2024-01-01T00:00:00Z"},
				}
				body, _ := json.Marshal(manifest)
				digest := fr.addManifest("alpha/widget", "", body, "application/vnd.oci.image.manifest.v1+json")
				return "/?image=" + fr.Host() + "/alpha/widget@" + digest
			},
		},
		{
			name: "blob_render_xxd",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := []byte("hello world\nthis is a binary blob\x00\x01\x02")
				digest := fr.addBlob("alpha/widget", body)
				return "/?blob=" + fr.Host() + "/alpha/widget@" + digest +
					"&mt=application/octet-stream&render=xxd"
			},
		},
		{
			name: "blob_render_history",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				cfg := map[string]any{
					"architecture": "amd64",
					"os":           "linux",
					"config":       map[string]any{"Cmd": []string{"/bin/sh"}},
					"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{}},
					"history": []map[string]any{
						{"created": "2024-01-01T00:00:00Z", "created_by": "/bin/sh -c #(nop) ADD file:abc in /"},
						{"created": "2024-01-01T00:00:01Z", "created_by": "/bin/sh -c apk add --no-cache curl", "empty_layer": false},
						{"created": "2024-01-01T00:00:02Z", "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]", "empty_layer": true},
					},
				}
				cfgBody, _ := json.Marshal(cfg)
				cfgDigest := fr.addBlob("alpha/widget", cfgBody)
				return "/?blob=" + fr.Host() + "/alpha/widget@" + cfgDigest +
					"&mt=application/vnd.oci.image.config.v1%2Bjson&render=history"
			},
		},
		{
			name: "blob_render_der",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				digest := fr.addBlob("alpha/widget", certDER(t))
				return "/?blob=" + fr.Host() + "/alpha/widget@" + digest +
					"&mt=application/pkix-cert&render=der"
			},
		},
		{
			name: "blob_render_cert_pem",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				digest := fr.addBlob("alpha/widget", certPEM(t))
				return "/?blob=" + fr.Host() + "/alpha/widget@" + digest +
					"&mt=application/x-pem-file&render=cert"
			},
		},
		{
			name: "blob_render_x509_pem",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				digest := fr.addBlob("alpha/widget", certPEM(t))
				return "/?blob=" + fr.Host() + "/alpha/widget@" + digest +
					"&mt=application/x-pem-file&render=x509"
			},
		},
		{
			name: "blob_dsse_envelope",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				stmt := map[string]any{
					"_type":         "https://in-toto.io/Statement/v1",
					"subject":       []map[string]any{{"name": "alpha/widget", "digest": map[string]string{"sha256": "0000"}}},
					"predicateType": "https://slsa.dev/provenance/v1",
					"predicate":     map[string]any{"buildType": "test"},
				}
				stmtBody, _ := json.Marshal(stmt)
				envelope := map[string]any{
					"payloadType": "application/vnd.in-toto+json",
					"payload":     base64.StdEncoding.EncodeToString(stmtBody),
					"signatures":  []map[string]any{{"keyid": "k1", "sig": "FAKE"}},
				}
				body, _ := json.Marshal(envelope)
				digest := fr.addBlob("alpha/widget", body)
				return "/?blob=" + fr.Host() + "/alpha/widget@" + digest +
					"&mt=application/vnd.dsse.envelope.v1%2Bjson"
			},
		},
		{
			name: "blob_spdx_sbom",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				sbom := map[string]any{
					"spdxVersion": "SPDX-2.3",
					"name":        "alpha/widget",
					"packages": []map[string]any{
						{
							"name":             "curl",
							"versionInfo":      "8.0.0",
							"externalRefs":     []map[string]any{{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:apk/alpine/curl@8.0.0"}},
							"SPDXID":           "SPDXRef-Package-curl",
							"downloadLocation": "NOASSERTION",
						},
					},
				}
				body, _ := json.Marshal(sbom)
				digest := fr.addBlob("alpha/widget", body)
				return "/?blob=" + fr.Host() + "/alpha/widget@" + digest +
					"&mt=application/spdx%2Bjson"
			},
		},
		{
			name: "blob_buildkit_metadata",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				cfg := map[string]any{
					"architecture": "amd64",
					"os":           "linux",
					"config": map[string]any{
						"Env":        []string{"PATH=/usr/bin", "HOME=/root"},
						"WorkingDir": "/app",
						"Cmd":        []string{"/bin/sh"},
						"Labels":     map[string]string{"org.opencontainers.image.base.name": "alpine:3.19"},
					},
					"rootfs": map[string]any{"type": "layers", "diff_ids": []string{}},
					"history": []map[string]any{
						{"created": "2024-01-01T00:00:00Z", "created_by": "/bin/sh -c #(nop) ADD file:abc in /"},
					},
					"moby.buildkit.buildinfo.v1": map[string]any{"frontend": "dockerfile.v0"},
				}
				body, _ := json.Marshal(cfg)
				digest := fr.addBlob("alpha/widget", body)
				return "/?blob=" + fr.Host() + "/alpha/widget@" + digest +
					"&mt=application/vnd.oci.image.config.v1%2Bjson"
			},
		},
		{
			name: "catalog",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				fr.addImage("alpha/widget", "v1", nil)
				fr.addImage("bravo/gadget", "v1", nil)
				return "/?repo=" + fr.Host()
			},
		},
		sociFileFromIndexCase(),
		{
			name: "kitchen_sink_manifest",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := loadFixture(t, "kitchen/manifest.json")
				digest := fr.addManifest("alpha/widget", "", body, "application/vnd.oci.image.manifest.v1+json")
				return "/?image=" + fr.Host() + "/alpha/widget@" + digest
			},
		},
		{
			name: "config_blob_with_manifest",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				cfg := map[string]any{
					"architecture": "amd64",
					"os":           "linux",
					"config": map[string]any{
						"Env":        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/bin", "HOME=/root"},
						"WorkingDir": "/app/src",
						"Cmd":        []string{"/bin/sh"},
					},
					"rootfs": map[string]any{"type": "layers", "diff_ids": []string{}},
				}
				cfgBody, _ := json.Marshal(cfg)
				cfgDigest := fr.addBlob("alpha/widget", cfgBody)
				// ?manifest= drives the Env/WorkingDir handlers in renderMap to
				// build /layers/ links via layersPathHref.
				manifestRef := fr.Host() + "/alpha/widget@sha256:0000000000000000000000000000000000000000000000000000000000000000"
				return "/?blob=" + fr.Host() + "/alpha/widget@" + cfgDigest +
					"&mt=application/vnd.oci.image.config.v1%2Bjson&manifest=" + manifestRef
			},
		},
		{
			name: "annotation_base_scratch",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				// Same shape as kitchen_sink but with base.name set to
				// "scratch" so renderAnnotations exercises the hub-special-
				// cased Doc branch instead of LinkImage.
				body := []byte(`{
					"schemaVersion": 2,
					"mediaType": "application/vnd.oci.image.manifest.v1+json",
					"config": {
						"mediaType": "application/vnd.oci.image.config.v1+json",
						"digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
						"size": 100
					},
					"layers": [],
					"annotations": {
						"org.opencontainers.image.base.name": "scratch"
					}
				}`)
				digest := fr.addManifest("alpha/widget", "", body, "application/vnd.oci.image.manifest.v1+json")
				return "/?image=" + fr.Host() + "/alpha/widget@" + digest
			},
		},
		{
			name: "cosign_bundle_via_jq",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := loadFixture(t, "cosign/sig_manifest.json")
				digest := fr.addManifest("chainguard/crane", "", body, "application/vnd.oci.image.manifest.v1+json")
				// Rendering the bundle annotation as JSON walks into Payload
				// where logIndex triggers BlueDocNumber → search.sigstore.dev.
				return "/?image=" + fr.Host() + "/chainguard/crane@" + digest +
					`&jq=.layers[0].annotations["dev.sigstore.cosign/bundle"]`
			},
		},
		{
			name: "cosign_bundle_body_decoded",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := loadFixture(t, "cosign/sig_manifest.json")
				digest := fr.addManifest("chainguard/crane", "", body, "application/vnd.oci.image.manifest.v1+json")
				// Pipe through Payload.body → base64 -d → jq so the rendered
				// root is the decoded Rekor hashedrekord entry. That root has
				// kind/apiVersion set so kindVer/maybeMap fire, and the spec
				// substructure exercises the value/content/publicKey branches
				// inside renderMap.
				return "/?image=" + fr.Host() + "/chainguard/crane@" + digest +
					`&jq=.layers%5B0%5D.annotations%5B%22dev.sigstore.cosign%2Fbundle%22%5D&jq=.Payload.body&jq=base64+-d&jq=jq`
			},
		},
		{
			name: "cosign_signature_manifest",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := loadFixture(t, "cosign/sig_manifest.json")
				digest := fr.addManifest("chainguard/crane", "", body, "application/vnd.oci.image.manifest.v1+json")
				return "/?image=" + fr.Host() + "/chainguard/crane@" + digest
			},
		},
		{
			name: "cosign_cert_via_jq",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := loadFixture(t, "cosign/sig_manifest.json")
				digest := fr.addManifest("chainguard/crane", "", body, "application/vnd.oci.image.manifest.v1+json")
				// jq extracts the PEM cert annotation, render=cert wraps it in
				// the linked-to-x509 view; this exercises evalBytes + renderCert
				// against a real Fulcio leaf certificate.
				return "/?image=" + fr.Host() + "/chainguard/crane@" + digest +
					`&jq=.layers[0].annotations["dev.sigstore.cosign/certificate"]&render=cert`
			},
		},
		{
			name: "cosign_chain_via_jq",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := loadFixture(t, "cosign/sig_manifest.json")
				digest := fr.addManifest("chainguard/crane", "", body, "application/vnd.oci.image.manifest.v1+json")
				// Two-cert PEM chain with sigstore intermediate + root through
				// the multi-cert renderx509 path.
				return "/?image=" + fr.Host() + "/chainguard/crane@" + digest +
					`&jq=.layers[0].annotations["dev.sigstore.cosign/chain"]&render=x509`
			},
		},
		{
			name: "cosign_attestation_manifest",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				body := loadFixture(t, "cosign/att_manifest.json")
				digest := fr.addManifest("chainguard/crane", "", body, "application/vnd.oci.image.manifest.v1+json")
				return "/?image=" + fr.Host() + "/chainguard/crane@" + digest
			},
		},
		{
			name: "fs_plain_tar_listing",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				layer := buildTar(t, []tarFile{
					{name: "etc/", typ: '5'},
					{name: "etc/raw.txt", body: "uncompressed\n"},
				})
				digest := fr.addBlob("alpha/widget", layer)
				return fmt.Sprintf(
					"/fs/%s/alpha/widget@%s/?mt=application/vnd.oci.image.layer.v1.tar&size=%d",
					fr.Host(), digest, len(layer),
				)
			},
		},
		{
			name: "fs_tar_zst_listing",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				layer := buildTarZst(t, []tarFile{
					{name: "etc/", typ: '5'},
					{name: "etc/zstd.txt", body: "compressed with zstd\n"},
				})
				digest := fr.addBlob("alpha/widget", layer)
				return fmt.Sprintf(
					"/fs/%s/alpha/widget@%s/?mt=application/vnd.oci.image.layer.v1.tar%%2Bzstd&size=%d",
					fr.Host(), digest, len(layer),
				)
			},
		},
		{
			name: "sizes_multi_layer",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				base := buildTarGz(t, []tarFile{
					{name: "etc/", typ: '5'},
					{name: "etc/baseline.cfg", body: strings.Repeat("b", 2048)},
					{name: "etc/small.txt", body: "tiny"},
				})
				upper := buildTarGz(t, []tarFile{
					{name: "var/", typ: '5'},
					{name: "var/data.bin", body: strings.Repeat("u", 4096)},
					{name: "var/log.txt", body: strings.Repeat("l", 64)},
				})
				baseDigest := fr.addBlob("alpha/widget", base)
				upperDigest := fr.addBlob("alpha/widget", upper)
				cfg := map[string]any{
					"architecture": "amd64",
					"os":           "linux",
					"config":       map[string]any{"Cmd": []string{"/bin/sh"}},
					"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{baseDigest, upperDigest}},
				}
				cfgBody, _ := json.Marshal(cfg)
				cfgDigest := fr.addBlob("alpha/widget", cfgBody)
				manifest := map[string]any{
					"schemaVersion": 2,
					"mediaType":     "application/vnd.oci.image.manifest.v1+json",
					"config": map[string]any{
						"mediaType": "application/vnd.oci.image.config.v1+json",
						"digest":    cfgDigest,
						"size":      len(cfgBody),
					},
					"layers": []map[string]any{
						{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": baseDigest, "size": len(base)},
						{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": upperDigest, "size": len(upper)},
					},
				}
				body, _ := json.Marshal(manifest)
				digest := fr.addManifest("alpha/widget", "v1", body, "application/vnd.oci.image.manifest.v1+json")
				return fmt.Sprintf("/sizes/%s/alpha/widget@%s?mt=application/vnd.oci.image.manifest.v1%%2Bjson&size=%d", fr.Host(), digest, len(body))
			},
		},
		{
			name: "size_tar_gz",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				layer := buildTarGz(t, []tarFile{
					{name: "etc/", typ: '5'},
					{name: "etc/large.bin", body: strings.Repeat("L", 4096)},
					{name: "etc/small.txt", body: "small\n"},
					{name: "etc/medium.dat", body: strings.Repeat("M", 256)},
				})
				digest := fr.addBlob("alpha/widget", layer)
				return fmt.Sprintf(
					"/size/%s/alpha/widget@%s?mt=application/vnd.oci.image.layer.v1.tar%%2Bgzip&size=%d",
					fr.Host(), digest, len(layer),
				)
			},
		},
		{
			name: "fs_tar_gz_listing",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				layer := buildTarGz(t, []tarFile{
					{name: "etc/", typ: '5'}, // tar.TypeDir
					{name: "etc/hello.txt", body: "hello world\n"},
					{name: "etc/empty.txt", body: ""},
					{name: "etc/sub/", typ: '5'},
					{name: "etc/sub/inner.txt", body: "nested\n"},
				})
				digest := fr.addBlob("alpha/widget", layer)
				return fmt.Sprintf(
					"/fs/%s/alpha/widget@%s/?mt=application/vnd.oci.image.layer.v1.tar%%2Bgzip&size=%d",
					fr.Host(), digest, len(layer),
				)
			},
		},
		{
			name: "blob_jq_filter",
			setup: func(t *testing.T, fr *fakeRegistry) string {
				cfg := map[string]any{
					"architecture": "amd64",
					"os":           "linux",
					"config":       map[string]any{"Cmd": []string{"/usr/bin/server", "--port", "8080"}},
					"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{}},
				}
				cfgBody, _ := json.Marshal(cfg)
				cfgDigest := fr.addBlob("alpha/widget", cfgBody)
				return "/?blob=" + fr.Host() + "/alpha/widget@" + cfgDigest +
					"&mt=application/vnd.oci.image.config.v1%2Bjson&jq=.config.Cmd"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runGolden(t, tc)
		})
	}
}

// sociFileFromIndexCase builds a goldenCase that exercises the
// random-access indexedFS path: a warmup request indexes the layer (cached
// to CACHE_DIR), then the recorded request fetches a single file from
// inside the tarball through the SOCI index. setup and warmup share the
// fixture via captured locals so both can see the same digest/size.
func sociFileFromIndexCase() goldenCase {
	var (
		digest string
		size   int
	)
	return goldenCase{
		name: "fs_serve_file_from_index",
		setup: func(t *testing.T, fr *fakeRegistry) string {
			layer := buildTarGz(t, []tarFile{
				{name: "etc/", typ: '5'},
				{name: "etc/hello.txt", body: "hello world\n"},
				{name: "etc/empty.txt", body: ""},
				{name: "etc/sub/", typ: '5'},
				{name: "etc/sub/inner.txt", body: "nested content\n"},
			})
			digest = fr.addBlob("alpha/widget", layer)
			size = len(layer)
			return fmt.Sprintf(
				"/fs/%s/alpha/widget@%s/etc/hello.txt?mt=application/vnd.oci.image.layer.v1.tar%%2Bgzip&size=%d",
				fr.Host(), digest, size,
			)
		},
		warmup: func(fr *fakeRegistry) []string {
			return []string{
				fmt.Sprintf(
					"/fs/%s/alpha/widget@%s/?mt=application/vnd.oci.image.layer.v1.tar%%2Bgzip&size=%d",
					fr.Host(), digest, size,
				),
			}
		},
	}
}

func TestForbiddenUserAgent(t *testing.T) {
	tc := goldenCase{
		name: "forbidden_user_agent",
		setup: func(t *testing.T, fr *fakeRegistry) string {
			return "/"
		},
		headers:    map[string]string{"User-Agent": "Go-http-client/1.1"},
		wantStatus: 403,
	}
	runGolden(t, tc)
}

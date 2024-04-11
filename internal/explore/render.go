package explore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	CosignMediaType = `application/vnd.dev.cosign.simplesigning.v1+json`
	cosignPointee   = `application/vnd.dev.ggcr.magic/cosign-thing+json`
	emptyDigest     = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
	hcsshim         = `https://github.com/microsoft/hcsshim/blob/main/osversion/windowsbuilds.go`
)

type jsonOutputter struct {
	w    io.Writer
	u    *url.URL
	name string
	repo string
	mt   string

	fresh []bool
	jq    []string
	key   bool
	root  map[string]interface{}
	isMap bool

	dockerHub bool
}

func (w *jsonOutputter) Annotation(url, text string) {
	w.tabf()
	w.Printf(`"<a class="mt" href="%s">%s</a>":`, url, html.EscapeString(text))
	w.key = true
}

func (w *jsonOutputter) BlueDoc(url, text string) {
	w.tabf()
	w.Printf(`"<a href="%s">%s</a>"`, url, html.EscapeString(strings.Trim(strconv.Quote(text), `"`)))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) BlueDocNumber(url, text string) {
	w.tabf()
	w.Printf(`<a href="%s">%s</a>`, url, html.EscapeString(text))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) Doc(url, text string) {
	w.tabf()
	w.Printf(`<a class="mt" href="%s">%s</a>`, url, html.EscapeString(text))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) URL(url, text string) {
	w.tabf()
	w.Printf(`"<a href="%s/">%s</a>"`, url, html.EscapeString(text))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) Linkify(mt string, h v1.Hash, size int64) {
	w.tabf()
	qs := "/?"
	handler := handlerForMT(mt)
	if strings.Contains(handler, "?") {
		qs = "&"
	}
	if strings.HasSuffix(mt, "+wasm") {
		w.Printf(`"<a href="https://github.com/opencontainers/artifacts/issues/61">%s</a>"`, html.EscapeString(h.String()))
	} else if h.String() == emptyDigest {
		w.Printf(`"<a href="/%s%s@%s%smt=%s" title="this is an empty layer that only modifies metadata, so it has no filesystem content">%s</a>"`, handler, w.repo, h.String(), qs, url.QueryEscape(mt), html.EscapeString(h.String()))
	} else if size != 0 {
		image := w.u.Query().Get("image")
		if w.jth(-1) == ".config" && image != "" {
			w.Printf(`"<a href="/%s%s@%s%smt=%s&size=%d&manifest=%s">%s</a>"`, handler, w.repo, h.String(), qs, url.QueryEscape(mt), size, image, html.EscapeString(h.String()))
		} else {
			w.Printf(`"<a href="/%s%s@%s%smt=%s&size=%d">%s</a>"`, handler, w.repo, h.String(), qs, url.QueryEscape(mt), size, html.EscapeString(h.String()))
		}
	} else {
		w.Printf(`"<a href="/%s%s@%s%smt=%s">%s</a>"`, handler, w.repo, h.String(), qs, url.QueryEscape(mt), html.EscapeString(h.String()))
	}
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) Blob(ref, text string) {
	w.tabf()
	w.Printf(`"<a href="/?blob=%s">%s</a>"`, url.PathEscape(ref), html.EscapeString(text))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) History(text string) {
	u := *w.u
	qs := u.Query()
	qs.Set("render", "history")
	qs.Set("mt", w.mt)
	u.RawQuery = qs.Encode()

	w.tabf()
	w.Printf(`"<a href="%s">%s</a>":`, u.String(), html.EscapeString(text))
	w.key = true
}

func (w *jsonOutputter) Layers(ref, text string) {
	w.tabf()
	w.Printf(`"<a href="/layers/%s/">%s</a>":`, ref, html.EscapeString(text))
	w.key = true
}

func (w *jsonOutputter) LinkImage(ref, text string) {
	w.tabf()
	w.Printf(`"<a href="/?image=%s">%s</a>"`, url.PathEscape(ref), html.EscapeString(text))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) LinkRepo(ref, text string) {
	w.tabf()
	w.Printf(`"<a href="/?repo=%s">%s</a>"`, url.PathEscape(ref), html.EscapeString(text))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) Key(k string) {
	w.tabf()
	w.Printf(`"%s":`, k)
	w.key = true
}

func (w *jsonOutputter) Value(b []byte) {
	w.tabf()
	w.Print(html.EscapeString(string(b)))
	w.unfresh()
	w.key = false
}

func (w *jsonOutputter) StartMap() {
	w.tabf()
	w.Print("{")
	w.newline()
	w.push()
	w.key = false
}

func (w *jsonOutputter) EndMap() {
	if !w.Fresh() {
		w.undiv()
	}
	w.pop()
	w.newline()
	w.Print(w.tabs() + "}")
	w.key = false
	w.name = ""
	w.unfresh()
}

func (w *jsonOutputter) StartArray() {
	w.tabf()
	w.Print("[")
	w.newline()
	w.push()
	w.key = false
}

func (w *jsonOutputter) EndArray() {
	if !w.Fresh() {
		w.undiv()
	}
	w.pop()
	w.newline()
	w.Print(w.tabs() + "]")
	w.key = false
	w.unfresh()
}

func (w *jsonOutputter) Printf(s string, arg ...interface{}) {
	fmt.Fprintf(w.w, s, arg...)
}

func (w *jsonOutputter) Print(s string) {
	fmt.Fprint(w.w, s)
}

func (w *jsonOutputter) tabf() {
	if !w.key {
		if !w.Fresh() {
			w.Print(",")
			w.undiv()
			w.newline()
		}
		w.div()
		//w.Printf(w.tabs())
	} else {
		w.Print(" ")
	}
}

func (w *jsonOutputter) Fresh() bool {
	if len(w.fresh) == 0 {
		return true
	}
	return w.fresh[len(w.fresh)-1]
}

func (w *jsonOutputter) push() {
	w.Print(w.tabs() + `<div class="indent">` + "\n")
	w.fresh = append(w.fresh, true)
}

func (w *jsonOutputter) pop() {
	w.fresh = w.fresh[:len(w.fresh)-1]
	w.newline()
	w.Print(w.tabs())
	w.undiv()
}

func (w *jsonOutputter) jpush(j string) {
	w.jq = append(w.jq, j)
	//log.Printf("%v", w.jq)
}

func (w *jsonOutputter) jpop() {
	w.jq = w.jq[:len(w.jq)-1]
}

func (w *jsonOutputter) jth(idx int) string {
	if len(w.jq)+idx-1 < 0 {
		//log.Printf("jth(%d) = %s", idx, "")
		return ""
	}
	if len(w.jq)+idx-1 > len(w.jq)-1 {
		return ""
	}

	s := w.jq[len(w.jq)+idx-1]
	//log.Printf("jth(%d) = %s", idx, s)
	return s
}

func (w *jsonOutputter) path(s string) bool {
	return strings.Join(w.jq, "") == s
}

func (w *jsonOutputter) kindVer(s string) bool {
	return w.maybeMap("kind")+"/"+w.maybeMap("apiVersion") == s
}

func (w *jsonOutputter) maybeMap(k string) string {
	if w.root == nil {
		return ""
	}
	v, ok := w.root[k]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (w *jsonOutputter) tabs() string {
	return strings.Repeat("  ", len(w.fresh))
}

func (w *jsonOutputter) newline() {
	w.Print("\n")
}

func (w *jsonOutputter) div() {
	w.Print(w.tabs() + "<div>")
}

func (w *jsonOutputter) undiv() {
	w.Print("</div>")
}

func (w *jsonOutputter) unfresh() {
	if len(w.fresh) == 0 {
		return
	}
	w.fresh[len(w.fresh)-1] = false
}

func (w *jsonOutputter) refresh() {
	w.fresh[len(w.fresh)-1] = true
}

func (w *jsonOutputter) addQuery(key, value string) url.URL {
	u := *w.u
	qs := u.Query()
	qs.Add(key, value)
	u.RawQuery = qs.Encode()
	return u
}

func (w *jsonOutputter) setQuery(key, value string) url.URL {
	u := *w.u
	qs := u.Query()
	qs.Set(key, value)
	u.RawQuery = qs.Encode()
	return u
}

// renderJSON formats some JSON bytes in an OCI-specific way.
//
// We try to convert maps to meaningful values based on a Descriptor:
// - mediaType: well-known links to their definitions.
// - digest: links to raw content or well-known handlers:
//  1. Well-known OCI types get rendered as renderJSON
//  2. Layers get rendered as a filesystem via http.FileSystem
//  3. Blobs ending in +json get rendered as formatted JSON
//  4. Cosign blobs (SimpleSigning) get rendered specially
//  5. Everything else is raw content
//
// If we see a map, try to parse as Descriptor and use those values.
//
// Anything else, recursively look for maps to try to parse as descriptors.
//
// Keep the rest of the RawMessage in tact.
//
// []byte -> json.RawMessage
// json.RawMessage -> map[string]json.RawMessage (v1.Desciptor?)
// json.RawMessage -> {map[string]raw, []raw, float64, string, bool, nil}
func renderJSON(w *jsonOutputter, b []byte) error {
	raw := json.RawMessage(b)

	// Unmarshal an extra time at the beginning to check if it's a map for easy
	// access to root fields. This is dumb but I'm lazy.
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if m, ok := v.(map[string]interface{}); ok {
		w.root = m
	}

	if err := renderRaw(w, &raw); err != nil {
		return fmt.Errorf("renderRaw: %w", err)
	}
	w.undiv()
	return nil
}

func renderRaw(w *jsonOutputter, raw *json.RawMessage) error {
	var v interface{}
	if err := json.Unmarshal(*raw, &v); err != nil {
		return err
	}

	switch vv := v.(type) {
	case []interface{}:
		return renderList(w, raw)
	case map[string]interface{}:
		return renderMap(w, vv, raw)
	case string:
		vs := v.(string)
		if strings.HasPrefix(vs, "https://") && !strings.Contains(vs, " ") {
			// Probably a link?
			w.tabf()
			w.Printf(`"<a class="mt" href="%s">%s</a>"`, vs, html.EscapeString(strings.Trim(strconv.Quote(vs), `"`)))
			w.unfresh()
			w.key = false
		} else {
			w.Value([]byte(strconv.Quote(vs)))
		}
		return nil
	default:
		b, err := raw.MarshalJSON()
		if err != nil {
			return err
		}
		w.Value(b)
		return nil
	}
}

// Make sure we see things in this order.
var precedence = []string{
	"schemaVersion",
	"mediaType",
	"artifactType",
	"config",
	"layers",
	"blobs",
	"manifests",
	"subject",
	"name",
	"digest",
	"size",
	"platform",
	"urls",
	"annotations",
	"_type",
	"predicateType",
	"predicate",
	"child",
	"tags",
	"manifest",
}
var ociMap map[string]int

func init() {
	ociMap = map[string]int{}
	for i, s := range precedence {
		ociMap[s] = i
	}
}

func compare(a, b string) bool {
	i, ok := ociMap[a]
	j, kk := ociMap[b]

	// Inter-OCI comparison.
	if ok && kk {
		return i < j
	}

	// Straight string comparison.
	if !ok && !kk {
		return a < b
	}

	// If ok == true,  a = OCI, b = string
	// If ok == false, a = string, b = OCI
	return ok
}

func renderMap(w *jsonOutputter, o map[string]interface{}, raw *json.RawMessage) error {
	rawMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawMap); err != nil {
		return err
	}

	// Handle empty maps as {}.
	if len(rawMap) == 0 {
		w.Value([]byte("{}"))
		return nil
	}

	w.StartMap()

	// Make this a stable order.
	keys := make([]string, 0, len(rawMap))
	for k := range rawMap {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return compare(keys[i], keys[j])
	})

	for idx, k := range keys {
		if idx != 0 {
			// Handle continues.
			w.jpop()
		}

		v := rawMap[k]
		if k == "layers" && len(w.jq) == 0 {
			image := w.u.Query().Get("image")
			w.Layers(image, "layers")
		} else if k == "history" && shouldHistory(w.mt) {
			w.History(k)
		} else {
			linkWindows := false
			if k == "os.version" {
				if os, ok := o["os"]; ok {
					if oss, ok := os.(string); ok {
						if oss == "windows" {
							linkWindows = true
						}
					}
				}
			}

			if linkWindows {
				w.Annotation(hcsshim, k)
			} else {
				w.Key(k)
			}
		}
		if _, err := strconv.Atoi(k); err == nil || strings.Contains(k, ".") {
			if len(w.jq) == 0 {
				w.jpush(fmt.Sprintf(".[%q]", k))
			} else {
				w.jpush(fmt.Sprintf("[%q]", k))
			}
		} else {
			w.jpush("." + k)
		}

		switch k {
		case "annotations":
			var i interface{}
			if err := json.Unmarshal(v, &i); err != nil {
				return err
			}
			if vv, ok := i.(map[string]interface{}); ok {
				if err := renderAnnotations(w, vv, &v); err != nil {
					return err
				}

				// Don't fall through to renderRaw.
				continue
			}
		case "name":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if strings.HasPrefix(s, "pkg:") {
						p, err := parsePurl(s)
						if err == nil {
							u, err := p.url(w.repo)
							if err == nil {
								w.BlueDoc(u, s)

								// Don't fall through to renderRaw.
								continue
							}
						}
					}
					if w.dockerHub {
						w.LinkRepo(path.Join(w.repo, s), s)
						continue
					}
				}
			}
		case "digest":
			if mt, ok := o["mediaType"]; ok {
				if s, ok := mt.(string); ok {
					h := v1.Hash{}
					if err := json.Unmarshal(v, &h); err != nil {
						log.Printf("Unmarshal digest %q: %v", string(v), err)
					} else {
						size := int64(0)
						if sz, ok := o["size"]; ok {
							if i64, ok := sz.(int64); ok {
								size = i64
							} else if f64, ok := sz.(float64); ok {
								size = int64(f64)
							}
						}

						w.Linkify(s, h, size)

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
			if name, ok := o["name"]; ok {
				// Set this for DSSE digest.name
				if ns, ok := name.(string); ok {
					w.name = ns // cleared by EndMap
				}
			}
			if uri, ok := o["uri"]; ok {
				// Set this for DSSE digest.name
				if ns, ok := uri.(string); ok {
					if strings.HasPrefix(ns, "pkg:") {
						w.name = ns // cleared by EndMap
					}
				}
			}
		case "sha256":
			if w.name != "" {
				if _, err := name.ParseReference(w.name); err == nil {
					if js, ok := o["sha256"]; ok {
						if d, ok := js.(string); ok {
							w.LinkImage(w.name+"@"+"sha256"+":"+d, d)

							// Don't fall through to renderRaw.
							continue
						}
					}
				} else if strings.HasPrefix(w.name, "pkg:") {
					p, err := parsePurl(w.name)
					if err == nil {
						if js, ok := o["sha256"]; ok {
							if d, ok := js.(string); ok {
								p.version = "sha256:" + d
								href, err := p.url(w.repo)
								if err == nil {
									w.BlueDoc(href, d)

									// Don't fall through to renderRaw.
									continue
								} else {
									log.Printf("p.url: %v", err)
								}
							}
						}
					} else {
						log.Printf("purl: %v", err)
					}
				}
			}
		case "mediaType":
			mt := ""
			if err := json.Unmarshal(v, &mt); err != nil {
				log.Printf("Unmarshal mediaType %q: %v", string(v), err)
			} else {
				w.Doc(getLink(mt), strconv.Quote(mt))

				// Don't fall through to renderRaw.
				continue
			}
		case "urls":
			if digest, ok := rawMap["digest"]; ok {
				h := v1.Hash{}
				if err := json.Unmarshal(digest, &h); err != nil {
					log.Printf("Unmarshal digest %q: %v", string(digest), err)
				} else {
					// We got a digest, so we can link to some blob.
					if urls, ok := o["urls"]; ok {
						if ii, ok := urls.([]interface{}); ok {
							if len(ii) == 0 {
								w.Value([]byte("[]"))
								continue
							}
							w.StartArray()
							for _, iface := range ii {
								if original, ok := iface.(string); ok {
									scheme := "https"
									u := original
									if strings.HasPrefix(original, "https://") {
										u = strings.TrimPrefix(original, "https://")
									} else if strings.HasPrefix(original, "http://") {
										u = strings.TrimPrefix(original, "http://")
										scheme = "http"
									}
									w.URL("/"+scheme+"/"+url.PathEscape(u)+"@"+h.String(), original)
								} else {
									// This wasn't a list of strings, render whatever we found.
									b, err := json.Marshal(iface)
									if err != nil {
										return err
									}
									raw := json.RawMessage(b)
									if err := renderRaw(w, &raw); err != nil {
										return err
									}
								}
							}
							w.EndArray()

							// Don't fall through to renderRaw.
							continue
						}
					}
				}
			}
		case "Docker-reference", "docker-reference":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					ref, err := name.ParseReference(s)
					if err != nil {
						log.Printf("Parse[%q](%q): %v", k, ref, err)
					} else {
						w.LinkImage(ref.String(), ref.String())

						// Don't fall through to renderRaw.
						continue
					}
				}
			}

		case "Docker-manifest-digest", "docker-manifest-digest":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				// TODO: This could maybe be better but we don't have a MT.
				w.Linkify(cosignPointee, h, 0)

				// Don't fall through to renderRaw.
				continue
			}
		case "blobSum":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				w.Linkify(string(types.DockerLayer), h, 0)

				// Don't fall through to renderRaw.
				continue
			}
		case "x5c":
			jose := strings.HasSuffix(w.mt, "jose+json")
			if jose {
				rawList := []json.RawMessage{}
				if err := json.Unmarshal(v, &rawList); err != nil {
					return err
				}

				// Handle empty lists as [].
				if len(rawList) == 0 {
					w.Value([]byte("[]"))
					return nil
				}

				w.StartArray()
				for index, vraw := range rawList {
					w.jpush(fmt.Sprintf("[%d]", index))

					var lv interface{}
					if err := json.Unmarshal(vraw, &lv); err != nil {
						return err
					}
					if href, ok := lv.(string); ok {
						u := *w.u
						qs := u.Query()
						qs.Add("jq", strings.Join(w.jq, ""))
						qs.Add("jq", "base64 -d")
						qs.Set("render", "der")
						u.RawQuery = qs.Encode()
						w.BlueDoc(u.String(), href)
					}

					w.jpop()
				}
				w.EndArray()

				continue
			}
		case "protected":
			// TODO: Dedupe and use jq to append an =
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					jose := strings.HasSuffix(w.mt, "jose+json")
					if jose {
						u := *w.u
						qs := u.Query()
						qs.Add("jq", strings.Join(w.jq, ""))

						if jose {
							v, err := base64.RawStdEncoding.DecodeString(href)
							if err != nil {
								return fmt.Errorf("base64 -d: %w", err)
							}
							remainder := len(v) % 3
							if remainder == 1 {
								qs.Add("jq", `awk '{print $1"=="}'`)
							} else if remainder == 2 {
								qs.Add("jq", `awk '{print $1"="}'`)
							}
						}

						qs.Add("jq", "base64 -d")
						qs.Add("jq", "jq")
						u.RawQuery = qs.Encode()
						w.BlueDoc(u.String(), href)

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "payload":
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					jsonPt := false
					if pt, ok := o["payloadType"]; ok {
						if s, ok := pt.(string); ok {
							if s == "application/json" || strings.HasSuffix(s, "+json") {
								jsonPt = true
							}
						}
					}

					jose := strings.HasSuffix(w.mt, "jose+json")
					if jsonPt || jose {
						u := *w.u
						qs := u.Query()
						qs.Add("jq", strings.Join(w.jq, ""))

						if jose {
							v, err := base64.RawStdEncoding.DecodeString(href)
							if err != nil {
								return fmt.Errorf("base64 -d: %w", err)
							}
							remainder := len(v) % 3
							if remainder == 1 {
								qs.Add("jq", `awk '{print $1"=="}'`)
							} else if remainder == 2 {
								qs.Add("jq", `awk '{print $1"="}'`)
							}
						}

						qs.Add("jq", "base64 -d")
						qs.Add("jq", "jq")
						u.RawQuery = qs.Encode()
						w.BlueDoc(u.String(), href)

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "payloadType":
			if js, ok := o[k]; ok {
				if pt, ok := js.(string); ok {
					if href := getLink(pt); href != "" {
						w.Doc(href, strconv.Quote(pt))
					}

					// Don't fall through to renderRaw.
					continue
				}
			}
		case "uri", "_type", "$schema", "informationUri":
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
						w.BlueDoc(href, href)

						// Don't fall through to renderRaw.
						continue
					} else if strings.HasPrefix(href, "pkg:") {
						p, err := parsePurl(href)
						if err == nil {
							u, err := p.url(w.repo)
							if err == nil {
								w.BlueDoc(u, href)
								// Don't fall through to renderRaw.
								continue
							}
						}
					}
				}
			}
		case "referenceLocator":
			if js, ok := o[k]; ok {
				if ps, ok := js.(string); ok {
					p, err := parsePurl(ps)
					if err == nil {
						href, err := p.url(w.repo)
						if err == nil {
							w.BlueDoc(href, ps)
							// Don't fall through to renderRaw.
							continue
						}
					}
				}
			}
		case "logIndex":
			if inside(w.u, "dev.sigstore.cosign/bundle") {
				if js, ok := rawMap[k]; ok {
					index := 0
					if err := json.Unmarshal(js, &index); err != nil {
						log.Printf("json.Unmarshal[logIndex]: %v", err)
					} else if index != 0 {
						w.BlueDocNumber(fmt.Sprintf("https://rekor.tlog.dev/?logIndex=%d", index), strconv.FormatInt(int64(index), 10))

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "body":
			if inside(w.u, "dev.sigstore.cosign/bundle") {
				if js, ok := o[k]; ok {
					if s, ok := js.(string); ok {
						jq := strings.Join(w.jq, "")
						if jq == ".Payload.body" {
							u := *w.u
							qs := u.Query()
							qs.Add("jq", jq)
							qs.Add("jq", "base64 -d")
							u.RawQuery = qs.Encode()
							w.BlueDoc(u.String(), s)

							continue
						}
					}
				}
			}
		case "data":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					u := *w.u
					qs := u.Query()
					qs.Add("jq", strings.Join(w.jq, ""))

					if _, err := base64.StdEncoding.DecodeString(s); err == nil {
						qs.Add("jq", "base64 -d")
						qs.Set("render", "raw")
						u.RawQuery = qs.Encode()
						w.BlueDoc(u.String(), s)

						// Don't fall through to renderRaw.
						continue
					} else {
						log.Printf("data: %v", err)
					}
				}
			}
		case "content", "publicKey", "verifier":
			if inside(w.u, "dev.sigstore.cosign/bundle") {
				if js, ok := o[k]; ok {
					if s, ok := js.(string); ok {
						if (w.path(".spec.publicKey") && w.kindVer("intoto/0.0.1")) || (w.path(".spec.signature.publicKey.content") && w.kindVer("hashedrekord/0.0.1")) || (strings.HasPrefix(strings.Join(w.jq, ""), ".spec.signatures") && w.kindVer("dsse/0.0.1")) {
							u := *w.u
							qs := u.Query()
							qs.Add("jq", strings.Join(w.jq, ""))
							qs.Add("jq", "base64 -d")
							qs.Set("render", "cert")
							u.RawQuery = qs.Encode()
							w.BlueDoc(u.String(), s)

							continue
						}
					}
				}
			}
		case "value":
			if inside(w.u, "dev.sigstore.cosign/bundle") {
				if (w.path(".spec.content.hash.value") && w.kindVer("intoto/0.0.1")) || (w.path(".spec.data.hash.value") && w.kindVer("hashedrekord/0.0.1")) || (w.path(".spec.envelopeHash.value") && w.kindVer("dsse/0.0.1")) {
					if i, ok := o["algorithm"]; ok {
						if s, ok := i.(string); ok {
							if s == "sha256" {
								if js, ok := o[k]; ok {
									if d, ok := js.(string); ok {
										w.Blob(w.repo+"@"+"sha256"+":"+d, d)
										continue
									}
								}
							}
						}
					}
				}
			}
		case "v1Compatibility":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if w.jth(-2) == ".history" {
						u := w.addQuery("jq", strings.Join(w.jq, ""))
						w.BlueDoc(u.String(), s)

						continue
					}
				}
			}
		case "io.buildpacks.build.metadata", "io.buildpacks.lifecycle.metadata", "io.buildpacks.project.metadata":
			// TODO: Just check for `{"` for json.
			// TODO: Check for `ey` for base64 json?
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					u := w.addQuery("jq", strings.Join(w.jq, ""))
					w.BlueDoc(u.String(), s)

					continue
				}
			}
		case "predicateType":
			if js, ok := o[k]; ok {
				if pt, ok := js.(string); ok {
					if href := getPredicateLink(pt); href != "" {
						w.Doc(href, strconv.Quote(pt))

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "tags":
			if mv, ok := o[k]; ok {
				if ii, ok := mv.([]interface{}); ok {
					if len(ii) == 0 {
						w.Value([]byte("[]"))
						continue
					}
					w.StartArray()
					for _, iface := range ii {
						if original, ok := iface.(string); ok {
							w.LinkImage(w.repo+":"+original, original)
						} else {
							// This wasn't a list of strings, render whatever we found.
							b, err := json.Marshal(iface)
							if err != nil {
								return err
							}
							raw := json.RawMessage(b)
							if err := renderRaw(w, &raw); err != nil {
								return err
							}
						}
					}
					w.EndArray()

					// Don't fall through to renderRaw.
					continue
				}
			}
		case "next", "previous":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					u := w.setQuery("next", s)
					w.BlueDoc(u.String(), s)

					// Don't fall through to renderRaw.
					continue
				}
			}
		case "tag":
			if mv, ok := o[k]; ok {
				if ii, ok := mv.([]interface{}); ok {
					if len(ii) == 0 {
						w.Value([]byte("[]"))
						continue
					}
					w.StartArray()
					for _, iface := range ii {
						if original, ok := iface.(string); ok {
							if w.jth(-2) == ".manifest" {
								maybeHash := strings.TrimLeft(w.jth(-1), ".")
								h, err := v1.NewHash(maybeHash)
								if err == nil {
									w.LinkImage(w.repo+":"+original+"@"+h.String(), original)
									continue
								} else {
									log.Printf("maybeHash(%q): %v", maybeHash, err)
								}
							}
							w.LinkImage(w.repo+":"+original, original)
						} else {
							// This wasn't a list of strings, render whatever we found.
							b, err := json.Marshal(iface)
							if err != nil {
								return err
							}
							raw := json.RawMessage(b)
							if err := renderRaw(w, &raw); err != nil {
								return err
							}
						}
					}
					w.EndArray()

					// Don't fall through to renderRaw.
					continue
				}
			}
		case "repositories", "child":
			if !w.path(".predicate.contents.repositories") {
				if mv, ok := o[k]; ok {
					if ii, ok := mv.([]interface{}); ok {
						if len(ii) == 0 {
							w.Value([]byte("[]"))
							continue
						}
						w.StartArray()
						for _, iface := range ii {
							if original, ok := iface.(string); ok {
								w.LinkRepo(path.Join(w.repo, original), original)
							} else {
								// This wasn't a list of strings, render whatever we found.
								b, err := json.Marshal(iface)
								if err != nil {
									return err
								}
								raw := json.RawMessage(b)
								if err := renderRaw(w, &raw); err != nil {
									return err
								}
							}
						}
						w.EndArray()

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "packages":
			if w.path(".predicate.contents.packages") {
				firstRepo := ""
				if rv, ok := o["repositories"]; ok {
					if ri, ok := rv.([]interface{}); ok {
						if len(ri) != 0 {
							ii := ri[0]
							if rs, ok := ii.(string); ok {
								firstRepo = strings.Replace(rs, "://", "/", 1)
								log.Printf("firstRepo: %q", firstRepo)
							}
						}
					}
				}

				// TODO: Care about this.
				arch := "x86_64"

				if firstRepo != "" {
					if mv, ok := o[k]; ok {
						if ii, ok := mv.([]interface{}); ok {
							if len(ii) == 0 {
								w.Value([]byte("[]"))
								continue
							}
							w.StartArray()
							for _, iface := range ii {
								if original, ok := iface.(string); ok {
									name, ver, ok := strings.Cut(original, "=")
									if ok {
										href := fmt.Sprintf("https://apk.dag.dev/%s/%s/%s-%s.apk", firstRepo, arch, name, ver)
										w.BlueDoc(href, original)
										continue
									}
								}

								// This wasn't a list of strings, render whatever we found.
								b, err := json.Marshal(iface)
								if err != nil {
									return err
								}
								raw := json.RawMessage(b)
								if err := renderRaw(w, &raw); err != nil {
									return err
								}
							}
							w.EndArray()

							// Don't fall through to renderRaw.
							continue
						}
					}
				}
			}
		case "manifest":
			var i interface{}
			if err := json.Unmarshal(v, &i); err != nil {
				return err
			}
			if vv, ok := i.(map[string]interface{}); ok {
				if err := renderManifest(w, vv, &v); err != nil {
					return err
				}

				// Don't fall through to renderRaw.
				continue
			}
		case "timeCreatedMs", "timeUploadedMs", "integratedTime":
			if js, ok := o[k]; ok {
				if ts, ok := js.(string); ok {
					if w.jth(-2) == ".manifest" {
						ms, err := strconv.ParseInt(ts, 10, 64)
						if err == nil {
							sec := ms / 1000
							ns := (ms % 1000) * 1000000
							t := time.Unix(sec, ns)

							// TODO: dedupe with Value
							w.tabf()
							w.Print(fmt.Sprintf(`"<span title="%s">%s</span>"`, t.String(), ts))
							w.unfresh()
							w.key = false
							// Don't fall through to renderRaw.
							continue
						}
					}
				} else if f64, ok := js.(float64); ok {
					i64 := int64(f64)
					t := time.Unix(i64, 0)

					// TODO: dedupe with Value
					w.tabf()
					w.Print(fmt.Sprintf(`<span title="%s">%d</span>`, t.String(), i64))
					w.unfresh()
					w.key = false
					// Don't fall through to renderRaw.
					continue
				}
			}
		case "imageSizeBytes":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if w.jth(-2) == ".manifest" {
						bs, err := strconv.ParseInt(s, 10, 64)
						if err == nil {
							// TODO: dedupe with Value
							w.tabf()
							w.Print(fmt.Sprintf(`"<span title="%s">%s</span>"`, humanize.Bytes(uint64(bs)), s))
							w.unfresh()
							w.key = false
							// Don't fall through to renderRaw.
							continue
						}
					}
				}
			}
		case "size":
			// check we're in a descriptor
			if js, ok := o[k]; ok {
				if bs, ok := js.(float64); ok {
					n := uint64(bs)
					if d, ok := o["digest"]; ok {
						if ds, ok := d.(string); ok {
							if m, ok := o["mediaType"]; ok {
								if ms, ok := m.(string); ok {
									if shouldSize(ms) {
										w.tabf()
										w.Print(fmt.Sprintf(`<a href="/size/%s@%s?mt=%s&size=%d"><span title="%s">%d</span></a>`, w.repo, ds, ms, int64(bs), humanize.Bytes(n), n))
										w.unfresh()
										w.key = false
										// Don't fall through to renderRaw.
										continue
									}
								}
							}
						}
					}

					w.tabf()
					w.Print(fmt.Sprintf(`<span title="%s">%d</span>`, humanize.Bytes(n), n))
					w.unfresh()
					w.key = false
					// Don't fall through to renderRaw.
					continue
				}
			}
		case "created_by":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if w.jth(-2) == ".history" {
						u := *w.u
						qs := u.Query()
						qs.Add("jq", strings.Join(w.jq, ""))
						qs.Set("render", "created_by")
						u.RawQuery = qs.Encode()
						w.BlueDoc(u.String(), s)

						continue
					}
				}
			}
		case "moby.buildkit.buildinfo.v1", "moby.buildkit.cache.v0":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					jq := strings.Join(w.jq, "")
					u := *w.u
					qs := u.Query()
					qs.Add("jq", jq)
					qs.Add("jq", "base64 -d")
					qs.Add("jq", "jq .")
					u.RawQuery = qs.Encode()
					w.BlueDoc(u.String(), s)

					continue
				}
			}
		case "identifier":
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "git://") {
						w.BlueDoc(gitUrl(href), href)

						continue
					} else if _, after, ok := strings.Cut(href, "docker-image://"); ok {
						w.LinkImage(after, href)

						continue
					}
				}
			}
		}

		if w.mt == "application/cose" {
			if v, ok := o[k]; ok {
				if s, ok := v.(string); ok {
					u := *w.u
					qs := u.Query()
					qs.Add("jq", strings.Join(w.jq, ""))
					qs.Add("jq", "base64 -d")
					if k == "io.cncf.notary.timestampSignature" {
						qs.Set("render", "timestamp")
					} else if !(len(s) > 2 && s[0] == 'e' && s[1] == 'y') {
						qs.Set("render", "xxd")
					}
					u.RawQuery = qs.Encode()
					w.BlueDoc(u.String(), s)

					continue
				}
			}
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}
	w.EndMap()
	w.jpop()

	return nil
}

// todo: refactor
func renderAnnotations(w *jsonOutputter, o map[string]interface{}, raw *json.RawMessage) error {
	rawMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawMap); err != nil {
		return err
	}
	// Handle empty maps as {}.
	if len(rawMap) == 0 {
		w.Value([]byte("{}"))
		return nil
	}

	// Make this a stable order.
	keys := make([]string, 0, len(rawMap))
	for k := range rawMap {
		keys = append(keys, k)
		if v, ok := o[k]; ok {
			if _, ok := v.(string); !ok {
				return renderRaw(w, raw)
			}
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return compare(keys[i], keys[j])
	})

	w.StartMap()

	for idx, k := range keys {
		if idx != 0 {
			// Handle continues.
			w.jpop()
		}

		v := rawMap[k]
		if href := getAnnotationLink(k); href != "" {
			w.Annotation(href, k)
		} else {
			w.Key(k)
		}

		if strings.Contains(k, ".") {
			w.jpush(fmt.Sprintf("[%q]", k))
		} else {
			w.jpush("." + k)
		}

		switch k {
		case "org.opencontainers.image.base.name":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if s == "scratch" {
						w.Doc("https://hub.docker.com/_/scratch", strconv.Quote(s))
						continue
					}
					ref, err := name.ParseReference(s)
					if err != nil {
						log.Printf("Parse[%q](%q): %v", k, ref, err)
					} else {
						w.LinkImage(ref.String(), ref.String())

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "org.opencontainers.image.base.digest":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				if js, ok := o["org.opencontainers.image.base.name"]; ok {
					if s, ok := js.(string); ok {
						base, err := name.ParseReference(s)
						if err != nil {
							log.Printf("Parse[%q](%q): %v", k, base, err)
						} else {
							w.LinkImage(base.Context().Digest(h.String()).String(), h.String())

							// Don't fall through to renderRaw.
							continue
						}
					}
				}
			}
		case "vnd.docker.reference.digest":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				w.LinkImage(w.repo+"@"+h.String(), h.String())

				// Don't fall through to renderRaw.
				continue
			}
		case "vnd.docker.reference.type":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if s == "attestation-manifest" {
						w.Doc("https://github.com/moby/buildkit/blob/master/docs/attestations/attestation-storage.md", strconv.Quote(s))
						continue
					}
				}
			}

		case "dev.sigstore.cosign/bundle", "dev.sigstore.cosign/timestamp", "sh.brew.tab":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if w.jth(-1) == ".annotations" {
						u := w.addQuery("jq", strings.Join(w.jq, ""))
						w.BlueDoc(u.String(), s)

						continue
					}
				}
			}
		case "dev.sigstore.cosign/certificate", "dev.sigstore.cosign/chain":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if w.jth(-1) == ".annotations" {
						u := *w.u
						qs := u.Query()
						qs.Add("jq", strings.Join(w.jq, ""))
						qs.Set("render", "cert")
						u.RawQuery = qs.Encode()
						w.BlueDoc(u.String(), s)

						continue
					}
				}
			}
		case "org.opencontainers.image.documentation", "org.opencontainers.image.url":
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
						w.BlueDoc(href, href)

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "org.opencontainers.image.source":
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
						w.BlueDoc(gitUrl(href), href)
						continue
					}
				}
			}
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}

	w.EndMap()
	w.jpop()

	return nil
}

// todo: refactor
func renderManifest(w *jsonOutputter, o map[string]interface{}, raw *json.RawMessage) error {
	rawMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawMap); err != nil {
		return err
	}
	// Handle empty maps as {}.
	if len(rawMap) == 0 {
		w.Value([]byte("{}"))
		return nil
	}

	// Make this a stable order.
	keys := make([]string, 0, len(rawMap))
	for k := range rawMap {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return compare(keys[i], keys[j])
	})

	w.StartMap()

	for idx, k := range keys {
		if idx != 0 {
			// Handle continues.
			w.jpop()
		}

		if strings.Contains(k, ".") {
			w.jpush(fmt.Sprintf("[%q]", k))
		} else {
			w.jpush("." + k)
		}

		v := rawMap[k]
		h, err := v1.NewHash(k)
		if err != nil {
			log.Printf("Unmarshal digest %q: %v", k, err)
			w.Key(k)
		} else {
			href := fmt.Sprintf(`<a href="?image=%s">%s</a>`, w.repo+"@"+h.String(), html.EscapeString(k))
			w.Key(href)
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}

	w.EndMap()
	w.jpop()

	return nil
}

func renderList(w *jsonOutputter, raw *json.RawMessage) error {
	rawList := []json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawList); err != nil {
		return err
	}

	// Handle empty lists as [].
	if len(rawList) == 0 {
		w.Value([]byte("[]"))
		return nil
	}

	w.StartArray()
	for index, v := range rawList {
		w.jpush(fmt.Sprintf("[%d]", index))

		if w.mt == "application/cose" {
			var i interface{}
			if err := json.Unmarshal(v, &i); err != nil {
				return err
			}
			if s, ok := i.(string); ok {
				u := *w.u
				qs := u.Query()
				qs.Add("jq", strings.Join(w.jq, ""))
				qs.Add("jq", "base64 -d")
				if w.jth(-1) == "[\"33\"]" {
					qs.Set("render", "der")
				} else if !(len(s) > 2 && s[0] == 'e' && s[1] == 'y') {
					qs.Set("render", "xxd")
				}
				u.RawQuery = qs.Encode()
				w.BlueDoc(u.String(), s)

				w.jpop()
				continue

			}
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
		w.jpop()
	}
	w.EndArray()

	return nil
}

func handlerForMT(s string) string {
	mt := types.MediaType(s)
	if !mt.IsDistributable() {
		return `fs/`
	}
	if mt.IsImage() {
		return `?image=`
	}
	if mt.IsIndex() {
		return `?image=`
	}
	switch mt {
	case types.OCILayer, types.OCIUncompressedLayer, types.DockerLayer, types.DockerUncompressedLayer:
		return `fs/`
	case types.OCIContentDescriptor, CosignMediaType, types.OCIConfigJSON, types.DockerConfigJSON:
		return `?blob=`
	case cosignPointee:
		return `?image=`
	case types.DockerManifestSchema1, types.DockerManifestSchema1Signed:
		return `?image=`
	case "application/vnd.oci.artifact.manifest.v1+json":
		return `?image=`
	}
	if strings.HasSuffix(s, "+json") || strings.HasSuffix(s, "+dsse") || strings.HasSuffix(s, "cose") || strings.HasSuffix(s, "cbor") {
		return `?blob=`
	}

	return `blob/`
}

func getLink(s string) string {
	mt := types.MediaType(s)
	if !mt.IsDistributable() {
		return `https://github.com/opencontainers/image-spec/blob/main/layer.md#non-distributable-layers`
	}
	if mt.IsImage() {
		return `https://github.com/opencontainers/image-spec/blob/main/manifest.md`
	}
	if mt.IsIndex() {
		return `https://github.com/opencontainers/image-spec/blob/main/image-index.md`
	}
	if strings.HasPrefix(s, "application/vnd.in-toto.") && strings.HasSuffix(s, "+dsse") {
		return `https://github.com/in-toto/attestation/blob/a7a9d0712d5115af3e8e1f6b3564158a1bbb73e4/spec/v1/envelope.md`
	}
	switch mt {
	case types.OCIConfigJSON, types.DockerConfigJSON:
		return `https://github.com/opencontainers/image-spec/blob/main/config.md`
	case types.OCILayer, types.OCIUncompressedLayer, types.DockerLayer, types.DockerUncompressedLayer:
		return `https://github.com/opencontainers/image-spec/blob/main/layer.md`
	case types.OCIContentDescriptor:
		return `https://github.com/opencontainers/image-spec/blob/main/descriptor.md`
	case `application/vnd.dev.cosign.simplesigning.v1+json`:
		return `https://github.com/containers/image/blob/master/docs/containers-signature.5.md`
	case `application/vnd.dsse.envelope.v1+json`:
		return `https://github.com/secure-systems-lab/dsse/blob/469c6e9fa6c4b7252fb71101084561cfc4cd0fa5/envelope.md`
	case `application/vnd.in-toto+json`:
		return `https://github.com/in-toto/attestation/blob/a7a9d0712d5115af3e8e1f6b3564158a1bbb73e4/spec/v1/statement.md`
	case `spdx+json`:
		return `https://github.com/spdx/spdx-spec/blob/7ba7bf571c0c3c3fd6a4bd780914d58f9274adcc/schemas/spdx-schema.json`
	case "application/vnd.oci.artifact.manifest.v1+json":
		return `https://github.com/opencontainers/image-spec/pull/999`
	}
	return `https://github.com/opencontainers/image-spec/blob/main/media-types.md`
}

func getPredicateLink(s string) string {
	switch s {
	case `cosign.sigstore.dev/attestation/vuln/v1`:
		return `https://github.com/sigstore/cosign/blob/b01a173cab389e93c5f3b46d50fe503f9c2454c2/specs/COSIGN_VULN_ATTESTATION_SPEC.md`
	}
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
		return s
	}
	return ""
}

func getAnnotationLink(s string) string {
	switch s {
	case `dev.cosignproject.cosign/signature`:
		return `https://github.com/sigstore/cosign/blob/20d75e71920599fc5dcdb0d1c5ddba6358227c62/specs/SIGNATURE_SPEC.md#signature`
	case `dev.sigstore.cosign/certificate`:
		return `https://github.com/sigstore/cosign/blob/20d75e71920599fc5dcdb0d1c5ddba6358227c62/specs/SIGNATURE_SPEC.md#certificate`
	case `dev.sigstore.cosign/chain`:
		return `https://github.com/sigstore/cosign/blob/20d75e71920599fc5dcdb0d1c5ddba6358227c62/specs/SIGNATURE_SPEC.md#chain`
	case `dev.sigstore.cosign/bundle`:
		return `https://github.com/sigstore/cosign/blob/20d75e71920599fc5dcdb0d1c5ddba6358227c62/specs/SIGNATURE_SPEC.md#properties`
	}
	return ""
}

func inside(u *url.URL, ann string) bool {
	for _, jq := range u.Query()["jq"] {
		if strings.Contains(jq, `.annotations["`+ann+`"]`) {
			return true
		}
	}
	return false
}

func shouldHistory(mt string) bool {
	tmt := types.MediaType(mt)
	return tmt == types.DockerManifestSchema1 ||
		tmt == types.DockerManifestSchema1Signed ||
		tmt == types.DockerConfigJSON ||
		tmt == types.OCIConfigJSON
}

func shouldSize(mt string) bool {
	return strings.HasSuffix(mt, "tar") ||
		strings.HasSuffix(mt, "tar.gzip") ||
		strings.HasSuffix(mt, "tar+gzip") ||
		strings.HasSuffix(mt, "tar+zstd")
}

// TODO: Just reuse this:
// https://github.com/moby/moby/blob/ff05850e7e0d101c90cdafdb7f359b335e9f2fc3/builder/remotecontext/urlutil/urlutil.go
//
// Example:
// In:  https://github.com/docker-library/rabbitmq.git#6cc0f66ec13b06c153a7527c033cf1ad59a97ef3:3.13/ubuntu
// Out: https://github.com/docker-library/rabbitmq/tree/6cc0f66ec13b06c153a7527c033cf1ad59a97ef3/3.13/ubuntu
func gitUrl(href string) string {
	before, after, ok := strings.Cut(href, "#")
	if !ok {
		return href
	}

	if !strings.Contains(before, "github.com") {
		return href
	}

	prefix := strings.TrimSuffix(before, ".git")
	prefix = strings.ReplaceAll(prefix, "git://", "https://")

	commit, fp, ok := strings.Cut(after, ":")
	if !ok {
		return fmt.Sprintf("%s/tree/%s", prefix, after)
	}

	return fmt.Sprintf("%s/tree/%s/%s", prefix, commit, fp)
}

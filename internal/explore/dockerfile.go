package explore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type BlobSum struct {
	BlobSum string `json:"blobSum"`
}

type Schema1History struct {
	V1Compatibility string `json:"v1Compatibility"`
}

type Schema1 struct {
	FSLayers []BlobSum        `json:"fsLayers"`
	History  []Schema1History `json:"history"`
}

type Config struct {
	Cmd []string `json:"Cmd"`
}

type Compat struct {
	ContainerConfig Config `json:"container_config"`
}

var whitespaceRegex = regexp.MustCompile(`( )(?:    )+`)

func whitespaceRepl(in []byte) []byte {
	return bytes.Replace(in, []byte(" "), []byte(" \\\n"), 1)
}

func renderDockerfileSchema1(w io.Writer, b []byte, repo name.Repository) error {
	m := Schema1{}
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	args := []string{}
	fmt.Fprintf(w, "<table>\n")
	for i := len(m.History) - 1; i >= 0; i-- {
		compat := m.History[i]
		c := Compat{}
		if err := json.Unmarshal([]byte(compat.V1Compatibility), &c); err != nil {
			return err
		}

		cb := strings.Join(c.ContainerConfig.Cmd, " ")

		href, digest, size := "", "", int64(0)
		if i < len(m.FSLayers) {
			fsl := m.FSLayers[i]
			href = fmt.Sprintf("/fs/%s/", repo.Digest(fsl.BlobSum).String())
			digest = fsl.BlobSum
			if _, after, ok := strings.Cut(digest, ":"); ok {
				if len(after) > 8 {
					digest = after[:8]
				}
			}

			if fsl.BlobSum != "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4" {
				l, err := remote.Layer(repo.Digest(fsl.BlobSum))
				if err == nil {
					size, _ = l.Size()
				}
			}
		}

		fmt.Fprintf(w, "<tr>\n")
		fmt.Fprintf(w, "<td class=\"noselect\"><p><a href=%q><em>%s</em></a></p></td>\n", href, digest)
		if size != 0 {
			human := humanize.Bytes(uint64(size))
			fmt.Fprintf(w, "<td class=\"noselect\"><p title=\"%d bytes\">%s</p></td>\n", size, human)
		} else {
			fmt.Fprintf(w, "<td></td>\n")
		}

		fmt.Fprintf(w, "<td>\n<pre>\n")
		args, err = renderArg(w, cb, args)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>\n</td>\n")
		fmt.Fprintf(w, "</tr>\n")
	}
	fmt.Fprintf(w, "</table>\n")
	return nil
}

// TODO: add timestamps
func renderDockerfile(w io.Writer, b []byte, m *v1.Manifest, repo name.Repository) error {
	cf, err := v1.ParseConfigFile(bytes.NewReader(b))
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "<table>\n")
	args := []string{}
	index := -1
	for _, hist := range cf.History {
		digest := ""
		href := ""
		size := int64(0)
		if m != nil {
			if !hist.EmptyLayer {
				index++
				if index < len(m.Layers) {
					desc := m.Layers[index]
					digest = desc.Digest.String()
					href = fmt.Sprintf("/fs/%s/?mt=%s", repo.Digest(digest).String(), desc.MediaType)
					if _, after, ok := strings.Cut(digest, ":"); ok {
						if len(after) > 8 {
							digest = after[:8]
						}
					}
					size = m.Layers[index].Size
				}
			}
		}
		fmt.Fprintf(w, "<tr>\n")
		fmt.Fprintf(w, "<td class=\"noselect\"><p><a href=%q><em>%s</em></a></p></td>\n", href, digest)
		if size != 0 {
			human := humanize.Bytes(uint64(size))
			fmt.Fprintf(w, "<td class=\"noselect\"><p title=\"%d bytes\">%s</p></td>\n", size, human)
		} else {
			fmt.Fprintf(w, "<td></td>\n")
		}

		cb := hist.CreatedBy
		fmt.Fprintf(w, "<td>\n<pre>\n")

		args, err = renderArg(w, cb, args)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>\n</td>\n")
		fmt.Fprintf(w, "</tr>\n")
	}
	fmt.Fprintf(w, "</table>\n")
	return nil
}

func renderArg(w io.Writer, cb string, args []string) ([]string, error) {
	var sb strings.Builder
	// Attempt to handle weird ARG stuff.
	maybe := strings.TrimSpace(strings.TrimPrefix(cb, "/bin/sh -c #(nop)"))
	if before, after, ok := strings.Cut(maybe, "ARG "); ok && before == "" {
		args = append(args, after)
	} else if strings.HasPrefix(cb, "|") {
		if _, cb, ok = strings.Cut(cb, " "); ok {
			for _, arg := range args {
				cb = strings.TrimSpace(strings.TrimPrefix(cb, arg))
			}

			// Hack around array syntax.
			if !strings.HasPrefix(cb, "/bin/sh -c ") {
				cb = "/bin/sh -c " + cb
			}
		}
	}
	if err := renderCreatedBy(&sb, []byte(cb)); err != nil {
		return nil, err
	}
	if _, err := sb.Write([]byte("\n\n")); err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte(sb.String())); err != nil {
		return nil, err
	}

	return args, nil
}

const (
	winPrefix = `powershell -Command $ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';`
	linPrefix = `/bin/sh -c`
)

func renderCreatedBy(w io.Writer, b []byte) error {
	// Heuristically try to format this correctly.
	for _, prefix := range []string{linPrefix, winPrefix} {
		b = bytes.TrimPrefix(b, []byte(prefix+" #(nop)"))
		if bytes.HasPrefix(b, []byte(prefix)) {
			b = bytes.Replace(b, []byte(prefix), []byte("RUN"), 1)
		}
	}
	b = bytes.ReplaceAll(b, []byte(" \t"), []byte(" \\\n\t"))
	b = bytes.ReplaceAll(b, []byte("&&\t"), []byte("\\\n&&\t"))
	b = whitespaceRegex.ReplaceAllFunc(b, whitespaceRepl)
	b = bytes.TrimSpace(b)
	if bytes.HasPrefix(b, []byte("EXPOSE")) {
		// Turn the map version into the dockerfile version
		b = bytes.TrimSuffix(b, []byte("]"))
		b = bytes.Replace(b, []byte("map["), []byte(""), 1)
		b = bytes.ReplaceAll(b, []byte(":{}"), []byte(""))
	}
	if bytes.HasPrefix(b, []byte("|")) {
		if _, after, ok := bytes.Cut(b, []byte("/bin/sh -c")); ok {
			b = []byte("RUN")
			b = append(b, after...)
		}
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("Write: %w", err)
	}
	return nil
}

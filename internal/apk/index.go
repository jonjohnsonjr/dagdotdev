package apk

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type stanza struct {
	checksum []byte
	name     string
	version  string
	deps     []string
	provides []string
}

func (h *handler) renderIndex(w http.ResponseWriter, r *http.Request, in io.Reader, ref string) error {
	title := ref
	if before, _, ok := strings.Cut(ref, "@"); ok {
		title = path.Base(before)
	}
	if err := headerTmpl.Execute(w, TitleData{title}); err != nil {
		return err
	}
	header := headerData(ref, v1.Descriptor{})
	before, _, ok := strings.Cut(ref, "@")
	if ok {
		u := "https://" + strings.TrimSuffix(strings.TrimPrefix(before, "/https/"), "/")
		header.JQ = "curl" + " " + u + " | tar -Oxz APKINDEX"
	}

	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	fmt.Fprintf(w, "<pre><div>\n")

	scanner := bufio.NewScanner(bufio.NewReaderSize(in, 1<<16))

	pkg := stanza{}

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, ":")
		if !ok {
			// reset pkg
			pkg = stanza{}

			fmt.Fprintf(w, "</div><div>\n")

			continue
		}

		switch before {
		case "C":
			chk := strings.TrimPrefix(after, "Q1")
			decoded, err := base64.StdEncoding.DecodeString(chk)
			if err != nil {
				return fmt.Errorf("base64 decode: %w", err)
			}

			pkg.checksum = decoded
		case "P":
			pkg.name = after
		case "V":
			pkg.version = after
		}

		switch before {
		case "V":
			prefix, _, ok := strings.Cut(r.URL.Path, "APKINDEX.tar.gz")
			if !ok {
				return fmt.Errorf("something funky with path...")
			}
			apk := fmt.Sprintf("%s-%s.apk", pkg.name, pkg.version)
			hexsum := "sha1:" + hex.EncodeToString(pkg.checksum)
			href := fmt.Sprintf("%s@%s", path.Join(prefix, apk), hexsum)
			fmt.Fprintf(w, "<a id=%q href=%q>V:%s</a>\n", apk, href, pkg.version)
		case "S", "I":
			i, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as int: %w", after, err)
			}
			fmt.Fprintf(w, "%s:<span title=%q>%s</span>\n", before, humanize.Bytes(uint64(i)), after)
		case "t":
			sec, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", after, err)
			}
			t := time.Unix(sec, 0)
			fmt.Fprintf(w, "<span title=%q>t:%s</span>\n", t.String(), after)
		default:
			fmt.Fprintf(w, "%s\n", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	fmt.Fprintf(w, "</div></pre>\n</body>\n</html>\n")

	return nil
}

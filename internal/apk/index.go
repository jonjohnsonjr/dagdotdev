package apk

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type apkindex struct {
	checksum string
	name     string
	version  string
	provides map[string]string
	depends  []string
}

type pkginfo struct {
	origin string
	commit string
}

func (a apkindex) needs(provides []string) bool {
	if len(provides) == 0 {
		return true
	}
outer:
	for _, prov := range provides {
		for _, dep := range a.depends {
			if dep == prov {
				continue outer
			}
		}

		return false
	}

	return true
}

func (a apkindex) satisfies(depends []string) bool {
	if len(depends) == 0 {
		return true
	}
	for _, depend := range depends {
		if _, ok := a.provides[depend]; !ok {
			if a.name != depend {
				return false
			}
		}
	}

	return true
}

func (h *handler) renderIndex(w http.ResponseWriter, r *http.Request, in io.Reader, ref string) error {
	short := r.URL.Query().Get("short") != "false"
	provides := r.URL.Query()["provide"]
	depends := r.URL.Query()["depend"]

	pkgs := []apkindex{}
	ptov := map[string]string{}

	if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
		return err
	}
	header := headerData(ref, v1.Descriptor{})
	before, _, ok := strings.Cut(ref, "@")
	if ok {
		u := "https://" + strings.TrimSuffix(strings.TrimPrefix(before, "/https/"), "/")
		if short {
			// TODO: This stuff is not super robust. We could write a real awk program to do it better.

			// Link to long form.
			header.JQ = "curl -L" + " " + u + ` | tar -Oxz <a class="mt" href="?short=false">APKINDEX</a>`

			if len(provides) == 0 && len(depends) == 0 {
				// awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'
				header.JQ += ` | awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk\n", $2}'`
			} else {
				if len(provides) != 0 {
					// awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk", $2} $1 == "p" { printf " %s", substr($0, 3)} /^$/ {printf "\n"}' | grep "so:libc.so.6" | cut -d" " -f1
					header.JQ += ` | awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk", $2} $1 == "p" { printf " %s", substr($0, 3)} /^$/ {printf "\n"}'`

					for _, dep := range provides {
						header.JQ += ` | grep "` + dep + `"`
					}

					header.JQ += ` | cut -d" " -f1`
					header.JQ += ` # this is approximate`
				} else {
					header.JQ += ` | awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk", $2} $1 == "D" { printf " %s", substr($0, 3)} /^$/ {printf "\n"}'`

					for _, dep := range depends {
						header.JQ += ` | grep "` + dep + `"`
					}

					header.JQ += ` | cut -d" " -f1`
					header.JQ += ` # this is approximate`
				}
			}
		} else {
			header.JQ = "curl -L" + " " + u + ` | tar -Oxz <a class="mt" href="?short=true">APKINDEX</a>`
		}
	} else if before, _, ok := strings.Cut(ref, "APKINDEX.tar.gz"); ok {
		before = path.Join(before, "APKINDEX.tar.gz")
		u := "https://" + strings.TrimSuffix(strings.TrimPrefix(before, "/https/"), "/")
		if short {
			// Link to long form.
			header.JQ = "curl -L" + " " + u + ` | tar -Oxz <a class="mt" href="?short=false">APKINDEX</a>`

			// awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'
			header.JQ += ` | awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'`
		} else {
			header.JQ = "curl -L" + " " + u + ` | tar -Oxz <a class="mt" href="?short=true">APKINDEX</a>`
		}
	}

	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	fmt.Fprintf(w, "<pre><div>")

	scanner := bufio.NewScanner(bufio.NewReaderSize(in, 1<<16))

	prefix, _, ok := strings.Cut(r.URL.Path, "APKINDEX.tar.gz")
	if !ok {
		return fmt.Errorf("something funky with path...")
	}

	added := false
	pkg := apkindex{}

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, ":")
		if !ok {
			if pkg.name != "" {
				pkgs = append(pkgs, pkg)
				added = true
			}

			// reset pkg
			pkg = apkindex{}
			added = false

			if !short {
				fmt.Fprintf(w, "</div><div>\n")
			}

			continue
		}

		switch before {
		case "C":
			chk := strings.TrimPrefix(after, "Q1")
			decoded, err := base64.StdEncoding.DecodeString(chk)
			if err != nil {
				return fmt.Errorf("base64 decode: %w", err)
			}

			pkg.checksum = hex.EncodeToString(decoded)
		case "P":
			pkg.name = after
		case "V":
			pkg.version = after
		case "p":
			items := strings.Split(after, " ")
			pkg.provides = make(map[string]string, len(items))
			for _, i := range items {
				before, after, ok := strings.Cut(i, "=")
				if ok {
					pkg.provides[before] = after
				}
			}
		case "D":
			pkg.depends = strings.Split(after, " ")
		}

		if short {
			if before == "V" {
				ptov[pkg.name] = pkg.version
			}
			if before == "p" {
			}
			continue
		}

		switch before {
		case "V":
			apk := fmt.Sprintf("%s-%s.apk", pkg.name, pkg.version)
			hexsum := "sha1:" + pkg.checksum
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
	if short && !added {
		if pkg.name != "" {
			pkgs = append(pkgs, pkg)
			added = true
		}
	}

	// pkgs is empty if short is false
	for _, pkg := range pkgs {
		last, ok := ptov[pkg.name]
		if !ok {
			return fmt.Errorf("did not see %q", pkg.name)
		}

		if !pkg.needs(depends) {
			continue
		}

		if !pkg.satisfies(provides) {
			continue
		}

		apk := fmt.Sprintf("%s-%s.apk", pkg.name, pkg.version)
		hexsum := "sha1:" + pkg.checksum
		href := fmt.Sprintf("%s@%s", path.Join(prefix, apk), hexsum)

		bold := pkg.version == last
		if !bold {
			fmt.Fprintf(w, "<a class=%q href=%q>%s</a>\n", "mt", href, apk)
		} else {
			fmt.Fprintf(w, "<a href=%q>%s</a>\n", href, apk)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	fmt.Fprintf(w, "</div></pre>\n</body>\n</html>\n")

	return nil
}

func (h *handler) renderPkgInfo(w http.ResponseWriter, r *http.Request, in io.Reader, ref string) error {
	if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
		return err
	}

	header := headerData(ref, v1.Descriptor{})
	before, _, ok := strings.Cut(ref, "@")
	if ok {
		u := "https://" + strings.TrimSuffix(strings.TrimPrefix(before, "/https/"), "/")
		header.JQ = "curl -L" + " " + u + " | tar -Oxz .PKGINFO"
	}

	// TODO: We need a cookie or something.
	apkindex := path.Join(path.Dir(before), "APKINDEX.tar.gz", "APKINDEX")

	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	fmt.Fprintf(w, "<pre><div>")

	scanner := bufio.NewScanner(bufio.NewReaderSize(in, 1<<16))

	pkg := pkginfo{}

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, "=")
		if !ok {

			fmt.Fprintf(w, "%s\n", line)

			continue
		}

		before = strings.TrimSpace(before)
		after = strings.TrimSpace(after)

		switch before {
		case "origin":
			pkg.origin = after
		case "commit":
			pkg.commit = after
		}

		switch before {
		case "commit":
			if !strings.Contains(r.URL.Path, "packages.wolfi.dev") {
				fmt.Fprintf(w, "%s\n", line)
				continue
			}

			href := fmt.Sprintf("https://github.com/wolfi-dev/os/blob/%s/%s.yaml", pkg.commit, pkg.origin)
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "pkgname":
			href := fmt.Sprintf("%s?depend=%s", apkindex, url.QueryEscape(after))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "depend":
			href := fmt.Sprintf("%s?provide=%s", apkindex, url.QueryEscape(after))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "provides":
			p, _, ok := strings.Cut(after, "=")
			if !ok {
				p = after
			}
			href := fmt.Sprintf("%s?depend=%s", apkindex, url.QueryEscape(p))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "size":
			i, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as int: %w", after, err)
			}
			fmt.Fprintf(w, "%s = <span title=%q>%s</span>\n", before, humanize.Bytes(uint64(i)), after)
		case "builddate":
			sec, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", after, err)
			}
			t := time.Unix(sec, 0)
			fmt.Fprintf(w, "%s = <span title=%q>%s</span>\n", before, t.String(), after)
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

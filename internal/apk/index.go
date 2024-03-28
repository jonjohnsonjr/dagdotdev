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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/logs"
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
		dep := depend

		// TODO: This is insane.
		equals := false

		name, ver, fuzzy := strings.Cut(depend, "=~")
		if !fuzzy {
			name, ver, fuzzy = strings.Cut(depend, "~")
		}
		if fuzzy {
			dep = name
		} else {
			name, ver, equals = strings.Cut(depend, "=")
			if equals {
				dep = name
			}
		}

		if _, ok := a.provides[dep]; !ok {
			if a.name != dep {
				return false
			}
		}

		if ver != "" {
			if equals {
				if a.version != ver {
					return false
				}
			}
			if fuzzy {
				want := strings.Split(ver, ".")
				have := strings.Split(a.version, ".")

				if len(want) > len(have) {
					return false
				}

				for i := range want {
					if want[i] != have[i] {
						return false
					}
				}
			}
		}
	}

	return true
}

func (h *handler) renderIndex(w http.ResponseWriter, r *http.Request, in io.Reader, ref string) error {
	logs.Debug.Printf("renderIndex(%q)", ref)
	short := r.URL.Query().Get("short") != "false"
	full := r.URL.Query().Get("full") != "" && r.URL.Query().Get("full") != "false"
	provides := r.URL.Query()["provide"]
	provides = slices.DeleteFunc(provides, func(s string) bool {
		return s == ""
	})
	depends := r.URL.Query()["depend"]
	depends = slices.DeleteFunc(depends, func(s string) bool {
		return s == ""
	})
	search := r.URL.Query().Get("search")

	pkgs := []apkindex{}
	ptov := map[string]string{}

	isCurl := r.Header.Get("Accept") == "*/*"
	if !isCurl {
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}
	}

	header := headerData(ref, v1.Descriptor{})
	header.ShowSearch = true
	if search != "" {
		header.Search = search
	}
	header.Full = full

	// TODO: Add search into the links.
	before, _, ok := strings.Cut(ref, "@")
	if ok {
		u, err := refToUrl(before)
		if err != nil {
			return err
		}
		scheme, after, ok := strings.Cut(u, "://")
		if !ok {
			return fmt.Errorf("no scheme in %q", u)
		}
		u = scheme + "://" + strings.TrimSuffix(after, "/")
		if scheme == "file" {
			u = strings.TrimPrefix(u, "file://")
		}

		// u := "https://" + strings.TrimSuffix(strings.TrimPrefix(before, "/https/"), "/")
		u = fmt.Sprintf("<a class=%q, href=%q>%s</a>", "mt", path.Dir(r.URL.Path), u)
		if short {
			// TODO: This stuff is not super robust. We could write a real awk program to do it better.

			// Link to long form.
			if scheme == "file" {
				header.JQ = "cat" + " " + u + ` | ` + fmt.Sprintf(`tar -Oxz <a class="mt" href="?short=false&search=%s">APKINDEX</a>`, search)
			} else {
				header.JQ = "curl -sL" + " " + u + ` | ` + fmt.Sprintf(`tar -Oxz <a class="mt" href="?short=false&search=%s">APKINDEX</a>`, search)
			}

			if len(provides) == 0 && len(depends) == 0 {
				// awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'
				header.JQ += ` | awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk\n", $2}'`

				u := r.URL
				q := u.Query()

				firstLink := "all packages"

				if full {
					q.Set("full", "false")
				} else {
					firstLink = "latest packages"
					q.Set("full", "true")
				}

				u.RawQuery = q.Encode()
				firstHref := u.String()
				firstMsg := fmt.Sprintf("<a class=\"mt\" href=%q>%s</a>", firstHref, firstLink)

				secondMessage := "in APKINDEX"
				if search != "" {
					secondMessage = fmt.Sprintf("that contain %q", search)
				}

				header.Message = fmt.Sprintf("# %s %s", firstMsg, secondMessage)
			} else {
				header.Expanded = true
				if len(provides) != 0 {
					header.Provide = provides[0]
					// awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk", $2} $1 == "p" { printf " %s", substr($0, 3)} /^$/ {printf "\n"}' | grep "so:libc.so.6" | cut -d" " -f1
					header.JQ += ` | awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk", $2} $1 == "p" { printf " %s", substr($0, 3)} /^$/ {printf "\n"}'`

					for _, dep := range provides {
						header.JQ += ` | grep "` + dep + `"`
					}

					header.JQ += ` | cut -d" " -f1`
					header.JQ += ` # this is approximate`

					firstLink := "all packages"
					firstHref := strings.ReplaceAll(r.URL.String(), "full=true", "full=false")
					firstMsg := fmt.Sprintf("<a class=\"mt\" href=%q>%s</a>", firstHref, firstLink)

					if !full {
						firstLink = "latest packages"
						firstHref = strings.ReplaceAll(r.URL.String(), "full=false", "full=true")
						firstMsg = fmt.Sprintf("<a class=\"mt\" href=%q>%s</a>", firstHref, firstLink)
					}

					secondHref := strings.ReplaceAll(r.URL.String(), "provide=", "depend=")
					secondLink := " provide " + strings.Join(provides, ", ")
					secondMsg := fmt.Sprintf("<a class=\"mt\" href=%q>%s</a>", secondHref, secondLink)

					header.Message = fmt.Sprintf("# %s that %s ", firstMsg, secondMsg)
				} else {
					header.Depend = depends[0]
					header.JQ += ` | awk -F':' '$1 == "P" {printf "%s-", $2} $1 == "V" {printf "%s.apk", $2} $1 == "D" { printf " %s", substr($0, 3)} /^$/ {printf "\n"}'`

					for _, dep := range depends {
						header.JQ += ` | grep "` + dep + `"`
					}

					header.JQ += ` | cut -d" " -f1`
					header.JQ += ` # this is approximate`

					firstLink := "all packages"
					firstHref := strings.ReplaceAll(r.URL.String(), "full=true", "full=false")
					firstMsg := fmt.Sprintf("<a class=\"mt\" href=%q>%s</a>", firstHref, firstLink)

					if !full {
						firstLink = "latest packages"
						firstHref = strings.ReplaceAll(r.URL.String(), "full=false", "full=true")
						firstMsg = fmt.Sprintf("<a class=\"mt\" href=%q>%s</a>", firstHref, firstLink)
					}

					secondHref := strings.ReplaceAll(r.URL.String(), "depend=", "provide=")
					secondLink := " depend on " + strings.Join(depends, ", ")
					secondMsg := fmt.Sprintf("<a class=\"mt\" href=%q>%s</a>", secondHref, secondLink)

					header.Message = fmt.Sprintf("# %s that %s ", firstMsg, secondMsg)
				}
			}

			if search != "" {
				header.JQ += fmt.Sprintf(" | grep %q", search)
			}
		} else {
			if scheme == "file" {
				header.JQ = "cat" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
			} else {
				header.JQ = "curl -sL" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
			}
		}
	} else if before, _, ok := strings.Cut(ref, "APKINDEX.tar.gz"); ok {
		before = path.Join(before, "APKINDEX.tar.gz")

		u, err := refToUrl(before)
		if err != nil {
			return err
		}
		scheme, after, ok := strings.Cut(u, "://")
		if !ok {
			return fmt.Errorf("no scheme in %q", u)
		}
		u = scheme + "://" + strings.TrimSuffix(after, "/")
		if scheme == "file" {
			u = strings.TrimPrefix(u, "file://")
		}
		u = fmt.Sprintf("<a class=%q, href=%q>%s</a>", "mt", path.Dir(r.URL.Path), u)
		if short {
			// Link to long form.
			if scheme == "file" {
				header.JQ = "cat" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
			} else {
				header.JQ = "curl -sL" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=false&search=%s">APKINDEX</a>`, search)
			}

			// awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'
			header.JQ += ` | awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'`
		} else {
			if scheme == "file" {
				header.JQ = "cat" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
			} else {
				header.JQ = "curl -sL" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
			}
		}
	}

	if !isCurl {
		if err := bodyTmpl.Execute(w, header); err != nil {
			return err
		}

		fmt.Fprintf(w, "<pre><div>")
	}

	scanner := bufio.NewScanner(bufio.NewReaderSize(in, 1<<16))

	prefix, _, ok := strings.Cut(r.URL.Path, "APKINDEX.tar.gz")
	if !ok {
		return fmt.Errorf("something funky with path...")
	}

	added := false
	pkg := apkindex{}

	prevLines := []string{}
	skip := false

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

			if !skip {
				if !short {
					if !isCurl {
						fmt.Fprintf(w, "</div><div>\n")
					} else {
						fmt.Fprintf(w, "\n")
					}
				}
			}

			skip = false

			continue
		}

		if skip {
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
				} else {
					pkg.provides[i] = ""
				}
			}
		case "D":
			pkg.depends = strings.Split(after, " ")
		}

		if short {
			if before == "V" {
				_, exists := ptov[pkg.name]

				prerelease := strings.Contains(pkg.version, "_") &&
					strings.Contains(pkg.version, "_alpha") ||
					strings.Contains(pkg.version, "_beta") ||
					strings.Contains(pkg.version, "_rc")

				// Don't overwrite non-prerelease versions with prerelease versions.
				if prerelease && exists {
					continue
				}

				ptov[pkg.name] = pkg.version
			}
			if before == "p" {
			}
			continue
		}

		switch before {
		case "C", "P":
			if search != "" {
				prevLines = append(prevLines, line)
				skip = false
			} else {
				fmt.Fprintf(w, "%s\n", line)
			}
		case "V":
			apk := fmt.Sprintf("%s-%s.apk", pkg.name, pkg.version)
			hexsum := "sha1:" + pkg.checksum
			href := fmt.Sprintf("%s@%s", path.Join(prefix, apk), hexsum)

			// Set skip so that we don't print anything until the next "P:".
			if search != "" {
				if strings.HasPrefix(search, "^") {
					if !strings.HasPrefix(apk, search[1:]) {
						// log.Printf("!HasPrefix(%q, %q)", apk, search[1:])
						skip = true
					}
				} else {
					if !strings.Contains(apk, search) {
						// log.Printf("!Contains(%q, %q)", apk, search)
						skip = true
					}
				}
			}

			if !skip {
				// Since we buffer the P: line, we need to print it if this matches.
				for _, prevLine := range prevLines {
					fmt.Fprintf(w, "%s\n", prevLine)
				}

				if !isCurl {
					fmt.Fprintf(w, "<a id=%q href=%q>V:%s</a>\n", apk, href, pkg.version)
				} else {
					fmt.Fprintf(w, "V:%s\n", pkg.version)
				}
			}
			prevLines = []string{}

		case "S", "I":
			i, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as int: %w", after, err)
			}
			if !isCurl {
				fmt.Fprintf(w, "%s:<span title=%q>%s</span>\n", before, humanize.Bytes(uint64(i)), after)
			} else {
				fmt.Fprintf(w, "%s:%s\n", before, after)
			}
		case "t":
			sec, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", after, err)
			}
			t := time.Unix(sec, 0)
			if !isCurl {
				fmt.Fprintf(w, "<span title=%q>t:%s</span>\n", t.String(), after)
			} else {
				fmt.Fprintf(w, "%s:%s\n", before, after)
			}
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
	if short {
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

			if search != "" {
				if strings.HasPrefix(search, "^") {
					if !strings.HasPrefix(apk, search[1:]) {
						continue
					}
				} else {
					if !strings.Contains(apk, search) {
						continue
					}
				}
			}
			bold := pkg.version == last
			if !bold {
				if full {
					if !isCurl {
						fmt.Fprintf(w, "<a class=%q href=%q>%s</a>\n", "mt", href, apk)
					} else {
						fmt.Fprintf(w, "%s\n", apk)
					}
				}
			} else {
				if !isCurl {
					fmt.Fprintf(w, "<a href=%q>%s</a>\n", href, apk)
				} else {
					fmt.Fprintf(w, "%s\n", apk)
				}
			}
		}
	}

	if short && !full {
		if !isCurl {
			fmt.Fprintf(w, "\n<a title=%q href=%q>...</a>", "show old versions", "?full=true")
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	if !isCurl {
		fmt.Fprintf(w, "</div></pre>\n</body>\n</html>\n")
	}

	return nil
}

func (h *handler) renderPkgInfo(w http.ResponseWriter, r *http.Request, in io.Reader, ref string) error {
	if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
		return err
	}

	header := headerData(ref, v1.Descriptor{})
	before, _, ok := strings.Cut(ref, "@")
	if ok {
		u, err := refToUrl(before)
		if err != nil {
			return err
		}

		scheme, after, ok := strings.Cut(u, "://")
		if !ok {
			return fmt.Errorf("no scheme in %q", u)
		}
		dir := scheme + "://" + path.Dir(after)
		if scheme == "file" {
			dir = strings.TrimPrefix(dir, "file://")
		}
		base := path.Base(u)

		index := path.Join(path.Dir(before), "APKINDEX.tar.gz")

		href := fmt.Sprintf("<a class=%q href=%q>%s</a>/<a class=%q href=%q>%s</a>", "mt", index, dir, "mt", ref, base)

		u = href

		if scheme == "file" {
			header.JQ = "cat" + " " + u + " | tar -Oxz .PKGINFO"
		} else {
			header.JQ = "curl -sL" + " " + u + " | tar -Oxz .PKGINFO"
		}
	}

	// TODO: We need a cookie or something.
	apkindex := path.Join(path.Dir(before), "APKINDEX.tar.gz", "APKINDEX")
	sizeHref := path.Join("/size", path.Dir(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/https/"), "/")))

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
		case "origin":
			if strings.Contains(r.URL.Path, "packages.wolfi.dev") {
				href := fmt.Sprintf("https://github.com/wolfi-dev/os/blob/main/%s.yaml", pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
			} else if strings.Contains(r.URL.Path, "packages.cgr.dev") {
				// TODO
				fmt.Fprintf(w, "%s\n", line)
			} else {
				fmt.Fprintf(w, "%s\n", line)
			}
		case "commit":
			if strings.Contains(r.URL.Path, "packages.wolfi.dev") {
				href := fmt.Sprintf("https://github.com/wolfi-dev/os/blob/%s/%s.yaml", pkg.commit, pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
			} else if strings.Contains(r.URL.Path, "packages.cgr.dev") {
				// TODO
				fmt.Fprintf(w, "%s\n", line)
			} else if strings.Contains(r.URL.Path, "dl-cdn.alpinelinux.org/alpine/edge/main") {
				href := fmt.Sprintf("https://gitlab.alpinelinux.org/alpine/aports/-/blob/%s/main/%s/APKBUILD", pkg.commit, pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
			} else {
				fmt.Fprintf(w, "%s\n", line)
			}

		case "pkgname":
			href := fmt.Sprintf("%s?depend=%s&full=true", apkindex, url.QueryEscape(after))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "depend":
			href := fmt.Sprintf("%s?provide=%s&full=true", apkindex, url.QueryEscape(after))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "provides":
			p, _, ok := strings.Cut(after, "=")
			if !ok {
				p = after
			}
			href := fmt.Sprintf("%s?depend=%s&full=true", apkindex, url.QueryEscape(p))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "size":
			i, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as int: %w", after, err)
			}
			fmt.Fprintf(w, "%s = <a title=%q href=%q>%s</a>\n", before, humanize.Bytes(uint64(i)), sizeHref, after)
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

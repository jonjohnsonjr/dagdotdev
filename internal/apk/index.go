package apk

import (
	"bufio"
	"cmp"
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

	"chainguard.dev/apko/pkg/apk/apk"
	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/logs"
	httpserve "github.com/jonjohnsonjr/dagdotdev/internal/forks/http"
)

type apkindex struct {
	origin    string
	checksum  string
	name      string
	version   string
	apk       string
	provides  map[string]string
	depends   []string
	builddate int64
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

// TODO: We want to be able to render links inside APKINDEX full view too like .PKGINFO (commit, origin, etc)
func (h *handler) renderApkError(w http.ResponseWriter, r *http.Request, ref string, err error) error {
	before, _, ok := strings.Cut(ref, ".apk")
	if !ok {
		return fmt.Errorf("this shouldn't happen: %w", err)
	}
	li := strings.LastIndex(before, "/")
	if li == -1 {
		return fmt.Errorf("this shouldn't happen: %w", err)
	}
	apkindex, apk := path.Join(before[:li], "APKINDEX.tar.gz", "APKINDEX"), before[li+1:]
	href := fmt.Sprintf("%s?short=false&search=%s", apkindex, apk)
	msg := fmt.Sprintf(`Could not load APK, <a href="%s">see APKINDEX entry</a>`, href)

	httpserve.ServeContent(w, r, "", time.Time{}, strings.NewReader(err.Error()), func(w http.ResponseWriter, r *http.Request, ctype string) error {
		// Kind at this poin can be "gzip", "zstd" or ""
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}
		header := headerData(ref)

		before, _, ok := strings.Cut(ref, "@")
		if ok {
			u, err := refToUrl(before)
			if err == nil {
				if strings.Contains(ref, "apk.cgr.dev/chainguard-private") {
					header.JQ = "curl -sL" + printToken + " " + u
				} else {
					header.JQ = "curl -sL" + " " + u
				}
			}
		}

		header.Message = msg

		return bodyTmpl.Execute(w, header)
	})

	return nil
}

func (h *handler) renderIndex(w http.ResponseWriter, r *http.Request, open func() (io.ReadCloser, error), ref string) error {
	logs.Debug.Printf("renderIndex(%q)", ref)
	short := r.URL.Query().Get("short") != "false"

	if short {
		return h.renderShort(w, r, open, ref)
	}

	return h.renderExpanded(w, r, open, ref)
}

func (h *handler) renderExpanded(w http.ResponseWriter, r *http.Request, open func() (io.ReadCloser, error), ref string) error {
	logs.Debug.Printf("renderExpanded(%q)", ref)
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

	isCurl := r.Header.Get("Accept") == "*/*"
	if !isCurl {
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}
	}

	header := headerData(ref)
	header.ShowSearch = true
	if search != "" {
		header.Search = search
	}
	header.Full = full

	if len(provides) != 0 {
		header.Expanded = true
		header.Provide = provides[0]
	}
	if len(depends) != 0 {
		header.Expanded = true
		header.Depend = depends[0]
	}

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
		if scheme == "file" {
			header.JQ = "cat" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
		} else {
			header.JQ = "curl -sL" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
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
		if scheme == "file" {
			header.JQ = "cat" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
		} else {
			header.JQ = "curl -sL" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
		}
	}

	if !isCurl {
		if err := bodyTmpl.Execute(w, header); err != nil {
			return err
		}

		fmt.Fprintf(w, "<pre><div>")
	}

	in, err := open()
	if err != nil {
		return err
	}
	defer in.Close()

	scanner := bufio.NewScanner(bufio.NewReaderSize(in, 1<<16))

	// Allow 1MB of allocations because some lines are huge in alpine, like community/coq.provides.
	// Default to 16KB because the default is 4KB which is too small even for wolfi.
	buf := make([]byte, 16*1024)
	big := 1024 * 1024
	scanner.Buffer(buf, big)

	prefix, _, ok := strings.Cut(r.URL.Path, "APKINDEX.tar.gz")
	if !ok {
		return fmt.Errorf("something funky with path...")
	}

	pkg := apkindex{}

	prevLines := []string{}
	skip := false

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, ":")
		if !ok {
			skip = skip || !pkg.needs(depends) || !pkg.satisfies(provides)
			if !skip {
				// Since we buffer the P: line, we need to print it if this matches.
				for _, prevLine := range prevLines {
					fmt.Fprintf(w, "%s\n", prevLine)
				}

				if !isCurl {
					fmt.Fprintf(w, "</div><div>\n")
				} else {
					fmt.Fprintf(w, "\n")
				}
			}
			prevLines = []string{}

			// reset pkg
			pkg = apkindex{}
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

		switch before {
		case "o":
			pkg.origin = strings.TrimSpace(after)
			if search != "" {
				if strings.Contains(r.URL.Path, "packages.wolfi.dev") {
					href := fmt.Sprintf("https://github.com/wolfi-dev/os/blob/main/%s.yaml", pkg.origin)
					prevLines = append(prevLines, fmt.Sprintf("<a href=%q>%s:%s</a>", href, before, after))
				} else if strings.Contains(r.URL.Path, "packages.cgr.dev") {
					href := fmt.Sprintf("https://github.com/chainguard-dev/enterprise-packages/blob/main/%s.yaml", pkg.origin)
					prevLines = append(prevLines, fmt.Sprintf("<a href=%q>%s:%s</a>", href, before, after))
				} else {
					prevLines = append(prevLines, line)
				}
			} else {
				prevLines = append(prevLines, line)
			}
		case "c":
			commit := strings.TrimSpace(after)
			if search != "" && pkg.origin != "" {
				if strings.Contains(r.URL.Path, "packages.wolfi.dev") {
					href := fmt.Sprintf("https://github.com/wolfi-dev/os/blob/%s/%s.yaml", commit, pkg.origin)
					prevLines = append(prevLines, fmt.Sprintf("<a href=%q>%s:%s</a>", href, before, after))
				} else if strings.Contains(r.URL.Path, "packages.cgr.dev") {
					href := fmt.Sprintf("https://github.com/chainguard-dev/enterprise-packages/blob/%s/%s.yaml", commit, pkg.origin)
					prevLines = append(prevLines, fmt.Sprintf("<a href=%q>%s:%s</a>", href, before, after))
				} else if strings.Contains(r.URL.Path, "dl-cdn.alpinelinux.org/alpine/edge/main") {
					href := fmt.Sprintf("https://gitlab.alpinelinux.org/alpine/aports/-/blob/%s/main/%s/APKBUILD", commit, pkg.origin)
					prevLines = append(prevLines, fmt.Sprintf("<a href=%q>%s:%s</a>", href, before, after))
				} else {
					prevLines = append(prevLines, line)
				}
			} else {
				prevLines = append(prevLines, line)
			}
		case "C", "P":
			prevLines = append(prevLines, line)
		case "V":
			apk := pkg.name + "-" + pkg.version + ".apk"

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

			hexsum := "sha1:" + pkg.checksum
			href := path.Join(prefix, apk) + "@" + hexsum

			if !isCurl {
				prevLines = append(prevLines, fmt.Sprintf("<a id=%q href=%q>V:%s</a>", apk, href, pkg.version))
			} else {
				prevLines = append(prevLines, fmt.Sprintf("%s:%s", before, after))
			}
		case "S", "I":
			i, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as int: %w", after, err)
			}
			if !isCurl {
				prevLines = append(prevLines, fmt.Sprintf("%s:<span title=%q>%s</span>", before, humanize.IBytes(uint64(i)), after))
			} else {
				prevLines = append(prevLines, fmt.Sprintf("%s:%s", before, after))
			}
		case "t":
			sec, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", after, err)
			}
			t := time.Unix(sec, 0)
			if !isCurl {
				prevLines = append(prevLines, fmt.Sprintf("<span title=%q>t:%s</span>", t.String(), after))
			} else {
				prevLines = append(prevLines, fmt.Sprintf("%s:%s", before, after))
			}
		default:
			prevLines = append(prevLines, line)
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

// TODO: Cache parsed APKINDEX and go directly here if we're short.
func (h *handler) renderShort(w http.ResponseWriter, r *http.Request, open func() (io.ReadCloser, error), ref string) error {
	logs.Debug.Printf("renderShort(%q)", ref)
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

	isCurl := r.Header.Get("Accept") == "*/*"
	if !isCurl {
		if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
			return err
		}
	}

	header := headerData(ref)
	header.ShowSearch = true
	if search != "" {
		header.Search = search
	}
	header.Full = full

	// TODO: Add search into the kinks.
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
		// TODO: This stuff is not super robust. We could write a real awk program to do it better.

		qs := make(url.Values)
		qs.Set("short", "false")
		qs.Set("search", search)

		// Kinda hacky but usually we only do one.
		for _, p := range provides {
			qs.Add("provide", p)
		}
		for _, d := range depends {
			qs.Add("depend", d)
		}
		href := "?" + qs.Encode()

		// Link to long form.
		if scheme == "file" {
			header.JQ = "cat" + " " + u + ` | ` + fmt.Sprintf(`tar -Oxz <a class="mt" href=%q">APKINDEX</a>`, href)
		} else {
			header.JQ = "curl -sL" + " " + u + ` | ` + fmt.Sprintf(`tar -Oxz <a class="mt" href=%q>APKINDEX</a>`, href)
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
		// Link to long form.
		if scheme == "file" {
			header.JQ = "cat" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=true&search=%s">APKINDEX</a>`, search)
		} else {
			header.JQ = "curl -sL" + " " + u + fmt.Sprintf(` | tar -Oxz <a class="mt" href="?short=false&search=%s">APKINDEX</a>`, search)
		}

		// awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'
		header.JQ += ` | awk -F':' '/^P:/{printf "%s-", $2} /^V:/{printf "%s.apk\n", $2}'`
	}

	if !isCurl {
		if err := bodyTmpl.Execute(w, header); err != nil {
			return err
		}

		fmt.Fprintf(w, `<div><template shadowrootmode="open"><pre><slot name="contents">Loading...</slot></pre></template>`)

		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		fmt.Fprintf(w, "<pre slot=\"contents\">\n")
	}

	prefix, _, ok := strings.Cut(r.URL.Path, "APKINDEX.tar.gz")
	if !ok {
		return fmt.Errorf("something funky with path...")
	}
	prefix = strings.TrimSuffix(prefix, "/")

	in, err := open()
	if err != nil {
		return err
	}
	defer in.Close()

	pkgs, ptov, err := h.parseIndex(w, r, in, ref)
	if err != nil {
		return err
	}

	if r.URL.Query().Get("sort") == "t" {
		slices.SortFunc(pkgs, func(a, b apkindex) int {
			return cmp.Compare(a.builddate, b.builddate)
		})
	}

	for _, pkg := range pkgs {
		if !pkg.needs(depends) {
			continue
		}

		if !pkg.satisfies(provides) {
			continue
		}

		apk := pkg.apk

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

		href := prefix + "/" + apk + "@" + "sha1:" + pkg.checksum + "/"

		last, ok := ptov[pkg.name]
		if !ok {
			return fmt.Errorf("did not see %q", pkg.name)
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

	if !full {
		if !isCurl {
			u := r.URL
			q := u.Query()
			q.Set("full", "true")
			u.RawQuery = q.Encode()
			fmt.Fprintf(w, "\n<a title=%q href=%q>...</a>", "show old versions", u.String())
		}
	}

	if !isCurl {
		fmt.Fprintf(w, "\n</pre>\n</div>\n</body>\n</html>\n")
	}

	return nil
}

func (h *handler) parseIndex(w http.ResponseWriter, r *http.Request, in io.Reader, ref string) ([]apkindex, map[string]string, error) {
	if pkgs, ptov, ok := h.apkCache.Get(ref); ok {
		return pkgs, ptov, nil
	}

	pkgs := []apkindex{}
	ptov := map[string]string{}

	scanner := bufio.NewScanner(bufio.NewReaderSize(in, 1<<16))

	// Allow 1MB of allocations because some lines are huge in alpine, like community/coq.provides.
	// Default to 16KB because the default is 4KB which is too small even for wolfi.
	buf := make([]byte, 16*1024)
	big := 1024 * 1024
	scanner.Buffer(buf, big)

	pkg := apkindex{}

	skip := false

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, ":")
		if !ok {
			if pkg.name != "" {
				pkg.apk = pkg.name + "-" + pkg.version + ".apk"
				pkgs = append(pkgs, pkg)
			}

			// reset pkg
			pkg = apkindex{}
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
				return nil, nil, fmt.Errorf("base64 decode: %w", err)
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
		case "t":
			i, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot parse build time %s: %w", before, err)
			}
			pkg.builddate = i
		}

		if before == "V" {
			got, exists := ptov[pkg.name]

			prerelease := strings.Contains(pkg.version, "_") &&
				strings.Contains(pkg.version, "_alpha") ||
				strings.Contains(pkg.version, "_beta") ||
				strings.Contains(pkg.version, "_rc")

			// Don't overwrite non-prerelease versions with prerelease versions.
			if prerelease && exists {
				continue
			}

			old, err := apk.ParseVersion(got)
			if err != nil {
				ptov[pkg.name] = pkg.version
			} else {
				new, err := apk.ParseVersion(pkg.version)
				if err == nil {
					if apk.CompareVersions(old, new) < 0 {
						ptov[pkg.name] = pkg.version
					}
				}
			}
		}
	}

	if pkg.name != "" {
		pkg.apk = pkg.name + "-" + pkg.version + ".apk"
		pkgs = append(pkgs, pkg)
	}

	h.apkCache.Put(ref, pkgs, ptov)

	return pkgs, ptov, nil
}

func (h *handler) renderPkgInfo(w http.ResponseWriter, r *http.Request, in io.Reader, ref string) error {
	if err := headerTmpl.Execute(w, TitleData{title(ref)}); err != nil {
		return err
	}

	header := headerData(ref)
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
			} else if strings.Contains(r.URL.Path, "apk.cgr.dev/extra-packages") {
				href := fmt.Sprintf("https://github.com/chainguard-dev/extra-packages/blob/main/%s.yaml", pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
			} else if strings.Contains(r.URL.Path, "apk.cgr.dev/chainguard-private") {
				href := fmt.Sprintf("https://github.com/chainguard-dev/enterprise-packages/blob/main/%s.yaml", pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
			} else {
				fmt.Fprintf(w, "%s\n", line)
			}
		case "commit":
			if strings.Contains(r.URL.Path, "packages.wolfi.dev") {
				href := fmt.Sprintf("https://github.com/wolfi-dev/os/blob/%s/%s.yaml", pkg.commit, pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
			} else if strings.Contains(r.URL.Path, "apk.cgr.dev/extra-packages") {
				href := fmt.Sprintf("https://github.com/chainguard-dev/extra-packages/blob/%s/%s.yaml", pkg.commit, pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
			} else if strings.Contains(r.URL.Path, "apk.cgr.dev/chainguard-private") {
				href := fmt.Sprintf("https://github.com/chainguard-dev/enterprise-packages/blob/%s/%s.yaml", pkg.commit, pkg.origin)
				fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
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
			fmt.Fprintf(w, "%s = <a title=%q href=%q>%s</a>\n", before, humanize.IBytes(uint64(i)), sizeHref, after)
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

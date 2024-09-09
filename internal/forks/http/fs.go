// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP file system request handler

package http

import (
	"archive/tar"
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/elf"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/safefilepath"
	"github.com/jonjohnsonjr/dagdotdev/internal/xxd"
	"golang.org/x/exp/slices"
)

const TooBig = elf.TooBig

// HeaderRenderer renders a header for a FileSystem.
type HeaderRenderer interface {
	RenderHeader(w http.ResponseWriter, r *http.Request, name string, f File, ctype string) error
}

// A Dir implements FileSystem using the native file system restricted to a
// specific directory tree.
//
// While the FileSystem.Open method takes '/'-separated paths, a Dir's string
// value is a filename on the native file system, not a URL, so it is separated
// by filepath.Separator, which isn't necessarily '/'.
//
// Note that Dir could expose sensitive files and directories. Dir will follow
// symlinks pointing out of the directory tree, which can be especially dangerous
// if serving from a directory in which users are able to create arbitrary symlinks.
// Dir will also allow access to files and directories starting with a period,
// which could expose sensitive directories like .git or sensitive files like
// .htpasswd. To exclude files with a leading period, remove the files/directories
// from the server or create a custom FileSystem implementation.
//
// An empty Dir is treated as ".".
type Dir string

// RenderHeader is unused.
func (d Dir) RenderHeader(w http.ResponseWriter, r *http.Request, name string, f File, ctype string) error {
	// We don't use this.
	return nil
}

// mapOpenError maps the provided non-nil error from opening name
// to a possibly better non-nil error. In particular, it turns OS-specific errors
// about opening files in non-directories into fs.ErrNotExist. See Issues 18984 and 49552.
func mapOpenError(originalErr error, name string, sep rune, stat func(string) (fs.FileInfo, error)) error {
	if errors.Is(originalErr, fs.ErrNotExist) || errors.Is(originalErr, fs.ErrPermission) {
		return originalErr
	}

	parts := strings.Split(name, string(sep))
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := stat(strings.Join(parts[:i+1], string(sep)))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return fs.ErrNotExist
		}
	}
	return originalErr
}

// Open implements FileSystem using os.Open, opening files for reading rooted
// and relative to the directory d.
func (d Dir) Open(name string) (File, error) {
	path, err := safefilepath.FromFS(path.Clean("/" + name))
	if err != nil {
		return nil, errors.New("http: invalid or unsafe file path")
	}
	dir := string(d)
	if dir == "" {
		dir = "."
	}
	fullName := filepath.Join(dir, path)
	f, err := os.Open(fullName)
	if err != nil {
		return nil, mapOpenError(err, fullName, filepath.Separator, os.Stat)
	}
	return f, nil
}

// A FileSystem implements access to a collection of named files.
// The elements in a file path are separated by slash ('/', U+002F)
// characters, regardless of host operating system convention.
// See the FileServer function to convert a FileSystem to a Handler.
//
// This interface predates the fs.FS interface, which can be used instead:
// the FS adapter function converts an fs.FS to a FileSystem.
type FileSystem interface {
	Open(name string) (File, error)
	HeaderRenderer
}

// A File is returned by a FileSystem's Open method and can be
// served by the FileServer implementation.
//
// The methods should behave the same as those on an *os.File.
type File interface {
	io.Closer
	io.Reader
	io.Seeker
	Readdir(count int) ([]fs.FileInfo, error)
	Stat() (fs.FileInfo, error)
}

type anyDirs interface {
	len() int
	name(i int) string
	isDir(i int) bool
	info(i int) (fs.FileInfo, error)
	layer(i int) string
	whiteout(i int) string
	overwritten(i int) string
	index(i int) int
}

type fileInfoDirs []fs.FileInfo

func (d fileInfoDirs) len() int                        { return len(d) }
func (d fileInfoDirs) isDir(i int) bool                { return d[i].IsDir() }
func (d fileInfoDirs) name(i int) string               { return d[i].Name() }
func (d fileInfoDirs) info(i int) (fs.FileInfo, error) { return d[i], nil }
func (d fileInfoDirs) layer(i int) string              { return "" }
func (d fileInfoDirs) whiteout(i int) string           { return "" }
func (d fileInfoDirs) overwritten(i int) string        { return "" }
func (d fileInfoDirs) index(i int) int                 { return 0 }

type dirEntryDirs []fs.DirEntry

func (d dirEntryDirs) len() int                        { return len(d) }
func (d dirEntryDirs) isDir(i int) bool                { return d[i].IsDir() }
func (d dirEntryDirs) name(i int) string               { return d[i].Name() }
func (d dirEntryDirs) info(i int) (fs.FileInfo, error) { return d[i].Info() }
func (d dirEntryDirs) layer(i int) string {
	if wl, ok := d[i].(withLayer); ok {
		return wl.Layer()
	}
	return ""
}
func (d dirEntryDirs) whiteout(i int) string {
	if se, ok := d[i].(sociEntry); ok {
		return se.Whiteout()
	}
	return ""
}
func (d dirEntryDirs) overwritten(i int) string {
	if se, ok := d[i].(sociEntry); ok {
		return se.Overwritten()
	}
	return ""
}
func (d dirEntryDirs) index(i int) int {
	if se, ok := d[i].(sociEntry); ok {
		return se.Index()
	}
	return 0
}

type withLayer interface {
	Layer() string
}

type sociEntry interface {
	Whiteout() string
	Overwritten() string
	Index() int
}

func DirList(w http.ResponseWriter, r *http.Request, fsys FileSystem, prefix string, des []fs.DirEntry, render func() error) error {
	logs.Debug.Printf("DirList: %q", prefix)

	var dirs dirEntryDirs = des

	apks := map[string]string{}
	ownerLength := 0
	if fsys != nil {
		if db, err := fsys.Open("lib/apk/db/installed"); err != nil {
			log.Printf("no apk: %v", err)
		} else {
			scanner := bufio.NewScanner(db)
			owner := ""
			dir := ""
			for scanner.Scan() {
				line := scanner.Text()
				k, v, ok := strings.Cut(line, ":")
				if !ok {
					owner, dir = "", ""
					continue
				}
				switch k {
				case "P":
					owner = v
					ownerLength = max(len(owner), ownerLength)
				case "R":
					fullName := path.Join(dir, v)
					apks[fullName] = owner
					got, err := fsys.Open(fullName)
					if err != nil {
						log.Printf("apk open: %v", err)
						continue
					}
					fi, err := got.Stat()
					if err != nil {
						log.Printf("apk stat: %v", err)
						continue
					}
					header, ok := fi.Sys().(*tar.Header)
					if !ok {
						continue
					}
					if header.Name != fullName {
						log.Printf("apk name: %q != %q", header.Name, fullName)
						apks[header.Name] = owner
					}

				case "F":
					dir = v
				}
			}
			if err := scanner.Err(); err != nil {
				log.Printf("apk scan: %v", err)
			}
		}
	}

	search := r.URL.Query().Get("search")
	if search != "" {
		dirs = slices.DeleteFunc(dirs, func(de fs.DirEntry) bool {
			fi, err := de.Info()
			if err != nil {
				return true
			}

			header, ok := fi.Sys().(*tar.Header)
			if !ok {
				return true
			}

			if strings.HasPrefix(search, "^") {
				return !strings.HasPrefix(header.Name, search[1:])
			}
			return !strings.Contains(header.Name, search)
		})
	}

	showlayer := strings.HasPrefix(r.URL.Path, "/sizes")
	less := func(i, j int) bool {
		ii, err := dirs.info(i)
		if err != nil {
			logs.Debug.Printf("info(%d): %v", i, err)
			return i < j
		}
		ji, err := dirs.info(j)
		if err != nil {
			logs.Debug.Printf("info(%d): %v", j, err)
			return i < j
		}
		return ii.Size() > ji.Size()
	}
	if showlayer {
		less = func(i, j int) bool {
			ii, err := dirs.info(i)
			if err != nil {
				logs.Debug.Printf("info(%d): %v", i, err)
				return i < j
			}
			ji, err := dirs.info(j)
			if err != nil {
				logs.Debug.Printf("info(%d): %v", j, err)
				return i < j
			}

			iw, jw := dirs.whiteout(i), dirs.whiteout(j)
			io, jo := dirs.overwritten(i), dirs.overwritten(j)
			iStays := iw == "" && io == ""
			jStays := jw == "" && jo == ""
			iStrike := iw != "" || io != ""
			jStrike := jw != "" || jo != ""

			if iStrike && jStays {
				return true
			} else if iStays && jStrike {
				return false
			}

			return ii.Size() > ji.Size()
		}
	}

	showAll := r.URL.Query().Get("all") == "true" || search != ""

	if !showAll {
		sort.Slice(dirs, less)
	}

	if len(dirs) > TooBig {
		dirs = dirs[0:TooBig]
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if render != nil {
		if err := render(); err != nil {
			return fmt.Errorf("render(): %w", err)
		}
	}

	fprefix := ""
	if _, after, ok := strings.Cut(prefix, "@"); ok {
		if _, after, ok := strings.Cut(after, "/"); ok {
			fprefix = after
		} else {
			fprefix = "/"
		}
	}

	fmt.Fprintf(w, "<pre>\n")
	for i, n := 0, dirs.len(); i < n; i++ {
		name := dirs.name(i)
		if dirs.isDir(i) {
			name += "/"
		}
		info, err := dirs.info(i)
		if err != nil {
			log.Printf("(%q).info(): %v", name, err)
		}
		// name may contain '?' or '#', which must be escaped to remain
		// part of the URL path, and not indicate the start of a query
		// string or fragment.
		u := url.URL{Path: strings.TrimPrefix(name, "/")}

		if info == nil {
			fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", u.String(), htmlReplacer.Replace(name))
		} else if showAll {
			if strings.HasPrefix(name, fprefix) || fprefix == "/" {
				u.Path = strings.TrimPrefix(u.Path, fprefix)
				u.Path = strings.TrimPrefix(u.Path, "/")
				fmt.Fprint(w, tarListAll(i, dirs, info, u, prefix, fprefix, r.URL.Query().Get("pax") == "true"))
			}
		} else {
			fmt.Fprint(w, tarListSize(i, dirs, showlayer, info, u, prefix, apks, ownerLength))
			fmt.Fprint(w, "\n")
		}
	}
	fmt.Fprintf(w, "</pre>\n</body>\n</html>")
	return nil
}

func dirList(w http.ResponseWriter, r *http.Request, fname string, f File, render renderFunc) {
	logs.Debug.Printf("dirList: %q", fname)
	prefix := fname

	// Prefer to use ReadDir instead of Readdir,
	// because the former doesn't require calling
	// Stat on every entry of a directory on Unix.
	var dirs anyDirs
	var err error
	if d, ok := f.(fs.ReadDirFile); ok {
		var list dirEntryDirs
		list, err = d.ReadDir(-1)
		dirs = list
	} else {
		var list fileInfoDirs
		list, err = f.Readdir(-1)
		dirs = list
	}

	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}
	less := func(i, j int) bool {
		in, jn := dirs.name(i), dirs.name(j)
		if in == ".." {
			return true
		} else if jn == ".." {
			return false
		}

		if !strings.HasPrefix(r.URL.Path, "/layers/") && !strings.HasPrefix(r.URL.Path, "/sizes/") {
			return i < j
		}

		// Only interesting for overlays.
		if in == jn {
			iw, jw := dirs.whiteout(i), dirs.whiteout(j)
			io, jo := dirs.overwritten(i), dirs.overwritten(j)
			ii, ji := dirs.index(i), dirs.index(j)

			iStays := iw == "" && io == ""
			jStrike := jw != "" || jo != ""
			if iStays && jStrike {
				return true
			}

			if ji != ii {
				return ii < ji
			}
		}

		return in < jn
	}
	sort.Slice(dirs, less)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if render != nil {
		if err := render(w, r, ""); err != nil {
			logs.Debug.Printf("render(w): %v", err)
		}
	}
	showlayer := strings.HasPrefix(r.URL.Path, "/layers")

	fstat, err := f.Stat()
	if err != nil {
		logs.Debug.Printf("fstat: %v", err)
	} else {
		header, ok := fstat.Sys().(*tar.Header)
		if ok {
			prefix = strings.TrimSuffix(prefix, strings.TrimSuffix(header.Name, "/"))
		}
	}

	fmt.Fprintf(w, "<pre>\n")
	for i, n := 0, dirs.len(); i < n; i++ {
		name := dirs.name(i)
		if dirs.isDir(i) {
			name += "/"
		}
		info, err := dirs.info(i)
		if err != nil {
			log.Printf("(%q).info(): %v", name, err)
		}
		// name may contain '?' or '#', which must be escaped to remain
		// part of the URL path, and not indicate the start of a query
		// string or fragment.
		url := url.URL{Path: strings.TrimPrefix(name, "/")}
		if info == nil {
			fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), htmlReplacer.Replace(name))
		} else {
			fmt.Fprint(w, tarList(i, dirs, showlayer, info, url, prefix))
		}
	}
	fmt.Fprintf(w, "</pre>\n</body>\n</html>")
}

func tarListAll(i int, dirs anyDirs, fi fs.FileInfo, u url.URL, uprefix, fprefix string, pax bool) string {
	header, ok := fi.Sys().(*tar.Header)
	if !ok {
		name := fi.Name()
		ts := "????-??-?? ??:??"
		ug := "?/?"
		mode := "d?????????"
		padding := 18 - len(ug)
		s := fmt.Sprintf("%s %s %*d %s", mode, ug, padding, 0, ts)
		s += fmt.Sprintf(" <a href=\"%s\">%s</a>\n", u.String(), htmlReplacer.Replace(name))
		return s
	}
	ts := header.ModTime.Format("2006-01-02 15:04")
	ug := fmt.Sprintf("%d/%d", header.Uid, header.Gid)
	mode := modeStr(header)
	padding := 18 - len(ug)
	s := fmt.Sprintf("%s %s <span title=%q>%*d</span> %s", mode, ug, humanize.Bytes(uint64(header.Size)), padding, header.Size, ts)

	name := dirs.name(i)
	if header.Linkname != "" {
		if header.Linkname == "." {
			u.Path = path.Dir(u.Path)
		} else if containsDotDot(header.Linkname) {
			u.Path = strings.TrimPrefix(header.Linkname, "/")
		} else if strings.HasPrefix(header.Linkname, "/") {
			u.Path = path.Join(strings.TrimSuffix(uprefix, fprefix), header.Linkname)
		} else {
			u.Path = path.Join(u.Path, "..", header.Linkname)
		}
		if header.Typeflag == tar.TypeLink {
			name += " link to " + header.Linkname
		} else {
			name += " -> " + header.Linkname
		}
	}

	s += fmt.Sprintf(" <a href=\"%s?all=true\">%s</a>\n", u.String(), htmlReplacer.Replace(name))
	if pax {
		for k, v := range header.PAXRecords {
			s += fmt.Sprintf("    %s: %s\n", htmlReplacer.Replace(k), htmlReplacer.Replace(v))
		}
		if len(header.PAXRecords) != 0 {
			s += "\n"
		}
	}
	return s
}

func tarList(i int, dirs anyDirs, showlayer bool, fi fs.FileInfo, u url.URL, uprefix string) string {
	layer := dirs.layer(i)
	whiteout := dirs.whiteout(i)
	overwritten := dirs.overwritten(i)

	prefix := "        "

	header, ok := fi.Sys().(*tar.Header)
	if !ok {
		name := fi.Name()
		ts := "????-??-?? ??:??"
		ug := "?/?"
		mode := "d?????????"
		padding := 18 - len(ug)
		s := fmt.Sprintf("%s %s %*d %s", mode, ug, padding, 0, ts)
		if showlayer {
			s = prefix + " " + s
		}
		s += fmt.Sprintf(" <a href=\"%s\">%s</a>\n", u.String(), htmlReplacer.Replace(name))
		return s
	}
	ts := header.ModTime.Format("2006-01-02 15:04")
	ug := fmt.Sprintf("%d/%d", header.Uid, header.Gid)
	mode := modeStr(header)
	padding := 18 - len(ug)
	s := fmt.Sprintf("%s %s <span title=%q>%*d</span> %s", mode, ug, humanize.Bytes(uint64(header.Size)), padding, header.Size, ts)
	if showlayer {
		if _, after, ok := strings.Cut(layer, "@"); ok {
			if _, after, ok := strings.Cut(after, ":"); ok {
				if len(after) > 8 {
					href := after[:8]
					u := url.URL{Path: "/fs/" + strings.TrimPrefix(layer, "/")}
					prefix = fmt.Sprintf("<a href=%q>%s</a>", u.String(), href)
				}
			}
		}
		s = prefix + " " + s
	}
	name := fi.Name()
	if header.Linkname != "" {
		if header.Linkname == "." {
			u.Path = path.Dir(u.Path)
		} else if containsDotDot(header.Linkname) {
			u.Path = strings.TrimPrefix(header.Linkname, "/")
		} else if strings.HasPrefix(header.Linkname, "/") {
			u.Path = path.Join(uprefix, header.Linkname)
		} else {
			u.Path = path.Join(u.Path, "..", header.Linkname)
		}
		if header.Typeflag == tar.TypeLink {
			name += " link to " + header.Linkname
		} else {
			name += " -> " + header.Linkname
		}
	}

	if whiteout != "" {
		u.Path = path.Join("/fs/", layer, header.Name)
		title := fmt.Sprintf("deleted by %s", whiteout)
		if _, after, ok := strings.Cut(whiteout, "@"); ok {
			if _, after, ok := strings.Cut(after, ":"); ok && len(after) > 8 {
				title = fmt.Sprintf("deleted by %s", after[:8])
			}
		}
		s += fmt.Sprintf(" <a href=\"%s\"><strike title=%q>%s</strike></a>\n", u.String(), title, htmlReplacer.Replace(name))
	} else if overwritten != "" {
		u.Path = path.Join("/fs/", layer, header.Name)
		title := fmt.Sprintf("overwritten by %s", overwritten)
		if _, after, ok := strings.Cut(overwritten, "@"); ok {
			if _, after, ok := strings.Cut(after, ":"); ok && len(after) > 8 {
				title = fmt.Sprintf("overwritten by %s", after[:8])
			}
		}
		s += fmt.Sprintf(" <a href=\"%s\"><strike title=%q>%s</strike></a>\n", u.String(), title, htmlReplacer.Replace(name))
	} else {
		s += fmt.Sprintf(" <a href=\"%s\">%s</a>\n", u.String(), htmlReplacer.Replace(name))
	}
	return s
}

func tarListSize(i int, dirs anyDirs, showlayer bool, fi fs.FileInfo, u url.URL, uprefix string, apks map[string]string, ownerLength int) string {
	layer := dirs.layer(i)
	whiteout := dirs.whiteout(i)
	overwritten := dirs.overwritten(i)

	prefix := "        "

	header, ok := fi.Sys().(*tar.Header)
	if !ok {
		name := fi.Name()
		ts := "????-??-?? ??:??"
		ug := "?/?"
		mode := "d?????????"
		padding := 18 - len(ug)
		s := fmt.Sprintf("%s %s %*d %s", mode, ug, padding, 0, ts)
		if showlayer {
			s = prefix + " " + s
		}
		s += fmt.Sprintf(" %s", htmlReplacer.Replace(name))
		return s
	}
	ts := header.ModTime.Format("2006-01-02 15:04")
	ug := fmt.Sprintf("%d/%d", header.Uid, header.Gid)
	mode := modeStr(header)
	padding := 18 - len(ug)
	s := fmt.Sprintf("%s %s <span title=%q>%*d</span> %s", mode, ug, humanize.Bytes(uint64(header.Size)), padding, header.Size, ts)
	if showlayer {
		if _, after, ok := strings.Cut(layer, "@"); ok {
			if _, after, ok := strings.Cut(after, ":"); ok {
				if len(after) > 8 {
					href := after[:8]
					prefix = fmt.Sprintf("<small>%s</small>", href)
				}
			}
		}
		s = prefix + " " + s
	}
	if ownerLength != 0 {
		owner := apks[header.Name]
		s = fmt.Sprintf("<small>%*s</small> ", ownerLength, owner) + s
	}
	name := dirs.name(i)
	if header.Linkname != "" {
		if header.Linkname == "." {
			u.Path = path.Dir(u.Path)
		} else if containsDotDot(header.Linkname) {
			u.Path = strings.TrimPrefix(header.Linkname, "/")
		} else if strings.HasPrefix(header.Linkname, "/") {
			u.Path = path.Join(uprefix, header.Linkname)
		} else {
			u.Path = path.Join(u.Path, "..", header.Linkname)
		}
		if header.Typeflag == tar.TypeLink {
			name += " link to " + header.Linkname
		} else {
			name += " -> " + header.Linkname
		}
	}

	if whiteout != "" {
		u.Path = path.Join("/fs/", layer, header.Name)
		title := fmt.Sprintf("deleted by %s", whiteout)
		if _, after, ok := strings.Cut(whiteout, "@"); ok {
			if _, after, ok := strings.Cut(after, ":"); ok && len(after) > 8 {
				title = fmt.Sprintf("deleted by %s", after[:8])
			}
		}
		s += fmt.Sprintf(" <strike title=%q><small>%s</small></strike>", title, htmlReplacer.Replace(name))
	} else if overwritten != "" {
		u.Path = path.Join("/fs/", layer, header.Name)
		title := fmt.Sprintf("overwritten by %s", overwritten)
		if _, after, ok := strings.Cut(overwritten, "@"); ok {
			if _, after, ok := strings.Cut(after, ":"); ok && len(after) > 8 {
				title = fmt.Sprintf("overwritten by %s", after[:8])
			}
		}
		s += fmt.Sprintf(" <strike title=%q><small>%s</small></strike>", title, htmlReplacer.Replace(name))
	} else {
		s += fmt.Sprintf(" %s", htmlReplacer.Replace(name))
	}
	return s
}

func TarList(fi fs.FileInfo, u url.URL, uprefix string) string {
	header, ok := fi.Sys().(*tar.Header)
	if !ok {
		name := fi.Name()
		ts := "????-??-?? ??:??"
		ug := "?/?"
		mode := "d?????????"
		padding := 18 - len(ug)
		s := fmt.Sprintf("%s %s %*d %s", mode, ug, padding, 0, ts)
		s += fmt.Sprintf(" <a href=\"%s\">%s</a>\n", u.String(), htmlReplacer.Replace(name))
		return s
	}
	ts := header.ModTime.Format("2006-01-02 15:04")
	ug := fmt.Sprintf("%d/%d", header.Uid, header.Gid)
	mode := modeStr(header)
	padding := 18 - len(ug)
	s := fmt.Sprintf("%s %s <span title=%q>%*d</span> %s", mode, ug, humanize.Bytes(uint64(header.Size)), padding, header.Size, ts)
	name := fi.Name()
	if header.Linkname != "" {
		if header.Linkname == "." {
			u.Path = path.Dir(u.Path)
		} else if containsDotDot(header.Linkname) {
			u.Path = strings.TrimPrefix(header.Linkname, "/")
		} else if strings.HasPrefix(header.Linkname, "/") {
			u.Path = path.Join(uprefix, header.Linkname)
		} else {
			u.Path = path.Join(u.Path, "..", header.Linkname)
		}
		if header.Typeflag == tar.TypeLink {
			name += " link to " + header.Linkname
		} else {
			name += " -> " + header.Linkname
		}
	}

	s += fmt.Sprintf(" <a href=\"%s\">%s</a>\n", u.String(), htmlReplacer.Replace(name))
	return s
}

func modeStr(hdr *tar.Header) string {
	fi := hdr.FileInfo()
	mm := fi.Mode()

	mode := []byte(fs.FileMode(hdr.Mode).String())
	mode[0] = typeStr(hdr.Typeflag)

	if mm&fs.ModeSetuid != 0 {
		if mm&0100 != 0 {
			mode[3] = 's'
		} else {
			mode[3] = 'S'
		}
	}
	if mm&fs.ModeSetgid != 0 {
		if mm&0010 != 0 {
			mode[6] = 's'
		} else {
			mode[6] = 'S'
		}
	}
	if mm&fs.ModeSticky != 0 {
		if mm&0001 != 0 {
			mode[9] = 't'
		} else {
			mode[9] = 'T'
		}
	}
	return string(mode)
}

func typeStr(t byte) byte {
	switch t {
	case tar.TypeReg:
		return '-'
	case tar.TypeLink:
		return 'h'
	case tar.TypeSymlink:
		return 'l'
	case tar.TypeDir:
		return 'd'
	case tar.TypeChar:
		return 'c'
	case tar.TypeBlock:
		return 'b'
	case tar.TypeFifo:
		return 'p'
	}

	return '?'
}

type Sizer interface {
	Size() int64
}

// ServeContent replies to the request using the content in the
// provided ReadSeeker. The main benefit of ServeContent over io.Copy
// is that it handles Range requests properly, sets the MIME type, and
// handles If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since,
// and If-Range requests.
//
// If the response's Content-Type header is not set, ServeContent
// first tries to deduce the type from name's file extension and,
// if that fails, falls back to reading the first block of the content
// and passing it to DetectContentType.
// The name is otherwise unused; in particular it can be empty and is
// never sent in the response.
//
// If modtime is not the zero time or Unix epoch, ServeContent
// includes it in a Last-Modified header in the response. If the
// request includes an If-Modified-Since header, ServeContent uses
// modtime to decide whether the content needs to be sent at all.
//
// The content's Seek method must work: ServeContent uses
// a seek to the end of the content to determine its size.
//
// If the caller has set w's ETag header formatted per RFC 7232, section 2.3,
// ServeContent uses it to handle requests using If-Match, If-None-Match, or If-Range.
//
// Note that *os.File implements the io.ReadSeeker interface.
func ServeContent(w http.ResponseWriter, req *http.Request, name string, modtime time.Time, content io.ReadSeeker, render renderFunc) {
	sizeFunc := func() (int64, error) {
		if s, ok := content.(Sizer); ok {
			return s.Size(), nil
		}
		size, err := content.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, errSeeker
		}
		_, err = content.Seek(0, io.SeekStart)
		if err != nil {
			return 0, errSeeker
		}
		return size, nil
	}
	serveContent(w, req, name, modtime, sizeFunc, content, render)
}

// errSeeker is returned by ServeContent's sizeFunc when the content
// doesn't seek properly. The underlying Seeker's error text isn't
// included in the sizeFunc reply so it's not sent over HTTP to end
// users.
var errSeeker = errors.New("seeker can't seek")

// errNoOverlap is returned by serveContent's parseRange if first-byte-pos of
// all of the byte-range-spec values is greater than the content size.
var errNoOverlap = errors.New("invalid range: failed to overlap")

// TODO: Define sentinel error to return early.
type renderFunc func(w http.ResponseWriter, r *http.Request, ctype string) error

// if name is empty, filename is unknown. (used for mime type, before sniffing)
// if modtime.IsZero(), modtime is unknown.
// content must be seeked to the beginning of the file.
// The sizeFunc is called at most once. Its error, if any, is sent in the HTTP response.
func serveContent(w http.ResponseWriter, r *http.Request, name string, modtime time.Time, sizeFunc func() (int64, error), content io.ReadSeeker, render renderFunc) {
	setLastModified(w, modtime)
	done, rangeReq := checkPreconditions(w, r, modtime)
	if done {
		return
	}

	code := http.StatusOK
	br := bufio.NewReaderSize(content, sniffLen)

	isElf := false
	// If Content-Type isn't set, use the file's extension to find it, but
	// if the Content-Type is unset explicitly, do not sniff the type.
	ctypes, haveType := w.Header()["Content-Type"]
	var ctype string
	if !haveType {
		ctype = mime.TypeByExtension(filepath.Ext(name))
		if ctype == "" {
			// read a chunk to decide between utf-8 text and binary
			buf, err := br.Peek(sniffLen)
			if err != nil && err != io.EOF {
				http.Error(w, "serveContent.Peek: "+err.Error(), http.StatusInternalServerError)
				return
			}

			ctype = DetectContentType(buf)
			logs.Debug.Printf("DetectContentType = %s", ctype)

			if len(buf) > 4 {
				if buf[0] == '\x7f' || buf[1] == 'E' || buf[2] == 'L' || buf[3] == 'F' {
					isElf = true
					w.Header().Del("Last-Modified")
					ctype = "elf"
				}
			}
		} else {
			logs.Debug.Printf("ByExtension = %s", ctype)
		}
		w.Header().Set("Content-Type", ctype)
	} else if len(ctypes) > 0 {
		ctype = ctypes[0]
	}

	size, err := sizeFunc()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if size < 0 {
		if _, ok := w.(http.Flusher); !ok {
			// Should never happen but just to be sure
			http.Error(w, "negative content size computed", http.StatusInternalServerError)
			return
		}
	}

	// handle Content-Range header.
	sendSize := size
	var sendContent io.Reader = br
	ranges, err := parseRange(rangeReq, size)
	switch err {
	case nil:
	case errNoOverlap:
		if size == 0 {
			// Some clients add a Range header to all requests to
			// limit the size of the response. If the file is empty,
			// ignore the range header and respond with a 200 rather
			// than a 416.
			ranges = nil
			break
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		fallthrough
	default:
		http.Error(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	if sumRangesSize(ranges) > size {
		// The total number of bytes in all the ranges
		// is larger than the size of the file by
		// itself, so this is probably an attack, or a
		// dumb client. Ignore the range request.
		ranges = nil
	}
	switch {
	case len(ranges) == 1:
		// RFC 7233, Section 4.1:
		// "If a single part is being transferred, the server
		// generating the 206 response MUST generate a
		// Content-Range header field, describing what range
		// of the selected representation is enclosed, and a
		// payload consisting of the range.
		// ...
		// A server MUST NOT generate a multipart response to
		// a request for a single range, since a client that
		// does not request multiple parts might not support
		// multipart responses."
		ra := ranges[0]
		if _, err := content.Seek(ra.start, io.SeekStart); err != nil {
			http.Error(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
			return
		}
		sendSize = ra.length
		code = http.StatusPartialContent
		w.Header().Set("Content-Range", ra.contentRange(size))
	case len(ranges) > 1:
		sendSize = rangesMIMESize(ranges, ctype, size)
		code = http.StatusPartialContent

		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		w.Header().Set("Content-Type", "multipart/byteranges; boundary="+mw.Boundary())
		sendContent = pr
		defer pr.Close() // cause writing goroutine to fail and exit if CopyN doesn't finish.
		go func() {
			for _, ra := range ranges {
				part, err := mw.CreatePart(ra.mimeHeader(ctype, size))
				if err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := content.Seek(ra.start, io.SeekStart); err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := io.CopyN(part, content, ra.length); err != nil {
					pw.CloseWithError(err)
					return
				}
			}
			mw.Close()
			pw.Close()
		}()
	}

	if render != nil && r.URL.Query().Get("dl") == "" {
		if err := render(w, r, ctype); err != nil {
			logs.Debug.Printf("render(w): %v", err)
		} else {
			fmt.Fprintf(w, "<pre>")
		}
	} else {
		w.Header().Set("Accept-Ranges", "bytes")
		if w.Header().Get("Content-Encoding") == "" {
			if sendSize >= 0 {
				w.Header().Set("Content-Length", strconv.FormatInt(sendSize, 10))
			}
		}

		w.WriteHeader(code)
	}

	if r.Method != "HEAD" {
		if render != nil && r.URL.Query().Get("dl") == "" {
			logs.Debug.Printf("ctype=%q", ctype)
			if sendSize < 0 || sendSize > TooBig {
				sendSize = TooBig
			}

			if isElf {
				key := r.URL.Path
				if r.URL.Query().Get("render") == "elf" {
					err := elf.Print(w, size, br, key)
					if err != nil {
						log.Printf("elf print: %v", err)
						http.Error(w, "elf.Print: "+err.Error(), http.StatusInternalServerError)
						return
					}
				} else {
					pr, err := elf.Xxd(w, size, br, key)
					if err != nil {
						log.Printf("elf xxd: %v", err)
						http.Error(w, "<p>elf.Xxd: "+err.Error()+"</p>", http.StatusInternalServerError)

						rw := w
						var w io.Writer

						w = xxd.NewWriter(rw, sendSize)
						if sendSize < 0 {
							if _, err := io.Copy(w, pr); err != nil {
								logs.Debug.Printf("Copy: %v", err)
							}
						} else {
							if _, err := io.CopyN(w, pr, sendSize); err != nil {
								logs.Debug.Printf("CopyN: %v", err)
							}
						}

						return
					}
				}
			} else {
				rw := w
				var w io.Writer

				if strings.HasPrefix(ctype, "text/") || strings.Contains(ctype, "json") || ctype == "application/x-sh" {
					w = &dumbEscaper{buf: bufio.NewWriter(rw)}
				} else {
					w = xxd.NewWriter(rw, sendSize)
				}

				if sendSize < 0 {
					if _, err := io.Copy(w, sendContent); err != nil {
						logs.Debug.Printf("Copy: %v", err)
					}
				} else {
					if _, err := io.CopyN(w, sendContent, sendSize); err != nil {
						logs.Debug.Printf("CopyN: %v", err)
					}
				}
			}
		} else {
			logs.Debug.Printf("got here :(")
			io.CopyN(w, sendContent, sendSize)
		}
	}

	if render != nil && r.URL.Query().Get("dl") == "" {
		fmt.Fprintf(w, "</pre>\n</body>\n</html>\n")
	}
}

// scanETag determines if a syntactically valid ETag is present at s. If so,
// the ETag and remaining text after consuming ETag is returned. Otherwise,
// it returns "", "".
func scanETag(s string) (etag string, remain string) {
	s = textproto.TrimString(s)
	start := 0
	if strings.HasPrefix(s, "W/") {
		start = 2
	}
	if len(s[start:]) < 2 || s[start] != '"' {
		return "", ""
	}
	// ETag is either W/"text" or "text".
	// See RFC 7232 2.3.
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		// Character values allowed in ETags.
		case c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80:
		case c == '"':
			return s[:i+1], s[i+1:]
		default:
			return "", ""
		}
	}
	return "", ""
}

// etagStrongMatch reports whether a and b match using strong ETag comparison.
// Assumes a and b are valid ETags.
func etagStrongMatch(a, b string) bool {
	return a == b && a != "" && a[0] == '"'
}

// etagWeakMatch reports whether a and b match using weak ETag comparison.
// Assumes a and b are valid ETags.
func etagWeakMatch(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// condResult is the result of an HTTP request precondition check.
// See https://tools.ietf.org/html/rfc7232 section 3.
type condResult int

const (
	condNone condResult = iota
	condTrue
	condFalse
)

func checkIfMatch(w http.ResponseWriter, r *http.Request) condResult {
	im := r.Header.Get("If-Match")
	if im == "" {
		return condNone
	}
	for {
		im = textproto.TrimString(im)
		if len(im) == 0 {
			break
		}
		if im[0] == ',' {
			im = im[1:]
			continue
		}
		if im[0] == '*' {
			return condTrue
		}
		etag, remain := scanETag(im)
		if etag == "" {
			break
		}
		if etagStrongMatch(etag, w.Header().Get("Etag")) {
			return condTrue
		}
		im = remain
	}

	return condFalse
}

func checkIfUnmodifiedSince(r *http.Request, modtime time.Time) condResult {
	ius := r.Header.Get("If-Unmodified-Since")
	if ius == "" || isZeroTime(modtime) {
		return condNone
	}
	t, err := http.ParseTime(ius)
	if err != nil {
		return condNone
	}

	// The Last-Modified header truncates sub-second precision so
	// the modtime needs to be truncated too.
	modtime = modtime.Truncate(time.Second)
	if modtime.Equal(t) || modtime.Before(t) {
		return condTrue
	}
	return condFalse
}

func checkIfNoneMatch(w http.ResponseWriter, r *http.Request) condResult {
	inm := r.Header.Get("If-None-Match")
	if inm == "" {
		return condNone
	}
	buf := inm
	for {
		buf = textproto.TrimString(buf)
		if len(buf) == 0 {
			break
		}
		if buf[0] == ',' {
			buf = buf[1:]
			continue
		}
		if buf[0] == '*' {
			return condFalse
		}
		etag, remain := scanETag(buf)
		if etag == "" {
			break
		}
		if etagWeakMatch(etag, w.Header().Get("Etag")) {
			return condFalse
		}
		buf = remain
	}
	return condTrue
}

func checkIfModifiedSince(r *http.Request, modtime time.Time) condResult {
	if r.Method != "GET" && r.Method != "HEAD" {
		return condNone
	}
	ims := r.Header.Get("If-Modified-Since")
	if ims == "" || isZeroTime(modtime) {
		return condNone
	}
	t, err := http.ParseTime(ims)
	if err != nil {
		return condNone
	}
	// The Last-Modified header truncates sub-second precision so
	// the modtime needs to be truncated too.
	modtime = modtime.Truncate(time.Second)
	if modtime.Equal(t) || modtime.Before(t) {
		return condFalse
	}
	return condTrue
}

func checkIfRange(w http.ResponseWriter, r *http.Request, modtime time.Time) condResult {
	if r.Method != "GET" && r.Method != "HEAD" {
		return condNone
	}
	ir := r.Header.Get("If-Range")
	if ir == "" {
		return condNone
	}
	etag, _ := scanETag(ir)
	if etag != "" {
		if etagStrongMatch(etag, w.Header().Get("Etag")) {
			return condTrue
		} else {
			return condFalse
		}
	}
	// The If-Range value is typically the ETag value, but it may also be
	// the modtime date. See golang.org/issue/8367.
	if modtime.IsZero() {
		return condFalse
	}
	t, err := http.ParseTime(ir)
	if err != nil {
		return condFalse
	}
	if t.Unix() == modtime.Unix() {
		return condTrue
	}
	return condFalse
}

var unixEpochTime = time.Unix(0, 0)

// isZeroTime reports whether t is obviously unspecified (either zero or Unix()=0).
func isZeroTime(t time.Time) bool {
	return t.IsZero() || t.Equal(unixEpochTime)
}

func setLastModified(w http.ResponseWriter, modtime time.Time) {
	if !isZeroTime(modtime) {
		w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	}
}

func writeNotModified(w http.ResponseWriter) {
	// RFC 7232 section 4.1:
	// a sender SHOULD NOT generate representation metadata other than the
	// above listed fields unless said metadata exists for the purpose of
	// guiding cache updates (e.g., Last-Modified might be useful if the
	// response does not have an ETag field).
	h := w.Header()
	delete(h, "Content-Type")
	delete(h, "Content-Length")
	delete(h, "Content-Encoding")
	if h.Get("Etag") != "" {
		delete(h, "Last-Modified")
	}
	w.WriteHeader(http.StatusNotModified)
}

// checkPreconditions evaluates request preconditions and reports whether a precondition
// resulted in sending StatusNotModified or StatusPreconditionFailed.
func checkPreconditions(w http.ResponseWriter, r *http.Request, modtime time.Time) (done bool, rangeHeader string) {
	// This function carefully follows RFC 7232 section 6.
	ch := checkIfMatch(w, r)
	if ch == condNone {
		ch = checkIfUnmodifiedSince(r, modtime)
	}
	if ch == condFalse {
		w.WriteHeader(http.StatusPreconditionFailed)
		return true, ""
	}
	switch checkIfNoneMatch(w, r) {
	case condFalse:
		if r.Method == "GET" || r.Method == "HEAD" {
			writeNotModified(w)
			return true, ""
		} else {
			w.WriteHeader(http.StatusPreconditionFailed)
			return true, ""
		}
	case condNone:
		if checkIfModifiedSince(r, modtime) == condFalse {
			writeNotModified(w)
			return true, ""
		}
	}

	rangeHeader = r.Header.Get("Range")
	if rangeHeader != "" && checkIfRange(w, r, modtime) == condFalse {
		rangeHeader = ""
	}
	return false, rangeHeader
}

// name is '/'-separated, not filepath.Separator.
func serveFile(w http.ResponseWriter, r *http.Request, fsys FileSystem, name string, redirect bool) {
	f, err := fsys.Open(name)
	if err != nil {
		logs.Debug.Printf("serveFile: %v", err)
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	defer f.Close()

	d, err := f.Stat()
	if err != nil {
		logs.Debug.Printf("serveFile: %v", err)
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}

	if redirect {
		// redirect to canonical path: / at end of directory url
		// r.URL.Path always begins with /
		url := r.URL.Path
		if d.IsDir() {
			if url[len(url)-1] != '/' {
				localRedirect(w, r, path.Base(url)+"/")
				return
			}
		} else {
			if url[len(url)-1] == '/' {
				localRedirect(w, r, "../"+path.Base(url))
				return
			}
		}
	}

	if d.IsDir() {
		url := r.URL.Path
		// redirect if the directory name doesn't end in a slash
		if url == "" || url[len(url)-1] != '/' {
			localRedirect(w, r, path.Base(url)+"/")
			return
		}
	}

	render := func(w http.ResponseWriter, r *http.Request, ctype string) error {
		return fsys.RenderHeader(w, r, name, f, ctype)
	}

	// Still a directory? (we didn't find an index.html file)
	if d.IsDir() {
		if checkIfModifiedSince(r, d.ModTime()) == condFalse {
			writeNotModified(w)
			return
		}
		setLastModified(w, d.ModTime())

		if r.URL.Query().Get("all") == "true" || r.URL.Query().Get("search") != "" {
			if ifs, ok := fsys.(ioFS); ok {
				if efs, ok := ifs.fsys.(interface {
					Everything() ([]fs.DirEntry, error)
				}); ok {
					des, err := efs.Everything()
					if err != nil {
						log.Printf("everything: %v", err)
					}

					renderf := func() error {
						if render == nil {
							return nil
						}
						return render(w, r, "")
					}
					if err := DirList(w, r, fsys, name, des, renderf); err != nil {
						log.Printf("DirList: %v", err)
					} else {
						return
					}
				}
			}
		}

		renderFiles(w, r, name, f, render)
		return
	}

	// serveContent will check modification time
	sizeFunc := func() (int64, error) { return d.Size(), nil }
	serveContent(w, r, d.Name(), d.ModTime(), sizeFunc, f, render)
}

type Files interface {
	Files() iter.Seq2[fs.FileInfo, error]
}

func renderFiles(w http.ResponseWriter, r *http.Request, fname string, f File, render renderFunc) {
	files, ok := f.(Files)
	if !ok {
		dirList(w, r, fname, f, render)
		return
	}

	logs.Debug.Printf("rendering Files")

	if render != nil {
		if err := render(w, r, ""); err != nil {
			logs.Debug.Printf("render(): %v", err)
		}
	}

	fmt.Fprintf(w, `<div><template shadowrootmode="open"><style>@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes twist-up {
  to {
    transform: rotateX(360deg);
  }
}</style><p><slot name="message">Loading... <span style="display: inline-block; animation: spin 1.0s infinite linear;">🤐</span></slot></p><pre><slot name="file"></slot></pre></template>`)

	start := time.Now()

	prefix := fname
	fstat, err := f.Stat()
	if err != nil {
		logs.Debug.Printf("fstat: %v", err)
	} else {
		header, ok := fstat.Sys().(*tar.Header)
		if ok {
			prefix = strings.TrimSuffix(prefix, strings.TrimSuffix(header.Name, "/"))
		}
	}

	for fi, err := range files.Files() {
		if err != nil {
			fmt.Fprintf(w, "error: %v\n", err)
			continue
		}

		name := fi.Name()
		if fi.IsDir() {
			name += "/"
		}
		// name may contain '?' or '#', which must be escaped to remain
		// part of the URL path, and not indicate the start of a query
		// string or fragment.
		url := url.URL{Path: strings.TrimPrefix(name, "/")}
		fmt.Fprintf(w, "<span slot=%q>%s</span>", "file", TarList(fi, url, prefix))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	// We need some kind of indication that we finished indexing, so include some interesting info.
	fmt.Fprintf(w, `<p slot="message">Indexed in %s</p>`, time.Since(start))

	fmt.Fprintf(w, "\n</div>\n</body>\n</html>")
}

// toHTTPError returns a non-specific HTTP error message and status code
// for a given non-nil error value. It's important that toHTTPError does not
// actually return err.Error(), since msg and httpStatus are returned to users,
// and historically Go's ServeContent always returned just "404 Not Found" for
// all errors. We don't want to start leaking information in error messages.
func toHTTPError(err error) (msg string, httpStatus int) {
	if errors.Is(err, fs.ErrNotExist) {
		return "404 page not found", http.StatusNotFound
	}
	if errors.Is(err, fs.ErrPermission) {
		return "403 Forbidden", http.StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", http.StatusInternalServerError
}

// localRedirect gives a Moved Permanently response.
// It does not convert relative paths to absolute paths like Redirect does.
func localRedirect(w http.ResponseWriter, r *http.Request, newPath string) {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)
}

// ServeFile replies to the request with the contents of the named
// file or directory.
//
// If the provided file or directory name is a relative path, it is
// interpreted relative to the current directory and may ascend to
// parent directories. If the provided name is constructed from user
// input, it should be sanitized before calling ServeFile.
//
// As a precaution, ServeFile will reject requests where r.URL.Path
// contains a ".." path element; this protects against callers who
// might unsafely use filepath.Join on r.URL.Path without sanitizing
// it and then use that filepath.Join result as the name argument.
//
// As another special case, ServeFile redirects any request where r.URL.Path
// ends in "/index.html" to the same path, without the final
// "index.html". To avoid such redirects either modify the path or
// use ServeContent.
//
// Outside of those two special cases, ServeFile does not use
// r.URL.Path for selecting the file or directory to serve; only the
// file or directory provided in the name argument is used.
func ServeFile(w http.ResponseWriter, r *http.Request, name string) {
	if containsDotDot(r.URL.Path) {
		// Too many programs use r.URL.Path to construct the argument to
		// serveFile. Reject the request under the assumption that happened
		// here and ".." may not be wanted.
		// Note that name might not contain "..", for example if code (still
		// incorrectly) used filepath.Join(myDir, r.URL.Path).
		http.Error(w, "invalid URL path", http.StatusBadRequest)
		return
	}
	dir, file := filepath.Split(name)
	serveFile(w, r, Dir(dir), file, false)
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }

type fileHandler struct {
	root FileSystem
}

type ioFS struct {
	fsys fs.FS
}

func (i ioFS) RenderHeader(w http.ResponseWriter, r *http.Request, name string, f File, ctype string) error {
	if hr, ok := i.fsys.(HeaderRenderer); ok {
		return hr.RenderHeader(w, r, name, f, ctype)
	}
	logs.Debug.Printf("i.fsys (%T) does not implement RenderHeader", i.fsys)
	return nil
}

type ioFile struct {
	file fs.File
}

func (f ioFS) Open(name string) (File, error) {
	if name == "/" {
		name = "."
	} else {
		name = strings.TrimPrefix(name, "/")
	}
	file, err := f.fsys.Open(name)
	if err != nil {
		return nil, mapOpenError(err, name, '/', func(path string) (fs.FileInfo, error) {
			return fs.Stat(f.fsys, path)
		})
	}
	return ioFile{file}, nil
}

func (f ioFile) Close() error               { return f.file.Close() }
func (f ioFile) Read(b []byte) (int, error) { return f.file.Read(b) }
func (f ioFile) Stat() (fs.FileInfo, error) { return f.file.Stat() }

var errMissingSeek = errors.New("io.File missing Seek method")
var errMissingReadDir = errors.New("io.File directory missing ReadDir method")

func (f ioFile) Seek(offset int64, whence int) (int64, error) {
	s, ok := f.file.(io.Seeker)
	if !ok {
		return 0, errMissingSeek
	}
	return s.Seek(offset, whence)
}

func (f ioFile) ReadDir(count int) ([]fs.DirEntry, error) {
	d, ok := f.file.(fs.ReadDirFile)
	if !ok {
		return nil, errMissingReadDir
	}
	return d.ReadDir(count)
}

func (f ioFile) Readdir(count int) ([]fs.FileInfo, error) {
	d, ok := f.file.(fs.ReadDirFile)
	if !ok {
		return nil, errMissingReadDir
	}
	var list []fs.FileInfo
	for {
		dirs, err := d.ReadDir(count - len(list))
		for _, dir := range dirs {
			info, err := dir.Info()
			if err != nil {
				// Pretend it doesn't exist, like (*os.File).Readdir does.
				continue
			}
			list = append(list, info)
		}
		if err != nil {
			return list, err
		}
		if count < 0 || len(list) >= count {
			break
		}
	}
	return list, nil
}

// FS converts fsys to a FileSystem implementation,
// for use with FileServer and NewFileTransport.
// The files provided by fsys must implement io.Seeker.
func FS(fsys fs.FS) FileSystem {
	return ioFS{fsys}
}

// FileServer returns a handler that serves HTTP requests
// with the contents of the file system rooted at root.
//
// As a special case, the returned file server redirects any request
// ending in "/index.html" to the same path, without the final
// "index.html".
//
// To use the operating system's file system implementation,
// use http.Dir:
//
//	http.Handle("/", http.FileServer(http.Dir("/tmp")))
//
// To use an fs.FS implementation, use http.FS to convert it:
//
//	http.Handle("/", http.FileServer(http.FS(fsys)))
func FileServer(root FileSystem) http.Handler {
	return &fileHandler{root}
}

func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const options = http.MethodOptions + ", " + http.MethodGet + ", " + http.MethodHead

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !strings.HasPrefix(r.URL.Path, "/") {
			r.URL.Path = "/" + r.URL.Path
		}
		serveFile(w, r, f.root, path.Clean(r.URL.Path), true)

	case http.MethodOptions:
		w.Header().Set("Allow", options)

	default:
		w.Header().Set("Allow", options)
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
	}
}

// httpRange specifies the byte range to be sent to the client.
type httpRange struct {
	start, length int64
}

func (r httpRange) contentRange(size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.start, r.start+r.length-1, size)
}

func (r httpRange) mimeHeader(contentType string, size int64) textproto.MIMEHeader {
	return textproto.MIMEHeader{
		"Content-Range": {r.contentRange(size)},
		"Content-Type":  {contentType},
	}
}

// parseRange parses a Range header string as per RFC 7233.
// errNoOverlap is returned if none of the ranges overlap.
func parseRange(s string, size int64) ([]httpRange, error) {
	if s == "" {
		return nil, nil // header not present
	}
	const b = "bytes="
	if !strings.HasPrefix(s, b) {
		return nil, errors.New("invalid range")
	}
	var ranges []httpRange
	noOverlap := false
	for _, ra := range strings.Split(s[len(b):], ",") {
		ra = textproto.TrimString(ra)
		if ra == "" {
			continue
		}
		start, end, ok := strings.Cut(ra, "-")
		if !ok {
			return nil, errors.New("invalid range")
		}
		start, end = textproto.TrimString(start), textproto.TrimString(end)
		var r httpRange
		if start == "" {
			// If no start is specified, end specifies the
			// range start relative to the end of the file,
			// and we are dealing with <suffix-length>
			// which has to be a non-negative integer as per
			// RFC 7233 Section 2.1 "Byte-Ranges".
			if end == "" || end[0] == '-' {
				return nil, errors.New("invalid range")
			}
			i, err := strconv.ParseInt(end, 10, 64)
			if i < 0 || err != nil {
				return nil, errors.New("invalid range")
			}
			if i > size {
				i = size
			}
			r.start = size - i
			r.length = size - r.start
		} else {
			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i < 0 {
				return nil, errors.New("invalid range")
			}
			if i >= size {
				// If the range begins after the size of the content,
				// then it does not overlap.
				noOverlap = true
				continue
			}
			r.start = i
			if end == "" {
				// If no end is specified, range extends to end of the file.
				r.length = size - r.start
			} else {
				i, err := strconv.ParseInt(end, 10, 64)
				if err != nil || r.start > i {
					return nil, errors.New("invalid range")
				}
				if i >= size {
					i = size - 1
				}
				r.length = i - r.start + 1
			}
		}
		ranges = append(ranges, r)
	}
	if noOverlap && len(ranges) == 0 {
		// The specified ranges did not overlap with the content.
		return nil, errNoOverlap
	}
	return ranges, nil
}

// countingWriter counts how many bytes have been written to it.
type countingWriter int64

func (w *countingWriter) Write(p []byte) (n int, err error) {
	*w += countingWriter(len(p))
	return len(p), nil
}

// rangesMIMESize returns the number of bytes it takes to encode the
// provided ranges as a multipart response.
func rangesMIMESize(ranges []httpRange, contentType string, contentSize int64) (encSize int64) {
	var w countingWriter
	mw := multipart.NewWriter(&w)
	for _, ra := range ranges {
		mw.CreatePart(ra.mimeHeader(contentType, contentSize))
		encSize += ra.length
	}
	mw.Close()
	encSize += int64(w)
	return
}

func sumRangesSize(ranges []httpRange) (size int64) {
	for _, ra := range ranges {
		size += ra.length
	}
	return
}

// server.go
var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	// "&#34;" is shorter than "&quot;".
	`"`, "&#34;",
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
	"'", "&#39;",
)

func htmlEscape(s string) string {
	return htmlReplacer.Replace(s)
}

type dumbEscaper struct {
	buf *bufio.Writer
}

var (
	amp = []byte("&amp;")
	lt  = []byte("&lt;")
	gt  = []byte("&gt;")
	dq  = []byte("&#34;")
	sq  = []byte("&#39;")
)

func (d *dumbEscaper) Write(p []byte) (n int, err error) {
	for i, b := range p {
		switch b {
		case '&':
			_, err = d.buf.Write(amp)
		case '<':
			_, err = d.buf.Write(lt)
		case '>':
			_, err = d.buf.Write(gt)
		case '"':
			_, err = d.buf.Write(dq)
		case '\'':
			_, err = d.buf.Write(sq)
		default:
			err = d.buf.WriteByte(b)
		}
		if err != nil {
			return i, err
		}
	}
	return len(p), d.buf.Flush()
}

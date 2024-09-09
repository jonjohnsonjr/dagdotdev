package apk

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/v1/types"
	httpserve "github.com/jonjohnsonjr/dagdotdev/internal/forks/http"
)

// Lots of debugging that we don't want to compile into the binary.
const debug = false

func debugf(s string, i ...interface{}) {
	if debug {
		log.Printf(s, i...)
	}
}

type tarReader interface {
	io.Reader
	Next() (*tar.Header, error)
}

// Implements http.FileSystem.
type layerFS struct {
	h       *handler
	prefix  string
	tr      tarReader
	headers []*tar.Header

	ref  string
	size int64
	kind string
	mt   types.MediaType
}

func (h *handler) newLayerFS(tr tarReader, size int64, prefix, ref, kind string, mt types.MediaType) *layerFS {
	logs.Debug.Printf("size: %d, prefix: %q, ref: %q, kind: %q", size, prefix, ref, kind)
	return &layerFS{
		h:       h,
		tr:      tr,
		size:    size,
		prefix:  prefix,
		ref:     ref,
		kind:    kind,
		mt:      mt,
		headers: []*tar.Header{},
	}
}

func (fs *layerFS) RenderHeader(w http.ResponseWriter, r *http.Request, fname string, f httpserve.File, ctype string) error {
	return fs.h.renderHeader(w, r, fname, strings.Trim(fs.prefix, "/"), fs.ref, fs.kind, fs.mt, fs.size, f, ctype)
}

func (fs *layerFS) Open(original string) (httpserve.File, error) {
	logs.Debug.Printf("Open(%q)", original)
	logs.Debug.Printf("prefix=%q", fs.prefix)
	name := strings.TrimPrefix(original, fs.prefix)
	logs.Debug.Printf("name=%q", name)

	// Short-circuit top-level listing so we can stream results.
	if name == "/" || name == "" {
		logs.Debug.Printf("returning early for name=%q", name)
		return &rootFile{
			layerFile: layerFile{
				name: name,
				fs:   fs,
			},
		}, nil
	}

	var found httpserve.File
	// Scan through the layer, looking for a matching tar.Header.Name.
	for {
		header, err := fs.tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Open(%q): %w", original, err)
		}

		// Cache the headers, so we don't have to re-fetch the blob. This comes
		// into play mostly for ReadDir() at the top level, where we already scan
		// the entire layer to tell FileServer "/" and "index.html" don't exist.
		fs.headers = append(fs.headers, header)
		if got := path.Clean("/" + header.Name); got == name {
			found = &layerFile{
				name:   name,
				header: header,
				fs:     fs,
			}
			// For directories, we need to keep listing everything to populate
			// fs.headers. For other files, we can return immediately.
			if header.Typeflag != tar.TypeDir {
				return found, nil
			}
		} else {
			if strings.Contains(got, path.Base(name)) {
				logs.Debug.Printf("got: %q, want %q", got, name)
			}
		}
	}

	if found != nil {
		return found, nil
	}

	// FileServer is trying to find index.html, but it doesn't exist in the image.
	if path.Base(name) == "index.html" {
		return nil, fmt.Errorf("nope: %s", name)
	}

	// We didn't find the entry in the tarball, so we're probably trying to list
	// a file or directory that does not exist.
	return &layerFile{
		name: name,
		fs:   fs,
	}, nil
}

// Implements http.File.
type layerFile struct {
	name   string
	header *tar.Header
	fs     *layerFS
}

// This used to try to handle Seeking, but it was complicated, so I
// forked net/http instead.
func (f *layerFile) Seek(offset int64, whence int) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

// Allows us to drop Seek impl for http.ServeContent.
func (f *layerFile) Size() int64 {
	if f.header == nil {
		return 0
	}
	return f.header.Size
}

// This used to handle content sniffing, but I forked net/http instead.
func (f *layerFile) Read(p []byte) (int, error) {
	debugf("Read(%q): len(p) = %d", f.name, len(p))

	return f.fs.tr.Read(p)
}

func (f *layerFile) Close() error {
	return nil
}

// Scan through the tarball looking for prefixes that match the layerFile's name.
func (f *layerFile) Readdir(count int) ([]os.FileInfo, error) {
	debugf("ReadDir(%q)", f.name)

	if f.header != nil && f.header.Typeflag == tar.TypeSymlink {
		fi := f.header.FileInfo()
		return []os.FileInfo{symlink{
			FileInfo: fi,
			name:     ".",
			link:     f.header.Linkname,
		}}, nil
	}

	prefix := path.Clean("/" + f.name)
	if f.Root() {
		prefix = "/"
	}
	fis := []os.FileInfo{}
	if !f.Root() {
		fis = append(fis, dirInfo{".."})
	}

	implicitDirs := map[string]struct{}{}
	realDirs := map[string]struct{}{}

	for _, hdr := range f.fs.headers {
		name := path.Clean("/" + hdr.Name)

		if prefix != "/" && name != prefix && !strings.HasPrefix(name, prefix+"/") {
			continue
		}

		fdir := path.Dir(strings.TrimPrefix(name, prefix))
		if !(fdir == "/" || (fdir == "." && prefix == "/")) {
			if fdir != "" && fdir != "." {
				if fdir[0] == '/' {
					fdir = fdir[1:]
				}
				implicit := strings.Split(fdir, "/")[0]
				if implicit != "" {
					implicitDirs[implicit] = struct{}{}
				}
			}
			continue
		}

		if hdr.Typeflag == tar.TypeDir {
			dirname := strings.TrimPrefix(name, prefix)
			if dirname != "" && dirname != "." {
				if dirname[0] == '/' {
					dirname = dirname[1:]
				}
				realDirs[dirname] = struct{}{}
			}
		}
		fis = append(fis, hdr.FileInfo())
	}

	for dir := range implicitDirs {
		if _, ok := realDirs[dir]; !ok {
			logs.Debug.Printf("Adding implicit dir: %s", dir)
			fis = append(fis, dirInfo{dir})
		}
	}

	return fis, nil
}

func (f *layerFile) Stat() (os.FileInfo, error) {
	debugf("Stat(%q)", f.name)

	// This is a non-existent entry in the tarball, we need to synthesize one.
	if f.header == nil || f.Root() {
		return dirInfo{f.name}, nil
	}

	// If you try to load a symlink directly, we will render it as a directory.
	if f.header.Typeflag == tar.TypeSymlink {
		hdr := *f.header
		hdr.Typeflag = tar.TypeDir
		return hdr.FileInfo(), nil
	}

	return f.header.FileInfo(), nil
}

func (f *layerFile) Root() bool {
	return f.name == "" || f.name == "/" || f.name == "/index.html"
}

// Implements os.FileInfo for empty directory.
type dirInfo struct {
	name string
}

func (f dirInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f dirInfo) Name() string       { return f.name }
func (f dirInfo) Size() int64        { return 0 }
func (f dirInfo) Mode() os.FileMode  { return os.ModeDir }
func (f dirInfo) IsDir() bool        { return true }
func (f dirInfo) Sys() interface{}   { return nil }

type symlink struct {
	os.FileInfo
	name string
	link string
}

func (s symlink) Name() string {
	return s.name
}

// Same as layerFile but implements an iterator-based file listing mechanism.
type rootFile struct {
	layerFile
}

// Scan through the tarball looking for prefixes that match the rootFile's name.
func (f *rootFile) Files() iter.Seq2[fs.FileInfo, error] {
	logs.Debug.Printf("Files(%q)", f.name)

	prefix := path.Clean("/" + f.name)
	if f.Root() {
		prefix = "/"
	}

	sawDirs := map[string]struct{}{}
	return func(yield func(fs.FileInfo, error) bool) {
		for {
			hdr, err := f.fs.tr.Next()
			if err == io.EOF {
				return
			}
			if err != nil {
				if !yield(nil, fmt.Errorf("Files(%q): %w", f.name, err)) {
					return
				}
				continue
			}

			// Cache the headers, so we don't have to re-fetch the blob. This comes
			// into play mostly for ReadDir() at the top level, where we already scan
			// the entire layer to tell FileServer "/" and "index.html" don't exist.
			f.fs.headers = append(f.fs.headers, hdr)
			name := path.Clean("/" + hdr.Name)

			if prefix != "/" && name != prefix && !strings.HasPrefix(name, prefix+"/") {
				continue
			}

			fdir := path.Dir(strings.TrimPrefix(name, prefix))
			if !(fdir == "/" || (fdir == "." && prefix == "/")) {
				if fdir != "" && fdir != "." {
					if fdir[0] == '/' {
						fdir = fdir[1:]
					}
					implicit := strings.Split(fdir, "/")[0]
					if implicit != "" {
						if _, ok := sawDirs[implicit]; ok {
							continue
						}
						sawDirs[implicit] = struct{}{}
						if !yield(dirInfo{implicit}, nil) {
							return
						}
						continue
					}
				}
			}

			if hdr.Typeflag == tar.TypeDir {
				dirname := strings.TrimPrefix(name, prefix)
				if dirname != "" && dirname != "." {
					if dirname[0] == '/' {
						dirname = dirname[1:]
					}
					if _, ok := sawDirs[dirname]; ok {
						continue
					}
					sawDirs[dirname] = struct{}{}
				}
			}

			if !yield(hdr.FileInfo(), nil) {
				return
			}
		}
	}
}

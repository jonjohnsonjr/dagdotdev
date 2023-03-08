package explore

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	httpserve "github.com/jonjohnsonjr/dag.dev/internal/forks/http"
)

// Lots of debugging that we don't want to compile into the binary.
const debug = false

func debugf(s string, i ...interface{}) {
	if debug {
		log.Printf(s, i...)
	}
}

// More than enough for FileServer to Peek at file contents.
const bufferLen = 2 << 16

type tarReader interface {
	io.Reader
	Next() (*tar.Header, error)
}

// Implements http.FileSystem.
type layerFS struct {
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
		tr:      tr,
		size:    size,
		prefix:  prefix,
		ref:     ref,
		kind:    kind,
		mt:      mt,
		headers: []*tar.Header{},
	}
}

func (fs *layerFS) RenderHeader(w http.ResponseWriter, fname string, f httpserve.File, ctype string) error {
	ref, err := name.ParseReference(fs.ref)
	if err != nil {
		return err
	}
	return renderHeader(w, fname, strings.Trim(fs.prefix, "/"), ref, fs.kind, fs.mt, fs.size, f, ctype)
}

func (fs *layerFS) Open(original string) (httpserve.File, error) {
	logs.Debug.Printf("Open(%q)", original)
	name := strings.TrimPrefix(original, fs.prefix)

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
		if path.Clean("/"+header.Name) == name {
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
	name     string
	link     string
	typeflag byte
}

func (s symlink) Name() string {
	return s.name
}

// Implements os.FileInfo for a file that is too large.
type bigFifo struct {
	name    string
	content []byte
}

func (b bigFifo) Name() string       { return b.name }
func (b bigFifo) Size() int64        { return int64(len(b.content)) }
func (b bigFifo) ModTime() time.Time { return time.Now() }
func (b bigFifo) Mode() os.FileMode  { return 0 }
func (b bigFifo) IsDir() bool        { return false }
func (b bigFifo) Sys() interface{}   { return nil }

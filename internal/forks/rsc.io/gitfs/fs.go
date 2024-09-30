// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gitfs

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	hashpkg "hash"
	"io"
	"io/fs"
	"runtime/debug"
	"strings"
	"time"
)

// A Hash is a SHA-1 Hash identifying a particular Git object.
type Hash [20]byte

func (h Hash) String() string { return fmt.Sprintf("%x", h[:]) }

// ParseHash parses the (full-length) Git hash text.
func ParseHash(text string) (Hash, error) {
	x, err := hex.DecodeString(text)
	if err != nil || len(x) != 20 {
		return Hash{}, fmt.Errorf("invalid hash")
	}
	var h Hash
	copy(h[:], x)
	return h, nil
}

// An ObjType is an object type indicator.
// The values are the ones used in Git pack encoding
// (https://git-scm.com/docs/pack-format#_object_types).
type ObjType int

const (
	objNone   ObjType = 0
	objCommit ObjType = 1
	objTree   ObjType = 2
	objBlob   ObjType = 3
	objTag    ObjType = 4
	// 5 undefined
	objOfsDelta ObjType = 6
	objRefDelta ObjType = 7
)

var objTypes = [...]string{
	objCommit: "commit",
	objTree:   "tree",
	objBlob:   "blob",
	objTag:    "tag",
}

func (t ObjType) String() string {
	if t < 0 || int(t) >= len(objTypes) || objTypes[t] == "" {
		return fmt.Sprintf("objType(%d)", int(t))
	}
	return objTypes[t]
}

// A DirEntry is a Git directory entry parsed from a tree object.
type DirEntry struct {
	Mode int
	Name []byte
	Hash Hash
}

// parseDirEntry parses the next directory entry from data,
// returning the entry and the number of bytes it occupied.
// If data is malformed, parseDirEntry returns dirEntry{}, 0.
func parseDirEntry(data []byte) (DirEntry, int) {
	// Unclear where or if this format is documented by Git.
	// Each directory entry is an octal mode, then a space,
	// then a file name, then a NUL byte, then a 20-byte binary hash.
	// Note that 'git cat-file -p <treehash>' shows a textual representation
	// of this data, not the actual binary data. To see the binary data,
	// use 'echo <treehash> | git cat-file --batch | hexdump -C'.
	mode := 0
	i := 0
	for i < len(data) && data[i] != ' ' {
		c := data[i]
		if c < '0' || '7' < c {
			return DirEntry{}, 0
		}
		mode = mode*8 + int(c) - '0'
		i++
	}
	i++
	j := i
	for j < len(data) && data[j] != 0 {
		j++
	}
	if len(data)-j < 1+20 {
		return DirEntry{}, 0
	}
	name := data[i:j]
	var h Hash
	copy(h[:], data[j+1:])
	return DirEntry{mode, name, h}, j + 1 + 20
}

// treeLookup looks in the tree object data for the directory entry with the given name,
// returning the mode and hash associated with the name.
func treeLookup(data []byte, name string) (mode int, h Hash, ok bool) {
	// Note: The tree object directory entries are sorted by name,
	// but the directory entry data is not self-synchronizing,
	// so it's not possible to be clever and use a binary search here.
	for len(data) > 0 {
		e, size := parseDirEntry(data)
		if size == 0 {
			break
		}
		// if e.mode == 0o40000 {
		// 	fmt.Fprintf(os.Stderr, "%06o tree %s\t%s\n", e.mode, e.hash, e.name)
		// } else {
		// 	fmt.Fprintf(os.Stderr, "%06o blob %s\t%s\n", e.mode, e.hash, e.name)
		// }
		if string(e.Name) == name {
			return e.Mode, e.Hash, true
		}
		data = data[size:]
	}
	return 0, Hash{}, false
}

// commitKeyValue parses the commit object data
// looking for the first header line "key: value" matching the given key.
// It returns the associated value.
// (Try 'git cat-file -p <commithash>' to see the commit data format.)
func commitKeyValue(data []byte, key string) ([]byte, bool) {
	for i := 0; i < len(data); i++ {
		if i == 0 || data[i-1] == '\n' {
			if data[i] == '\n' {
				break
			}
			if len(data)-i >= len(key)+1 && data[len(key)] == ' ' && string(data[:len(key)]) == key {
				val := data[len(key)+1:]
				for j := 0; j < len(val); j++ {
					if val[j] == '\n' {
						val = val[:j]
						break
					}
				}
				return val, true
			}
		}
	}
	return nil, false
}

// A store is a collection of Git objects, indexed for lookup by hash.
type store struct {
	repo  *Repo
	sha1  hashpkg.Hash    // reused hash state
	index map[Hash]stored // lookup index
	data  []byte          // concatenation of all object data
}

// A stored describes a single stored object.
type stored struct {
	typ ObjType // object type
	off int     // object data is store.data[off:off+len]
	len int
}

// add adds an object with the given type and content to s, returning its Hash.
// If the object is already stored in s, add succeeds but doesn't store a second copy.
func (s *store) add(typ ObjType, data []byte) (Hash, []byte) {
	if s.sha1 == nil {
		s.sha1 = sha1.New()
	}

	// Compute Git hash for object.
	s.sha1.Reset()
	fmt.Fprintf(s.sha1, "%s %d\x00", typ, len(data))
	s.sha1.Write(data)
	var h Hash
	s.sha1.Sum(h[:0]) // appends into h

	e, ok := s.index[h]
	if !ok {
		if s.index == nil {
			s.index = make(map[Hash]stored)
		}
		e = stored{typ, len(s.data), len(data)}
		s.index[h] = e
		s.data = append(s.data, data...)
	}
	return h, s.data[e.off : e.off+e.len]
}

// Object returns the type and data for the Object with hash h.
// If there is no Object with hash h, Object returns 0, nil.
func (s *store) Object(h Hash) (typ ObjType, data []byte) {
	d, ok := s.index[h]
	if !ok {
		return 0, nil
	}
	return d.typ, s.data[d.off : d.off+d.len]
}

// Commit returns a treeFS for the file system tree associated with the given Commit hash.
func (s *store) Commit(c Hash) (*treeFS, []byte, error) {
	// The commit object data starts with key-value pairs
	typ, data := s.Object(c)
	if typ == objNone {
		return nil, nil, fmt.Errorf("commit %s: no such hash", c)
	}
	// fmt.Fprintf(os.Stderr, "typ=%d\n", typ)
	// fmt.Fprintf(os.Stderr, "%s", data)
	// os.Stderr.Write([]byte("\n"))
	if typ != objCommit {
		return nil, nil, fmt.Errorf("commit %s: unexpected type %s", c, typ)
	}
	treeHash, ok := commitKeyValue(data, "tree")
	if !ok {
		return nil, nil, fmt.Errorf("commit %s: no tree", c)
	}
	h, err := ParseHash(string(treeHash))
	if err != nil {
		return nil, nil, fmt.Errorf("commit %s: invalid tree %q", c, treeHash)
	}
	return &treeFS{s, h, c}, data, nil
}

// A treeFS is an fs.FS serving a Git file system tree rooted at a given tree object hash.
type treeFS struct {
	s      *store
	tree   Hash // root tree
	commit Hash
}

func (t *treeFS) Tree() string {
	return t.tree.String()
}

// Open opens the given file or directory, implementing the fs.FS Open method.
func (t *treeFS) Open(name string) (f fs.File, err error) {
	defer func() {
		if e := recover(); e != nil {
			f = nil
			err = fmt.Errorf("gitfs panic: %v\n%s", e, debug.Stack())
		}
	}()

	if t.s.repo != nil {
		prefix := t.s.repo.root + "@" + t.commit.String()
		name = strings.TrimPrefix(name, prefix)
		name = strings.TrimPrefix(name, "/")
		if name == "" {
			name = "."
		}
	}

	// Process each element in the slash-separated path, producing hash identified by name.
	h := t.tree
	start := 0 // index of start of final path element in name
	if name != "." {
		for i := 0; i <= len(name); i++ {
			if i == len(name) || name[i] == '/' {
				// Look up name in current tree object h.
				typ, data := t.s.Object(h)
				if typ != objTree {
					return nil, &fs.PathError{Path: name, Op: "open", Err: fs.ErrNotExist}
				}
				_, th, ok := treeLookup(data, name[start:i])
				if !ok {
					return nil, &fs.PathError{Path: name, Op: "open", Err: fs.ErrNotExist}
				}
				h = th
				if i < len(name) {
					start = i + 1
				}
			}
		}
	}

	// The hash h is the hash for name. Load its object.
	typ, data := t.s.Object(h)
	info := fileInfo{name, name[start:], 0, 0, nil}
	if typ == objBlob {
		// Regular file.
		info.mode = 0444
		info.size = int64(len(data))
		info.sys = &DirEntry{
			Mode: 0444,
			Name: []byte(info.name),
			Hash: h,
		}
		return &blobFile{info, bytes.NewReader(data)}, nil
	}
	if typ == objTree {
		// Directory.
		info.mode = fs.ModeDir | 0555
		info.sys = &DirEntry{
			Mode: 0444,
			Name: []byte(info.name),
			Hash: h,
		}
		return &dirFile{t.s, info, data, 0}, nil
	}
	return nil, &fs.PathError{Path: name, Op: "open", Err: fmt.Errorf("unexpected git object type %s", typ)}
}

// fileInfo implements fs.FileInfo.
type fileInfo struct {
	path string
	name string
	mode fs.FileMode
	size int64
	sys  *DirEntry
}

func (i *fileInfo) Name() string               { return i.name }
func (i *fileInfo) Type() fs.FileMode          { return i.mode & fs.ModeType }
func (i *fileInfo) Mode() fs.FileMode          { return i.mode }
func (i *fileInfo) Sys() interface{}           { return i.sys }
func (i *fileInfo) IsDir() bool                { return i.mode&fs.ModeDir != 0 }
func (i *fileInfo) Size() int64                { return i.size }
func (i *fileInfo) Info() (fs.FileInfo, error) { return i, nil }
func (i *fileInfo) ModTime() time.Time         { return time.Time{} }

func (i *fileInfo) err(op string, err error) error {
	return &fs.PathError{Path: i.path, Op: op, Err: err}
}

// A blobFile implements fs.File for a regular file.
// The embedded bytes.Reader provides Read, Seek and other I/O methods.
type blobFile struct {
	info fileInfo
	*bytes.Reader
}

func (f *blobFile) Close() error               { return nil }
func (f *blobFile) Stat() (fs.FileInfo, error) { return &f.info, nil }

// A dirFile implements fs.File for a directory.
type dirFile struct {
	s    *store
	info fileInfo
	data []byte
	off  int
}

func (f *dirFile) Close() error               { return nil }
func (f *dirFile) Read([]byte) (int, error)   { return 0, f.info.err("read", fs.ErrInvalid) }
func (f *dirFile) Stat() (fs.FileInfo, error) { return &f.info, nil }

func (f *dirFile) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 && whence == 0 {
		// Allow rewind to start of directory.
		f.off = 0
		return 0, nil
	}
	return 0, f.info.err("seek", fs.ErrInvalid)
}

func (f *dirFile) ReadDir(n int) (list []fs.DirEntry, err error) {
	defer func() {
		if e := recover(); e != nil {
			list = nil
			err = fmt.Errorf("gitfs panic: %v\n%s", e, debug.Stack())
		}
	}()

	for (n <= 0 || len(list) < n) && f.off < len(f.data) {
		e, size := parseDirEntry(f.data[f.off:])
		if size == 0 {
			break
		}
		f.off += size
		typ, data := f.s.Object(e.Hash)
		mode := fs.FileMode(0444)
		if typ == objTree {
			mode = fs.ModeDir | 0555
		}
		infoSize := int64(0)
		if typ == objBlob {
			infoSize = int64(len(data))
		}
		name := string(e.Name)
		list = append(list, &fileInfo{name, name, mode, infoSize, &e})
	}
	if len(list) == 0 && n > 0 {
		return list, io.EOF
	}
	return list, nil
}

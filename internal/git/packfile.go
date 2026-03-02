package git

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/jonjohnsonjr/dagdotdev/internal/forks/rsc.io/gitfs"
)

type PackIndex struct {
	Version    uint32       `json:"version"`
	NumObjects uint32       `json:"numObjects"`
	Size       int64        `json:"size"`
	Checksum   string       `json:"checksum"`
	Objects    []PackObject `json:"objects"`
}

type PackObject struct {
	Offset      int    `json:"offset"`
	EncodedSize int    `json:"encodedSize"`
	Type        string `json:"type"`         // raw type: commit, tree, blob, tag, ofs-delta, ref-delta
	ResolvedType string `json:"resolvedType"` // resolved type after delta resolution
	Size        int    `json:"size"`
	Hash        string `json:"hash"`

	// Delta info (only for ofs-delta and ref-delta objects)
	DeltaBase  string `json:"deltaBase,omitempty"`  // raw base ref (hash for ref-delta, offset string for ofs-delta)
	BaseHash   string `json:"baseHash,omitempty"`   // resolved base object hash
	BaseOffset int    `json:"baseOffset,omitempty"`
	Depth      int    `json:"depth,omitempty"`       // delta chain depth (0 for non-delta)
}

// BuildPackIndex parses a raw packfile and builds an index of all objects.
func BuildPackIndex(data []byte) (*PackIndex, error) {
	if len(data) < 12+20 {
		return nil, fmt.Errorf("packfile too short")
	}

	hdr := data[:12]
	vers := binary.BigEndian.Uint32(hdr[4:8])
	nobj := binary.BigEndian.Uint32(hdr[8:12])
	if string(hdr[:4]) != "PACK" || (vers != 2 && vers != 3) {
		return nil, fmt.Errorf("not a packfile")
	}
	if vers == 3 {
		return nil, fmt.Errorf("packfile v3 not supported")
	}

	sum := sha1.Sum(data[:len(data)-20])
	if !bytes.Equal(sum[:], data[len(data)-20:]) {
		return nil, fmt.Errorf("packfile checksum mismatch")
	}

	idx := &PackIndex{
		Version:    vers,
		NumObjects: nobj,
		Size:       int64(len(data)),
		Checksum:   hex.EncodeToString(data[len(data)-20:]),
		Objects:    make([]PackObject, 0, nobj),
	}

	// We need a store to resolve delta chains and compute hashes.
	var s gitfs.Store
	objs := data[12 : len(data)-20]
	off := 0

	for i := 0; i < int(nobj); i++ {
		obj, encSize, err := indexObject(&s, objs, off)
		if err != nil {
			return nil, fmt.Errorf("object %d at offset %d: %v", i, off+12, err)
		}
		obj.Offset = off + 12 // offset from start of packfile
		obj.EncodedSize = encSize
		idx.Objects = append(idx.Objects, obj)
		off += encSize
	}

	// Compute delta chain depths.
	byHash := map[string]int{} // hash -> index into Objects
	for i, obj := range idx.Objects {
		byHash[obj.Hash] = i
	}
	for i := range idx.Objects {
		if idx.Objects[i].BaseHash == "" {
			continue
		}
		depth := 1
		baseHash := idx.Objects[i].BaseHash
		for {
			bi, ok := byHash[baseHash]
			if !ok || idx.Objects[bi].BaseHash == "" {
				break
			}
			depth++
			baseHash = idx.Objects[bi].BaseHash
		}
		idx.Objects[i].Depth = depth
	}

	return idx, nil
}

// indexObject parses the object at objs[off:] and returns structural info.
func indexObject(s *gitfs.Store, objs []byte, off int) (PackObject, int, error) {
	if off < 0 || off >= len(objs) {
		return PackObject{}, 0, fmt.Errorf("invalid offset")
	}

	u, size := binary.Uvarint(objs[off:])
	if size <= 0 {
		return PackObject{}, 0, fmt.Errorf("bad varint")
	}
	typ := gitfs.ObjType((u >> 4) & 7)
	n := int(u&15 | u>>7<<4)

	obj := PackObject{}

	switch typ {
	case gitfs.ObjRefDelta:
		if len(objs)-(off+size) < 20 {
			return PackObject{}, 0, fmt.Errorf("bad ref-delta")
		}
		var h gitfs.Hash
		copy(h[:], objs[off+size:])
		size += 20
		obj.Type = "ref-delta"
		obj.DeltaBase = h.String()

	case gitfs.ObjOfsDelta:
		i := off + size
		if len(objs)-i < 20 {
			return PackObject{}, 0, fmt.Errorf("bad ofs-delta")
		}
		d := int64(objs[i] & 0x7f)
		for objs[i]&0x80 != 0 {
			i++
			d = d<<7 | int64(objs[i]&0x7f)
			d += 1 << 7
		}
		i++
		size = i - off
		obj.Type = "ofs-delta"
		obj.BaseOffset = off - int(d) + 12 // offset from start of packfile
		obj.DeltaBase = fmt.Sprintf("-%d", int(d))

	case gitfs.ObjCommit:
		obj.Type = "commit"
	case gitfs.ObjTree:
		obj.Type = "tree"
	case gitfs.ObjBlob:
		obj.Type = "blob"
	case gitfs.ObjTag:
		obj.Type = "tag"
	default:
		return PackObject{}, 0, fmt.Errorf("unknown type %d", typ)
	}

	// Decompress to get the actual size and compute hash.
	br := bytes.NewReader(objs[off+size:])
	zr, err := zlib.NewReader(br)
	if err != nil {
		return PackObject{}, 0, fmt.Errorf("zlib: %v", err)
	}
	content, err := io.ReadAll(zr)
	if err != nil {
		return PackObject{}, 0, fmt.Errorf("zlib read: %v", err)
	}
	if len(content) != n {
		return PackObject{}, 0, fmt.Errorf("size mismatch: %d != %d", len(content), n)
	}
	encSize := len(objs[off:]) - br.Len()

	// For non-delta objects, the hash is straightforward.
	// For delta objects, we need to resolve the chain via the store.
	switch typ {
	case gitfs.ObjCommit, gitfs.ObjTree, gitfs.ObjBlob, gitfs.ObjTag:
		h, _ := s.Add(typ, content)
		obj.Hash = h.String()
		obj.Size = len(content)
		obj.ResolvedType = obj.Type

	case gitfs.ObjRefDelta:
		baseTyp, baseData := s.Object(gitfs.Hash(mustParseHash(obj.DeltaBase)))
		if baseTyp == gitfs.ObjNone {
			return PackObject{}, 0, fmt.Errorf("unknown ref-delta base %s", obj.DeltaBase)
		}
		resolved, err := applyPackDelta(baseData, content)
		if err != nil {
			return PackObject{}, 0, fmt.Errorf("apply ref-delta: %v", err)
		}
		h, _ := s.Add(baseTyp, resolved)
		obj.Hash = h.String()
		obj.Size = len(resolved)
		obj.ResolvedType = baseTyp.String()
		obj.BaseHash = obj.DeltaBase

	case gitfs.ObjOfsDelta:
		baseOff := off - mustParseOfsOffset(obj.DeltaBase)
		baseTyp, baseHash, baseContent, _, err := gitfs.UnpackObject(s, objs, baseOff)
		if err != nil {
			return PackObject{}, 0, fmt.Errorf("resolve ofs-delta base: %v", err)
		}
		resolved, err := applyPackDelta(baseContent, content)
		if err != nil {
			return PackObject{}, 0, fmt.Errorf("apply ofs-delta: %v", err)
		}
		h, _ := s.Add(baseTyp, resolved)
		obj.Hash = h.String()
		obj.Size = len(resolved)
		obj.ResolvedType = baseTyp.String()
		obj.BaseHash = baseHash.String()
	}

	return obj, encSize, nil
}

func mustParseHash(s string) [20]byte {
	b, _ := hex.DecodeString(s)
	var h [20]byte
	copy(h[:], b)
	return h
}

func mustParseOfsOffset(s string) int {
	// s is like "-1234"
	var n int
	fmt.Sscanf(s, "-%d", &n)
	return n
}

// resolveBaseType follows the delta chain to find the base object type.
func resolveBaseType(s *gitfs.Store, objs []byte, off int) (gitfs.ObjType, error) {
	u, size := binary.Uvarint(objs[off:])
	if size <= 0 {
		return 0, fmt.Errorf("bad varint")
	}
	typ := gitfs.ObjType((u >> 4) & 7)
	switch typ {
	case gitfs.ObjCommit, gitfs.ObjTree, gitfs.ObjBlob, gitfs.ObjTag:
		return typ, nil
	case gitfs.ObjOfsDelta:
		i := off + size
		d := int64(objs[i] & 0x7f)
		for objs[i]&0x80 != 0 {
			i++
			d = d<<7 | int64(objs[i]&0x7f)
			d += 1 << 7
		}
		return resolveBaseType(s, objs, off-int(d))
	case gitfs.ObjRefDelta:
		var h gitfs.Hash
		copy(h[:], objs[off+size:])
		baseTyp, _ := s.Object(h)
		return baseTyp, nil
	}
	return 0, fmt.Errorf("unknown type %d", typ)
}

// applyPackDelta applies a delta to a base to produce the target.
func applyPackDelta(base, delta []byte) ([]byte, error) {
	// Delta starts with base size and target size as varints.
	baseSize, s := binary.Uvarint(delta)
	delta = delta[s:]
	if baseSize != uint64(len(base)) {
		return nil, fmt.Errorf("base size mismatch: %d != %d", baseSize, len(base))
	}
	targSize, s := binary.Uvarint(delta)
	delta = delta[s:]

	targ := make([]byte, targSize)
	dst := targ
	for len(delta) > 0 {
		cmd := delta[0]
		delta = delta[1:]
		switch {
		case cmd == 0:
			return nil, fmt.Errorf("invalid delta cmd")
		case cmd&0x80 != 0:
			var off, size int64
			for i := uint(0); i < 4; i++ {
				if cmd&(1<<i) != 0 {
					off |= int64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			for i := uint(0); i < 3; i++ {
				if cmd&(0x10<<i) != 0 {
					size |= int64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			if size == 0 {
				size = 0x10000
			}
			copy(dst[:size], base[off:off+size])
			dst = dst[size:]
		default:
			n := int(cmd)
			copy(dst[:n], delta[:n])
			dst = dst[n:]
			delta = delta[n:]
		}
	}
	if len(dst) != 0 {
		return nil, fmt.Errorf("delta too short")
	}
	return targ, nil
}

// DeltaOp represents a single instruction in a delta encoding.
type DeltaOp struct {
	Kind   string // "copy" or "insert"
	Offset int64  // copy: offset into base object
	Size   int64  // copy: bytes to copy; insert: bytes of literal data
	Data   []byte // insert: the literal bytes
}

// DeltaInfo holds the parsed delta instructions for a delta object.
type DeltaInfo struct {
	BaseSize   uint64
	TargetSize uint64
	Ops        []DeltaOp
}

// ParseDelta parses a raw delta byte stream into structured operations.
func ParseDelta(delta []byte) (*DeltaInfo, error) {
	info := &DeltaInfo{}

	baseSize, s := binary.Uvarint(delta)
	delta = delta[s:]
	info.BaseSize = baseSize

	targSize, s := binary.Uvarint(delta)
	delta = delta[s:]
	info.TargetSize = targSize

	for len(delta) > 0 {
		cmd := delta[0]
		delta = delta[1:]

		switch {
		case cmd == 0:
			return nil, fmt.Errorf("invalid delta cmd 0")

		case cmd&0x80 != 0:
			// Copy from base.
			var off, size int64
			for i := uint(0); i < 4; i++ {
				if cmd&(1<<i) != 0 {
					off |= int64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			for i := uint(0); i < 3; i++ {
				if cmd&(0x10<<i) != 0 {
					size |= int64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			if size == 0 {
				size = 0x10000
			}
			info.Ops = append(info.Ops, DeltaOp{Kind: "copy", Offset: off, Size: size})

		default:
			// Insert literal data.
			n := int(cmd)
			info.Ops = append(info.Ops, DeltaOp{Kind: "insert", Size: int64(n), Data: append([]byte(nil), delta[:n]...)})
			delta = delta[n:]
		}
	}

	return info, nil
}

// RawDelta extracts the raw (zlib-decompressed, pre-resolution) delta bytes
// for the object at the given packfile offset.
func RawDelta(data []byte, offset int) ([]byte, error) {
	if offset < 12 || offset >= len(data)-20 {
		return nil, fmt.Errorf("invalid offset %d", offset)
	}
	objs := data[12 : len(data)-20]
	off := offset - 12

	u, size := binary.Uvarint(objs[off:])
	if size <= 0 {
		return nil, fmt.Errorf("bad varint")
	}
	typ := gitfs.ObjType((u >> 4) & 7)

	switch typ {
	case gitfs.ObjRefDelta:
		size += 20
	case gitfs.ObjOfsDelta:
		i := off + size
		for objs[i]&0x80 != 0 {
			i++
		}
		i++
		size = i - off
	default:
		return nil, fmt.Errorf("not a delta object (type %s)", typ)
	}

	br := bytes.NewReader(objs[off+size:])
	zr, err := zlib.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("zlib: %v", err)
	}
	return io.ReadAll(zr)
}

// DecompressObject decompresses a single object from packfile data, identified by hash.
// It does a full unpack to populate the store (required for ref-delta resolution),
// then looks up the object by hash.
func DecompressObject(data []byte, hash string) (objType string, content []byte, err error) {
	if len(data) < 12+20 {
		return "", nil, fmt.Errorf("packfile too short")
	}

	var s gitfs.Store
	if err := gitfs.Unpack(&s, data); err != nil {
		return "", nil, err
	}

	h, err := gitfs.ParseHash(hash)
	if err != nil {
		return "", nil, fmt.Errorf("invalid hash %q: %v", hash, err)
	}

	typ, objData := s.Object(h)
	if typ == gitfs.ObjNone {
		return "", nil, fmt.Errorf("object %s not found", hash)
	}

	return typ.String(), objData, nil
}

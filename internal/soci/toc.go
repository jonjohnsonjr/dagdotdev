package soci

import (
	"archive/tar"
	"time"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/compress/flate"
)

type TOC struct {
	// TODO: Move these so files/checkpoints can be streamingly parsed.
	// metadata.json?
	Csize       int64  `json:"csize,omitempty"`
	Usize       int64  `json:"usize,omitempty"`
	Ssize       int64  `json:"ssize,omitempty"`
	ArchiveSize int64  `json:"asize,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Type        string `json:"type,omitempty"`
	MediaType   string `json:"mediaType,omitempty"`

	// TODO: Checkpoints as jsonlines in separate file.
	Checkpoints []*flate.Checkpoint `json:"checkpoints,omitempty"`

	// TODO: This should probably be a pointer!!!
	// TODO: Files as jsonlines in separate file.
	Files []TOCFile `json:"files,omitempty"`
}

type TOCFile struct {
	// The tar stuff we actually care about.
	// TODO: Just include all of it, for completeness?
	Typeflag   byte              `json:"typeflag,omitempty"`
	Name       string            `json:"name,omitempty"`
	Linkname   string            `json:"linkname,omitempty"`
	Size       int64             `json:"size,omitempty"`
	Mode       int64             `json:"mode,omitempty"`
	ModTime    time.Time         `json:"mod,omitempty"`
	Uid        int               `json:"uid,omitempty"`
	Gid        int               `json:"gid,omitempty"`
	PAXRecords map[string]string `json:"pax,omitempty"`

	// Our uncompressed offset so we can seek ahead.
	Offset int64 `json:"offset,omitempty"`
}

func (toc *TOC) Checkpoint(tf *TOCFile) *Checkpointer {
	if len(toc.Checkpoints) == 0 {
		return &Checkpointer{
			Checkpoint: &flate.Checkpoint{
				Empty: true,
			},
			File:  tf,
			start: tf.Offset,
			end:   tf.Offset + tf.Size,
		}
	}
	from := toc.Checkpoints[0]
	discard := int64(0)
	index := 0
	for i, c := range toc.Checkpoints {
		if c.BytesWritten() > tf.Offset {
			discard = tf.Offset - from.BytesWritten()
			break
		}
		if i == len(toc.Checkpoints)-1 {
			discard = tf.Offset - c.BytesWritten()
		}
		from = toc.Checkpoints[i]
		index = i
	}
	start := from.BytesRead()
	uend := tf.Offset + tf.Size

	logs.Debug.Printf("start=%d, uend=%d", start, uend)

	end := toc.Csize
	for _, c := range toc.Checkpoints {
		if c.BytesWritten() > uend {
			end = c.BytesRead()
			break
		}
	}

	return &Checkpointer{
		Checkpoint: from,
		File:       tf,
		index:      index,
		start:      start,
		end:        end,
		Discard:    discard,
	}
}

type Checkpointer struct {
	Checkpoint *flate.Checkpoint
	File       *TOCFile
	index      int
	start      int64
	end        int64
	Discard    int64
}

func TarHeader(header *TOCFile) *tar.Header {
	return &tar.Header{
		Typeflag:   header.Typeflag,
		Name:       header.Name,
		Linkname:   header.Linkname,
		Size:       header.Size,
		Mode:       header.Mode,
		ModTime:    header.ModTime,
		Uid:        header.Uid,
		Gid:        header.Gid,
		PAXRecords: header.PAXRecords,
	}
}

func FromTar(header *tar.Header) *TOCFile {
	return &TOCFile{
		Typeflag:   header.Typeflag,
		Name:       header.Name,
		Linkname:   header.Linkname,
		Size:       header.Size,
		Mode:       header.Mode,
		ModTime:    header.ModTime,
		Gid:        header.Gid,
		Uid:        header.Uid,
		PAXRecords: header.PAXRecords,
	}
}

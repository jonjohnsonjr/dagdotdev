// Copyright 2022 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/internal/compress/gzip"
	"github.com/google/go-containerregistry/internal/soci"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

func NewCmdSoci(options *[]crane.Option) *cobra.Command {
	cmd := &cobra.Command{
		Hidden: true,
		Use:    "soci",
		Short:  "soci stuff",
		Args:   cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(
		NewCmdSociIndex(options),
		NewCmdSociList(options),
		NewCmdSociServe(options),
		NewCmdSociExtract(options),
	)

	return cmd
}

func NewCmdSociList(options *[]crane.Option) *cobra.Command {
	return &cobra.Command{
		Use:     "list BLOB",
		Short:   "List files in a soci index",
		Example: "crane soci list index.json",
		//Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			index := soci.Index{}
			if err := json.NewDecoder(f).Decode(&index); err != nil {
				return err
			}
			for _, fm := range index.TOC {
				fmt.Fprintln(cmd.OutOrStdout(), tarList(toTar(&fm)))
			}
			return nil
		},
	}
}

func NewCmdSociServe(options *[]crane.Option) *cobra.Command {
	indexFile := ""
	tag := ""
	cmd := &cobra.Command{
		Use:     "serve BLOB --index FILE",
		Short:   "Read a blob from the registry and generate a soci index",
		Example: "crane soci list index.json",
		//Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := crane.GetOptions(*options...)
			ctx := cmd.Context()

			var index *soci.Index
			if indexFile != "" {
				f, err := os.Open(indexFile)
				if err != nil {
					return err
				}
				defer f.Close()

				if err := json.NewDecoder(f).Decode(index); err != nil {
					return err
				}
			} else if tag != "" {
				img, err := crane.Pull(tag, *options...)
				if err != nil {
					return err
				}
				idx, err := soci.FromImage(img)
				if err != nil {
					return err
				}
				index = idx
			}

			digest, err := name.NewDigest(args[0], o.Name...)
			if err != nil {
				return err
			}
			opts := o.Remote
			opts = append(opts, remote.WithSize(int64(index.Csize)))
			blob, err := remote.Blob(digest, opts...)
			if err != nil {
				return err
			}

			port := os.Getenv("PORT")
			if port == "" {
				port = "8080"
			}

			srv := &http.Server{
				Handler: http.FileServer(http.FS(soci.FS(index, blob, args[0], 1<<25))),
				Addr:    fmt.Sprintf(":%s", port),
			}

			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				<-ctx.Done()
				return srv.Shutdown(ctx)
			})
			g.Go(func() error {
				return srv.ListenAndServe()
			})
			return g.Wait()

		},
	}
	cmd.Flags().StringVarP(&indexFile, "index", "i", "", "TODO")
	cmd.Flags().StringVarP(&tag, "tag", "t", "", "Tag to cache the index")
	return cmd
}

// NewCmdSociIndex creates a new cobra.Command for the soci subcommand.
func NewCmdSociIndex(options *[]crane.Option) *cobra.Command {
	newTag := ""
	cmd := &cobra.Command{
		Use:     "index BLOB",
		Short:   "Read a blob from the registry and generate a soci index",
		Example: "crane soci index ubuntu@sha256:4c1d20cdee96111c8acf1858b62655a37ce81ae48648993542b7ac363ac5c0e5",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := crane.GetOptions(*options...)
			src := args[0]

			digest, err := name.NewDigest(src, o.Name...)
			if err != nil {
				return err
			}
			l, err := remote.Layer(digest, o.Remote...)
			if err != nil {
				return err
			}

			rc, err := l.Compressed()
			if err != nil {
				return err
			}

			indexer, err := soci.NewIndexer(rc, int64(1<<22))
			if err != nil {
				return err
			}

			for {
				header, err := indexer.Next()
				if errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					return err
				}
				logs.Debug.Println(tarList(header))
			}

			index, err := indexer.Index()
			if err != nil {
				return err
			}

			if newTag != "" {
				img, err := soci.ToImage(index)
				if err != nil {
					return err
				}

				if err := crane.Push(img, newTag, *options...); err != nil {
					return err
				}
			} else {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(index)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&newTag, "tag", "t", "", "Tag to cache the index")
	return cmd
}

// NewCmdSociExtract creates a new cobra.Command for the soci subcommand.
func NewCmdSociExtract(options *[]crane.Option) *cobra.Command {
	indexFile := ""
	extractFile := ""
	cmd := &cobra.Command{
		Use:     "extract BLOB",
		Short:   "TODO",
		Example: "crane soci extract ubuntu@sha256:4c1d20cdee96111c8acf1858b62655a37ce81ae48648993542b7ac363ac5c0e5 --index index.json -f usr/lib/os-release",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := crane.GetOptions(*options...)
			src := args[0]

			digest, err := name.NewDigest(src, o.Name...)
			if err != nil {
				return err
			}

			f, err := os.Open(indexFile)
			if err != nil {
				return err
			}
			defer f.Close()

			index := soci.Index{}
			if err := json.NewDecoder(f).Decode(&index); err != nil {
				return err
			}

			opts := o.Remote
			opts = append(opts, remote.WithSize(index.Csize))
			blob, err := remote.Blob(digest, opts...)
			if err != nil {
				return err
			}

			from := index.Checkpoints[0]

			discard := int64(0)
			size := int64(0)
			for _, tf := range index.TOC {
				if tf.Name == extractFile {
					offset := tf.Offset
					for i, c := range index.Checkpoints {
						if c.Out > offset || i == len(index.Checkpoints)-1 {
							discard = offset - from.Out
							size = tf.Size
							break
						}
						from = index.Checkpoints[i]
					}
					break
				}
			}

			// Add 10 for gzip header.
			start := from.In + 10

			rc, err := blob.Reader(cmd.Context(), start, index.Csize)
			if err != nil {
				return err
			}
			defer rc.Close()

			r, err := gzip.Continue(rc, 1<<22, &from, nil)
			if err != nil {
				return err
			}

			if _, err := io.CopyN(io.Discard, r, discard); err != nil {
				return err
			}

			if _, err := io.CopyN(cmd.OutOrStdout(), r, size); err != nil {
				return err
			}
			return nil

		},
	}
	cmd.Flags().StringVarP(&indexFile, "index", "i", "", "TODO")
	cmd.Flags().StringVarP(&extractFile, "file", "f", "", "TODO")
	cmd.MarkFlagRequired("index")
	cmd.MarkFlagRequired("file")
	return cmd
}

// E.g. from ubuntu
// drwxr-xr-x 0/0               0 2022-11-29 18:07 var/lib/systemd/deb-systemd-helper-enabled/
// lrwxrwxrwx 0/0               0 2022-11-29 18:04 var/run -> /run
// hrwxr-xr-x 0/0               0 2022-09-05 06:33 usr/bin/uncompress link to usr/bin/gunzip
// drwxrwxrwt 0/0               0 2022-11-29 18:04 run/lock/
// -rwsr-xr-x 0/0           72072 2022-11-24 04:05 usr/bin/gpasswd
func tarList(header *tar.Header) string {
	ts := header.ModTime.Format("2006-01-02 15:04")
	ug := fmt.Sprintf("%d/%d", header.Uid, header.Gid)
	mode := modeStr(header)
	padding := 18 - len(ug)
	s := fmt.Sprintf("%s %s %*d %s %s", mode, ug, padding, header.Size, ts, header.Name)
	if header.Linkname != "" {
		if header.Typeflag == tar.TypeLink {
			s += " link to " + header.Linkname
		} else {
			s += " -> " + header.Linkname
		}
	}
	return s
}

func toTar(header *soci.TOCFile) *tar.Header {
	return &tar.Header{
		Typeflag: header.Typeflag,
		Name:     header.Name,
		Linkname: header.Linkname,
		Size:     header.Size,
		Mode:     header.Mode,
	}
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

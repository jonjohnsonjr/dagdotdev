// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gitfs presents a file tree downloaded from a remote Git repo as an in-memory fs.FS.
package gitfs

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// A Repo is a connection to a remote repository served over HTTP or HTTPS.
type Repo struct {
	root string
	url  string // trailing slash removed
	caps map[string]string
}

// NewRepo connects to a Git repository at the given http:// or https:// URL.
func NewRepo(ctx context.Context, url string) (*Repo, error) {
	r := &Repo{
		url:  strings.TrimSuffix(url, "/"),
		root: strings.ReplaceAll(url, "://", "/"),
	}
	if err := r.Handshake(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Handshake runs the initial Git opening Handshake, learning the capabilities of the server.
// See https://git-scm.com/docs/protocol-v2#_initial_client_request.
func (r *Repo) Handshake(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", r.url+"/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Git-Protocol", "version=2")

	// fmt.Fprintf(os.Stderr, "\nGET %s\n\n", r.url+"/info/refs?service=git-upload-pack")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("handshake: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("handshake: %v\n%s", resp.Status, data)
	}
	// os.Stderr.Write(data)
	if err != nil {
		return fmt.Errorf("handshake: reading body: %v", err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		return fmt.Errorf("handshake: invalid response Content-Type: %v", ct)
	}

	pr := newPktLineReader(bytes.NewReader(data))
	lines, err := pr.Lines()
	if len(lines) == 1 && lines[0] == "# service=git-upload-pack" {
		lines, err = pr.Lines()
	}
	if err != nil {
		return fmt.Errorf("handshake: parsing response: %v", err)
	}
	caps := make(map[string]string)
	for _, line := range lines {
		// os.Stderr.Write([]byte(line))
		// os.Stderr.Write([]byte("\n"))
		verb, args, _ := strings.Cut(line, "=")
		caps[verb] = args
	}
	if _, ok := caps["version 2"]; !ok {
		return fmt.Errorf("handshake: not version 2: %q", lines)
	}
	r.caps = caps
	return nil
}

// Resolve looks up the given ref and returns the corresponding Hash.
func (r *Repo) Resolve(ctx context.Context, ref string) (Hash, error) {
	if h, err := ParseHash(ref); err == nil {
		return h, nil
	}

	fail := func(err error) (Hash, error) {
		return Hash{}, fmt.Errorf("resolve %s: %v", ref, err)
	}
	refs, err := r.Refs(ctx, ref)
	if err != nil {
		return fail(err)
	}
	for _, known := range refs {
		if known.Name == ref {
			return known.Hash, nil
		}
	}
	return fail(fmt.Errorf("unknown ref"))
}

// A Ref is a single Git reference, like refs/heads/main, refs/tags/v1.0.0, or HEAD.
type Ref struct {
	Name string // "refs/heads/main", "refs/tags/v1.0.0", "HEAD"
	Hash Hash   // hexadecimal hash
}

// Refs executes an ls-Refs command on the remote server
// to look up Refs with the given prefixes.
// See https://git-scm.com/docs/protocol-v2#_ls_refs.
func (r *Repo) Refs(ctx context.Context, prefixes ...string) ([]Ref, error) {
	if _, ok := r.caps["ls-refs"]; !ok {
		return nil, fmt.Errorf("refs: server does not support ls-refs")
	}

	var buf bytes.Buffer
	pw := newPktLineWriter(&buf)
	pw.WriteString("command=ls-refs")
	pw.Delim()
	pw.WriteString("peel")
	pw.WriteString("symrefs")
	for _, prefix := range prefixes {
		pw.WriteString("ref-prefix " + prefix)
	}
	pw.Close()
	postbody := buf.Bytes()

	req, _ := http.NewRequestWithContext(ctx, "POST", r.url+"/git-upload-pack", &buf)
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Git-Protocol", "version=2")

	// fmt.Fprintf(os.Stderr, "\nPOST %s\n%s\n\n", r.url+"/git-upload-pack", postbody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refs: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	// os.Stderr.Write(data)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("refs: %v\n%s", resp.Status, data)
	}
	if err != nil {
		return nil, fmt.Errorf("refs: reading body: %v", err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-result" {
		return nil, fmt.Errorf("refs: invalid response Content-Type: %v", ct)
	}

	var refs []Ref
	lines, err := newPktLineReader(bytes.NewReader(data)).Lines()
	if err != nil {
		return nil, fmt.Errorf("refs: parsing response: %v %d\n%s\n%s", err, len(data), hex.Dump(postbody), hex.Dump(data))
	}
	for _, line := range lines {
		hash, rest, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("refs: parsing response: invalid line: %q", line)
		}
		h, err := ParseHash(hash)
		if err != nil {
			return nil, fmt.Errorf("refs: parsing response: invalid line: %q", line)
		}
		name, _, _ := strings.Cut(rest, " ")
		refs = append(refs, Ref{Hash: h, Name: name})
	}
	return refs, nil
}

// Clone resolves the given ref to a hash and returns the corresponding fs.FS.
func (r *Repo) Clone(ctx context.Context, ref string) (Hash, fs.FS, error) {
	fail := func(err error) (Hash, fs.FS, error) {
		return Hash{}, nil, fmt.Errorf("clone %s: %v", ref, err)
	}
	h, err := r.Resolve(ctx, ref)
	if err != nil {
		return fail(err)
	}
	tfs, _, err := r.fetch(ctx, h)
	if err != nil {
		return fail(err)
	}
	return h, tfs, nil
}

// CloneHash returns the fs.FS for the given hash.
func (r *Repo) CloneHash(ctx context.Context, h Hash) (fs.FS, []byte, error) {
	tfs, data, err := r.fetch(ctx, h)
	if err != nil {
		return nil, nil, fmt.Errorf("clone %s: %v", h, err)
	}
	return tfs, data, nil
}

// fetch returns the fs.FS for a given hash.
func (r *Repo) fetch(ctx context.Context, h Hash) (fs.FS, []byte, error) {
	// Fetch a shallow packfile from the remote server.
	// Shallow means it only contains the tree at that one commit,
	// not the entire history of the repo.
	// See https://git-scm.com/docs/protocol-v2#_fetch.
	opts, ok := r.caps["fetch"]
	if !ok {
		return nil, nil, fmt.Errorf("fetch: server does not support fetch")
	}
	if !strings.Contains(" "+opts+" ", " shallow ") {
		return nil, nil, fmt.Errorf("fetch: server does not support shallow fetch")
	}

	// Prepare and send request for pack file.
	var buf bytes.Buffer
	pw := newPktLineWriter(&buf)
	pw.WriteString("command=fetch")
	pw.Delim()
	pw.WriteString("deepen 1")
	pw.WriteString("want " + h.String())
	pw.WriteString("done")
	pw.Close()
	postbody := buf.Bytes()

	req, _ := http.NewRequestWithContext(ctx, "POST", r.url+"/git-upload-pack", &buf)
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Git-Protocol", "version=2")

	// fmt.Fprintf(os.Stderr, "\nPOST %s\n%s\n\n", r.url+"/git-upload-pack", postbody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("fetch: %v\n%s\n%s", resp.Status, data, hex.Dump(postbody))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-result" {
		return nil, nil, fmt.Errorf("fetch: invalid response Content-Type: %v", ct)
	}

	// Response is sequence of pkt-line packets.
	// It is plain text output (printed by git) until we find "packfile".
	// Then it switches to packets with a single prefix byte saying
	// what kind of data is in that packet:
	// 1 for pack file data, 2 for text output, 3 for errors.
	var data []byte
	pr := newPktLineReader(resp.Body)
	sawPackfile := false
	for {
		line, err := pr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, fmt.Errorf("fetch: parsing response: %v", err)
		}
		if line == nil { // ignore delimiter
			continue
		}
		if !sawPackfile {
			// Discard response lines until we get to packfile start.
			if strings.TrimSuffix(string(line), "\n") == "packfile" {
				sawPackfile = true
			}
			continue
		}
		if len(line) == 0 || line[0] == 0 || line[0] > 3 {
			fmt.Printf("%q\n", line)
			continue
		}
		switch line[0] {
		case 1:
			data = append(data, line[1:]...)
		case 2:
			fmt.Printf("%s\n", line[1:])
		case 3:
			return nil, nil, fmt.Errorf("fetch: server error: %s", line[1:])
		}
	}

	if !bytes.HasPrefix(data, []byte("PACK")) {
		return nil, nil, fmt.Errorf("fetch: malformed response: not packfile")
	}

	// Unpack pack file and return fs.FS for the commit we downloaded.
	var s store
	if err := unpack(&s, data); err != nil {
		return nil, nil, fmt.Errorf("fetch: %v", err)
	}
	s.repo = r
	tfs, cdata, err := s.Commit(h)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch: %v", err)
	}
	return tfs, cdata, nil
}

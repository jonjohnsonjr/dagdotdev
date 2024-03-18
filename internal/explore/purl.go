package explore

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/types"
)

type purl struct {
	tipe       string
	namespace  string
	name       string
	version    string
	qualifiers url.Values
	subpath    string
}

func (p *purl) url(repo string) (string, error) {
	switch p.tipe {
	case "docker":
		if p.version == "" {
			return "", fmt.Errorf("no version in purl")
		}
		repository := p.qualifiers.Get("repository_url")
		if repository == "" {
			if p.namespace == "" {
				p.namespace = "library"
			}
			if p.namespace != "" && p.name != "" {
				repository = path.Join("index.docker.io", p.namespace, p.name)
			}
		} else {
			repository = path.Join(repository, p.namespace, p.name)
		}
		mt := p.qualifiers.Get("mediaType")
		if mt == "" {
			mt = string(types.OCIManifestSchema1)
		}
		h := handlerForMT(mt)
		delim := "@"
		if !strings.Contains(p.version, ":") {
			delim = ":"
		}
		dig := p.qualifiers.Get("digest")
		if dig != "" {
			if delim == ":" {
				// tag and digest
				return fmt.Sprintf("/%s%s:%s@%s", h, repository, p.version, dig), nil
			}
			// just digest
			return fmt.Sprintf("/%s%s%s%s", h, repository, delim, dig), nil
		}

		// tag or digest as version
		return fmt.Sprintf("/%s%s%s%s", h, repository, delim, p.version), nil
	case "oci":
		if p.version == "" {
			return "", fmt.Errorf("no version in purl")
		}
		repository := p.qualifiers.Get("repository_url")
		if repository != "" {
			if p.namespace != "" {
				repository = path.Join(repository, p.namespace, p.name)
			} else {
				repository = path.Join(repository, p.name)
			}
		} else {
			repository = repo
		}
		mt := p.qualifiers.Get("mediaType")
		if mt == "" {
			mt = string(types.OCIManifestSchema1)
		}
		h := handlerForMT(mt)
		delim := "@"
		if !strings.Contains(p.version, ":") {
			delim = ":"
		}
		return fmt.Sprintf("/%s%s%s%s", h, repository, delim, p.version), nil
	case "github":
		return fmt.Sprintf("https://github.com/%s/%s/tree/%s", p.namespace, p.name, p.version), nil
	case "bitbucket":
		return fmt.Sprintf("https://www.bitbucket.org/%s/%s/changeset/%s", p.namespace, p.name, p.version), nil
	case "apk":
		if p.namespace == "alpine" {
			arch := p.qualifiers.Get("arch")
			return fmt.Sprintf("https://apk.dag.dev/https/dl-cdn.alpinelinux.org/alpine/edge/main/%s/%s-%s.apk", arch, p.name, p.version), nil
		} else if p.namespace == "wolfi" {
			arch := p.qualifiers.Get("arch")
			return fmt.Sprintf("https://apk.dag.dev/https/packages.wolfi.dev/os/%s/%s-%s.apk", arch, p.name, p.version), nil
		}
	}

	return "", fmt.Errorf("TODO: implement %q", p.tipe)
}

// scheme:type/namespace/name@version?qualifiers#subpath
func parsePurl(s string) (*purl, error) {
	if !strings.HasPrefix(s, "pkg:") {
		return nil, fmt.Errorf("does not start with 'pkg:': %s", s)
	}

	p := &purl{}
	s = strings.TrimPrefix(s, "pkg:")
	chunks := strings.SplitN(s, "/", 2)
	if len(chunks) != 2 {
		return nil, fmt.Errorf("weird purl: %s", s)
	}

	p.tipe = chunks[0]
	s = chunks[1]

	chunks = strings.SplitN(s, "/", 2)
	if len(chunks) == 2 {
		p.namespace = chunks[0]
		s = chunks[1]
	}

	// Optional stuff...
	version := false
	qualifiers := false

	chunks = strings.SplitN(s, "@", 2)
	if len(chunks) == 2 {
		p.name = chunks[0]
		s = chunks[1]
		version = true
	}

	chunks = strings.SplitN(s, "?", 2)
	if len(chunks) == 2 {
		if version {
			p.version = chunks[0]
		} else {
			p.name = chunks[0]
		}
		s = chunks[1]
		qualifiers = true
		version = false
	}

	chunks = strings.Split(s, "#")
	if len(chunks) == 2 {
		p.subpath = chunks[1]
	}

	if qualifiers {
		q, err := url.ParseQuery(chunks[0])
		if err != nil {
			return nil, err
		}
		p.qualifiers = q
	} else if version {
		p.version = chunks[0]
	} else {
		p.name = chunks[0]
	}

	return p, nil
}

package apk

import (
	"log"
	"strings"
	"sync"

	"github.com/jonjohnsonjr/dagdotdev/pkg/blobcache"
	"github.com/jonjohnsonjr/dagdotdev/pkg/soci"
)

func buildIndexCache() soci.BlobStore { return blobcache.BuildIndexCache("apk") }
func buildTocCache() soci.TOCCache    { return blobcache.BuildTOCCache() }

// apkCache caches parsed APKINDEX entries. Keyed by the part of an apk ref
// before the "@" digest; entries are tagged with the digest as an etag so a
// changed digest invalidates without an explicit purge.
type apkCache struct {
	mu sync.Mutex
	m  map[string]*apkCacheEntry
}

type apkCacheEntry struct {
	etag string
	pkgs []apkindex
	ptov map[string]string
}

func buildApkCache() *apkCache {
	return &apkCache{m: make(map[string]*apkCacheEntry)}
}

func (a *apkCache) Get(ref string) ([]apkindex, map[string]string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	before, digest, ok := strings.Cut(ref, "@")
	if !ok {
		log.Printf("ref: %q", ref)
		return nil, nil, false
	}

	e, ok := a.m[before]
	if !ok || e.etag != digest {
		return nil, nil, false
	}

	return e.pkgs, e.ptov, true
}

func (a *apkCache) Put(ref string, pkgs []apkindex, ptov map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	before, digest, ok := strings.Cut(ref, "@")
	if !ok {
		log.Printf("ref: %q", ref)
		return
	}
	a.m[before] = &apkCacheEntry{
		etag: digest,
		pkgs: pkgs,
		ptov: ptov,
	}
}

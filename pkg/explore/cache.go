package explore

import (
	"github.com/jonjohnsonjr/dagdotdev/pkg/blobcache"
	"github.com/jonjohnsonjr/dagdotdev/pkg/soci"
)

func buildIndexCache() soci.BlobStore { return blobcache.BuildIndexCache("soci") }
func buildTocCache() soci.TOCCache    { return blobcache.BuildTOCCache() }

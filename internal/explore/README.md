# Registry Explorer

How is this so fast?

## The Browser

We take advantage of content-addressability by setting aggressive `Cache-Control` headers so that your browser can cache as much as possible.
For example, navigating the filesystem will avoid hitting the server for a folder that your browser has already seen.

## Avoiding the Registry Preamble

Normally, registry interactions start with two requests:
```
# Ping
GET /v2/

# Token
GET /v2/token?scope=foo&service=bar
```

Followed by the request you actually want to make:
```
GET /v2/foo/manifests/latest
```

Most clients will do the Ping and Token requests once for a given invocation.
The registry explorer doesn't have the luxury of being very stateful, so a naive implmentation would have to do this preamble for every request.
That's unfortunate, because this adds ~200ms to every page load.

How do we get around that?

### Ping Cache

Note that the `GET /v2/` request isn't specific to any repository -- it's per domain -- and the ping response is usually very small.
We take advantage of that by maintaining a small in-memory cache mapping registry domains to their ping response.
That cache gets blown away whenever we scale to zero or scale up, but for someone clicking around multiple times, we can save that ~100ms for most page loads.

### Registry Cookie

We could do a similar thing for the token response, but that has some drawbacks:

1. We'd have an entry for every _repository_ instead of just every _domain_, so we would have a lot more entries.
2. The token response is generally a lot _larger_, so each entry would take up more space.
3. Token responses expire, so we'd have to manage eviction.
4. For non-public repositories, we wouldn't be able to share the token response anyway.

Instead, we let the client help us out by storing some state for us in a cookie:

```go
type CookieValue struct {
  Reg           string
  PingResp      *transport.PingResp
  Repo          string
  TokenResponse *transport.TokenResponse
}
```

This includes both the `PingResp` (which we can reuse if it's the same `Reg`)
and the `TokenResponse`, which we can reuse if it's the same `Repo`.

Navigating to a different repository will overwrite the `TokenResponse`, but most usage patterns result in only one TokenResponse per session.

Making this work required exposing some `transport` internals in `go-containerregistry` (which I haven't upstreamed as of this writing).
We could expose these changes and possibly take advantage of them in `crane` via a ping/token cache on disk.

## Manifests

For public manifests, we just cache a `remote.Descriptor` by digest in memory.
This gives us enough info to render manifests without having to re-fetch them for each request, similar to the ping cache.

When render a manifest _by tag_, we render any hyperlinks _by digest_ to ensure we can reuse this cache for subsequent requests.

For DockerHub in particular, we always send a HEAD request for tags and attempt to use this cache in order to avoid rate limiting.

## Blobs

Most blobs are gzipped tarballs, so we will focus on that.
For a long time, this was the slowest part of the registry explorer, which prevented me from being happy with it.
We could make browsing the layer filesystem fast by caching tar headers, but loading any content would require scanning the entire layer from the start every time.

### Seeking a Faster Gzip

My initial plan was to [stargzify](https://github.com/google/crfs) each layer to get seekable access, but I was hesitant to do that because:

1. It's expensive to re-compress layers.
2. It's expensive to store these stargzified layers somewhere.

A conversation with @aidansteele about [ima.ge.cx](https://ima.ge.cx) showed me a better way.
He explained how [`awslabs/soci-snapshotter`](https://github.com/awslabs/soci-snapshotter) works, which made me realize I was too quick to dismiss it.
In zlib examples, there is a [`zran.c`](https://github.com/madler/zlib/blob/04f42ceca40f73e2978b50e93806c2a18c1281fc/examples/zran.c) file that has been sitting there since 2005.
It demonstrates how to implement random access with gzip streaming!

This has been repackaged as [`gztool`](https://github.com/circulosmeos/gztool) ([blog post](https://circulosmeos.wordpress.com/2019/08/11/continuous-tailing-of-a-gzip-file-efficiently/)) to make it easier to use, but `soci-snapshotter` uses the same technique.
A hand-wavey explanation of how it works:

In order to seek to a given point in a gzip stream, you usually have to decompress and discard everything up to that point (in order to know how to decompress the next sequence of bytes).
The reason for this is that you need to get the gzip decoder into the correct state to decode the compressed stream.
That was my entire understanding of gzip, which is why I thought random access gzip was impossible, but if you know a little more about gzip internals, you can do something very clever.
The state of a gzip decoder isn't actually dependent on _all_ the bytes of the input stream.
The state it maintains is actually just a sliding window of the previous 32K bytes of uncompressed data (the _dictionary_).
If you have the 32K of uncompressed data leading up to a given offset in a gzip stream, you can start reading from there.
In fact, there is a [`NewReaderDict`](https://pkg.go.dev/compress/flate#NewReaderDict) function in `compress/flate` that does exactly that.

So how do we use this to our advantage?

Every so often (at the end of a [DEFLATE](https://en.wikipedia.org/wiki/Deflate) block), we can decide to create a checkpoint by:

1. Recording how many _compressed_ bytes we've read.
2. Recording how many _uncompressed_ bytes we've written.
3. Recording the 32K of uncompressed state.

Deciding the distance between checkpoints (the _span_) is a tradeoff between seek granularity and storage, but a reasonable interval results in an index that is ~1% of the size of the original compressed archive.

While we are creating the checkpoints, we also iterate through the decompressed tar file to create a table of contents by:

1. Recording each tar header we see.
2. Recording the offset into the _uncompressed_ stream where the tar files actual bytes can be found.

When we want to access a random file in the archive, we do so by:

1. Finding the offset for that file in our table of contents.
2. Finding the checkpoint with greatest _uncompressed_ offset less than `tar.Offset`.
3. Finding the checkpoint with the lowest _uncompressed_ offset greater than `tar.Offset + tar.Size`.
4. Sending a `Range` request to the registry that begins with the first checkpoint, ending with the second checkpoint (or EOF).
5. Initializing a `flate.Reader` with the first checkpoint's dictionary.
6. Discarding uncompressed bytes until we reach `tar.Offset`.

Now, to serve a given file, we only need to read (on average) `Span / 2` bytes instead of `LayerSize / 2` bytes.

For layers over ~50MB, this makes a noticeable difference and saves the registry on egress.

### Range Requests

Actually making those range requests is kind of pain.
You can see in [`soci-snapshotter`](https://github.com/awslabs/soci-snapshotter/blob/86ddfcdb2c521586177bf3c33eed7e7dcb516f86/fs/remote/resolver.go#L316-L350) that some registries behave differently for HEAD vs GET requests.
Most registries redirect once (or even multiple times, e.g. `registry.k8s.io`) to serve blobs, so we have to probe to figure out the _final_ URL to which we can send Range requests.
This adds 1 useless redirected roundtrip whenever we fetch a file, so we'd like to avoid that.

Similar to the registry token trick, we let the client cache this for us:

```go
type RedirectCookie struct {
  Digest string
  Url    string
  Body   bool
}
```

The first time we load the layer, we have to probe for the object URL, but subsequent requests will be able to send Range requests directly.
Those URLs are usually good for several minutes (downloads can take a while), so this works fine in practice.
We also store enough information here to know if the registry actually supports Range requests in the first place (or if we have to get the whole thing).

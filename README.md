# `oci.dag.dev`

This is a web server for exploring the contents of an OCI registry.

In the future, it may be all the best kinds of dags.

This code is _not_ production quality. It is a hack.

## Running it

Use [`ko`](https://github.com/ko-build/ko) to build this.

This is very much tailored to running my own stuff on Cloud Run.

Some things will probably break if the environment is different.

For local testing, I usually:

```
CACHE_DIR=/tmp/oci go run ./cmd/oci -v
```

On Cloud Run, I set `CACHE_BUCKET` to a GCS bucket in the same region as the service.

If you want private GCP images to work via oauth, you need to set `CLIENT_ID`, `CLIENT_SECRET`, and `REDIRECT_URL` to the correct values.

If you want to use ambient creds, set `AUTH=keychain`.

Deploying to cloud run should look something like:

```
gcloud run deploy explore --image $(ko build ./cmd/oci -B)
```

It is a good idea to deploy it in the same region as your `CACHE_BUCKET` and (if possible) registry in order to avoid egress costs.

## Contributions

Currently, this forks a lot of things in order to violate abstractions in the name of performance.

I'm very interested in anything that lets me unfork dependencies, docs, and features.

I'm somewhat interested in random cleanups, tests, and performance improvements.

I am okay with contributions that make this easier for you to run, as long as they don't add new external dependencies in a way that adds to my maintenance burden.

I am also not a frontend developer, so if there's something dumb I am doing with CSS or HTML that could be optimized or would make the frontend look nicer, I'm open to it; however, I will push back heavily against any javascript or frameworks unless there's a huge benefit to it.

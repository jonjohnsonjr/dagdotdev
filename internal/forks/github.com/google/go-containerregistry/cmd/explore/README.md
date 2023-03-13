# `explore.ggcr.dev`

This is a web server for exploring the contents of a registry.

By default, this only works for public images.

To explore a private registry using your `~/.docker/config.json` credentials:
```
go run ./cmd/explore -auth
```

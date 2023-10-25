# http-log

[![build](https://github.com/mt-inside/http-log/actions/workflows/test.yaml/badge.svg)](https://github.com/mt-inside/http-log/actions/workflows/test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mt-inside/http-log.svg)](https://pkg.go.dev/github.com/mt-inside/http-log)
[![Go Report Card](https://goreportcard.com/badge/github.com/mt-inside/http-log)](https://goreportcard.com/report/github.com/mt-inside/http-log)

TODO Asciinema etc

## Stand-alone Daemon

These args will listen on `https://0.0.0.0:8080` with a self-signed cert, log requests, and respond with a json object. See `http-log -h`.

Run from container image:
```bash
docker run -t --rm -p8080:8080 ghcr.io/mt-inside/http-log:v0.7.15
```

Download single, statically-linked binary
```bash
wget -O http-log https://github.com/mt-inside/http-log/releases/download/v0.7.15/http-log-$(uname -s)-$(uname -m)
chmod u+x http-log
./http-log
```

Install from source
```bash
go install github.com/mt-inside/http-log/cmd/http-log@latest
${GOPATH}/bin/http-log
```

## AWS Lambda

`docker build ./cmd/lambda`

Packaging and publishing is left as an exercise for the reader (I forgot how I did it)

# Usage

## HTTP Versions

Note: h2c - h2 cleartext - is the name for h2/plaintext. The "correct" way to initiate such a connection is to send an http/1.1 request with an `Upgrade: h2c` field. Of course a client (like an Envoy proxy) can be configured with a-priori knowledge that the server accepts h2c, and just send h2 right away.

* With TLS (a `-K` option other than `off`, or `-k/-c`)
  * Default: TLS's ALPN field allows client and server to negotiate HTTP version. http-log supports h2, and any modern client will do as well. The default with TLS enabled is "let it negotiate", which makes h2 effectively the default.
  * With `--http-11`: we force http/1.1. This is done by returning _no_ protocols in the ALPN field, which means negotiation can't happen, and the default is used, which is http/1.1.
* Without TLS (`-K=off`, or no `-K` and no `-k/-c`) http/1.1 is the "standard" version. It's usually quite hard to force clients (and server libraries) to do h2 over plaintext.
  * Default: because of some magic in the Go libraries, it's able to accept either http/1.1 or h2 simultaneously. h2 connections can either be h2 on the first request, or can upgrade with an HTTP/1.1 call with header `Upgrade: h2c`.
  * With `--http-11`: we disable the h2 handling. http/1.1 will work fine.
    * If you send an h2c upgrade request you'll see it printed, but the h2 upgrade and "main" request won't happen.
    * If you send an immediate h2 request, you'll see a log of a PRI method, with no other data (as that very first part of the h2 request is h1 compatible)

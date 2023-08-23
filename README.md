# http-log

[![build](https://github.com/mt-inside/http-log/actions/workflows/test.yaml/badge.svg)](https://github.com/mt-inside/http-log/actions/workflows/test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mt-inside/http-log.svg)](https://pkg.go.dev/github.com/mt-inside/http-log)
[![Go Report Card](https://goreportcard.com/badge/github.com/mt-inside/http-log)](https://goreportcard.com/report/github.com/mt-inside/http-log)

todo Asciinema etc

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

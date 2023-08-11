# http-log

[![build](https://github.com/mt-inside/http-log/actions/workflows/test.yaml/badge.svg)](https://github.com/mt-inside/http-log/actions/workflows/test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mt-inside/http-log.svg)](https://pkg.go.dev/github.com/mt-inside/http-log)
[![Go Report Card](https://goreportcard.com/badge/github.com/mt-inside/http-log)](https://goreportcard.com/report/github.com/mt-inside/http-log)

## Stand-alone Daemon

### Run locally
Listen on `http://0.0.0.0:8090`, log requests, and respond with a json object.
`go run ./cmd/http-log --addr :8090 --output json`

See all args
`go run ./cmd/http-log -h`

### Build and run docker image
`docker build . -t http-log`

`docker run http-log`

## AWS Lambda

`docker build ./cmd/lambda`

Packaging and publishing is left as an exercise for the reader (I forgot how I did it)

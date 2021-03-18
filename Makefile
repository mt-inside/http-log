.PHONY: lint build run image image-push image-run
.DEFAULT_GOAL := run

REPO ?= mtinside/http-log
TAG ?= v0.5

lint:
	go fmt ./...
	go vet ./...
	golint ./...
	golangci-lint run ./...
	go test ./...

build: lint
	go build -o http-log ./...

lambda: lint
	CGO_ENABLED=0 GOOS=linux go build -o http-log-lambda ./cmd/lambda
	zip http-log-lambda.zip http-log-lambda

run: lint
	go run ./cmd/daemon

image:
	docker build -t $(REPO):$(TAG) .

image-push: image
	docker push $(REPO):$(TAG)

image-run: image
	docker run -p8080:8080 $(REPO):$(TAG)

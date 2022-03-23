default:
	@just --list

REPO := "mtinside/http-log"
TAG := "0.6"

lint:
	go fmt ./...
	go vet ./...
	golint ./...
	golangci-lint run ./...
	go test ./...

build-lambda: lint
	CGO_ENABLED=0 GOOS=linux go build -o http-log-lambda ./cmd/lambda
	zip http-log-lambda.zip http-log-lambda

run-daemon *ARGS: #lint
	go run ./cmd/http-log -t -m -b -k=ecdsa {{ARGS}}

run-daemon-docker: package-docker
	docker run -p8080:8080 {{REPO}}:{{TAG}}

package-docker:
	docker build -t {{REPO}}:{{TAG}} .

publish-docker: package-docker
	docker push {{REPO}}:{{TAG}}

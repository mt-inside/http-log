default:
	@just --list

REPO := "mtinside/http-log"
TAG := `git describe --tags --abbrev`
TAGD := `git describe --tags --abbrev --dirty`
ARCHS := "linux/amd64,linux/arm64,linux/arm/v7"

install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

lint:
	go fmt ./...
	go vet ./...
	staticcheck ./...
	golangci-lint run ./... # TODO: --enable-all
	go test ./...

build-lambda: lint
	CGO_ENABLED=0 GOOS=linux go build -o http-log-lambda ./cmd/lambda
	zip http-log-lambda.zip http-log-lambda

run-daemon *ARGS: lint
	go run ./cmd/http-log -t -m -b -K=ecdsa {{ARGS}}

run-daemon-mtls-jwt *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -t -m -b -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/home/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -t -m -b -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/home/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-mtls-jwt-all-summaries *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -n -t -m -b -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/home/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt-all-summaries *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -n -t -m -b -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/home/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-mtls-jwt-all-fulls *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -N -T -M -B -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/home/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt-all-fulls *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -N -T -M -B -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/home/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-docker: package-docker
	docker run -ti -p8080:8080 {{REPO}}:{{TAG}}

package-docker:
	docker buildx build --build-arg VERSION={{TAGD}} -t {{REPO}}:{{TAG}} -t {{REPO}}:latest --load .
publish-docker:
	docker buildx build --platform={{ARCHS}} -t {{REPO}}:{{TAG}} -t {{REPO}}:latest --push .

docker-ls:
	hub-tool tag ls --platforms {{REPO}}
docker-inspect:
	docker buildx imagetools inspect {{REPO}}:{{TAG}}

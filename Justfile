set dotenv-load

default:
	@just --list --unsorted --color=always

DH_USER := "mtinside"
REPO := DH_USER + "/http-log"
TAG := `git describe --tags --abbrev`
TAGD := `git describe --tags --abbrev --dirty`
ARCHS := "linux/amd64,linux/arm64,linux/arm/v7"
CGR_ARCHS := "amd64" # "amd64,aarch64,armv7"

install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

lint:
	goimports -local github.com/mt-inside/http-log -w .
	go vet ./...
	staticcheck ./...
	golangci-lint run ./... # TODO: --enable-all
	go test ./...

build: lint
	# Use CGO here, like in the container, so this binary is pretty representative.
	# Don't statically link though, as that's a nightmare on all possible dev machines.
	go build -a -ldflags "-X 'github.com/mt-inside/http-log/pkg/build.Version="{{TAGD}}"'" ./cmd/http-log

build-lambda: lint
	CGO_ENABLED=0 GOOS=linux go build -o http-log-lambda ./cmd/lambda
	zip http-log-lambda.zip http-log-lambda

run-daemon *ARGS: lint
	go run ./cmd/http-log -K=ecdsa {{ARGS}}

run-daemon-mtls-jwt *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -l -t -m -b -r -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -l -t -m -b -r -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-mtls-jwt-all-summaries *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -l -n -t -m -b -r -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt-all-summaries *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -l -n -t -m -b -r -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-mtls-jwt-all-fulls *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -L -N -T -M -B -R -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt-all-fulls *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -L -N -T -M -B -R -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-proxy-mtls-self-sign-jwt-all-summaries *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -p http://localhost:8888 -L -n -t -m -b -R -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-proxy-mtls-self-sign-jwt-all-fulls *ARGS: lint
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run ./cmd/http-log -p http://localhost:8888 -L -N -T -M -B -R -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-proxy-backend *ARGS: lint
	go run ./cmd/http-log -a localhost:8888 -L -t -M -b -r {{ARGS}}
run-daemon-proxy-backend-all-fulls *ARGS: lint
	go run ./cmd/http-log -a localhost:8888 -L -T -M -B -R {{ARGS}}


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

snyk:
	snyk test .
	snyk container test {{REPO}}:{{TAG}}

melange:
	# keypair to verify the package between melange and apko. apko will very quietly refuse to find our apk if these args aren't present
	docker run --rm -v "${PWD}":/work cgr.dev/chainguard/melange keygen
	docker run --privileged --rm -v "${PWD}":/work cgr.dev/chainguard/melange build --arch {{CGR_ARCHS}} --signing-key melange.rsa melange.yaml
package-cgr: melange
	docker run --rm -v "${PWD}":/work cgr.dev/chainguard/apko build -k melange.rsa.pub --build-arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}} http-log.tar
	docker load < http-log.tar
publish-cgr: melange
	docker run --rm -v "${PWD}":/work --entrypoint sh cgr.dev/chainguard/apko --debug -c \
		'echo "'${DH_TOKEN}'" | apko login docker.io -u {{DH_USER}} --password-stdin && \
		apko publish apko.yaml {{REPO}}:{{TAG}} -k melange.rsa.pub --arch {{CGR_ARCHS}}'

sbom-show:
	docker sbom {{REPO}}:{{TAG}}

cosign-sign:
	# Experimental includes pushing the signature to a Rekor transparency log, default: rekor.sigstore.dev
	COSIGN_EXPERIMENTAL=1 cosign sign {{REPO}}:{{TAG}}
cosign-verify:
	COSIGN_EXPERIMENTAL=1 cosign verify {{REPO}}:{{TAG}} | jq .

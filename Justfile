set dotenv-load

default:
	@just --list --unsorted --color=always

DH_USER := "mtinside"
REPO := "docker.io/" + DH_USER + "/http-log"
TAG := `git describe --tags --always --abbrev`
TAGD := `git describe --tags --always --abbrev --dirty --broken`
CGR_ARCHS := "amd64,aarch64" # ,x86,armv7 - will fail cause no wolfi packages for these archs
LD_COMMON := "-ldflags \"-X 'github.com/mt-inside/http-log/internal/build.Version=" + TAGD + "'\""
LD_STATIC := "-ldflags \"-X 'github.com/mt-inside/http-log/internal/build.Version=" + TAGD + "' -w -linkmode external -extldflags '-static'\""
MELANGE := "melange"
APKO    := "apko"

tools-install:
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/exp/cmd/...@latest
	go install github.com/kisielk/godepgraph@latest
	go install golang.org/x/tools/cmd/stringer@latest

generate:
	go generate ./...

lint: generate
	gofmt -s -w .
	goimports -local github.com/mt-inside/http-log -w .
	go vet ./...
	staticcheck ./...
	golangci-lint run ./... # TODO: --enable-all

test: lint
	go test ./... -race -covermode=atomic -coverprofile=coverage.out

render-mod-graph:
	go mod graph | modgraphviz | dot -Tpng -o mod_graph.png

render-pkg-graph:
	godepgraph -s -onlyprefixes github.com/mt-inside ./cmd/http-log | dot -Tpng -o pkg_graph.png

build-dev: test
	# Use CGO here, like in the container, so this binary is pretty representative.
	# Don't statically link though, as that's a nightmare on all possible dev machines.
	go build {{LD_COMMON}} ./cmd/http-log

# Don't lint/test, because it doesn't work in various CI envs
build-ci *ARGS:
	# We use CGO, so that we get libc's sophisticated name resolution etc. This is basically pointless because we're in a container which won't have NIS/LDAP/etc set up, but maybe someone wants to mount that config in?
	# Since we use CGO, force gcc's ld, and tell it to statically link libc in, for ease of packaging in a container
	go build {{LD_STATIC}} {{ARGS}} ./cmd/http-log

build-lambda: test
	CGO_ENABLED=0 GOOS=linux go build -o http-log-lambda ./cmd/lambda
	zip http-log-lambda.zip http-log-lambda

package: test
	# if there's >1 package in this directory, apko seems to pick the _oldest_ without fail
	rm -rf ./packages/
	{{MELANGE}} bump melange.yaml {{TAGD}}
	{{MELANGE}} keygen
	{{MELANGE}} build --arch {{CGR_ARCHS}} --signing-key melange.rsa melange.yaml

image-local:
	{{APKO}} build --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}} http-log.tar
	docker load < http-log.tar
image-publish:
	{{APKO}} login docker.io -u {{DH_USER}} --password "${DH_TOKEN}"
	{{APKO}} publish --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko.yaml {{REPO}}:{{TAG}}
image-publish-no-certs:
	{{APKO}} login docker.io -u {{DH_USER}} --password "${DH_TOKEN}"
	{{APKO}} publish --keyring-append melange.rsa.pub --arch {{CGR_ARCHS}} apko-no-certs.yaml {{REPO}}:{{TAG}}-no-certs
cosign-sign:
	# Experimental includes pushing the signature to a Rekor transparency log, default: rekor.sigstore.dev
	COSIGN_EXPERIMENTAL=1 cosign sign {{REPO}}:{{TAG}}

image-ls:
	hub-tool tag ls --platforms {{REPO}}
image-inspect:
	docker buildx imagetools inspect {{REPO}}:{{TAG}}
sbom-show:
	docker sbom {{REPO}}:{{TAG}}
snyk:
	snyk test .
	snyk container test {{REPO}}:{{TAG}}
cosign-verify:
	COSIGN_EXPERIMENTAL=1 cosign verify {{REPO}}:{{TAG}} | jq .

clean:
	rm -f coverage.out
	rm -f mod_graph.png pkg_graph.png
	rm -f sbom-*
	rm -rf packages/
	rm -rf http-log.tar
	rm -f htto-log
	rm -f melange.rsa*

run-daemon-image:
	docker run -ti -p8080:8080 {{REPO}}:{{TAG}}

run-daemon *ARGS: test
	go run {{LD_COMMON}} ./cmd/http-log -K=ecdsa {{ARGS}}

run-daemon-mtls-jwt *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -l -t -m -b -r -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -l -t -m -b -r -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-mtls-jwt-all-summaries *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -l -n -t -m -b -r -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt-all-summaries *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -l -n -t -m -b -r -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-mtls-jwt-all-fulls *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -L -N -T -M -B -R -k=../print-cert/ssl/server-key.pem -c=../print-cert/ssl/server-cert.pem -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-mtls-self-sign-jwt-all-fulls *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -L -N -T -M -B -R -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-proxy-mtls-self-sign-jwt-all-summaries *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -p http://localhost:8888 -L -n -t -m -b -R -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}
run-daemon-proxy-mtls-self-sign-jwt-all-fulls *ARGS: test
	# FIXME hardcoded path; copy JWT creation stuff from istio-demo-master into mkpki
	go run {{LD_COMMON}} ./cmd/http-log -p http://localhost:8888 -L -N -T -M -B -R -K=ecdsa -C=../print-cert/ssl/client-ca-cert.pem -j=/Users/matt/work/personal/talks/istio-demo-master/41/pki/public.pem {{ARGS}}

run-daemon-proxy-backend *ARGS: test
	go run {{LD_COMMON}} ./cmd/http-log -a localhost:8888 -L -t -M -b -r {{ARGS}}
run-daemon-proxy-backend-all-fulls *ARGS: test
	go run {{LD_COMMON}} ./cmd/http-log -a localhost:8888 -L -T -M -B -R {{ARGS}}

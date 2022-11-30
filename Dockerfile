FROM golang:1.19 as build
# MUST come after FROM
ARG VERSION=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# including the .git dir
COPY . .
# Because we're building *in* a container for a container, there's no cross-OS-compilation; no need to specify GOOS
# Also because we take ARG ARCH and use buildx (invokes qemu), we always use the native compiler for any platform; never any need to specify GOARCH
# We leave CGO on (and don't set anti-CGO tag "netgo") so that we get the advanced name resolution etc functions from full glibc. To easily package this into a container, we ask for external (gcc) linking, and tell gcc's ld to do a static link
RUN go install -a -ldflags "-w -linkmode external -extldflags '-static' -X 'github.com/mt-inside/http-log/pkg/build.Version="${VERSION}"'" ./cmd/http-log


FROM gcr.io/distroless/static-debian10:latest AS run

ARG PORT=8080

COPY --from=build /go/bin/http-log /

EXPOSE $PORT
ENTRYPOINT ["/http-log"]
CMD ["-m", "-b"]

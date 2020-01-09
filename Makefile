.PHONY: build run test
.DEFAULT_GOAL := build

build:
	bazel run //:gazelle -- update-repos -prune=true -from_file=go.mod -to_macro=go_repos.bzl%go_repositories
	bazel run //:gazelle
	bazel build //...

test:
	bazel test --test_output=errors //...

run:
	bazel run //cmd

image:
	bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //cmd:image.tar

image-run-local: image
	docker load -i bazel-bin/cmd/image.tar
	docker run -p8080:8080 bazel/cmd:image

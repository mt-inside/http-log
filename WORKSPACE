load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# == Golang ==

# Load the rules' repo
http_archive(
    name = "io_bazel_rules_go",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/rules_go/releases/download/v0.20.3/rules_go-v0.20.3.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.20.3/rules_go-v0.20.3.tar.gz",
    ],
    sha256 = "e88471aea3a3a4f19ec1310a55ba94772d087e9ce46e41ae38ecebe17935de7b",
)

# From that repo, load these macros
load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()  # Dependencies for the toolchain and the rules' code itself

go_register_toolchains(nogo = "@//:my_nogo")  # Install a Golang toolchain into the sandbox

# == Docker ==

# Load the rules' repo
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "df13123c44b4a4ff2c2f337b906763879d94871d16411bf82dcfeba892b58607",
    strip_prefix = "rules_docker-0.13.0",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.13.0/rules_docker-v0.13.0.tar.gz"],
)

# From that repo, load these macros
load("@io_bazel_rules_docker//repositories:repositories.bzl", container_repositories = "repositories")

# And execute
container_repositories() # ??

# Now golang-specific stuff...
# Load
load("@io_bazel_rules_docker//go:image.bzl", _go_image_repos = "repositories")

# Execute
_go_image_repos()

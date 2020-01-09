load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_repositories():
    go_repository(
        name = "com_github_logrusorgru_aurora",
        importpath = "github.com/logrusorgru/aurora",
        sum = "h1:bqDmpDG49ZRnB5PcgP0RXtQvnMSgIF14M7CBd2shtXs=",
        version = "v0.0.0-20200102142835-e9ef32dff381",
    )

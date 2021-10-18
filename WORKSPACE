load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "bazel_skylib",
    branch = "main",
    remote = "https://github.com/bazelbuild/bazel-skylib",
)

git_repository(
    name = "rules_cc",
    branch = "main",
    remote = "https://github.com/bazelbuild/rules_cc",
)

load("@rules_cc//cc:repositories.bzl", "rules_cc_dependencies")

rules_cc_dependencies()

git_repository(
    name = "rules_proto",
    branch = "master",
    remote = "https://github.com/bazelbuild/rules_proto",
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

git_repository(
    name = "absl",
    branch = "master",
    remote = "https://github.com/abseil/abseil-cpp",
)

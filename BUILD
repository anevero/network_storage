load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

proto_library(
    name = "message_proto",
    srcs = ["message.proto"],
)

cc_proto_library(
    name = "message_cc_proto",
    deps = [":message_proto"],
)

cc_import(
    name = "cryptopp",
    hdrs = glob(["cryptopp/*.h"]),
    shared_library = "cryptopp/libcryptopp.so.8",
)

cc_library(
    name = "encryption",
    srcs = ["encryption.cc"],
    hdrs = ["encryption.h"],
    deps = [
        ":cryptopp",
        "@absl//absl/random",
    ],
)

cc_library(
    name = "utils",
    srcs = ["utils.cc"],
    hdrs = ["utils.h"],
    deps = [
        ":message_cc_proto",
        "@absl//absl/strings",
    ],
)

cc_library(
    name = "storage",
    srcs = ["storage.cc"],
    hdrs = ["storage.h"],
    deps = [
        "@absl//absl/container:flat_hash_map",
        "@absl//absl/status",
        "@absl//absl/types:optional",
    ],
)

cc_library(
    name = "connection",
    srcs = ["connection.cc"],
    hdrs = ["connection.h"],
    deps = [
        ":encryption",
        ":message_cc_proto",
        ":storage",
        ":utils",
    ],
)

cc_binary(
    name = "server",
    srcs = ["server.cc"],
    linkopts = ["-lpthread"],
    deps = [
        ":connection",
        ":storage",
        "@absl//absl/container:flat_hash_map",
    ],
)

cc_binary(
    name = "client",
    srcs = ["client.cc"],
    deps = [
        ":encryption",
        ":message_cc_proto",
        ":utils",
        "@absl//absl/strings",
    ],
)

// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Minizip",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "Minizip",
            targets: ["Core", "PKCRYPT", "WZAES", "BZIP2"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "Core",
            dependencies: [],
            path: ".",
            sources: ["mz","mz_os","mz_os_posix","mz_compat","mz_crypt","mz_strm","mz_strm_mem","mz_strm_buf","mz_strm_crypt","mz_strm_os_posix","mz_strm_zlib","mz_zip","mz_zip_rw","mz_strm_split"].flatMap { ["\($0).c", "\($0).h"] },
            cSettings: [
                .define("HAVE_INTTYPES_H"),
                .define("HAVE_STDINT_H"),
                .define("HAVE_ZLIB"),
            ],
            linkerSettings: [
                .linkedLibrary("z"),
                .linkedLibrary("iconv"),
            ]),
        .target(
            name: "PKCRYPT",
            dependencies: ["Core"],
            path: ".",
            sources: ["mz_strm_pkcrypt"].flatMap { ["\($0).c", "\($0).h"] },
            cSettings: [
                .define("HAVE_PKCRYPT"),
            ]),
        .target(
            name: "WZAES",
            dependencies: ["Core"],
            path: ".",
            sources: ["mz_strm_wzaes"].flatMap { ["\($0).c", "\($0).h"] } + ["mz_crypt_apple.c"],
            cSettings: [
                .define("HAVE_WZAES"),
            ],
            linkerSettings: [
                .linkedFramework("Security"),
            ]),
        .target(
            name: "BZIP2",
            dependencies: ["Core"],
            path: ".",
            sources: ["mz_strm_bzip"].flatMap { ["\($0).c", "\($0).h"] },
            cSettings: [
                .define("HAVE_BZIP2"),],
            linkerSettings: [
                .linkedLibrary("bz2"),
            ]),
    ]
)

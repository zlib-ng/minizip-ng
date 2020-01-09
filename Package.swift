// swift-tools-version:5.1

import PackageDescription
import Foundation

var minizipSources = [
    "mz",
    "mz_os", "mz_os_posix",
    "mz_compat",
    "mz_crypt",
    "mz_strm", "mz_strm_mem", "mz_strm_buf", "mz_strm_crypt", "mz_strm_os_posix", "mz_strm_zlib", "mz_strm_split",
    "mz_zip", "mz_zip_rw"
    ].flatMap { ["\($0).c", "\($0).h"] }

var minizipCSettings: [CSetting] = [
    .define("HAVE_INTTYPES_H"),
    .define("HAVE_STDINT_H"),
    .define("HAVE_ZLIB")
]

var minizipLinkerSettings: [LinkerSetting] = [
    .linkedLibrary("z"),
    .linkedLibrary("iconv")
]

if ProcessInfo.processInfo.environment["MZ_BZIP2"] != "OFF" {
    minizipSources += ["mz_strm_bzip"].flatMap { ["\($0).c", "\($0).h"] }
    minizipCSettings += [
        .define("HAVE_BZIP2")
    ]
    minizipLinkerSettings += [
        .linkedLibrary("bz2")
    ]
}

if ProcessInfo.processInfo.environment["MZ_WZAES"] != "OFF" {
    minizipSources += ["mz_strm_wzaes"].flatMap { ["\($0).c", "\($0).h"] } + ["mz_crypt_apple.c"]
    minizipCSettings += [
        .define("HAVE_WZAES")
    ]
    minizipLinkerSettings += [
        .linkedFramework("Security")
    ]
}

if ProcessInfo.processInfo.environment["MZ_PKCRYPT"] != "OFF" {
    minizipSources += ["mz_strm_pkcrypt"].flatMap { ["\($0).c", "\($0).h"] }
    minizipCSettings += [
        .define("HAVE_PKCRYPT")
    ]
}

let package = Package(
    name: "Minizip",
    products: [
        .library(
            name: "minizip",
            targets: ["CMinizip"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "CMinizip",
            dependencies: [],
            path: ".",
            sources: minizipSources,
            publicHeadersPath: "./swiftpm/include",
            cSettings: minizipCSettings,
            linkerSettings: minizipLinkerSettings)
    ]
)

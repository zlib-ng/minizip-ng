// swift-tools-version: 5.5
import PackageDescription

let package = Package(
  name: "minizip-ng",
  products: [
    .library(name: "minizip.3", type: .dynamic, targets: ["minizip-target"]),
    .library(name: "minizip", type: .static, targets: ["minizip-target"]),
  ],
  targets: [
    .target(
      name: "minizip-target",
      path: ".",
      exclude: [
        "mz_crypt_openssl.c",
        "mz_strm_lzma.c",
        "mz_strm_zstd.c",
        "mz_crypt_win32.c",
        "mz_os_win32.c",
        "mz_strm_os_win32.c",
      ],
      sources: [
        "minizip.c",
        "mz_compat.c",
        "mz_crypt.c",
        "mz_crypt_apple.c",
        "mz_os.c",
        "mz_os_posix.c",
        "mz_strm.c",
        "mz_strm_buf.c",
        "mz_strm_bzip.c",
        "mz_strm_libcomp.c",
        "mz_strm_libcomp.h",
        "mz_strm_mem.c",
        "mz_strm_os_posix.c",
        "mz_strm_pkcrypt.c",
        "mz_strm_split.c",
        "mz_strm_zlib.c",
        "mz_zip.c",
        "mz_zip_rw.c",
      ],
      publicHeadersPath: ".",
      cSettings: [
        .define("HAVE_ZLIB"),
        .define("HAVE_BZIP2"),
        .define("HAVE_LIBCOMP"),
        .define("HAVE_ICONV"),
        .define("MZ_ZIP_SIGNING", .when(platforms: [.macOS])),
        .define("MZ_ZIP_NO_MAIN"),
        .define("ZLIB_COMPAT"),
      ],
      linkerSettings: [
        .linkedLibrary("z"),
        .linkedLibrary("bz2"),
        .linkedLibrary("iconv"),
        .linkedLibrary("compression"),
        .linkedFramework("CoreFoundation"),
        .linkedFramework("Security"),
        // https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/DynamicLibraryDesignGuidelines.html
        .unsafeFlags([
          "-Xlinker", "-current_version",
          "-Xlinker", "3.0.8",
          "-Xlinker", "-compatibility_version",
          "-Xlinker", "3.0",
        ]),
      ]
    )
  ],
  cLanguageStandard: CLanguageStandard.c11
)

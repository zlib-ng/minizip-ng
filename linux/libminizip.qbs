import qbs;

Product {
    name: "libminizip"
    targetName: "minizip"
    type: [ "staticlibrary" ]

    Depends { name: "cpp" }

    cpp.commonCompilerFlags: [
        "-Wno-unused-parameter",
        "-Wno-unused-function",
        "-Wno-empty-body"
    ]

    Properties {
        condition: qbs.targetOS.contains("linux")
        cpp.includePaths: outer.concat([
            "/usr/include/"
        ])
        cpp.defines: [
            "__USE_LARGEFILE64",
            "_LARGEFILE64_SOURCE"
        ]
        cpp.dynamicLibraries: [
            "z"
        ]
    }

    Group {
        name: "sources"
        prefix: "../"
        files: [
            "crypt.c",
            "ioapi.c",
            "ioapi_buf.c",
            "ioapi_mem.c",
            "unzip.c",
            "zip.c"
        ]
    }

    Group {
        name: "headers"
        prefix: "../"
        files: [
            "crypt.h",
            "ioapi.h",
            "ioapi_buf.h",
            "ioapi_mem.h",
            "unzip.h",
            "zip.h"
        ]
    }
}




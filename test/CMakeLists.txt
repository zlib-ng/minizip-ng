cmake_minimum_required(VERSION 3.12)

include(FetchContent)

enable_language(CXX)

# Google test requires MSAN-instrumented C++ standard library headers and
# runtime. System libstdc++ and libc++ are not built with MSAN, so building
# against them produces false positives during gtest static registration.
# Expect LLVM_BUILD_DIR to point at an out-of-tree build of libc++ +
# libc++abi compiled with -DLLVM_USE_SANITIZER=MemoryWithOrigins.
if(MZ_SANITIZER STREQUAL "memory")
    if(NOT DEFINED ENV{LLVM_BUILD_DIR})
        message(FATAL_ERROR "MSAN instrumented C++ libraries required!")
    endif()

    # Must set include and compile options before fetching googletest
    include_directories($ENV{LLVM_BUILD_DIR}/include $ENV{LLVM_BUILD_DIR}/include/c++/v1)
    add_compile_options(-stdlib=libc++ -g)
elseif(NOT TARGET GTest::GTest)
    find_package(GTest QUIET)
endif()

if(NOT TARGET GTest::GTest)
    if (WIN32)
        # Prevent overriding the parent project's compiler/linker settings for Windows
        set(gtest_force_shared_crt ON CACHE BOOL
            "Use shared (DLL) run-time lib even when Google Test is built as static lib." FORCE)

        set(gtest_disable_pthreads ON CACHE BOOL "Disable pthreads" FORCE)
    endif()

    # Allow specifying alternative Google test repository
    if(NOT DEFINED GTEST_REPOSITORY)
        set(GTEST_REPOSITORY https://github.com/google/googletest.git)
    endif()
    if(NOT DEFINED GTEST_TAG)
        # Use older version of Google test to support older versions of GCC
        if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS_EQUAL 5.3)
            set(GTEST_TAG release-1.10.0)
        else()
            set(GTEST_TAG v1.16.0)
        endif()
    endif()

    # Fetch Google test source code from official repository
    FetchContent_Declare(googletest
        GIT_REPOSITORY ${GTEST_REPOSITORY}
        GIT_TAG ${GTEST_TAG})

    FetchContent_MakeAvailable(googletest)
    if(NOT googletest_POPULATED)
        FetchContent_Populate(googletest)
        add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
    add_library(GTest::GTest ALIAS gtest)
endif()

set(TEST_SRCS
    test_crypt.cc
    test_encoding.cc
    test_file.cc
    test_path.cc
    test_stream.cc
    test_stream_compress.cc
    test_stream_crypt.cc
    )

if(MZ_COMPAT)
    list(APPEND TEST_SRCS test_compat.cc)
endif()

add_executable(gtest_minizip test_main.cc ${TEST_SRCS})
target_compile_definitions(gtest_minizip PRIVATE ${STDLIB_DEF} ${MINIZIP_DEF})
target_include_directories(gtest_minizip PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_BINARY_DIR})

target_link_libraries(gtest_minizip MINIZIP::minizip GTest::gtest GTest::gmock)

if(MZ_SANITIZER STREQUAL "memory")
    target_link_directories(gtest_minizip PRIVATE $ENV{LLVM_BUILD_DIR}/lib)
    target_link_options(gtest_minizip PRIVATE
        -stdlib=libc++
        -lc++abi
        -Wl,-rpath,$ENV{LLVM_BUILD_DIR}/lib)
endif()

if(MSVC)
    set_target_properties(gtest_minizip PROPERTIES
        VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

add_test(NAME gtest_minizip
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} $<TARGET_FILE:gtest_minizip>
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

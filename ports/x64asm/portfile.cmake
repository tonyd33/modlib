vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

if(VCPKG_HOST_IS_WINDOWS)
	vcpkg_acquire_msys(
        MSYS_ROOT
        PACKAGES bash coreutils make pkg-config
        DIRECT_PACKAGES 
            # 7zip needed for stack/ghc
            "https://mirror.msys2.org/msys/x86_64/p7zip-17.05-2-x86_64.pkg.tar.zst"
            "6f8d2ba68c181eb41a1ce903e1d91882f0e05b89be813f66c7d78a6448c3f7ea7c156deb891d9e164ff23805aad505beae49dd2929863f70649846221af501f4"
            # gcc
            "https://mirror.msys2.org/msys/x86_64/gcc-13.3.0-1-x86_64.pkg.tar.zst"
            "9c7e25b1cd3acff9f1ab2f8ec810ceffd2d0f7e7a0d58bf24ca4c5da0cf5621a5d047564cb18e6500ac08d1f13153f7dde574e9566cf48f8d12107abaa353d4f"
    )
	vcpkg_add_to_path("${MSYS_ROOT}/usr/bin")
    set(BASH "${MSYS_ROOT}/usr/bin/bash.exe")
    set(MAKE "${MSYS_ROOT}/usr/bin/make.exe")
    # install ghc
    vcpkg_execute_required_process(
        COMMAND "${BASH}" "-c" "type -P stack || curl -sSL https://get.haskellstack.org/ | sh"
        WORKING_DIRECTORY "${CURRENT_BUILDTREES_DIR}"
        LOGNAME "build-${TARGET_TRIPLET}"
    )
endif()

vcpkg_download_distfile(
    ARCHIVE
    URLS "https://github.com/tonyd33/x64asm/archive/refs/tags/v2.1.1.zip"
    FILENAME "x64asm-2.1.1.zip"
    SHA512 2a2775c8f950b0ccc09f389e1bb2f4ff80f789454151d19a41da080b48687517270138aeb62a567a7ce5b2de0122714617b36968e746fa410652a63ed471368a
)

vcpkg_extract_source_archive(
    SOURCE_PATH
    ARCHIVE "${ARCHIVE}"
    SOURCE_BASE x64asm-2.1.1
    PATCHES
        "windows.patch"
)

vcpkg_list(
    SET COPY_LIST
    "codegen"
    "include"
    "lib"
    "src"
    "tools"
    "Makefile"
)

# foreach(item IN LISTS COPY_LIST)
    # message(STATUS "Item: ${item}")
	# file(INSTALL "${SOURCE_PATH}/${item}" DESTINATION "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel")
	# file(INSTALL "${SOURCE_PATH}/${item}" DESTINATION "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg")
# endforeach()

execute_process(
    COMMAND "${BASH}" -c "dirname $(realpath $(stack exec -- which ghc))"
    OUTPUT_VARIABLE GHC_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
vcpkg_add_to_path("${GHC_PATH}")
# vcpkg_host_path_list(PREPEND ENV{PATH} "${GHC_PATH}")
vcpkg_execute_required_process(
	COMMAND "${BASH}" -c "stack install regex regex-compat regex-tdfa split"
	WORKING_DIRECTORY "${SOURCE_PATH}"
	LOGNAME "build-${TARGET_TRIPLET}-asdf2"
)

# vcpkg_execute_required_process(
	# COMMAND "${BASH}" -c "make release"
	# WORKING_DIRECTORY "${SOURCE_PATH}"
	# LOGNAME "build-${TARGET_TRIPLET}"
# )

vcpkg_execute_required_process(
    COMMAND "${BASH}" -c "ls"
	WORKING_DIRECTORY "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg"
	LOGNAME "build-${TARGET_TRIPLET}-asdf3"
)

vcpkg_cmake_configure(SOURCE_PATH ${SOURCE_PATH})
vcpkg_cmake_build()

vcpkg_execute_required_process(
	COMMAND "${BASH}" --noprofile --norc "-c" "sleep 60s"
	# working dir doesn't matter'
	WORKING_DIRECTORY "${CURRENT_BUILDTREES_DIR}"
	LOGNAME "build-${TARGET_TRIPLET}"
)

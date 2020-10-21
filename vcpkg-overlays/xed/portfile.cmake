vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO intelxed/xed
    REF afbb851b5f2f2ac6cdb6e6d9bebbaf2d4e77286d
    SHA512 fe80db93d7734e318184a4fcf9737f4bc6a7169bce3e52fa59c95eaa27ba77027127964c557fcafee6b0fd490b860ee0bca6d790efa23d1a7b1b709f0c3b77ed
    HEAD_REF master
)

vcpkg_from_github(
    OUT_SOURCE_PATH MBUILD_SOURCE_PATH
    REPO intelxed/mbuild
    REF 5304b94361fccd830c0e2417535a866b79c1c297
    SHA512 741ec275c57c06fcd2be5d0ca0e8ad93c00fe5ca7fa56d3f8f112971dd02578977749e63c8357e54d2ab4162d1967aea741f7c17c1a702bef68bc6e29915902c
    HEAD_REF master
)

# Copy mbuild sources.
message(STATUS "Copying mbuild to parallel source directory...")
file(COPY ${MBUILD_SOURCE_PATH}/ DESTINATION ${SOURCE_PATH}/../mbuild)

# Build
vcpkg_find_acquire_program(PYTHON3)
vcpkg_execute_required_process(
  COMMAND ${PYTHON3} ${SOURCE_PATH}/mfile.py
  WORKING_DIRECTORY ${SOURCE_PATH}
  LOGNAME python-${TARGET_TRIPLET}-build
)

# Install
vcpkg_execute_required_process(
  COMMAND ${PYTHON3} ${SOURCE_PATH}/mfile.py install --install-dir="${CURRENT_PACKAGES_DIR}" "--extra-ccflags=${CFLAGS}" "--extra-cxxflags=${CPPFLAGS}" "--extra-linkflags=${LDFLAGS}" --verbose=9
  WORKING_DIRECTORY ${SOURCE_PATH}
  LOGNAME python-${TARGET_TRIPLET}-install
)

# Cleanup
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/bin"
                    "${CURRENT_PACKAGES_DIR}/extlib"
                    "${CURRENT_PACKAGES_DIR}/doc"
                    )

FILE(INSTALL ${CMAKE_CURRENT_LIST_DIR}/XEDConfig.cmake DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT})
file(INSTALL ${SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)
file(INSTALL ${MBUILD_SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME mbuild.copyright)

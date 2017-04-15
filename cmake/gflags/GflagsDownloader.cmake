macro(gflags_extract GFLAGS_ARCHIVE VERSION_STRING GFLAGS_SOURCE_PATH)

  if(EXISTS "${GFLAGS_ARCHIVE}")
    set(${GFLAGS_SOURCE_PATH} "${PROJECT_BINARY_DIR}/gflags-${VERSION_STRING}")
    message(STATUS "Extracting GFlags sources to '${${GFLAGS_SOURCE_PATH}}'...")
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E tar xzf "${GFLAGS_ARCHIVE}"
      WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
  endif()

endmacro(gflags_extract)

macro(gflags_download VERSION_STRING GFLAGS_ARCHIVE)

  set(GFLAGS_ARCHIVE_URL
      "https://github.com/gflags/gflags/archive/v${VERSION_STRING}.tar.gz")

  message(STATUS "Downloading GFlags version ${VERSION_STRING} from '${GFLAGS_ARCHIVE_URL}'...")

  set(GFLAGS_DOWNLOAD_PATH
    "${PROJECT_BINARY_DIR}/gflags-${VERSION_STRING}.tar.gz")

  file(DOWNLOAD "${GFLAGS_ARCHIVE_URL}" "${GFLAGS_DOWNLOAD_PATH}"
     STATUS status)

  list(GET status 0 error_code)

  if(error_code)
    file(REMOVE "${GFLAGS_DOWNLOAD_PATH}")
    list(GET status 1 error_msg)
    message(FATAL_ERROR
      "Failed to download GFlags source archive '${GFLAGS_ARCHIVE_URL}': ${error_msg}")
  else()
    set(${GFLAGS_ARCHIVE} "${GFLAGS_DOWNLOAD_PATH}")
    message(STATUS "Successfully downloaded GFlags version ${VERSION_STRING}.")
  endif()

endmacro(gflags_download)

macro(gflags_download_and_extract VERSION_STRING GFLAGS_SOURCE_PATH)
  gflags_download(${VERSION_STRING} GFLAGS_ARCHIVE)
  gflags_extract(${GFLAGS_ARCHIVE} ${VERSION_STRING} ${GFLAGS_SOURCE_PATH})
endmacro(gflags_download_and_extract)


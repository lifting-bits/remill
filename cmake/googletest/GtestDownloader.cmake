macro(googletest_extract GTEST_ARCHIVE VERSION_STRING GTEST_SOURCE_PATH)

  if(EXISTS "${GTEST_ARCHIVE}")
    set(${GTEST_SOURCE_PATH} "${PROJECT_BINARY_DIR}/googletest-release-${VERSION_STRING}")
    message(STATUS "Extracting Gtest sources to '${${GTEST_SOURCE_PATH}}'...")
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E tar xzf "${GTEST_ARCHIVE}"
      WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
  endif()

endmacro(googletest_extract)

macro(googletest_download VERSION_STRING GTEST_ARCHIVE)

  set(GTEST_ARCHIVE_URL
      "https://github.com/google/googletest/archive/release-${VERSION_STRING}.tar.gz")

  message(STATUS "Downloading Gtest version ${VERSION_STRING} from '${GTEST_ARCHIVE_URL}'...")

  set(GTEST_DOWNLOAD_PATH
    "${PROJECT_BINARY_DIR}/googletest-${VERSION_STRING}.tar.gz")

  file(DOWNLOAD "${GTEST_ARCHIVE_URL}" "${GTEST_DOWNLOAD_PATH}"
     STATUS status)

  list(GET status 0 error_code)

  if(error_code)
    file(REMOVE "${GTEST_DOWNLOAD_PATH}")
    list(GET status 1 error_msg)
    message(FATAL_ERROR
      "Failed to download Gtest source archive '${GTEST_ARCHIVE_URL}': ${error_msg}")
  else()
    set(${GTEST_ARCHIVE} "${GTEST_DOWNLOAD_PATH}")
    message(STATUS "Successfully downloaded Gtest version ${VERSION_STRING}.")
  endif()

endmacro(googletest_download)

macro(googletest_download_and_extract VERSION_STRING GTEST_SOURCE_PATH)
  googletest_download(${VERSION_STRING} GTEST_ARCHIVE)
  googletest_extract(${GTEST_ARCHIVE} ${VERSION_STRING} ${GTEST_SOURCE_PATH})
endmacro(googletest_download_and_extract)


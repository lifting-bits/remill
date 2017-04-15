macro(glog_extract GLOG_ARCHIVE VERSION_STRING GLOG_SOURCE_PATH)
  
  # TODO(pag): The master branch of version 0.3.4 has a CMakeLists.txt file,
  #            but the official release does not.

  if(EXISTS "${GLOG_ARCHIVE}")
    set(${GLOG_SOURCE_PATH} "${PROJECT_BINARY_DIR}/glog-master")
    message(STATUS "Extracting GLog sources to '${${GLOG_SOURCE_PATH}}'...")
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E tar xzf "${GLOG_ARCHIVE}"
      WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
  endif()

endmacro(glog_extract)

macro(glog_download VERSION_STRING GLOG_ARCHIVE)
  
  # TODO(pag): The master branch of version 0.3.4 has a CMakeLists.txt file,
  #            but the official release does not.

  set(GLOG_ARCHIVE_URL
      "https://github.com/google/glog/archive/master.tar.gz")

  message(STATUS "Downloading GLog version ${VERSION_STRING} from '${GLOG_ARCHIVE_URL}'...")

  set(GLOG_DOWNLOAD_PATH
    "${PROJECT_BINARY_DIR}/glog-${VERSION_STRING}.tar.gz")

  file(DOWNLOAD "${GLOG_ARCHIVE_URL}" "${GLOG_DOWNLOAD_PATH}"
     STATUS status)

  list(GET status 0 error_code)

  if(error_code)
    file(REMOVE "${GLOG_DOWNLOAD_PATH}")
    list(GET status 1 error_msg)
    message(FATAL_ERROR
      "Failed to download GLog source archive '${GLOG_ARCHIVE_URL}': ${error_msg}")
  else()
    set(${GLOG_ARCHIVE} "${GLOG_DOWNLOAD_PATH}")
    message(STATUS "Successfully downloaded GLog version ${VERSION_STRING}.")
  endif()

endmacro(glog_download)

macro(glog_download_and_extract VERSION_STRING GLOG_SOURCE_PATH)
  glog_download(${VERSION_STRING} GLOG_ARCHIVE)
  glog_extract(${GLOG_ARCHIVE} ${VERSION_STRING} ${GLOG_SOURCE_PATH})
endmacro(glog_download_and_extract)


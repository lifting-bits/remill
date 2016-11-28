/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "remill/OS/FileSystem.h"

namespace remill {

// Try to create a directory. Returns `true` if the directory was created or
// exists.
bool TryCreateDirectory(const std::string &dir_name) {
  mkdir(dir_name.c_str(), 0777);  // Ignore errors.
  if (auto d = opendir(dir_name.c_str())) {
    closedir(d);
    return true;
  } else {
    return false;
  }
}

std::string CurrentWorkingDirectory(void) {
  char result[PATH_MAX] = {};
  auto res = getcwd(result, PATH_MAX);
  CHECK(res)
      << "Could not determine current working directory: " << strerror(errno);
  return std::string(result);
}

bool FileExists(const std::string &path) {
  if (-1 == access(path.c_str(), F_OK)) {
    return false;
  }

  struct stat64 file_info = {};
  return stat64(path.c_str(), &file_info) == 0 &&
         (S_ISREG(file_info.st_mode) ||
          S_ISFIFO(file_info.st_mode));
}

uint64_t FileSize(const std::string &path, int fd) {
  struct stat64 file_info;
  CHECK(!fstat64(fd, &file_info))
      << "Cannot stat " << path << ": " << strerror(errno);
  return static_cast<uint64_t>(file_info.st_size);
}


uint64_t FileSize(const std::string &path) {
  struct stat64 file_info;
  CHECK(!stat64(path.c_str(), &file_info))
      << "Cannot stat " << path << ": " << strerror(errno);
  return static_cast<uint64_t>(file_info.st_size);
}

}  // namespace remill

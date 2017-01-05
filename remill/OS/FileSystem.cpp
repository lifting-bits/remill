/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <unistd.h>

#include "remill/OS/FileSystem.h"

#ifdef __APPLE__
# ifndef _DARWIN_USE_64_BIT_INODE
#   define _DARWIN_USE_64_BIT_INODE 1
# endif
# define stat64 stat
# define fstat64 fstat
#endif

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

void RemoveFile(const std::string &path) {
  unlink(path.c_str());
}

void RenameFile(const std::string &from_path, const std::string &to_path) {
  rename(from_path.c_str(), to_path.c_str());
}

void HardLinkOrCopy(const std::string &from_path, const std::string &to_path) {
  unlink(to_path.c_str());
  if (!link(from_path.c_str(), to_path.c_str())) {
    return;
  }

  DLOG(WARNING)
      << "Unable to link " << to_path << " to "
      << from_path << ": " << strerror(errno);

  auto from_fd = open(from_path.c_str(), O_RDONLY);
  auto to_fd = open(to_path.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0666);
  off_t offset = 0;
  auto file_size = FileSize(from_path);

  do {
    auto num_copied = sendfile(to_fd, from_fd, &offset, file_size);
    if (-1 == num_copied) {
      close(from_fd);
      close(to_fd);
      unlink(to_path.c_str());
      LOG(FATAL)
          << "Unable to copy data from " << from_path << " to " << to_path;
    }

    file_size -= static_cast<size_t>(num_copied);
  } while (file_size);
}


}  // namespace remill

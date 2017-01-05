/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <algorithm>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
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

namespace {
enum : size_t {
  kCopyDataSize = 4096ULL
};

static uint8_t gCopyData[kCopyDataSize];
}  // namespace

void HardLinkOrCopy(const std::string &from_path, const std::string &to_path) {
  unlink(to_path.c_str());
  if (!link(from_path.c_str(), to_path.c_str())) {
    return;
  }

  DLOG(WARNING)
      << "Unable to link " << to_path << " to "
      << from_path << ": " << strerror(errno);

  auto from_fd = open(from_path.c_str(), O_RDONLY);
  CHECK(-1 != from_fd)
      << "Unable to open source file " << from_path
      << " for copying: " << strerror(errno);

  auto to_fd = open(to_path.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0666);
  CHECK(-1 != to_fd)
      << "Unable to open destination file " << to_path
      << " for copying: " << strerror(errno);

  auto file_size = FileSize(from_path);
  int errno_copy = 0;

  do {
    auto num_read = read(
        from_fd, &(gCopyData[0]), std::min<size_t>(kCopyDataSize, file_size));
    if (-1 == num_read) {
      errno_copy = errno;
      break;
    }

    auto num_written = write(
        to_fd, &(gCopyData[0]), static_cast<size_t>(num_read));

    if (num_written != num_read) {
      errno_copy = errno;
      break;
    }

    file_size -= static_cast<size_t>(num_written);
  } while (file_size);

  close(from_fd);
  close(to_fd);

  if (errno_copy) {
    unlink(to_path.c_str());
    LOG(FATAL)
        << "Unable to copy all data read from " << from_path
        << " to " << to_path << ": " << strerror(errno_copy);
  }
}

}  // namespace remill

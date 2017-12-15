/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glog/logging.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#if REMILL_ON_MACOS
# ifndef _DARWIN_USE_64_BIT_INODE
#   define _DARWIN_USE_64_BIT_INODE 1
# endif
# define stat64 stat
# define fstat64 fstat
#endif

#if defined(_MAX_PATH) && !defined(PATH_MAX)
# define PATH_MAX _MAX_PATH
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

// Iterator over a directory.
void ForEachFileInDirectory(const std::string &dir_name,
                            DirectoryVisitor visitor) {
  std::vector<std::string> paths;
  auto dir = opendir(dir_name.c_str());
  CHECK(dir != nullptr)
      << "Could not list the " << dir_name << " directory";

  while (auto ent = readdir(dir)) {
    if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }

    std::stringstream ss;
    ss << dir_name << "/" << ent->d_name;
    paths.push_back(ss.str());
  }
  closedir(dir);

  for (const auto &path : paths) {
    if (!visitor(path)) {
      break;
    }
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

uint64_t FileSize(int fd) {
  struct stat64 file_info;
  CHECK(!fstat64(fd, &file_info))
      << "Cannot stat FD " << fd << ": " << strerror(errno);
  return static_cast<uint64_t>(file_info.st_size);
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

bool RenameFile(const std::string &from_path, const std::string &to_path) {
  auto ret = rename(from_path.c_str(), to_path.c_str());
  auto err = errno;
  if (-1 == ret) {
    LOG(ERROR)
        << "Unable to rename " << from_path << " to " << to_path
        << ": " << strerror(err);
    return false;
  } else {
    return true;
  }
}

namespace {
enum : size_t {
  kCopyDataSize = 4096ULL
};

static uint8_t gCopyData[kCopyDataSize];
}  // namespace

void CopyFile(const std::string &from_path, const std::string &to_path) {
  unlink(to_path.c_str());
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

void HardLinkOrCopyFile(const std::string &from_path,
                        const std::string &to_path) {
  unlink(to_path.c_str());
  if (!link(from_path.c_str(), to_path.c_str())) {
    return;
  }

  DLOG(WARNING)
      << "Unable to link " << to_path << " to "
      << from_path << ": " << strerror(errno);

  CopyFile(from_path, to_path);
}

void MoveFile(const std::string &from_path, const std::string &to_path) {
  if (!RenameFile(from_path, to_path)) {
    CopyFile(from_path, to_path);
    RemoveFile(from_path);
  }
}

std::string CanonicalPath(const std::string &path) {
  char buff[PATH_MAX + 1] = {};
#if REMILL_ON_WINDOWS
  auto canon_path_c = _fullpath(buff, path.c_str(), PATH_MAX);
  auto err = ENOENT;
#else
  auto canon_path_c = realpath(path.c_str(), buff);
  auto err = errno;
#endif
  if (!canon_path_c) {
    LOG(WARNING)
        << "Cannot compute full path of " << path
        << ": " << strerror(err);
    return path;
  } else {
    std::string canon_path(canon_path_c);
    return canon_path;
  }
}

// Returns the path separator character for this OS.
const char *PathSeparator(void) {
#if REMILL_ON_WINDOWS
  return "\\";
#else
  return "/";
#endif
}

}  // namespace remill

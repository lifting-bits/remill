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
#include <fstream>
#include <vector>

#ifndef _WIN32
#  include <dirent.h>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#if REMILL_ON_MACOS
#  ifndef _DARWIN_USE_64_BIT_INODE
#    define _DARWIN_USE_64_BIT_INODE 1
#  endif
#  define stat64 stat
#  define fstat64 fstat
#endif

#if defined(_MAX_PATH) && !defined(PATH_MAX)
#  define PATH_MAX _MAX_PATH
#endif

// Do not include windows.h, or its macros will end up shadowing our functions
// (i.e.: MoveFile)
#ifdef _WIN32
namespace {
const std::uint32_t INVALID_FILE_ATTRIBUTES = static_cast<std::uint32_t>(-1);
const std::uint32_t ERROR_NO_MORE_FILES = 18U;
const std::uint32_t FILE_ATTRIBUTE_DIRECTORY = 16U;
const std::uint32_t INVALID_HANDLE_VALUE = static_cast<std::uint32_t>(-1);
const int MAX_PATH = 260;

struct FILETIME {
  std::uint32_t dwLowDateTime;
  std::uint32_t dwHighDateTime;
};

struct WIN32_FIND_DATA {
  std::uint32_t dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  std::uint32_t nFileSizeHigh;
  std::uint32_t nFileSizeLow;
  std::uint32_t dwReserved0;
  std::uint32_t dwReserved1;
  char cFileName[MAX_PATH];
  char cAlternateFileName[14];
};

extern "C" int CreateDirectoryA(const char *path_name,
                                void *security_attributes);
extern "C" std::uint32_t GetCurrentDirectoryA(std::uint32_t buffer_length,
                                              char *buffer);
extern "C" std::uint32_t GetFileAttributesA(const char *file_name);
extern "C" int CopyFileA(const char *existing_file_name,
                         const char *new_file_name, int file_if_exists);
extern "C" int CreateHardLinkA(const char *file_name,
                               const char *existing_file_name,
                               void *security_attributes);
extern "C" std::uint32_t FindFirstFileA(const char *file_name,
                                        WIN32_FIND_DATA *find_data);
extern "C" std::uint32_t FindNextFileA(std::uint32_t handle,
                                       WIN32_FIND_DATA *find_data);
extern "C" int FindClose(std::uint32_t handle);
extern "C" std::uint32_t GetLastError();

int mkdir(const char *pathname, std::uint16_t mode) {
  static_cast<void>(mode);

  if (CreateDirectoryA(pathname, nullptr) == 0) {
    return -1;
  }

  return 0;
}

char *getcwd(char *buf, size_t size) {
  if (GetCurrentDirectoryA(static_cast<std::uint32_t>(size), buf) == 0) {
    return nullptr;
  }

  return buf;
}

int link(const char *path1, const char *path2) {
  if (CreateHardLinkA(path1, path2, nullptr) == 0) {
    return -1;
  }

  return 0;
}
}  // namespace
#endif

namespace remill {
#ifdef _WIN32
bool IsDirectory(const std::string &path_name) {
  auto attributes = GetFileAttributesA(path_name.data());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    return false;
  }

  return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool FileExists(const std::string &path) {
  auto attributes = GetFileAttributesA(path.data());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    return false;
  }

  return (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

uint64_t FileSize(const std::string &path) {
  std::ifstream stream(path, std::ifstream::binary | std::ifstream::ate);
  return static_cast<std::uint64_t>(stream.tellg());
}

// Iterator over a directory.
void ForEachFileInDirectory(const std::string &dir_name,
                            remill::DirectoryVisitor visitor) {

  WIN32_FIND_DATA find_data = {};

  auto handle = FindFirstFileA(dir_name.data(), &find_data);
  if (handle == INVALID_HANDLE_VALUE) {
    return;
  }

  do {
    std::string full_path = dir_name + "\\" + find_data.cFileName;
    if (!visitor(full_path)) {
      break;
    }

    if (FindNextFileA(handle, &find_data) == 0) {
      if (GetLastError() == ERROR_NO_MORE_FILES) {
        break;
      }

      LOG(ERROR) << "Could not list the " << dir_name << " directory";
      break;
    }
  } while (true);

  FindClose(handle);
}

#else
bool IsDirectory(const std::string &path_name) {
  auto d = opendir(path_name.c_str());
  if (d == 0) {
    return false;
  }

  closedir(d);
  return true;
}

bool FileExists(const std::string &path) {
  if (-1 == access(path.c_str(), F_OK)) {
    return false;
  }

  struct stat64 file_info = {};
  return stat64(path.c_str(), &file_info) == 0 &&
         (S_ISREG(file_info.st_mode) || S_ISFIFO(file_info.st_mode));
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

// Iterator over a directory.
void ForEachFileInDirectory(const std::string &dir_name,
                            DirectoryVisitor visitor) {
  std::vector<std::string> paths;
  auto dir = opendir(dir_name.c_str());
  CHECK(dir != nullptr) << "Could not list the " << dir_name << " directory";

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
#endif

// Try to create a directory. Returns `true` if the directory was created or
// exists.
bool TryCreateDirectory(const std::string &dir_name) {
  mkdir(dir_name.c_str(), 0777);  // Ignore errors.
  return IsDirectory(dir_name);
}

std::string CurrentWorkingDirectory(void) {
  char result[PATH_MAX] = {};
  auto res = getcwd(result, PATH_MAX);
  CHECK(res) << "Could not determine current working directory: "
             << strerror(errno);
  return std::string(result);
}

void RemoveFile(const std::string &path) {
  unlink(path.c_str());
}

bool RenameFile(const std::string &from_path, const std::string &to_path) {
  auto ret = rename(from_path.c_str(), to_path.c_str());
  auto err = errno;
  if (-1 == ret) {
    LOG(ERROR) << "Unable to rename " << from_path << " to " << to_path << ": "
               << strerror(err);
    return false;
  } else {
    return true;
  }
}

#ifndef _WIN32
namespace {
enum : size_t { kCopyDataSize = 4096ULL };

static uint8_t gCopyData[kCopyDataSize];
}  // namespace
#endif

#ifdef _WIN32
void CopyFile(const std::string &from_path, const std::string &to_path) {
  if (CopyFileA(from_path.data(), to_path.data(), false) == 0) {
    LOG(FATAL) << "Unable to copy all data read from " << from_path << " to "
               << to_path;
  }
}

#else
void CopyFile(const std::string &from_path, const std::string &to_path) {
  unlink(to_path.c_str());
  auto from_fd = open(from_path.c_str(), O_RDONLY);
  CHECK(-1 != from_fd) << "Unable to open source file " << from_path
                       << " for copying: " << strerror(errno);

  auto to_fd = open(to_path.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0666);
  CHECK(-1 != to_fd) << "Unable to open destination file " << to_path
                     << " for copying: " << strerror(errno);

  auto file_size = FileSize(from_path);
  int errno_copy = 0;

  do {
    auto num_read = read(from_fd, &(gCopyData[0]),
                         std::min<size_t>(kCopyDataSize, file_size));
    if (-1 == num_read) {
      errno_copy = errno;
      break;
    }

    auto num_written =
        write(to_fd, &(gCopyData[0]), static_cast<size_t>(num_read));

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
    LOG(FATAL) << "Unable to copy all data read from " << from_path << " to "
               << to_path << ": " << strerror(errno_copy);
  }
}
#endif

void HardLinkOrCopyFile(const std::string &from_path,
                        const std::string &to_path) {
  unlink(to_path.c_str());
  if (!link(from_path.c_str(), to_path.c_str())) {
    return;
  }

  DLOG(WARNING) << "Unable to link " << to_path << " to " << from_path << ": "
                << strerror(errno);

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
    DLOG(WARNING) << "Cannot compute full path of " << path << ": "
                  << strerror(err);
    return path;
  } else {
    std::string canon_path(canon_path_c);
    return canon_path;
  }
}

// Returns the path separator character for this OS.
const char *PathSeparator(void) {
#ifdef _WIN32
  return "\\";
#else
  return "/";
#endif
}

}  // namespace remill

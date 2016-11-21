/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_UTIL_FILEBACKEDCACHE_H_
#define TOOLS_VMILL_UTIL_FILEBACKEDCACHE_H_

#include <glog/logging.h>

#include <string>
#include <vector>

#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace remill {
namespace vmill {

template <typename T>
class FileBackedCache {
 public:

  enum : size_t {
    k1MiB = 1ULL << 20ULL,
    kMaxCacheFileSize = 64ULL * k1MiB,
  };

  ~FileBackedCache(void);

  template <typename Self>
  static Self *Open(const std::string &file_name);

  void Extend(const std::vector<T> &entries);
  void Sync(void);

  inline size_t NumEntries(void) const {
    return static_cast<size_t>(soft_limit - base);
  }

  inline size_t AvailableNumEntries(void) const {
    return static_cast<size_t>(hard_limit - base);
  }

  inline size_t MaxNumEntries(void) const {
    return kMaxCacheFileSize / sizeof(T);
  }

  T *begin(void) {
    return base;
  }

  T *end(void) {
    return soft_limit;
  }

  const T *begin(void) const {
    return base;
  }

  const T *end(void) const {
    return soft_limit;
  }

 private:
  FileBackedCache(const std::string &path_, int fd_, T *base_,
                  T *limit_, const T *mapped_limit_);

  std::string path;
  int fd;
  T * const base;
  T *soft_limit;
  const T *hard_limit;
};

template <typename T>
FileBackedCache<T>::FileBackedCache(const std::string &path_, int fd_,
                                    T *base_, T *limit_, const T *mapped_limit_)
    : path(path_),
      fd(fd_),
      base(base_),
      soft_limit(limit_),
      hard_limit(mapped_limit_) {}

template <typename T>
FileBackedCache<T>::~FileBackedCache(void) {
  munmap(base, kMaxCacheFileSize);
  if (NumEntries() < AvailableNumEntries()) {
    ftruncate(fd, sizeof(T) * NumEntries());
  }
  close(fd);
}

template <typename T>
template <typename Self>
Self *FileBackedCache<T>::Open(const std::string &file_name) {
  auto cache_fd = open(file_name.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0666);
  CHECK(-1 != cache_fd)
      << "Cannot open sequential cache file " << file_name;

  auto addr = mmap(nullptr, kMaxCacheFileSize, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                   -1, 0);

  CHECK(MAP_FAILED != addr)
      << "Unable to allocate space for sequential cache from "
      << file_name << ": " << strerror(errno);

  struct stat info = {};
  CHECK(!fstat(cache_fd, &info))
      << "Unable to stat sequential cache file " << file_name
      << ": " << strerror(errno);

  auto base = reinterpret_cast<T *>(addr);
  auto file_size = static_cast<size_t>(info.st_size);
  auto mapped_size = (file_size + 4095ULL) & ~4095ULL;
  if (mapped_size > file_size) {
    CHECK(!ftruncate(cache_fd, static_cast<off_t>(mapped_size)))
        << "Unable to resize sequential cache file " << file_name
        << " from " << file_size << " to " << mapped_size << ".";
  }

  if (mapped_size) {
    auto ret = mmap(addr, mapped_size, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_SHARED | MAP_FILE, cache_fd, 0);

    if (ret != addr) {
      LOG(ERROR)
          << "Unable to map sequential cache file " << file_name
          << " into memory; destroying the cache: " << strerror(errno);

      CHECK(!ftruncate(cache_fd, 0))
          << "Failed to destroy the sequential cache file "
          << file_name << ": " << strerror(errno);

      file_size = 0;
      mapped_size = 0;
    }
  }

  auto num_operations = file_size / sizeof(T);
  auto max_num_operations = mapped_size / sizeof(T);
  DLOG(INFO)
      << "Loaded " << num_operations << " entries from "
      << "the sequential cache file " << file_name;

  return new Self(
      file_name, cache_fd, base, base + num_operations,
      base + max_num_operations);
}

template <typename T>
void FileBackedCache<T>::Extend(const std::vector<T> &entries) {
  if (entries.empty()) {
    return;
  }
  auto old_soft_limit = soft_limit;
  auto new_num_entries = entries.size() + NumEntries();
  auto new_size = new_num_entries * sizeof(T);
  auto new_hard_size = (new_size + 4095ULL) & ~4095ULL;

  if (new_num_entries > AvailableNumEntries()) {
    CHECK(new_hard_size <= kMaxCacheFileSize)
        << "Exceeded the maximum file size for file-backed cache " << path;

    CHECK(!ftruncate(fd, static_cast<off_t>(new_hard_size)))
        << "Failed to grow the sequential cache file "
        << path << ": " << strerror(errno);

    auto ret = mmap(base, new_hard_size,
                    PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_SHARED | MAP_FILE,
                    fd, 0);

    CHECK(ret == base)
        << "Unable to extend file-backed cache "
        << path << ": " << strerror(errno);
  }

  hard_limit = base + (new_hard_size / sizeof(T));
  soft_limit = base + new_num_entries;
  CHECK(soft_limit <= hard_limit)
      << "Logic error! Soft limit exceeds the hard limit for the file-backed "
      << "cache " << path;

  // Copy the entries in.
  for (const auto &entry : entries) {
    *old_soft_limit++ = entry;
  }
}

template <typename T>
void FileBackedCache<T>::Sync(void) {
  msync(base, AvailableNumEntries() * sizeof(T), MS_SYNC | MS_INVALIDATE);
}

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_UTIL_FILEBACKEDCACHE_H_

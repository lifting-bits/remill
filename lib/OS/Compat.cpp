/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include <fcntl.h>
#include <sys/stat.h>

#if !defined(_WIN32)

// These headers are not present on a Windows build
// and seem to be not needed.
//
// _WIN32 is a general check for Windows, not just 32-bit windows.
//
// Per the documentation:
//
// _WIN32 Defined as 1 when the compilation target is 32-bit ARM, 64-bit
// ARM, x86, or x64. Otherwise, undefined.
#  include <sys/param.h>
#  include <sys/time.h>
#  include <unistd.h>
#endif

#if defined(__APPLE__)
#  include <Availability.h>
#  include <os/availability.h>
#  include <sys/syslimits.h>
#elif defined(__linux__)
#  include <linux/limits.h>
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

#ifndef MAXPATHLEN
#  define MAXPATHLEN PATH_MAX
#endif

#include <cerrno>

extern "C" {

#if defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_13

#  ifndef UTIME_NOW
#    define UTIME_NOW -1
#  endif

#  ifndef UTIME_OMIT
#    define UTIME_OMIT -2
#  endif

// Implementation of `futimens` for Mac OS X versions less than 10.13. This is
// so that any Remill dependencies (e.g. Google Log) will build.
int futimens(int fd, const struct timespec times[2]) {
  auto last_access = &(times[0]);
  auto last_modified = &(times[1]);

  auto need_now = !times || last_access->tv_nsec == UTIME_NOW ||
                  last_modified->tv_nsec == UTIME_NOW;

  struct timespec curr_last_access = {};
  struct timespec curr_last_modified = {};
  struct stat buf = {};
  int ret = fstat(fd, &buf);
  if (-1 == ret) {
    return ret;
  }

  // Extract the current last access and modified times.
#  if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
  curr_last_access = buf.st_atimespec;
  curr_last_modified = buf.st_mtimespec;
#  else
  curr_last_access.tv_sec = buf.st_atime;
  curr_last_access.tv_nsec = buf.st_atimensec;
  curr_last_modified.tv_sec = buf.st_mtime;
  curr_last_modified.tv_nsec = buf.st_mtimensec;
#  endif

  // Figure out the current time if it's needed.
  struct timespec time_now = {};
  if (need_now) {
    struct timeval time_now_usec = {};
    ret = gettimeofday(&time_now_usec, nullptr);
    if (-1 == ret) {
      return ret;
    }

    time_now.tv_sec = time_now_usec.tv_sec;
    time_now.tv_nsec = time_now_usec.tv_usec * 1000;

    if (!times) {
      last_access = &time_now;
      last_modified = &time_now;
    } else {
      if (last_access->tv_nsec == UTIME_NOW) {
        last_access = &time_now;
      }
      if (last_modified->tv_nsec == UTIME_NOW) {
        last_modified = &time_now;
      }
    }
  }

  if (last_access->tv_nsec == UTIME_OMIT) {
    last_access = &curr_last_access;
  }

  if (last_modified->tv_nsec == UTIME_OMIT) {
    last_modified = &curr_last_modified;
  }

  struct timeval new_utimes[2] = {};
  new_utimes[0].tv_sec = last_access->tv_sec;
  new_utimes[0].tv_usec = last_access->tv_nsec / 1000;

  new_utimes[1].tv_sec = last_modified->tv_sec;
  new_utimes[1].tv_usec = last_modified->tv_nsec / 1000;

  return futimes(fd, new_utimes);
}

int utimensat(int fd, const char *path, const struct timespec times[2],
              int flag) {
  errno = ENOSYS;
  return -1;
}

#else
void __dummy_symbol_compat_cpp(void) {}
#endif

}  // extern C

/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <climits>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "remill/Arch/Name.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "tools/vmill/Arch/X86/Snapshot.h"
#include "tools/vmill/Snapshot/File.h"

DEFINE_uint64(breakpoint, 0, "Address of where to inject a breakpoint.");

DEFINE_string(workspace, "", "Path to a directory in which the snapshot and "
                             "core files are placed.");

DEFINE_string(arch, "", "Architecture.");

DEFINE_string(os, "", "Operating system.");

namespace remill {
namespace vmill {
namespace {

enum : int {
  kMaxNumAttempts = 10
};

static int gTraceeArgc = 0;

static char **gTraceeArgv = nullptr;

static std::string gSnapshotPath;
static std::string gCorePath;

// Extract out the arguments of the tracee from the arguments to the tracer.
bool ExtractTraceeArgs(int *argc, char **argv) {
  const auto old_argc = *argc;
  auto new_argc = 0;

  for (auto i = 0; i < old_argc; ++i) {
    auto arg = argv[i];
    if (!strcmp("--", arg)) {
      break;
    } else {
      ++new_argc;
    }
  }

  if (old_argc == new_argc) {
    return false;
  }

  *argc = new_argc;
  argv[new_argc] = nullptr;
  gTraceeArgv = &(argv[new_argc + 1]);
  gTraceeArgc = old_argc - new_argc - 1;
  return true;
}

// Print out an argument, with double quotes in the argument escaped.
static void EscapeQuotedArg(std::stringstream &ss, const char *arg) {
  while (auto chr = *(arg++)) {
    if ('"' == chr) {
      ss << '\\';
    }
    ss << chr;
  }
}

// Log the command for the tracee.
static void LogPrepareExec(void) {
  std::stringstream ss;
  for (auto i = 0; i < gTraceeArgc; ++i) {
    if (strchr(gTraceeArgv[i], ' ')) {
      ss << '"';
      EscapeQuotedArg(ss, gTraceeArgv[i]);
      ss << '"' << ' ';
    } else {
      ss << gTraceeArgv[i] << " ";
    }
  }
  DLOG(INFO)
      << "Preparing to execute tracee: " << ss.str();
}

// Returns `true` if a signal looks like an error signal. Used when checking
// `WIFSTOPPED`.
static bool IsErrorSignal(int sig) {
  switch (sig) {
    case SIGHUP:
    case SIGQUIT:
    case SIGABRT:
    case SIGBUS:
    case SIGFPE:
    case SIGKILL:
    case SIGSEGV:
    case SIGPIPE:
    case SIGTERM:
      return true;
    default:
      return false;
  }
}

// Enable tracing of the target binary.
static void EnableTracing(void) {
  for (auto i = 0UL; i < kMaxNumAttempts; i++) {
    if (!ptrace(PTRACE_TRACEME, 0, nullptr, nullptr)) {
      raise(SIGSTOP);
      return;
    }
  }
  LOG(FATAL)
      << "Failed to enable ptrace for tracee.";
}

// Attach to the binary and wait for it to raise `SIGSTOP`.
static void TraceSubprocess(pid_t pid) {
  while (true) {
    auto status = 0;
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if (SIGSTOP == WSTOPSIG(status)) {
          break;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Unable to acquire control of tracee; it exited with signal "
              << WSTOPSIG(status);
        } else {
          DLOG(INFO)
              << "Still trying to acquire control of tracee; "
              << "it stopped with signal " << WSTOPSIG(status);
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Unable to acquire control of tracee; it exited with status "
            << WEXITSTATUS(status);

      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Unable to acquire control of tracee; it terminated with signal "
            << WTERMSIG(status);
      } else {
        DLOG(INFO)
            << "Unrecognized status " << status
            << " while trying to acquire control of tracee.";
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem waiting to acquire control of tracee: " << err;
    }
  }

  errno = 0;
  ptrace(PTRACE_SETOPTIONS, pid, 0,
         PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL);

  CHECK(ESRCH != errno)
      << "Unable to trace subprocess " << pid;
}

// Run until just after the `exec` system call.
static void RunUntilAfterExec(pid_t pid) {
  for (auto i = 0, status = 0; i < kMaxNumAttempts; ++i, status = 0) {
    errno = 0;
    ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if ((SIGTRAP | 0x80) == WSTOPSIG(status)) {
          return;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Tracee exited with signal " << WSTOPSIG(status)
              << " while doing exec of " << gTraceeArgv[0];
        } else {
          DLOG(INFO)
              << "Tracee stopped with signal " << WSTOPSIG(status)
              << " while doing exec of " << gTraceeArgv[0];
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Tracee exited with status " << WEXITSTATUS(status)
            << " while doing exec of " << gTraceeArgv[0];

      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Tracee received signal " << WTERMSIG(status)
            << " while doing exec of " << gTraceeArgv[0] << ". "
            << "Maybe an invalid program was specified?";

      } else {
        DLOG(INFO)
            << "Unrecognized status " << status
            << " while doing exec of " << gTraceeArgv[0];
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem during the exec of " << gTraceeArgv[0] << ": " << err;
    }
  }

  kill(pid, SIGKILL);
  LOG(FATAL)
      << "Exhausted maximum number of attempts to wait for exec of "
      << gTraceeArgv[0] << " to complete.";
}

// Run the tracee until just after it does an `execve`.
static void RunUntilInTracee(pid_t pid) {
  for (auto i = 0, status = 0; i < kMaxNumAttempts; ++i, status = 0) {
    ptrace(PTRACE_CONT, pid, 0, 0);
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
          DLOG(INFO)
              << "Preparing to execute " << gTraceeArgv[0];
          RunUntilAfterExec(pid);
          return;

        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Tracee exited with signal " << WSTOPSIG(status)
              << " before doing exec of " << gTraceeArgv[0];
        } else {
          DLOG(INFO)
              << "Tracee stopped with signal " << WSTOPSIG(status)
              << " before doing exec of " << gTraceeArgv[0];
        }

      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Tracee exited with status " << WEXITSTATUS(status)
            << " before doing exec of " << gTraceeArgv[0];

      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Tracee received signal " << WTERMSIG(status)
            << " before doing exec of " << gTraceeArgv[0];
      } else {
        DLOG(INFO)
            << "Unrecognized status " << status << " received doing exec of "
            << gTraceeArgv[0];
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem entering the tracee: " << err;
    }
  }

  kill(pid, SIGKILL);
  LOG(FATAL)
      << "Exhausted maximum number of attempts to wait for the tracee "
      << "to exec into " << gTraceeArgv[0];
}

// Set a breakpoint on an address within the tracee.
static void RunUntilBreakpoint(pid_t pid) {
  DLOG(INFO)
      << "Setting breakpoint at " << std::hex << FLAGS_breakpoint;

  errno = 0;
  auto old_text_word = ptrace(PTRACE_PEEKTEXT, pid, FLAGS_breakpoint, 0);
  auto has_err = 0 != errno;

  // Add in an `int3`.
  auto new_text_word = (old_text_word & (~0xFFL)) | 0xCCL;
  ptrace(PTRACE_POKETEXT, pid, FLAGS_breakpoint, new_text_word);

  if (has_err || 0 != errno) {
    kill(pid, SIGKILL);
    LOG(FATAL)
        << "Unable to write breakpoint at "
        << std::setw(16) << std::hex << std::setfill('0') << FLAGS_breakpoint
        << " into " << gTraceeArgv[0];
  }

  while (true) {  // Run until the breakpoint is hit.
    if (0 > ptrace(PTRACE_CONT, pid, 0, 0)) {
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Breakpoint won't be hit; unable to continue executing "
          << gTraceeArgv[0];
    }

    auto status = 0;
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status)) {
        if (SIGTRAP == WSTOPSIG(status)) {
          break;
        } else if (IsErrorSignal(WSTOPSIG(status))) {
          LOG(FATAL)
              << "Tracee exited with signal " << WSTOPSIG(status)
              << " before the breakpoint was hit.";
        } else {
          DLOG(INFO)
              << "Tracee " << gTraceeArgv[0] << " received signal "
              << WSTOPSIG(status) << " before the breakpoint was hit.";
        }
      } else if (WIFEXITED(status)) {
        LOG(FATAL)
            << "Tracee " << gTraceeArgv[0]
            << " exited before breakpoint was hit";
      } else if (WIFSIGNALED(status)) {
        LOG(FATAL)
            << "Tracee " << gTraceeArgv[0]
            << " exited before breakpoint was hit";
      } else {
        DLOG(INFO)
            << "Unrecognized status " << status << " received before "
            << "hitting breakpoint in " << gTraceeArgv[0];
      }

    } else if (EINTR != err) {
      auto err = strerror(errno);
      kill(pid, SIGKILL);
      LOG(FATAL)
          << "Problem waiting for the breakpoint in " << gTraceeArgv[0]
          << " to be hit: " << err;
    }
  }

  // Restore the original code.
  ptrace(PTRACE_POKETEXT, pid, FLAGS_breakpoint, old_text_word);
}

static SnapshotFile gFileInfo = {};
static uint64_t gStackBase = 0;
static uint64_t gStackLimit = 0;

// Parse a line from `/proc/<pid>/maps` and fill in a `PageInfo` structure.
static bool ReadPageInfoLine(const std::string &line, PageInfo *info) {
  auto cline = line.c_str();
  uint64_t begin = 0;
  uint64_t end = 0;
  char r = '-';
  char w = '-';
  char x = '-';
  char p = '-';

  if (6 != sscanf(cline, "%lx-%lx %c%c%c%c", &begin, &end, &r, &w, &x, &p)) {
    return false;
  }

  DLOG(INFO)
      << "Page info: " << line;

  info->base_address = begin;
  info->limit_address = end;

  auto is_r = 'r' == r;
  auto is_w = 'w' == w;
  auto is_x = 'x' == x;

  if (is_r && is_w && is_x) {
    info->perms = PagePerms::kReadWriteExec;

  } else if (is_r && is_w && !is_x) {
    info->perms = PagePerms::kReadWrite;

  } else if (is_r && !is_w && is_x) {
    info->perms = PagePerms::kReadExec;

  } else if (is_r && !is_w && !is_x) {
    info->perms = PagePerms::kReadOnly;

  } else if (!is_r && is_w && !is_x) {
    info->perms = PagePerms::kWriteOnly;

  // TODO(pag): These actually come up quite a bit, and it may be important
  //            to include them in the future so that they are not permitted
  //            to be allocated by `mmap`s.
  } else {
    LOG(WARNING)
        << "Unrecognized page permissions!";
    return false;
  }

  if (strstr(cline, "[stack]")) {
    CHECK(!gStackBase)
        << "Cannot snapshot a program with more than one stack.";

    gStackBase = info->base_address;
    gStackLimit = info->limit_address;

    struct rlimit limit;
    getrlimit(RLIMIT_STACK, &limit);
    DLOG(INFO)
        << "Current stack size limit is " << limit.rlim_cur;

    DLOG(INFO)
        << "Absolute maximum stack size is " << limit.rlim_max;

    limit.rlim_max = std::min<rlim_t>(limit.rlim_cur, 16UL << 20UL);
    limit.rlim_max = std::max<rlim_t>(
        limit.rlim_cur, info->limit_address - info->base_address);

    DLOG(INFO)
        << "New stack size is " << limit.rlim_max;
    info->base_address = info->limit_address - limit.rlim_max;
  }

  return true;
}

// Read out the ranges of mapped pages.
static void ReadTraceePageMaps(pid_t pid) {
  std::stringstream ss;
  ss << "/proc/" << pid << "/maps";

  std::ifstream maps_file(ss.str());
  std::string line;
  auto i = 0;
  auto file_size = sizeof(SnapshotFile);
  while (std::getline(maps_file, line)) {
    CHECK(i < SnapshotFile::kMaxNumPageInfos)
        << "Too many pages ranges in memory map!";

    auto &page_info = gFileInfo.pages[i];
    if (ReadPageInfoLine(line, &page_info)) {
      page_info.offset_in_file = file_size;
      file_size += (page_info.limit_address - page_info.base_address);
      i += 1;
    }
  }
}

// Copy some data from the tracee into the snapshot file, using ptrace to do
// the copying.
static bool CopyTraceeMemoryWithPtrace(pid_t pid, uint64_t addr,
                                       uint64_t size, void *dest) {
  for (auto i = 0UL; i < size; ) {
    errno = 0;
    auto copied_data = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    if (errno) {
      return false;
    }

    auto dest_data = reinterpret_cast<decltype(copied_data) *>(dest);
    dest_data[i / sizeof(copied_data)] = copied_data;

    i += sizeof(copied_data);
    addr += sizeof(copied_data);
  }
  return true;
}

// Copy memory from the tracee into the snapshot file.
static void CopyTraceeMemory(pid_t pid, int snapshot_fd) {
  std::stringstream ss;
  ss << "/proc/" << pid << "/mem";
  auto fd = open64(ss.str().c_str(), O_RDONLY | O_LARGEFILE);

  // Figure out how much memory we want to snapshot.
  uint64_t memory_size = 0;
  for (const auto &info : gFileInfo.pages) {
    memory_size += (info.limit_address - info.base_address);
  }

  // Resize file to fit all memory to be snapshotted.
  auto file_size = gFileInfo.pages[0].offset_in_file + memory_size;
  CHECK(!ftruncate64(snapshot_fd, file_size))
      << "Unable to resize snapshot file " << gSnapshotPath
      << " to contain the memory to be snapshotted: " << strerror(errno);

  // Map the snapshot file into memory, so we can directly read the tracee's
  // memory into the snapshot file.
  auto data = mmap(nullptr, memory_size, PROT_WRITE,
                   MAP_SHARED | MAP_FILE, snapshot_fd,
                   gFileInfo.pages[0].offset_in_file);

  CHECK(MAP_FAILED != data)
      << "Unable to map the memory of " << gSnapshotPath
      << ": " << strerror(errno);

  auto memory_copied = 0ULL;
  for (const auto &info : gFileInfo.pages) {
    if (PagePerms::kInvalid == info.perms) {
      break;
    }

    // Adjust when we are copying data from the stack, and the maximum possible
    // stack size does not match the mapped stack size.
    auto base_addr = info.base_address;
    if (gStackLimit == info.limit_address && gStackBase != info.base_address) {
      memory_copied += gStackBase - base_addr;
      base_addr = gStackBase;
    }

    auto dest = reinterpret_cast<void *>(
        reinterpret_cast<uintptr_t>(data) + memory_copied);
    auto size_to_copy = info.limit_address - base_addr;

    DLOG(INFO)
        << "Copying " << size_to_copy << " bytes from the tracee's memory from "
        << std::hex << base_addr << " to " << std::hex << info.limit_address
        << " into the snapshot file.";

    CHECK(-1 != lseek64(fd, static_cast<off64_t>(base_addr), SEEK_SET))
        << "Can't seek to page address in tracee memory: " << strerror(errno);

    auto read_size = read(fd, dest, size_to_copy);
    if (static_cast<uint64_t>(read_size) != size_to_copy &&
        !CopyTraceeMemoryWithPtrace(pid, base_addr, size_to_copy, dest)) {
      LOG(WARNING)
          << "Unable to copy data into snapshot file: " << strerror(errno)
          << "; trying ptrace backup. This is probably the [vvar] section "
          << "of memory.";
    }
    memory_copied += size_to_copy;
  }

  CHECK(memory_copied == memory_size)
      << "Unable to copy all memory to be snapshotted into " << gSnapshotPath;

  msync(data, memory_size, MS_SYNC);
  munmap(data, memory_size);
  close(fd);
}

// Create a snapshot file of the tracee.
static void SnapshotTracee(pid_t pid) {
  auto fd = open64(
      gSnapshotPath.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE,
      0666);

  CHECK(-1 != fd)
      << "Unable to create snapshot file " << gSnapshotPath
      << ": " << strerror(errno);

  ReadTraceePageMaps(pid);

  DLOG(INFO)
      << "Writing memory map info into " << gSnapshotPath;

  write(fd, &gFileInfo, sizeof(gFileInfo));

  DLOG(INFO)
      << "Copying tracee memory into " << gSnapshotPath;
  CopyTraceeMemory(pid, fd);

  switch (gFileInfo.arch_name) {
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
      DLOG(INFO)
          << "Writing X86 register state into " << gSnapshotPath;
      x86::CopyTraceeState(pid, fd);
      break;

    default:
      LOG(FATAL)
          << "Cannot copy tracee register state for unsupported architecture "
          << FLAGS_arch;
  }

  close(fd);
}

// Change file descriptor properties to close normal FDs on `execve` in the
// tracee.
static void CloseFdsOnExec(void) {
  auto dp = opendir("/proc/self/fd");
  CHECK(nullptr != dp)
      << "Unable to open /proc/self/fd directory of tracee: "
      << strerror(errno);

  while (true) {
    errno = 0;
    auto dirent = readdir(dp);
    if (!dirent) {
      CHECK(!errno)
          << "Unable to list /proc/self/fd directory of tracee: "
          << strerror(errno);
      break;
    }

    int fd = 0;
    if (1 != sscanf(dirent->d_name, "%d", &fd)) {
      continue;
    }

    switch (fd) {
      case STDIN_FILENO:
      case STDOUT_FILENO:
      case STDERR_FILENO:
        break;
      default:
        DLOG(INFO)
            << "Setting fd " << fd << " to close on exec.";

        CHECK(!fcntl(fd, F_SETFD, FD_CLOEXEC))
            << "Unable to change fd " << fd << " in tracee to close on exec: "
            << strerror(errno);
        break;
    }
  }

  closedir(dp);
}

// Enable core dumps in the current process (tracee).
static void EnableCoreDumps(void) {
  struct rlimit core_limit = {RLIM_INFINITY, RLIM_INFINITY};
  CHECK(!setrlimit(RLIMIT_CORE, &core_limit))
      << "Unable to enable core dumps in tracee: " << strerror(errno);
}

// Change the personality features of the tracee to restrict the address
// space layout, making it easier to snapshot.
static void ChangeAddressSpace(void) {
  CHECK(-1 != personality(ADDR_NO_RANDOMIZE))
      << "Unable to disable ASLR in tracee: " << strerror(errno);

  CHECK(-1 != personality(ADDR_LIMIT_32BIT))
      << "Unable to restrict address space size in tracee: " << strerror(errno);

  struct rlimit core_limit = {4294967296, 4294967296};  // 4 GiB.
  CHECK(!setrlimit(RLIMIT_AS, &core_limit))
      << "Unable to limit address space size: " << strerror(errno);
}

struct CoreFileLocation {
  std::string dir;
  std::string pattern;
};

static void ReplaceInString(std::string &str, const char *pattern,
                            const char *replacement) {
  auto len = strlen(pattern);
  auto loc = str.find(pattern);
  while (std::string::npos != loc) {
    str.replace(loc, len, replacement);
    loc = str.find(pattern);
  }
}

// Determine the storage location of core files.
static CoreFileLocation GetCoreFileLocation(void) {
  std::ifstream core_file_pattern("/proc/sys/kernel/core_pattern");
  std::string pattern;

  CHECK(!!std::getline(core_file_pattern, pattern))
      << "Cannot read core pattern from /proc/sys/kernel/core_pattern";

  CHECK(!pattern.empty())
      << "No core file pattern stored in /proc/sys/kernel/core_pattern";

  CHECK('|' != pattern[0])
      << "Core files are piped to programs; won't find core file.";

  DLOG(INFO)
      << "System core file pattern is: " << pattern;

  ReplaceInString(pattern, "%p", "%d");  // PID.
  ReplaceInString(pattern, "%u", "%d");  // User ID.
  ReplaceInString(pattern, "%g", "%d");  // Group ID.
  ReplaceInString(pattern, "%s", "%d");  // Signal number.
  ReplaceInString(pattern, "%t", "%d");  // UNIX timestamp.
  ReplaceInString(pattern, "%h", "%s");  // Hostname.
  ReplaceInString(pattern, "%e", "%s");  // Executable file name.
  pattern += "%s";  // Always need to make sure `sscanf` matches something.

  CoreFileLocation loc = {"", ""};
  if ('/' == pattern[0]) {
    auto last_slash_loc = pattern.find_last_of('/');
    loc.dir = pattern.substr(0, last_slash_loc);
    loc.pattern = pattern.substr(last_slash_loc + 1,
                                 pattern.size() - last_slash_loc - 1);

  } else {
    loc.dir = CurrentWorkingDirectory();
    loc.pattern = pattern;
  }

  DLOG(INFO)
      << "Core files are stored in: " << loc.dir;

  DLOG(INFO)
      << "Will search for files using the pattern: " << loc.pattern;

  return loc;
}

static int64_t GetTimeMs(struct timespec ts) {
  auto ns = ts.tv_nsec + (1000000LL - 1LL);  // Round up.
  return (ts.tv_sec * 1000LL) + (ns / 1000000LL);
}

static int64_t GetTimeMs(int64_t round) {
  struct timeval tv = {};
  struct timezone tz = {};
  CHECK(!gettimeofday(&tv, &tz))
      << "Can't get current time for bounding core dump file creation time.";

  auto us = tv.tv_usec + round * (1000LL - 1LL);  // Conditionally round up.
  return (tv.tv_sec * 1000LL) + (us / 1000LL);
}

// Send an abort signal to the tracee, hoping to produce a core dump. Then
// go and try to locate the core dump file, respecting the core file pattern
// of the kernel, then rename the core file to our desired file name.
//
// Note:  This whole function is sketchy on so many levels. There are several
//        failure modes, and if it "succeeds" it may actually do the wrong
//        thing.
static void CreateCoreFile(pid_t pid, const CoreFileLocation &where) {
  const auto created_lower_bound_ms = GetTimeMs(0);

  // Abort the tracee.
  kill(pid, SIGABRT);
  ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

  // Wait for the tracee to die, and hopefully this event will be reported
  // after the core dump is produced!
  while (true) {
    auto status = 0;
    const auto res = waitpid(pid, &status, 0);
    const auto err = -1 == res ? errno : 0;
    if (res == pid) {
      if (WIFSTOPPED(status) || WIFEXITED(status) || WIFSIGNALED(status)) {
        break;
      } else {
        DLOG(INFO)
            << "Unrecognized status " << status
            << " while waiting for a core dump of the tracee to be produced.";
      }
    } else if (ESRCH == err || ECHILD == err) {
      DLOG(INFO)
          << "Tracee has correctly died from abort signal.";
      break;

    } else if (EINTR != err) {
      LOG(FATAL)
          << "Problem waiting for core dump of tracee: " << strerror(errno);
    }
  }
  const auto created_upper_bound_ms = GetTimeMs(1);

  auto dp = opendir(where.dir.c_str());
  CHECK(nullptr != dp)
      << "Unable to open core file directory " << where.dir << strerror(errno);

  uint64_t storage_space[PATH_MAX / sizeof(uint64_t)];

  // Try to find the core file, and opportunistically resolve conflicts with
  // other possible core files
  std::string found_core_file;
  while (true) {
    errno = 0;
    auto dirent = readdir(dp);
    if (!dirent) {
      CHECK(!errno)
          << "Unable to list files in " << where.dir << strerror(errno);
      break;
    }

    if (DT_REG != dirent->d_type && DT_LNK != dirent->d_type) {
      continue;
    }

    std::stringstream ss;
    ss << where.dir << "/" << dirent->d_name;
    auto core_file_path = ss.str();

    DLOG(INFO)
        << "Checking to see if " << core_file_path
        << " looks like a core file.";

    // This is so sketchy. The idea is that the `sscanf` will fill in stuff,
    // but we don't know a priori what types of things it will fill in, so
    // we'll just send it a lot of pointers to an array and hope for the best.
    auto num_matched = sscanf(dirent->d_name, where.pattern.c_str(),
                              storage_space, storage_space, storage_space,
                              storage_space, storage_space, storage_space,
                              storage_space, storage_space, storage_space);
    if (!num_matched) {
      continue;
    }

    DLOG(INFO)
        << "Matched file " << core_file_path << " as a core dump candidate.";

    struct stat core_file_info = {};
    const auto found_info = stat(core_file_path.c_str(), &core_file_info);
    if (-1 == found_info) {
      LOG(WARNING)
          << "Could not stat core dump candidate " << core_file_path
          << ": " << strerror(errno);
      continue;
    }

    const auto created_time_ms = GetTimeMs(core_file_info.st_ctim);

    if (created_lower_bound_ms > created_time_ms &&
        100LL < (created_lower_bound_ms - created_time_ms)) {  // Slack.
      DLOG(INFO)
          << "Core file candidate " << core_file_path
          << " ignored; it is too old.";
      continue;
    }

    if (created_time_ms > created_upper_bound_ms &&
        100LL < (created_time_ms - created_upper_bound_ms)) {  // Slack.
      DLOG(INFO)
          << "Core file candidate " << core_file_path
          << " ignored; it is too new.";
      continue;
    }

    // TODO(pag): Check for ELF magic in the beginning of the core dump file?

    // The above checks are totally insufficient if the machine is producing
    // lots of core files. Our core file pattern matching completely ignores
    // things like PIDs being embedded in the file name, but we want to keep
    // the logic to a reasonable level.
    found_core_file = core_file_path;
    break;
  }

  closedir(dp);

  CHECK(!found_core_file.empty())
      << "Unable to find acceptable core dump file in directory: " << where.dir;

  CHECK(-1 != rename(found_core_file.c_str(), gCorePath.c_str()))
      << "Unable to rename core file " << found_core_file << " to "
      << gCorePath << ": " << strerror(errno);
}

// Spawn a sub-process, execute the program up until a breakpoint is hit, and
// snapshot the program at that breakpoint.
static void SnapshotProgram(ArchName arch, OSName os) {
  signal(SIGCHLD, SIG_IGN);

  // Try to figure out how to find the produced core file. Do this ahead of
  // time so that we don't produce a snapshot without first being able to
  // find the eventual core dump.
  const auto core_loc = GetCoreFileLocation();

  LogPrepareExec();

  if (const auto pid = fork()) {
    CHECK(-1 != pid)
        << "Could not fork process.";

    DLOG(INFO)
        << "Acquiring control of tracee with pid " << pid;

    TraceSubprocess(pid);
    DLOG(INFO)
        << "Acquired control of tracee with pid " << pid;

    RunUntilInTracee(pid);
    DLOG(INFO)
        << "Tracee with pid " << pid << " is now running " << gTraceeArgv[0];

    if (FLAGS_breakpoint) {
      RunUntilBreakpoint(pid);
      DLOG(INFO)
          << "Hit breakpoint at "
          << std::setw(16) << std::hex << std::setfill('0') << FLAGS_breakpoint
          << " in " << gTraceeArgv[0];
    }

    DLOG(INFO)
        << "Snapshotting " << gTraceeArgv[0];

    gFileInfo.arch_name = arch;
    gFileInfo.os_name = os;
    SnapshotTracee(pid);

    DLOG(INFO)
        << "Aborting " << gTraceeArgv[0] << " to produce core dump.";
    CreateCoreFile(pid, core_loc);

    DLOG(INFO)
        << "Snapshot file saved to " << gSnapshotPath
        << " and core file saved to " << gCorePath;

  } else {
    signal(SIGCHLD, SIG_DFL);  // Restore  signal handler state.

    EnableTracing();
    EnableCoreDumps();
    CloseFdsOnExec();
    ChangeAddressSpace();

    // Tell the tracee to load in all shared libraries as soon as possible.
    CHECK(!setenv("LD_BIND_NOW", "1", true))
        << "Unable to set LD_BIND_NOW=1 for tracee: " << strerror(errno);

    // Ideally speed up calls to `localtime`.
    if (!getenv("TZ")) {
      CHECK(!setenv("TZ", ":/etc/localtime", true))
          << "Unable to set TZ=\":/etc/localtime\" for tracee: "
          << strerror(errno);
    }

    CHECK(!execvpe(gTraceeArgv[0], gTraceeArgv, __environ))
        << "Unable to exec tracee: " << strerror(errno);
  }
}

}  // namespace
}  // namespace vmill
}  // namespace remill

int main(int argc, char **argv) {

  // Extract the arguments to the tracee before gflags and glog get at them,
  // that way gflags/glog don't complain about invalid arguments.
  const auto got_tracee_args = remill::vmill::ExtractTraceeArgs(&argc, argv);

  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --breakpoint ADDR \\" << std::endl
     << "    --snapshot SNAPSHOT_FILE \\" << std::endl
     << "    -- PROGRAM ..." << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(got_tracee_args)
      << "Unable to extract arguments to tracee. Make sure to provide "
      << "the program and command-line arguments to that program after "
      << "a '--'.";

  if (FLAGS_workspace.empty()) {
    FLAGS_workspace = remill::CurrentWorkingDirectory();
  }

  CHECK(!FLAGS_workspace.empty())
      << "Unable to locate workspace. Please specify it with --workspace.";

  if ('/' == FLAGS_workspace[FLAGS_workspace.size() - 1]) {
    FLAGS_workspace = FLAGS_workspace.substr(0, FLAGS_workspace.size() - 1);
  }

  CHECK(remill::TryCreateDirectory(FLAGS_workspace))
    << "Directory " << FLAGS_workspace << " specified by --workspace "
    << "does not exist or can't be created.";

  remill::vmill::gSnapshotPath = FLAGS_workspace + "/snapshot";
  remill::vmill::gCorePath = FLAGS_workspace + "/core";

  auto arch_name = remill::GetArchName(FLAGS_arch);
  CHECK(remill::kArchInvalid != arch_name)
      << "Invalid architecture name specified to --arch.";

  auto os_name = remill::GetOSName(FLAGS_os);
  CHECK(remill::kOSInvalid != os_name)
      << "Invalid operating system name specified to --os.";

  remill::vmill::SnapshotProgram(arch_name, os_name);

  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

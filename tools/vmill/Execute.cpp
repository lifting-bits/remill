/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>

#include <llvm/IR/LLVMContext.h>

//#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ManagedStatic.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "tools/vmill/BC/Manager.h"
#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"
#include "tools/vmill/Context/AddressSpace.h"
#include "tools/vmill/Context/Context.h"
#include "tools/vmill/Snapshot/File.h"
#include "tools/vmill/Snapshot/Snapshot.h"

DEFINE_string(workspace, ".", "Path to workspace in which the snapshot file is"
                              " stored, and in which files will be placed.");

DEFINE_string(arch, "", "Architecture of the code in the snapshot.");

DEFINE_string(os, "", "OS of the code in the snapshot.");

DEFINE_string(executor, "native", "Type of the executor to run.");

using namespace remill;
using namespace vmill;

namespace {

//remill::vmill::Context::InterceptWith(malloc, size_t size) {
//  return malloc(size);
//}

//static const char *kFakeArgV[] = {
//  "vmill-exec",
//  "-disable-debug-info-print",
//  "-regalloc=fast",
//  nullptr
//};

//
//static std::unique_ptr<Executor> CreateExecutor(const Arch *arch) {
//  if (FLAGS_executor == "native") {
//    return Executor::CreateNativeExecutor(arch);
//  } else {
//    LOG(FATAL)
//        << FLAGS_executor << "is not a valid executor. Valid executors are: "
//        << "native.";
//    return nullptr;
//  }
//}

std::unique_ptr<Snapshot> OpenSnapshot(void) {
  const std::string snapshot_path = FLAGS_workspace + "/snapshot";
  CHECK(FileExists(snapshot_path))
      << "Snapshot file " << snapshot_path << " does not exist. Make sure "
      << "to create it with vmill-snapshot.";

  return Snapshot::Open(snapshot_path);
}

static uint8_t gSnapshotDataBuf[4096] = {};

// Copy data from the snapshot file into a range of memory in the address
// space. This will not copy zero-valued bytes from the snapshot file because
// the initial memory allocations in the address space are zero-initialized.
// The benefit of avoiding zeroes is that large portions of the runtime call
// stack don't need to be copied.
static void CopyDataIntoAddressSpace(int fd, const PageInfo &page,
                                     AddressSpacePtr address_space) {
  const auto buf_size = sizeof(gSnapshotDataBuf);
  for (uint64_t num_read = 0; num_read < page.Size(); num_read += buf_size) {

    lseek(fd, static_cast<off_t>(page.offset_in_file + num_read), SEEK_SET);
    auto read_size = read(fd, &(gSnapshotDataBuf[0]), buf_size);

    CHECK(static_cast<size_t>(read_size) == buf_size)
        << "Unable to read data at logical address ["
        << std::hex << (page.base_address + num_read) << ", "
        << std::hex << (page.base_address + num_read + buf_size)
        << ") from range [" << std::hex << page.base_address << ", "
        << std::hex << page.limit_address << "): " << strerror(errno);

    for (uint64_t i = 0; i < buf_size; ++i) {
      if (gSnapshotDataBuf[i]) {  // Skip zero-valued bytes.
        auto addr = page.base_address + num_read + i;
        CHECK(address_space->TryWrite(addr, gSnapshotDataBuf[i]))
            << "Unable to write byte " << std::hex << gSnapshotDataBuf[i]
            << " into address space at address 0x" << std::hex << addr
            << " for range [" << std::hex << page.base_address << ", "
          << std::hex << page.limit_address << ")";
      }
    }
  }
}

// Go through the snapshotted pages and copy them into the address space.
static void CopyDataIntoAddressSpace(const std::unique_ptr<Snapshot> &snapshot,
                                     AddressSpacePtr address_space) {
  for (auto &page : snapshot->file->pages) {
    if (page.base_address) {
      address_space->AddMap(page.base_address, page.Size());

      CopyDataIntoAddressSpace(snapshot->fd, page, address_space);

      address_space->SetPermissions(
          page.base_address, page.Size(),
          page.CanRead(), page.CanWrite(),
          page.CanExec());
    }
  }

  address_space->LogMaps();
}

}  // namespace

#if defined(NDEBUG)
# define IF_DEBUG_ELSE(a, b) b
#else
# define IF_DEBUG_ELSE(a, b) a
#endif  // defined(NDEBUG)

int main(int argc, char **argv) {

  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --arch ARCH_NAME \\" << std::endl
     << "    --os OS_NAME \\" << std::endl
     << "    [--executor EXEC_KIND] \\" << std::endl
     << "    [--workspace WORKSPACE_DIR]" << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetCommandLineOption("GLOG_minloglevel", IF_DEBUG_ELSE("0", "2"));

  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

//  llvm::cl::ParseCommandLineOptions(3, kFakeArgV, "");

  if (FLAGS_workspace.empty()) {
    FLAGS_workspace = CurrentWorkingDirectory();
  }

  CHECK(!FLAGS_workspace.empty())
      << "Must specify a valid path to --workspace.";

  const auto arch_name = GetArchName(FLAGS_arch);
  CHECK(kArchInvalid != arch_name)
      << "Invalid architecture specified to --arch.";

  const auto os_name = GetOSName(FLAGS_os);
  CHECK(kOSInvalid != os_name)
      << "Invalid OS specified to --os.";

  auto snapshot = OpenSnapshot();

  CHECK(snapshot->GetOS() == os_name)
      << "OS name " << FLAGS_os << " passed to --os does not match the "
      << "OS name " << GetOSName(snapshot->GetOS()) << " of the snapshot file";

  CHECK(snapshot->GetArch() == arch_name)
      << "Architecture name " << FLAGS_arch << " passed to --arch does not "
      << "match the architecture name " << GetArchName(snapshot->GetArch())
      << " of the snapshot file";

  auto llvm_context = std::unique_ptr<llvm::LLVMContext>(new llvm::LLVMContext);
  auto manager = BitcodeManager::Create(llvm_context.get());
  auto context = Context::Create();
  auto memory = context->CreateAddressSpace();
  auto address_space = context->AddressSpaceOf(memory);

  CopyDataIntoAddressSpace(snapshot, address_space);

//  auto state = snapshot->GetState();

  manager->GetModuleWithLiftedBlock(address_space, 0xf77b8abf);

  DLOG(INFO)
      << "Shutting down, have a nice day!";

  llvm::llvm_shutdown();
  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

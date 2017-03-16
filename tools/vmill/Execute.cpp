/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <sys/prctl.h>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ManagedStatic.h>

#include "remill/Arch/Name.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "tools/vmill/Context/Context.h"

#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/Snapshot/Snapshot.h"

DEFINE_string(workspace, ".", "Path to workspace in which the snapshot file is"
                              " stored, and in which files will be placed.");

DEFINE_string(arch, "", "Architecture of the code in the snapshot.");

DEFINE_string(os, "", "OS of the code in the snapshot.");

DEFINE_string(executor, "native", "Type of the executor to run.");

using namespace remill;
using namespace vmill;

namespace {

static const char *kFakeArgV[] = {
  "vmill-exec",
  "-disable-debug-info-print",
  "-regalloc=fast",
  nullptr
};

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

//std::unique_ptr<Snapshot> OpenSnapshot(void) {
//  const std::string snapshot_path = FLAGS_workspace + "/snapshot";
//  CHECK(FileExists(snapshot_path))
//      << "Snapshot file " << snapshot_path << " does not exist. Make sure "
//      << "to create it with vmill-snapshot.";
//
//  return Snapshot::Open(snapshot_path);
//}

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

  llvm::cl::ParseCommandLineOptions(3, kFakeArgV, "");

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

//  auto snapshot = OpenSnapshot();
//
//  CHECK(snapshot->GetOS() == os_name)
//      << "OS name " << FLAGS_os << " passed to --os does not match the "
//      << "OS name " << GetOSName(snapshot->GetOS()) << " of the snapshot file";
//
//  CHECK(snapshot->GetArch() == arch_name)
//      << "Architecture name " << FLAGS_arch << " passed to --arch does not "
//      << "match the architecture name " << GetArchName(snapshot->GetArch())
//      << " of the snapshot file";

  auto arch = Arch::Get(os_name, arch_name);
  auto manager = std::make_shared<BitcodeManager>(arch);
  auto context = std::make_shared<Context>();

//  auto executor = CreateExecutor(arch);
  do {
    auto process = executor->CreateProcess(snapshot);
    CHECK(nullptr != process)
        << "Unable to create process.";

    switch (executor->Execute(process)) {
      case Executor::kStatusStoppedAtError:
        process->Kill();
        break;

      case Executor::kStatusStoppedAtAsyncHyperCall:
        process->HandleAsyncHyperCall(thread);
        break;
    }

    delete process;
  } while (false);

  DLOG(INFO)
      << "Shutting down, have a nice day!";

  llvm::llvm_shutdown();
  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <sys/prctl.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/OS/Linux32/System.h"
#include "tools/vmill/Snapshot/Snapshot.h"

DEFINE_string(workspace, "", "Path to workspace in which the snapshot file is "
                             "stored, and in which files will be placed.");

DEFINE_string(arch, "", "Architecture of the code in the snapshot.");

DEFINE_string(os, "", "OS of the code in the snapshot.");

int main(int argc, char **argv) {
  using namespace remill;
  using namespace vmill;

  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --arch ARCH_NAME \\" << std::endl
     << "    --os OS_NAME \\" << std::endl
     << "    [--workspace WORKSPACE_DIR]" << std::endl;

  google::InitGoogleLogging(argv[0]);
  GFLAGS_NAMESPACE::SetUsageMessage(ss.str());
  GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc, &argv, true);

  if (FLAGS_workspace.empty()) {
    FLAGS_workspace = CurrentWorkingDirectory();
  }

  CHECK(!FLAGS_workspace.empty())
      << "Must specify a valid path to --workspace.";

  const std::string snapshot_path = FLAGS_workspace + "/snapshot";
  CHECK(FileExists(snapshot_path))
      << "Snapshot file " << snapshot_path << " does not exist. Make sure "
      << "to create it with vmill-snapshot.";

  const auto arch_name = GetArchName(FLAGS_arch);
  CHECK(kArchInvalid != arch_name)
      << "Invalid architecture specified to --arch.";

  const auto os_name = GetOSName(FLAGS_os);
  CHECK(kOSInvalid != os_name)
      << "Invalid OS specified to --os.";

  auto snapshot = Snapshot::Open(snapshot_path);

  CHECK(snapshot->GetOS() == os_name)
      << "OS name " << FLAGS_os << " passed to --os does not match the "
      << "OS of the snapshot file";

  CHECK(snapshot->GetArch() == arch_name)
      << "Architecture name " << FLAGS_arch << " passed to --arch does not "
      << "match the architecture of the snapshot file";

  // Try to make sure that the remill-lift and remill-opt servers are killed.
  prctl(PR_SET_PDEATHSIG, SIGKILL);

  auto arch = Arch::Create(os_name, arch_name);
  do {
    auto process = Process32::Create(snapshot);
    CHECK(nullptr != process)
        << "Unable to create 32-bit process.";

    auto code_version = process->CodeVersion();
    auto executor = Executor::CreateNativeExecutor(arch, code_version);

    while (auto thread = process->ScheduleNextThread()) {
      DLOG(INFO)
          << "Scheduling virtual thread with TID " << thread->tid;

      switch (executor->Execute(process)) {
        case Executor::kStatusCannotContinue:
        case Executor::kStatusStoppedAtError:
          process->Kill();
          break;

        case Executor::kStatusStoppedAtAsyncHyperCall:
          process->ProcessAsyncHyperCall(thread);
          break;

        case Executor::kStatusPaused:
          break;
      }
    }

    delete executor;
    delete process;
  } while (false);

  DLOG(INFO)
      << "Shutting down, have a nice day!";

  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

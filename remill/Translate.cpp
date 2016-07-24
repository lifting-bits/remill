/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <fstream>
#include <sstream>

#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>

#include "remill/BC/Translator.h"
#include "remill/BC/Util.h"
#include "remill/Arch/Arch.h"
#include "remill/CFG/CFG.h"

#ifndef REMILL_OS
# if defined(__APPLE__)
#   define REMILL_OS "mac"
# elif defined(__linux__)
#   define REMILL_OS "linux"
# endif
#endif

// TODO(pag): Support separate source and target architectures?
DEFINE_string(arch_in, "", "Architecture of the code being translated. "
                           "Valid architectures: x86, amd64.");

DEFINE_string(arch_out, "", "Architecture of the target architecture on "
                            "which the translated code will run. Valid "
                            "architectures: x86, amd64.");

DEFINE_string(os_in, REMILL_OS, "Source OS. Valid OSes: linux, mac.");
DEFINE_string(os_out, REMILL_OS, "Target OS. Valid OSes: linux, mac.");

DEFINE_string(cfg, "", "Path to the CFG file containing code to lift.");

DEFINE_string(bc_in, "", "Input bitcode file into which code will "
                         "be lifted. This should either be a semantics file "
                         "associated with `--arch_in`, or it should be "
                         "a bitcode file produced by `cfg_to_bc`. Chaining "
                         "bitcode files produces by `cfg_to_bc` can be "
                         "used to iteratively link in libraries to lifted "
                         "code.");

DEFINE_string(bc_out, "", "Output bitcode file name.");

extern "C" int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  // GFlags will have removed everything that it recognized from argc/argv.
  llvm::cl::ParseCommandLineOptions(argc, argv, "Remill CFG to LLVM");

  CHECK(!FLAGS_os_out.empty())
      << "Need to specify a target operating system with --os.";

  CHECK(!FLAGS_arch_in.empty())
      << "Need to specify a source architecture with --arch_in.";

  CHECK(!FLAGS_arch_out.empty())
      << "Need to specify a target architecture with --arch_out.";

  CHECK(!FLAGS_cfg.empty())
      << "Must specify CFG file with --cfg.";

  CHECK(!FLAGS_bc_out.empty())
      << "Please specify an input bitcode file with --bc_in.";

  CHECK(!FLAGS_bc_out.empty())
      << "Please specify an output bitcode file with --bc_out.";

  auto source_os = remill::GetOSName(FLAGS_os_in);
  auto target_os = remill::GetOSName(FLAGS_os_out);

  auto source_arch = remill::Arch::Create(source_os, FLAGS_arch_in);
  auto target_arch = remill::Arch::Create(target_os, FLAGS_arch_out);

  auto cfg = remill::ReadCFG(FLAGS_cfg);
  auto source_module = remill::LoadModuleFromFile(FLAGS_bc_in);
  auto target_module = target_arch->PrepareModule(source_module);

  remill::Translator lifter(source_arch, target_module);
  lifter.LiftCFG(cfg);

  remill::StoreModuleToFile(target_module, FLAGS_bc_out);

  delete cfg;
  delete source_arch;

  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

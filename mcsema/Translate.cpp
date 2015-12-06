/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <fstream>
#include <sstream>

#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>

#include "mcsema/BC/Translator.h"
#include "mcsema/BC/Util.h"
#include "mcsema/Arch/Arch.h"
#include "mcsema/CFG/CFG.h"

// TODO(pag): Support separate source and target architectures?
DEFINE_string(source_arch, "", "Architecture of the code being translated. "
                               "Valid architectures: x86, amd64.");

DEFINE_string(target_arch, "", "Architecture of the target architecture on "
                               "which the translated code will run. Valid "
                                "architectures: x86, amd64.");

DEFINE_string(os, "", "Target OS. Valid OSes: linux, mac.");

DEFINE_string(cfg, "", "Path to the CFG file containing code to lift.");

DEFINE_string(bc_in, "", "Optional; input bitcode file into which code will "
                         "be lifted. If unspecified then cfg_to_bc will use "
                         "an arch-specific bitcode file. If specified, then "
                         "cfg_to_bc expects this file to have been produced "
                         "by cfg_to_bc on a different CFG file for the same "
                         "architecture. This 'chaining' of cfg_to_bc can be "
                         "used to iteratively link in libraries to lifted "
                         "code.");

DEFINE_string(bc_out, "", "Output bitcode file name.");

namespace mcsema {
namespace {

// Create an arch-specific LLVM module, or if a bitcode file is provided on
// the command-line, use that one. We do a simple verification on the input
// module by requiring that it has a specific ID.
static llvm::Module *CreateOrLoadModule(const Arch *arch,
                                        std::string module_file) {
  std::stringstream ss;
  ss << "mcsema:" << FLAGS_source_arch << ":" << FLAGS_target_arch
     << ":" << FLAGS_os;
  const std::string meta_id = ss.str();

  if (module_file.empty()) {
    auto module = arch->CreateModule();

    // Set a specific flag. This will provide a poor man's way of
    // verifying that an input module to `cfg_to_bc` is of the correct
    // architecture.
    module->getOrInsertNamedMetadata(meta_id);
    return module;

  } else {
    LOG(INFO) << "Using " << module_file << " as the base bitcode module.";
    auto module = LoadModuleFromFile(module_file);

    CHECK(nullptr != module->getNamedMetadata(meta_id))
        << "File " << FLAGS_bc_in << " doesn't have the right format for this "
        << "architecture/OS combination. Make sure to produce this file with "
        << "cfg_to_bc and the same --arch and --os specified.";

    return module;
  }
}

}  // namespace
}  // namespace mcsema

extern "C" int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  // GFlags will have removed everything that it recognized from argc/argv.
  llvm::cl::ParseCommandLineOptions(argc, argv, "McSema CFG to LLVM");

  CHECK(!FLAGS_os.empty())
      << "Need to specify a target operating system with --os.";

  CHECK(!FLAGS_source_arch.empty())
      << "Need to specify a source architecture with --source_arch.";

  CHECK(!FLAGS_target_arch.empty())
      << "Need to specify a target architecture with --target_arch.";

  CHECK(!FLAGS_cfg.empty())
      << "Must specify CFG file with --cfg.";

  CHECK(!FLAGS_bc_out.empty())
      << "Please specify an output bitcode file with --bc_out.";

  auto source_arch_name = mcsema::Arch::GetName(FLAGS_source_arch);
  auto source_arch = mcsema::Arch::Create(source_arch_name);

  //auto target_arch = mcsema::Arch::Create(FLAGS_target_arch);
  auto cfg = mcsema::ReadCFG(FLAGS_cfg);
  auto module = mcsema::CreateOrLoadModule(source_arch, FLAGS_bc_in);

  mcsema::Translator lifter(source_arch, module);
  lifter.LiftCFG(cfg);

  mcsema::StoreModuleToFile(module, FLAGS_bc_out);

  delete cfg;
  delete source_arch;

  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

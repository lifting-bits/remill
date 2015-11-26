/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <fstream>
#include <system_error>

#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/ToolOutputFile.h>

#include "mcsema/BC/Translator.h"
#include "mcsema/Arch/Arch.h"
#include "mcsema/CFG/CFG.h"

// TODO(pag): Support separate source and target architectures?
DEFINE_string(arch, "", "Architecture of the code being translated. Valid "
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
                                        std::string file_name) {
  const std::string meta_id = "mcsema:" + FLAGS_arch + ":" + FLAGS_os;

  if (file_name.empty()) {
    auto module = arch->CreateModule();

    // Set a specific flag. This will provide a poor man's way of
    // verifying that an input module to `cfg_to_bc` is of the correct
    // architecture.
    module->getOrInsertNamedMetadata(meta_id);
    return module;

  } else {
    // Parse a user-provided bitcode file.
    llvm::SMDiagnostic err;
    auto mod_ptr = llvm::parseIRFile(file_name, err, llvm::getGlobalContext());
    auto module = mod_ptr.get();
    mod_ptr.release();

    CHECK(nullptr != module)
        << "Unable to parse module file: " << file_name;

    CHECK(nullptr != module->getNamedMetadata(meta_id))
        << "File " << FLAGS_bc_in << " doesn't have the right format for this "
        << "architecture/OS combination. Make sure to produce this file with "
        << "cfg_to_bc and the same --arch and --os specified.";

    return module;
  }
}

// Write the LLVM module to a bitcode file.
static void SaveModuleToFile(const llvm::Module *mod, std::string file_name) {
  std::error_code ec;
  llvm::tool_output_file bc(file_name.c_str(), ec, llvm::sys::fs::F_None);

  CHECK(!ec)
      << "Unable to open output bitcode file for writing: " << file_name;

  llvm::WriteBitcodeToFile(mod, bc.os());
  bc.keep();

  CHECK(!ec)
      << "Error writing bitcode to file: " << file_name;
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

  CHECK(!FLAGS_arch.empty())
      << "Need to specify a source architecture with --arch.";

  CHECK(!FLAGS_cfg.empty())
      << "Must specify CFG file with --cfg.";

  CHECK(!FLAGS_bc_out.empty())
      << "Please specify an output bitcode file with --bc_out.";

  auto arch = mcsema::Arch::Create(FLAGS_arch);
  auto cfg = mcsema::ReadCFG(FLAGS_cfg);
  auto module = mcsema::CreateOrLoadModule(arch, FLAGS_bc_in);

  mcsema::Translator lifter(arch, module);
  lifter.LiftCFG(cfg);

  mcsema::SaveModuleToFile(module, FLAGS_bc_out);

  delete cfg;
  delete arch;

  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

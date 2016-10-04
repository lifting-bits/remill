/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h>

#include <llvm/IR/LLVMContext.h>
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

#ifndef BUILD_SEMANTICS_DIR
# error "Macro `BUILD_SEMANTICS_DIR` must be defined."
# define BUILD_SEMANTICS_DIR
#endif  // BUILD_SEMANTICS_DIR

#ifndef INSTALL_SEMANTICS_DIR
# error "Macro `INSTALL_SEMANTICS_DIR` must be defined."
# define INSTALL_SEMANTICS_DIR
#endif  // INSTALL_SEMANTICS_DIR


// TODO(pag): Support separate source and target architectures?
DEFINE_string(arch_in, "", "Architecture of the code being translated. "
                           "Valid architectures: x86, amd64 (with or without "
                           "`_avx` or `_avx512` appended).");

DEFINE_string(arch_out, "", "Architecture of the target architecture on "
                            "which the translated code will run. "
                            "Valid architectures: x86, amd64 (with or without "
                            "`_avx` or `_avx512` appended).");

DEFINE_string(os_in, REMILL_OS, "Source OS. Valid OSes: linux, mac.");
DEFINE_string(os_out, REMILL_OS, "Target OS. Valid OSes: linux, mac.");

DEFINE_string(cfg, "", "Path to the CFG file containing code to lift.");

DEFINE_string(bc_in, "", "Input bitcode file into which code will "
                         "be lifted. This should either be a semantics file "
                         "associated with `--arch_in`, or it should be "
                         "a bitcode file produced by `remill-lift`. Chaining "
                         "bitcode files produces by `remill-lift` can be "
                         "used to iteratively link in libraries to lifted "
                         "code.");

DEFINE_string(bc_out, "", "Output bitcode file name.");

namespace {

static const char *gSearchPaths[] = {
    // Derived from the build.
    BUILD_SEMANTICS_DIR "\0",
    INSTALL_SEMANTICS_DIR "\0",

    // Linux.
    "/usr/local/share/remill/semantics/",
    "/usr/share/remill/semantics/",

    // Other?
    "/opt/local/share/remill/semantics/",
    "/opt/share/remill/semantics/",
    "/opt/remill/semantics/",

    // FreeBSD.
    "/usr/share/compat/linux/remill/semantics",
    "/usr/local/share/compat/linux/remill/semantics",
    "/compat/linux/usr/share/remill/semantics",
    "/compat/linux/usr/local/share/remill/semantics",
};

static bool CheckPath(const std::string &path) {
  return !path.empty() && !access(path.c_str(), F_OK);
}

static std::string InputBCPath(void) {
  if (!FLAGS_bc_in.empty()) {
    return FLAGS_bc_in;
  }

  for (auto path : gSearchPaths) {
    std::stringstream ss;
    if ('/' != path[0]) {
      ss << "./";
    }
    ss << path;
    if ('/' != path[strlen(path) - 1]) {
      ss << "/";
    }
    ss << FLAGS_arch_in << ".bc";
    auto sem_path = ss.str();
    if (CheckPath(sem_path)) {
      return sem_path;
    }
  }

  LOG(FATAL) << "Cannot deduce path to " << FLAGS_arch_in
             << " semantics bitcode file.";
}

}  // namespace

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  // GFlags will have removed everything that it recognized from argc/argv.
  llvm::cl::ParseCommandLineOptions(argc, argv, "Remill: Lift CFG to LLVM");

  if (FLAGS_os_in.empty()) {
    std::cerr
        << "Need to specify a source operating system with --os_in."
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_os_out.empty()) {
    std::cerr
        << "Need to specify a target operating system with --os_out."
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_arch_in.empty()) {
    std::cerr
        << "Need to specify a source architecture with --arch_in."
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_arch_out.empty()) {
    std::cerr
        << "Need to specify a target architecture with --arch_out."
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_cfg.empty()) {
    std::cerr
        << "Must specify CFG file with --cfg."
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_bc_out.empty()) {
    std::cerr
        << "Please specify an output bitcode file with --bc_out."
        << std::endl;
    return EXIT_FAILURE;
  }

  auto source_os = remill::GetOSName(FLAGS_os_in);
  auto target_os = remill::GetOSName(FLAGS_os_out);

  auto source_arch = remill::Arch::Create(source_os, FLAGS_arch_in);
  auto target_arch = remill::Arch::Create(target_os, FLAGS_arch_out);

  if (!CheckPath(FLAGS_cfg)) {
    std::cerr
        << "Must specify valid path for `--cfg`. CFG file " << FLAGS_cfg
        << " cannot be opened."
        << std::endl;
    return EXIT_FAILURE;
  }

  FLAGS_bc_in = InputBCPath();
  if (!CheckPath(FLAGS_bc_in)) {
    std::cerr
        << "Must specify valid path for `--bc_in`. Bitcode file "
        << FLAGS_bc_in << " cannot be opened."
        << std::endl;
    return EXIT_FAILURE;
  }

  auto context = new llvm::LLVMContext;
  auto module = remill::LoadModuleFromFile(context, FLAGS_bc_in);
  target_arch->PrepareModule(module);

  remill::Translator lifter(source_arch, module);

  auto cfg = remill::ReadCFG(FLAGS_cfg);
  lifter.LiftCFG(cfg);

  remill::StoreModuleToFile(module, FLAGS_bc_out);

  delete cfg;
  delete source_arch;

  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}

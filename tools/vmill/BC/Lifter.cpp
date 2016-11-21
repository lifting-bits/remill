/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Util.h"
#include "remill/CFG/CFG.h"

#include "tools/vmill/BC/Lifter.h"

DECLARE_string(workspace);
DECLARE_string(arch);
DECLARE_string(os);

namespace remill {
namespace vmill {
namespace {

// Run a server process.
static pid_t RunServer(const char * const *args) {
  DLOG(INFO)
      << "Launching " << args[0] << " server.";

  if (auto pid = fork()) {
    CHECK(-1 != pid)
        << "Unable to fork to run remill-lift as a server: "
        << strerror(errno);
    return pid;

  } else {
    CHECK(!execvp(args[0], const_cast<char * const *>(args)))
        << "Unable to execute " << args[0];
    return -1;
  }
}

}  // namespace

Lifter::Lifter(pid_t lift_pid_, pid_t opt_pid_)
    : lift_pid(lift_pid_),
      opt_pid(opt_pid_) {}

Lifter *Lifter::Create(void) {
  DLOG(INFO)
      << "Creating CFG lifting and optimization pipeline.";

  auto cfg_to_lift = FLAGS_workspace + "/cfg_to_lift";
  unlink(cfg_to_lift.c_str());  // Remove it if it exists.
  CHECK(!mknod(cfg_to_lift.c_str(), S_IFIFO | 0666, 0))
      << "Unable to create FIFO " << cfg_to_lift
      << "for CFG files: " << strerror(errno);

  auto lifted_bitcode = FLAGS_workspace + "/lifted_bitcode";
  unlink(lifted_bitcode.c_str());  // Remove it if it exists.
  CHECK(!mknod(lifted_bitcode.c_str(), S_IFIFO | 0666, 0))
      << "Unable to create FIFO " << lifted_bitcode
      << " for CFG files: " << strerror(errno);

  auto optimized_bitcode = FLAGS_workspace + "/optimized_bitcode";
  unlink(optimized_bitcode.c_str());  // Remove it if it exists.
  CHECK(!mknod(optimized_bitcode.c_str(), S_IFIFO | 0666, 0))
      << "Unable to create FIFO " << optimized_bitcode
      << " for CFG files: " << strerror(errno);

  const char *lift_args[] = {
      "remill-lift",
      "--arch_in", FLAGS_arch.c_str(),
      "--os_in", FLAGS_os.c_str(),
      "--os_out", "linux",  // vmill is pretty Linux-specific.
      "--cfg", cfg_to_lift.c_str(),
      "--bc_out", lifted_bitcode.c_str(),
      "--server",
      nullptr
  };

  const char *opt_args[] = {
      "remill-opt",
      "--bc_in", lifted_bitcode.c_str(),
      "--bc_out", optimized_bitcode.c_str(),
      "--strip",
      "--server",
      nullptr
  };

  return new Lifter(RunServer(lift_args), RunServer(opt_args));
}

Lifter::~Lifter(void) {
  DLOG(INFO)
      << "Killing remill-lift server with PID " << lift_pid;
  kill(lift_pid, SIGKILL);

  DLOG(INFO)
      << "Killing remill-opt server with PID " << opt_pid;
  kill(opt_pid, SIGKILL);
}

llvm::Module *Lifter::LiftIntoContext(cfg::Module *code,
                                      llvm::LLVMContext *context) {
  DLOG(INFO)
      << "About to lift CFG with " << code->blocks_size()
      << " basic blocks into bitcode";

  auto cfg_file = FLAGS_workspace + "/cfg_to_lift";
  auto bc_file = FLAGS_workspace + "/optimized_bitcode";

  auto cfg_fd = open(cfg_file.c_str(), O_WRONLY, 0666);
  CHECK(-1 != cfg_fd)
      << "Could not open " << cfg_file << " for writing: " << strerror(errno);

  DLOG(INFO)
      << "Sending CFG file to remill-lift.";

  code->SerializeToFileDescriptor(cfg_fd);
  close(cfg_fd);

  DLOG(INFO)
      << "Waiting for lifted bitcode from remill-opt.";

  return remill::LoadModuleFromFile(context, bc_file);
}

void Lifter::ForEachLiftedFunctionInModule(
    llvm::Module *module,
    LiftedFunctionCallback on_each_function) {
  auto table_var = module->getGlobalVariable("__remill_indirect_blocks");
  auto init = table_var->getInitializer();
  auto module_id = module->getModuleIdentifier();

  CHECK(!llvm::isa<llvm::ConstantAggregateZero>(init))
      << "Bitcode file " << module_id << " does not contain any "
      << "lifted subroutines!";

  auto entries = llvm::dyn_cast<llvm::ConstantArray>(init);
  DLOG(INFO)
      << "Indirect block table from " << module_id << " has "
      << (entries->getNumOperands() - 1 /* Sentinel */) << " entries.";

  // Read in the addressable blocks from the indirect blocks table. Below,
  // the translator marks every decoded basic block in the CFG as being
  // addressable, so we expect all of them to be in the table.
  for (const auto &entry : entries->operands()) {
    if (llvm::isa<llvm::ConstantAggregateZero>(entry)) {
      continue;  // Sentinel.
    }

    auto indirect_block = llvm::dyn_cast<llvm::ConstantStruct>(entry.get());
    auto block_pc = llvm::dyn_cast<llvm::ConstantInt>(
        indirect_block->getOperand(0))->getZExtValue();
    auto lifted_func = llvm::dyn_cast<llvm::Function>(
        indirect_block->getOperand(1));

    on_each_function(block_pc, lifted_func);
  }
}

}  // namespace vmill
}  // namespace remill

/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <sstream>

#include <llvm/IR/Module.h>

#include "mcsema/Arch/X86/Arch.h"
#include "mcsema/Arch/X86/Instr.h"

#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DEFINE_bool(with_x86_avx, false, "Enable AVX support.");
DEFINE_bool(with_x86_avx512, false, "Enable AVX512 support.");

namespace mcsema {
namespace x86 {
namespace {

const xed_state_t kXEDState32 = {
    XED_MACHINE_MODE_LONG_COMPAT_32,
    XED_ADDRESS_WIDTH_32b};

const xed_state_t kXEDState64 = {
    XED_MACHINE_MODE_LONG_64,
    XED_ADDRESS_WIDTH_64b};

}  // namespace

Arch::Arch(unsigned address_size_)
    : ::mcsema::Arch(address_size_) {
  CHECK(32 == address_size || 64 == address_size)
      << "Unsupported x86 architecture: " << address_size << " bits";

  VLOG(1) << "Initializing XED tables for " << address_size << "-bit code";
  xed_tables_init();
}

Arch::~Arch(void) {}

// Decode an instruction and invoke a visitor with the decoded instruction.
void Arch::Decode(
    const cfg::Instr &instr,
    std::function<void(::mcsema::Instr &)> visitor) const {

  xed_decoded_inst_t xedd;
  auto dstate = (32 == address_size) ? &kXEDState32 : &kXEDState64;
  auto num_bytes = instr.size();
  auto bytes = reinterpret_cast<const uint8_t *>(instr.bytes().data());
  xed_decoded_inst_zero_set_mode(&xedd, dstate);
  xed_decoded_inst_set_input_chip(&xedd, XED_CHIP_INVALID);
  auto err = xed_decode(&xedd, bytes, num_bytes);

  CHECK(XED_ERROR_NONE == err)
      << "Unable to decode instruction with error: "
      << xed_error_enum_t2str(err);

  CHECK(xed_decoded_inst_get_length(&xedd) == num_bytes)
      << "Size of decoded instruction (" << xed_decoded_inst_get_length(&xedd)
      << ") doesn't match input instruction size (" << num_bytes << ")";

  ::mcsema::x86::Instr arch_instr(&instr, &xedd);
  visitor(arch_instr);
}

// Creates an LLVM module object for the lifted code. This module is based on
// an arch-specific template, found in the `State.inc` file.
llvm::Module *Arch::CreateModule(void) const {
  std::stringstream module_file_ss;

  // TODO(pag): Eventually make this relative to the build/install directory,
  //            such that it works in both cases.
  module_file_ss << MCSEMA_DIR "/generated/Arch/X86/Semantics_";
  module_file_ss << (64 == address_size ? "amd64" : "x86");

  // Select a bitcode file with specific features.
  if (FLAGS_with_x86_avx512) {
    module_file_ss << "_avx512.bc";
  } else if (FLAGS_with_x86_avx) {
    module_file_ss << "_avx.bc";
  } else {
    module_file_ss << ".bc";
  }

  auto module_file = module_file_ss.str();
  LOG(INFO) << "Using " << module_file << " as the base bitcode module.";

  return LoadModuleFromFile(module_file);
}

}  // namespace x86
}  // namespace mcsema


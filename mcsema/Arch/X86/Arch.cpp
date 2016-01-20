/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <sstream>

#include <llvm/IR/Module.h>

#include "mcsema/Arch/X86/Arch.h"
#include "mcsema/Arch/X86/Instr.h"

#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace x86 {
namespace {

const xed_state_t kXEDState32 = {
    XED_MACHINE_MODE_LONG_COMPAT_32,
    XED_ADDRESS_WIDTH_32b};

const xed_state_t kXEDState64 = {
    XED_MACHINE_MODE_LONG_64,
    XED_ADDRESS_WIDTH_64b};

static bool InitXED(void) {
  VLOG(1) << "Initializing XED tables";
  xed_tables_init();
  return true;
}

[[gnu::used]]
static bool gInitXED = InitXED();

}  // namespace

Arch::~Arch(void) {}

// Decode an instruction and invoke a visitor with the decoded instruction.
void Arch::Decode(
    const cfg::Instr &instr,
    std::function<void(::mcsema::Instr &)> visitor) const {

  CHECK(gInitXED)
      << "XED must be initialized before instructions can be decoded.";

  xed_decoded_inst_t xedd;
  auto dstate = kArchX86 == arch_name ? &kXEDState32 : &kXEDState64;
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

// Converts an LLVM module object to have the right triple / data layout
// information for the target architecture.
llvm::Module *Arch::ConvertModule(llvm::Module *mod) const {
  std::string dl;
  std::string triple;
  switch (os_name) {
    case kOSInvalid:
      LOG(FATAL) << "Cannot convert module for an unrecognized operating system.";
      return nullptr;
    case kOSLinux:
      if (kArchAMD64 == arch_name) {
        dl = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
        triple = "x86_64-unknown-linux-gnu";
      } else {
        dl = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128";
        triple = "i386-unknown-linux-gnu";
      }
      break;
    case kOSMacOSX:
      if (kArchAMD64 == arch_name) {
        dl = "e-m:o-i64:64-f80:128-n8:16:32:64-S128";
        triple = "x86_64-apple-macosx10.10.0";
      } else {
        dl = "e-m:o-p:32:32-f64:32:64-f80:128-n8:16:32-S128";
        triple = "i386-apple-macosx10.10.0";
      }
      break;
  }
  mod->setDataLayout(dl);
  mod->setTargetTriple(triple);
  return mod;
}

}  // namespace x86
}  // namespace mcsema


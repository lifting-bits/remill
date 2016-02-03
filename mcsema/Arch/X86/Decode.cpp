/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "mcsema/Arch/X86/Arch.h"
#include "mcsema/Arch/X86/Decode.h"
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

// Force the XED tables to be initialized.
[[gnu::used]]
static bool gInitXED = InitXED();

}  // namespace

xed_decoded_inst_t DecodeInstruction(const cfg::Instr &instr,
                                     ArchName arch_name) {
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

  return xedd;
}

}  // namespace x86
}  // namespace mcsema

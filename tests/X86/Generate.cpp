/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "remill/Arch/X86/XED.h"
#include "remill/CFG/CFG.h"

#include "tests/X86/Test.h"

#ifdef __APPLE__
# define SYMBOL_PREFIX "_"
#else
# define SYMBOL_PREFIX ""
#endif

DEFINE_string(cfg_out, "/dev/stdout",
              "Name of the file in which to place the generated CFG protobuf.");

namespace {

#if 32 == ADDRESS_SIZE_BITS
const xed_state_t kXEDState = {
    XED_MACHINE_MODE_LONG_COMPAT_32,
    XED_ADDRESS_WIDTH_32b};
#else
const xed_state_t kXEDState = {
    XED_MACHINE_MODE_LONG_64,
    XED_ADDRESS_WIDTH_64b};
#endif

// Return the length of an instruction starting at `addr`.
unsigned InstructionLength(const uint8_t *bytes, unsigned num_bytes) {
  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero_set_mode(&xedd, &kXEDState);
  xed_decoded_inst_set_input_chip(&xedd, XED_CHIP_HASWELL);
  auto err = xed_decode(&xedd, bytes, num_bytes);

  CHECK(XED_ERROR_NONE == err)
      << "Unable to decode instruction with error: "
      << xed_error_enum_t2str(err);

  auto iclass = xed_decoded_inst_get_iclass(&xedd);

  CHECK(XED_ICLASS_INVALID != iclass)
      << "Unable to decode instruction.";

  DLOG(INFO)
      << "Decoded: " << xed_iclass_enum_t2str(iclass);

  return xed_decoded_inst_get_length(&xedd);
}

// Decode a test and add it as a basic block to the module.
//
// TODO(pag): Eventually handle control-flow.
static void AddFunctionToModule(remill::cfg::Module *module,
                                const test::TestInfo &test) {
  const char *test_name = reinterpret_cast<const char *>(test.test_name);

  std::stringstream ss;
  ss << SYMBOL_PREFIX << test_name;

  DLOG(INFO) << "Adding named exported block for: " << test_name;

  auto func = module->add_named_blocks();
  func->set_address(test.test_begin);
  func->set_name(ss.str());
  func->set_visibility(remill::cfg::EXPORTED);

  DLOG(INFO) << "Adding block for: " << test_name;

  auto block = module->add_blocks();
  block->set_address(test.test_begin);

  auto addr = test.test_begin;
  while (addr < test.test_end) {
    auto bytes = reinterpret_cast<const uint8_t *>(addr);
    auto ilen = InstructionLength(
        bytes, std::min<unsigned>(
            test::kMaxInstrLen,
            static_cast<unsigned>(test.test_end - addr)));

    auto instr = block->add_instructions();
    instr->set_bytes(bytes, ilen);
    instr->set_address(addr);
    addr += ilen;
  }

  module->add_referenced_blocks(test.test_end);
}

}  // namespace

extern "C" int main(int argc, char *argv[]) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  xed_tables_init();

  DLOG(INFO) << "Generating tests.";

  auto module = new remill::cfg::Module;

  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
    AddFunctionToModule(module, test);
  }

  std::ofstream out(FLAGS_cfg_out);

  CHECK(out.is_open())
      << "Unable to open file: " << FLAGS_cfg_out;

  DLOG(INFO) << "Serializing CFG to " << FLAGS_cfg_out;
  module->SerializeToOstream(&out);
  DLOG(INFO) << "Done.";

  return 0;
}

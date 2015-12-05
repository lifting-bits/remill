/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "mcsema/Arch/X86/XED.h"
#include "mcsema/CFG/CFG.h"

#include "tests/X86/Test.h"

#ifdef __APPLE__
# define SYMBOL_PREFIX "_"
#else
# define SYMBOL_PREFIX ""
#endif

DEFINE_string(cfg_out, "/dev/stdout",
              "Name of the file in which to place the generated CFG protobuf.");

namespace test {
namespace {

#if 32 == ADDRESS_WITH_BITS
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

  LOG(INFO)
      << "Decoded: " << xed_iclass_enum_t2str(iclass);

  return xed_decoded_inst_get_length(&xedd);
}

}  // namespace

// Decode a test and add it as a basic block to the module.
//
// TODO(pag): Eventually handle control-flow.
static void AddFunctionToModule(mcsema::cfg::Module *module,
                                const TestInfo &test) {
  uintptr_t test_begin = test.test_begin;
  uintptr_t test_end = test.test_end;

  const char *test_name = reinterpret_cast<const char *>(
      static_cast<uintptr_t>(test.test_name));

  std::stringstream ss;
  ss << SYMBOL_PREFIX << "X86_LIFTED_" << test_name;

  LOG(INFO) << "Adding function for: " << test_name;

  auto func = module->add_functions();
  func->set_address(test_begin);
  func->set_name(ss.str());
  func->set_is_exported(true);
  func->set_is_imported(false);
  func->set_is_weak(false);

  LOG(INFO) << "Adding block for: " << test_name;

  auto block = module->add_blocks();
  block->set_address(test_begin);

  while (test_begin < test_end) {
    auto bytes = reinterpret_cast<const uint8_t *>(test_begin);
    auto ilen = InstructionLength(
        bytes, std::min<unsigned>(kMaxInstrLen, test_end - test_begin));

    auto instr = block->add_instructions();
    instr->set_address(test_begin);
    instr->set_size(ilen);
    instr->set_bytes(bytes, ilen);
    test_begin += ilen;
  }
}

}  // namespace

extern "C" int main(int argc, char *argv[]) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  xed_tables_init();

  LOG(INFO) << "Generating tests.";

  auto module = new mcsema::cfg::Module;
  module->set_binary_path(__FILE__);

  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
    test::AddFunctionToModule(module, test);
  }

  std::ofstream out(FLAGS_cfg_out);

  CHECK(out.is_open())
      << "Unable to open file: " << FLAGS_cfg_out;

  LOG(INFO) << "Serializing CFG to " << FLAGS_cfg_out;
  module->SerializeToOstream(&out);
  LOG(INFO) << "Done.";

  return 0;
}

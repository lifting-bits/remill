/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_BC_MANAGER_H_
#define TOOLS_VMILL_BC_MANAGER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace llvm {
class Function;
class LLVMContext;
class Module;
}  // namespace llvm
namespace remill {

class Arch;
class BlockHasher;

namespace vmill {

using CodeVersion = uint64_t;

class AddressSpacePtr;
class BitcodeSegment;
class Context;
class Decoder;
class Translator;

// Manages all lifted bitcode.
class BitcodeManager {
 public:
  ~BitcodeManager(void);

  static std::unique_ptr<BitcodeManager> Create(llvm::LLVMContext *context_);

  std::shared_ptr<llvm::Module> GetModuleWithLiftedBlock(
      const AddressSpacePtr &memory, uint64_t pc);

 private:
  BitcodeManager(void) = delete;

  explicit BitcodeManager(llvm::LLVMContext *context_);

  // LLVM context that manages all modules.
  llvm::LLVMContext *context;

  // Reads bytes from a process' memory, and uses the `arch`-specific
  // instruction decoder to produce a CFG data structure. The CFG organizes
  // machine code instructions into basic blocks. The CFG is sent to the
  // `translator`, which lifts the basic blocks into LLVM bitcode (by using
  // Remill's lifter).
  const std::unique_ptr<Decoder> decoder;

  // Maps code versions to bitcode segments.
  std::unordered_map<CodeVersion, std::unique_ptr<BitcodeSegment>> segments;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_BC_MANAGER_H_

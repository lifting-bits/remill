/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_AUTOANALYSIS_H_
#define REMILL_ARCH_X86_AUTOANALYSIS_H_

#include <unordered_map>
#include <vector>

#include "remill/CFG/AutoAnalysis.h"

namespace remill {

enum ArchName : unsigned;

namespace x86 {

struct BasicBlockRegs;
struct Function;

class RegisterAnalysis : public AutoAnalysis {
 public:
  inline explicit RegisterAnalysis(ArchName arch_name_)
      : arch_name(arch_name_),
        live_anywhere(~0U) {}

  virtual void AddBlock(const cfg::Block &block) override;
  virtual void AddFunction(const cfg::Function &block) override;
  virtual void InitWorkList(AnalysisWorkList &work_list) override;
  virtual void AnalyzeBlock(AnalysisWorkItem item,
                            AnalysisWorkList &work_list) override;
  virtual void Finalize(void) override;

  const ArchName arch_name;

  // Maps basic blocks to information about their flags, regs, and a graph
  // of info about their predecessors and successors.
  std::unordered_map<uint64_t, BasicBlockRegs *> blocks;

 private:
  RegisterAnalysis(void) = delete;

  uint32_t LiveFlags(uint64_t pc);
  uint16_t LiveRegs(uint64_t pc);

  uint32_t live_anywhere;

  // Maps basic block addresses to the functions in which they are contained.
  std::unordered_map<uint64_t, Function *> functions;

  // Given a block B ending in a function call, this maps
  // Addr(B) -> Addr(B)+Size(B) so that we can connect blocks before/after
  // function calls into logical functions.
  std::unordered_map<uint64_t, uint64_t> ret_blocks;
};

}  // namespace x86
}  // namespace remill

#endif  // REMILL_ARCH_X86_AUTOANALYSIS_H_

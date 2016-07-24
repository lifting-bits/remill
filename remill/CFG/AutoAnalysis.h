/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_CFG_AUTOANALYSIS_H_
#define REMILL_CFG_AUTOANALYSIS_H_

#include <cstdint>
#include <set>

namespace remill {
namespace cfg {
class Block;
class Function;
}  // namespace cfg

struct AnalysisWorkItem {
  uint64_t order;
  uint64_t pc;

  // Ordered so that
  inline bool operator<(const AnalysisWorkItem &that) const {
    if (order > that.order) return true;
    if (order == that.order) return pc > that.pc;
    return false;
  }
};

using AnalysisWorkList = std::set<AnalysisWorkItem>;

// Performs an analysis of the basic blocks of
class AutoAnalysis {
 public:
  virtual ~AutoAnalysis(void);
  virtual void AddBlock(const cfg::Block &block) = 0;
  virtual void AddFunction(const cfg::Function &block) = 0;
  virtual void InitWorkList(AnalysisWorkList &work_list) = 0;
  virtual void AnalyzeBlock(AnalysisWorkItem item,
                            AnalysisWorkList &work_list) = 0;
  virtual void Finalize(void) = 0;
};

}  // namespace remill

#endif  // REMILL_CFG_AUTOANALYSIS_H_

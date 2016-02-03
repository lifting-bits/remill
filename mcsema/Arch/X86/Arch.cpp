/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <sstream>

#include <llvm/IR/Module.h>

#include "mcsema/Arch/X86/Arch.h"
#include "mcsema/Arch/X86/Decode.h"
#include "mcsema/Arch/X86/Translator.h"
#include "mcsema/BC/Translator.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace x86 {

X86Arch::X86Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_)
    : Arch(os_name_, arch_name_, address_size_),
      analysis(arch_name_) {}

X86Arch::~X86Arch(void) {}

// Converts an LLVM module object to have the right triple / data layout
// information for the target architecture.
llvm::Module *X86Arch::PrepareModule(llvm::Module *mod) const {
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

// Decode an instruction and lift it into a basic block.
InstructionLiftAction X86Arch::LiftInstructionIntoBlock(
    const Translator &translator,
    const cfg::Block &block, const cfg::Instr &instr,
    llvm::BasicBlock *B) const {

  const auto xedd = DecodeInstruction(instr, arch_name);
  InstructionTranslator trans(analysis, block, instr, xedd);
  if (trans.LiftIntoBlock(translator, B)) {
    return kLiftNextInstruction;
  } else {
    return kTerminateBlock;
  }
}

// Return an arch-specific CFG analyzer.
AutoAnalysis &X86Arch::CFGAnalyzer(void) const {
  return analysis;
}

}  // namespace x86
}  // namespace mcsema


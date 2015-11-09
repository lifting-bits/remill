/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_INSTR_H_
#define MCSEMA_ARCH_X86_INSTR_H_

#include <vector>

#include "mcsema/Arch/Instr.h"
#include "mcsema/Arch/X86/XED.h"

namespace llvm {
class Context;
class Function;
class Type;
}  // namespace llvm

namespace mcsema {
namespace x86 {

class Arch;

class Instr : public ::mcsema::Instr {
 public:
  Instr(const cfg::Instr *, const struct xed_decoded_inst_s *xedd_);
  virtual ~Instr(void);

  virtual bool Lift(const BlockMap &blocks, llvm::BasicBlock *B_) override;

 private:
  void LiftPC(void);
  void LiftGeneric(void);
  void LiftConditionalBranch(const BlockMap &blocks);
  void LiftOperand(unsigned op_num);
  void LiftMemory(const xed_operand_t *xedo, unsigned op_num);
  void LiftImmediate(xed_operand_enum_t op_name);
  void LiftRegister(const xed_operand_t *xedo);
  void LiftBranchDisplacement(void);

  bool IsBranch(void) const;

  bool IsFunctionCall(void) const;
  bool IsFunctionReturn(void) const;

  bool IsDirectFunctionCall(void) const;
  bool IsIndirectFunctionCall(void) const;

  bool IsJump(void) const;
  bool IsDirectJump(void) const;
  bool IsIndirectJump(void) const;

  bool IsSystemCall(void) const;
  bool IsSystemReturn(void) const;

  bool IsInterruptCall(void) const;
  bool IsInterruptReturn(void) const;

  bool IsError(void) const;

  uintptr_t NextPC(void) const;
  uintptr_t TargetPC(void) const;

  const xed_decoded_inst_t * const xedd;
  const xed_inst_t * const xedi;
  const xed_iclass_enum_t iclass;

  llvm::BasicBlock *B;
  llvm::Function *F;
  llvm::Module *M;
  llvm::LLVMContext *C;

  std::vector<llvm::Value *> args;
  std::vector<llvm::Instruction *> append_instrs;
};

}  // namespace x86
}  // namespace mcsema

#endif  // MCSEMA_ARCH_X86_INSTR_H_

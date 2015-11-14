/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_INSTR_H_
#define MCSEMA_ARCH_INSTR_H_

namespace llvm {
class BasicBlock;
class Value;
}  // namespace llvm
namespace mcsema {
namespace cfg {
class Instr;
}  // namespace cfg

class BlockMap;
class Intrinsic;

class Instr {
 public:
  Instr(const cfg::Instr *instr_);

  virtual ~Instr(void);

  // Lift an instruction. If the lifter returns `false` then lifting of the
  // block has completed.
  //
  // TODO(pag): I'm not pleased with this interface.
  virtual bool Lift(const Intrinsic *intrinsic, const BlockMap &blocks,
                    llvm::BasicBlock *B) = 0;

 protected:
  const cfg::Instr * const instr;
};

}  // namespace mcsema

#endif  // MCSEMA_ARCH_INSTR_H_

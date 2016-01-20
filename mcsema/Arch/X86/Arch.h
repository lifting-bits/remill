/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_ARCH_H_
#define MCSEMA_ARCH_X86_ARCH_H_

#include "mcsema/Arch/Arch.h"

namespace mcsema {
namespace x86 {

typedef ::mcsema::Instr ArchInstr;

class Arch : public ::mcsema::Arch {
  public:

    virtual ~Arch(void);

    virtual void Decode(
        const cfg::Instr &instr,
        std::function<void(::mcsema::Instr &)> visitor) const override;

    virtual llvm::Module *ConvertModule(llvm::Module *mod) const override;

  protected:
    friend class ::mcsema::Arch;

    using ::mcsema::Arch::Arch;

  private:
    Arch(void) = delete;
};

}  // namespace x86
}  // namespace mcsema

#endif  // MCSEMA_ARCH_X86_ARCH_H_


#include "../Arch.h"

#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/Attributes.h"
#include "remill/BC/Compat/DebugInfo.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

namespace remill {
namespace sleighthumb2 {

class SleighThumb2Arch : public Arch {};

}  // namespace sleighthumb2
Arch::ArchPtr Arch::GetSleighThumb2(llvm::LLVMContext *context_,
                                    OSName os_name_, ArchName arch_name_) {
  return std::make_unique<sleighthumb2::SleighThumb2Arch>(context_, os_name_,
                                                          arch_name_);
}

}  // namespace remill

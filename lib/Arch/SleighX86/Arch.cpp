#include "../Arch.h"

#include <glog/logging.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

namespace remill {
namespace sleigh {

class SleighX86Arch final : public Arch {
 public:
  SleighX86Arch(llvm::LLVMContext *context_, OSName os_name_,
                ArchName arch_name_)
      : Arch(context_, os_name_, arch_name_) {}

  virtual ~SleighX86Arch(void) = default;

  // TODO(alex): Generate these from SLEIGH
  std::string_view StackPointerRegisterName(void) const final {
    if (IsX86()) {
      return "ESP";
    } else {
      return "RSP";
    }
  }

  std::string_view ProgramCounterRegisterName(void) const final {
    if (IsX86()) {
      return "EIP";
    } else {
      return "RIP";
    }
  }

  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst) const final {
    return true;
  }


  uint64_t MinInstructionAlign(void) const final {
    return 1;
  }

  uint64_t MinInstructionSize(void) const final {
    return 1;
  }

  uint64_t MaxInstructionSize(bool) const final {
    return 15;
  }

  llvm::CallingConv::ID DefaultCallingConv(void) const final {
    if (IsX86()) {
      switch (os_name) {
        case kOSInvalid:
        case kOSmacOS:
        case kOSLinux:
        case kOSWindows:
        case kOSSolaris: return llvm::CallingConv::C;  // cdecl.
      }
    } else {
      switch (os_name) {
        case kOSInvalid:
        case kOSmacOS:
        case kOSLinux:
        case kOSSolaris: return llvm::CallingConv::X86_64_SysV;
        case kOSWindows: return llvm::CallingConv::Win64;
      }
    }
  }

  llvm::Triple Triple(void) const final {
    auto triple = BasicTriple();
    switch (arch_name) {
      case kArchAMD64:
      case kArchAMD64_AVX:
      case kArchAMD64_AVX512: triple.setArch(llvm::Triple::x86_64); break;
      case kArchX86:
      case kArchX86_AVX:
      case kArchX86_AVX512: triple.setArch(llvm::Triple::x86); break;
      default:
        LOG(FATAL) << "Cannot get triple for non-x86 architecture "
                   << GetArchName(arch_name);
    }

    return triple;
  }

  llvm::DataLayout DataLayout(void) const final {
    std::string dl;
    switch (os_name) {
      case kOSInvalid:
        LOG(FATAL) << "Cannot convert module for an unrecognized OS.";
        break;

      case kOSLinux:
      case kOSSolaris:  // Probably.
        switch (arch_name) {
          case kArchAMD64:
          case kArchAMD64_AVX:
          case kArchAMD64_AVX512:
            dl = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
            break;
          case kArchX86:
          case kArchX86_AVX:
          case kArchX86_AVX512:
            dl = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128";
            break;
          default:
            LOG(FATAL) << "Cannot get data layout non-x86 architecture "
                       << GetArchName(arch_name);
            break;
        }
        break;

      case kOSmacOS:
        switch (arch_name) {
          case kArchAMD64:
          case kArchAMD64_AVX:
          case kArchAMD64_AVX512:
            dl = "e-m:o-i64:64-f80:128-n8:16:32:64-S128";
            break;
          case kArchX86:
          case kArchX86_AVX:
          case kArchX86_AVX512:
            dl = "e-m:o-p:32:32-f64:32:64-f80:128-n8:16:32-S128";
            break;
          default:
            LOG(FATAL) << "Cannot get data layout for non-x86 architecture "
                       << GetArchName(arch_name);
        }
        break;

      case kOSWindows:
        switch (arch_name) {
          case kArchAMD64:
          case kArchAMD64_AVX:
          case kArchAMD64_AVX512:
            dl = "e-m:w-i64:64-f80:128-n8:16:32:64-S128";
            break;
          case kArchX86:
          case kArchX86_AVX:
          case kArchX86_AVX512:
            dl = "e-m:x-p:32:32-i64:64-f80:32-n8:16:32-a:0:32-S32";
            break;
          default:
            LOG(FATAL) << "Cannot get data layout for non-x86 architecture "
                       << GetArchName(arch_name);
        }
        break;
    }

    return llvm::DataLayout(dl);
  }

  void PopulateRegisterTable(void) const final {}

  void PopulateBasicBlockFunction(llvm::Module *module,
                                  llvm::Function *bb_func) const final {}
};

}  // namespace sleigh

Arch::ArchPtr Arch::GetSleighX86(llvm::LLVMContext *context_, OSName os_name_,
                                 ArchName arch_name_) {
  return std::make_unique<sleigh::SleighX86Arch>(context_, os_name_,
                                                 arch_name_);
}


}  // namespace remill

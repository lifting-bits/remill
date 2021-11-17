#include "../Arch.h"

#include <glog/logging.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <sleigh/libsleigh.hh>

namespace remill {
namespace sleigh {

// Create a custom load image class that supports incrementally adding instructions to the buffer.
// On each instruction decode, we should call `AppendInstruction` and then proceed as usual.
class CustomLoadImage final : public LoadImage {
 public:
  CustomLoadImage(void) : LoadImage("nofile") {}

  void AppendInstruction(std::string_view instr_bytes) {
    image_buffer.append(instr_bytes);
  }

  void loadFill(unsigned char *ptr, int size, const Address &addr) override {
    uint8_t start = addr.getOffset();
    for (int i = 0; i < size; ++i) {
      uint64_t offset = start + i;
      ptr[i] = offset < image_buffer.size() ? image_buffer[i] : 0;
    }
  }

  std::string getArchType(void) const override {
    return "custom";
  }

  void adjustVma(long) override {}

 private:
  std::string image_buffer;
};

class PcodeHandler final : public PcodeEmit {
 public:
  void dump(const Address &, OpCode op, VarnodeData *outvar, VarnodeData *vars,
            int32_t isize) {}
};

class SleighX86Arch final : public Arch {
 public:
  SleighX86Arch(llvm::LLVMContext *context_, OSName os_name_,
                ArchName arch_name_)
      : Arch(context_, os_name_, arch_name_),
        engine(&image, &ctx),
        cur_addr(engine.getDefaultCodeSpace(), 0x0) {
    DocumentStorage storage;
    // TODO(alex): Once we have the SLA finding helpers in SLEIGH, replace this.
    Element *root =
        storage
            .openDocument(
                "/Users/tetsuo/Build/install/share/sleigh/Processors/x86/data/languages/x86-64.sla")
            ->getRoot();
    storage.registerTag(root);
    engine.initialize(storage);
  }

  virtual ~SleighX86Arch(void) = default;

  // TODO(alex): Query SLEIGH for these
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
    // TODO(alex): We'll need to do a lot of non-const stuff to decode. Just hack this until we get things working.
    return const_cast<SleighX86Arch *>(this)->DecodeInstructionImpl(
        address, instr_bytes, inst);
  }

  bool DecodeInstructionImpl(uint64_t address, std::string_view instr_bytes,
                             Instruction &inst) {
    // The SLEIGH engine will query this image when we try to decode an instruction. Append the bytes so SLEIGH has data to read.
    image.AppendInstruction(instr_bytes);

    // Now decode the instruction.
    int32_t instr_len = engine.oneInstruction(pcode_handler, cur_addr);
    cur_addr = cur_addr + instr_len;

    // TODO(alex): Figure out a way to populate the `remill::Instruction` with this information.

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

 private:
  CustomLoadImage image;
  ContextInternal ctx;
  Sleigh engine;
  Address cur_addr;
  PcodeHandler pcode_handler;
};

}  // namespace sleigh

Arch::ArchPtr Arch::GetSleighX86(llvm::LLVMContext *context_, OSName os_name_,
                                 ArchName arch_name_) {
  return std::make_unique<sleigh::SleighX86Arch>(context_, os_name_,
                                                 arch_name_);
}


}  // namespace remill

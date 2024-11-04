#include <glog/logging.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/X86/X86Base.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

namespace remill {


static const std::string_view kSPNames[] = {"RSP", "ESP"};
static const std::string_view kPCNames[] = {"RIP", "EIP"};

// Returns the name of the stack pointer register.
std::string_view X86ArchBase::StackPointerRegisterName(void) const {
  return kSPNames[IsX86()];
}

// Returns the name of the program counter register.
std::string_view X86ArchBase::ProgramCounterRegisterName(void) const {
  return kPCNames[IsX86()];
}


uint64_t X86ArchBase::MinInstructionAlign(const DecodingContext &) const {
  return 1;
}

uint64_t X86ArchBase::MinInstructionSize(const DecodingContext &) const {
  return 1;
}

uint64_t X86ArchBase::MaxInstructionSize(const DecodingContext &, bool) const {
  return 15;
}

llvm::CallingConv::ID X86ArchBase::DefaultCallingConv(void) const {
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

llvm::Triple X86ArchBase::Triple(void) const {
  auto triple = BasicTriple();
  switch (arch_name) {
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
    case kArchAMD64_SLEIGH: triple.setArch(llvm::Triple::x86_64); break;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
    case kArchX86_SLEIGH: triple.setArch(llvm::Triple::x86); break;
    default:
      LOG(FATAL) << "Cannot get triple for non-x86 architecture "
                 << GetArchName(arch_name);
  }

  return triple;
}

llvm::DataLayout X86ArchBase::DataLayout(void) const {
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
        case kArchAMD64_SLEIGH:
          dl = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
        case kArchX86_SLEIGH:
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
        case kArchAMD64_SLEIGH:
          dl = "e-m:o-i64:64-f80:128-n8:16:32:64-S128";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
        case kArchX86_SLEIGH:
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
        case kArchAMD64_SLEIGH:
          dl = "e-m:w-i64:64-f80:128-n8:16:32:64-S128";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
        case kArchX86_SLEIGH:
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

void X86ArchBase::PopulateRegisterTable(void) const {

  reg_by_offset.resize(sizeof(X86State));

  CHECK_NOTNULL(context);

  bool has_avx = false;
  bool has_avx512 = false;
  switch (arch_name) {
    case kArchX86_AVX:
    case kArchAMD64_AVX: has_avx = true; break;
    case kArchX86_AVX512:
    case kArchAMD64_AVX512:
      has_avx = true;
      has_avx512 = true;
      break;
    default: break;
  }

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u16 = llvm::Type::getInt16Ty(*context);
  auto u32 = llvm::Type::getInt32Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto f80 = llvm::Type::getX86_FP80Ty(*context);
  auto v128 = llvm::ArrayType::get(llvm::Type::getInt8Ty(*context), 128u / 8u);
  auto v256 = llvm::ArrayType::get(llvm::Type::getInt8Ty(*context), 256u / 8u);
  auto v512 = llvm::ArrayType::get(llvm::Type::getInt8Ty(*context), 512u / 8u);
  auto addr = llvm::Type::getIntNTy(*context, address_size);

#define OFFSET_OF(state, access) \
  (reinterpret_cast<uintptr_t>(&state.access) \
    - reinterpret_cast<uintptr_t>(&state))

#define REG(state, name, access, type) \
  AddRegister(#name, type, OFFSET_OF(state, access), nullptr)

#define SUB_REG(state, name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(state, access), #parent_reg_name)

#define SUB_REG64(state, name, access, type, parent_reg_name) \
  if (64 == address_size) { \
    SUB_REG(state, name, access, type, parent_reg_name); \
  } else { \
    REG(state, name, access, type); \
  }

#define SUB_REGAVX512(state, name, access, type, parent_reg_name) \
  if (has_avx512) { \
    SUB_REG(state, name, access, type, parent_reg_name); \
  } else { \
    REG(state, name, access, type); \
  }

#define SUB_REGAVX(state, name, access, type, parent_reg_name) \
  if (has_avx) { \
    SUB_REG(state, name, access, type, parent_reg_name); \
  } else { \
    REG(state, name, access, type); \
  }

  X86State state;

  if (64 == address_size) {
    REG(state, RAX, gpr.rax.qword, u64);
    REG(state, RBX, gpr.rbx.qword, u64);
    REG(state, RCX, gpr.rcx.qword, u64);
    REG(state, RDX, gpr.rdx.qword, u64);
    REG(state, RSI, gpr.rsi.qword, u64);
    REG(state, RDI, gpr.rdi.qword, u64);
    REG(state, RSP, gpr.rsp.qword, u64);
    REG(state, RBP, gpr.rbp.qword, u64);
    REG(state, RIP, gpr.rip.qword, u64);

    REG(state, R8, gpr.r8.qword, u64);
    REG(state, R9, gpr.r9.qword, u64);
    REG(state, R10, gpr.r10.qword, u64);
    REG(state, R11, gpr.r11.qword, u64);
    REG(state, R12, gpr.r12.qword, u64);
    REG(state, R13, gpr.r13.qword, u64);
    REG(state, R14, gpr.r14.qword, u64);
    REG(state, R15, gpr.r15.qword, u64);

    SUB_REG(state, R8D, gpr.r8.dword, u32, R8);
    SUB_REG(state, R9D, gpr.r9.dword, u32, R9);
    SUB_REG(state, R10D, gpr.r10.dword, u32, R10);
    SUB_REG(state, R11D, gpr.r11.dword, u32, R11);
    SUB_REG(state, R12D, gpr.r12.dword, u32, R12);
    SUB_REG(state, R13D, gpr.r13.dword, u32, R13);
    SUB_REG(state, R14D, gpr.r14.dword, u32, R14);
    SUB_REG(state, R15D, gpr.r15.dword, u32, R15);

    SUB_REG(state, R8W, gpr.r8.word, u16, R8D);
    SUB_REG(state, R9W, gpr.r9.word, u16, R9D);
    SUB_REG(state, R10W, gpr.r10.word, u16, R10D);
    SUB_REG(state, R11W, gpr.r11.word, u16, R11D);
    SUB_REG(state, R12W, gpr.r12.word, u16, R12D);
    SUB_REG(state, R13W, gpr.r13.word, u16, R13D);
    SUB_REG(state, R14W, gpr.r14.word, u16, R14D);
    SUB_REG(state, R15W, gpr.r15.word, u16, R15D);
  }

  SUB_REG64(state, EAX, gpr.rax.dword, u32, RAX);
  SUB_REG64(state, EBX, gpr.rbx.dword, u32, RBX);
  SUB_REG64(state, ECX, gpr.rcx.dword, u32, RCX);
  SUB_REG64(state, EDX, gpr.rdx.dword, u32, RDX);
  SUB_REG64(state, ESI, gpr.rsi.dword, u32, RSI);
  SUB_REG64(state, EDI, gpr.rdi.dword, u32, RDI);
  SUB_REG64(state, ESP, gpr.rsp.dword, u32, RSP);
  SUB_REG64(state, EBP, gpr.rbp.dword, u32, RBP);
  SUB_REG64(state, EIP, gpr.rip.dword, u32, RIP);

  SUB_REG(state, AX, gpr.rax.word, u16, EAX);
  SUB_REG(state, BX, gpr.rbx.word, u16, EBX);
  SUB_REG(state, CX, gpr.rcx.word, u16, ECX);
  SUB_REG(state, DX, gpr.rdx.word, u16, EDX);
  SUB_REG(state, SI, gpr.rsi.word, u16, ESI);
  SUB_REG(state, DI, gpr.rdi.word, u16, EDI);
  SUB_REG(state, SP, gpr.rsp.word, u16, ESP);
  SUB_REG(state, BP, gpr.rbp.word, u16, EBP);
  SUB_REG(state, IP, gpr.rip.word, u16, EIP);
  SUB_REG(state, AH, gpr.rax.byte.high, u8, AX);
  SUB_REG(state, BH, gpr.rbx.byte.high, u8, BX);
  SUB_REG(state, CH, gpr.rcx.byte.high, u8, CX);
  SUB_REG(state, DH, gpr.rdx.byte.high, u8, DX);
  SUB_REG(state, AL, gpr.rax.byte.low, u8, AX);
  SUB_REG(state, BL, gpr.rbx.byte.low, u8, BX);
  SUB_REG(state, CL, gpr.rcx.byte.low, u8, CX);
  SUB_REG(state, DL, gpr.rdx.byte.low, u8, DX);

  if (64 == address_size) {
    SUB_REG(state, SIL, gpr.rsi.byte.low, u8, SI);
    SUB_REG(state, DIL, gpr.rdi.byte.low, u8, DI);
    SUB_REG(state, SPL, gpr.rsp.byte.low, u8, SP);
    SUB_REG(state, BPL, gpr.rbp.byte.low, u8, BP);
    SUB_REG(state, R8B, gpr.r8.byte.low, u8, R8W);
    SUB_REG(state, R9B, gpr.r9.byte.low, u8, R9W);
    SUB_REG(state, R10B, gpr.r10.byte.low, u8, R10W);
    SUB_REG(state, R11B, gpr.r11.byte.low, u8, R11W);
    SUB_REG(state, R12B, gpr.r12.byte.low, u8, R12W);
    SUB_REG(state, R13B, gpr.r13.byte.low, u8, R13W);
    SUB_REG(state, R14B, gpr.r14.byte.low, u8, R14W);
    SUB_REG(state, R15B, gpr.r15.byte.low, u8, R15W);
  }

  if (64 == address_size) {
    SUB_REG(state, PC, gpr.rip.qword, u64, RIP);
  } else {
    SUB_REG(state, PC, gpr.rip.dword, u32, EIP);
  }

  REG(state, SS, seg.ss.flat, u16);
  REG(state, ES, seg.es.flat, u16);
  REG(state, GS, seg.gs.flat, u16);
  REG(state, FS, seg.fs.flat, u16);
  REG(state, DS, seg.ds.flat, u16);
  REG(state, CS, seg.cs.flat, u16);

  if (64 == address_size) {
    REG(state, GSBASE, addr.gs_base.qword, addr);
    REG(state, FSBASE, addr.fs_base.qword, addr);

  } else {
    REG(state, CSBASE, addr.cs_base.dword, addr);
    REG(state, SSBASE, addr.ss_base.dword, addr);
    REG(state, ESBASE, addr.es_base.dword, addr);
    REG(state, DSBASE, addr.ds_base.dword, addr);
    REG(state, GSBASE, addr.gs_base.dword, addr);
    REG(state, FSBASE, addr.fs_base.dword, addr);
  }

  if (has_avx) {
    if (has_avx512) {
      REG(state, ZMM0, vec[0].zmm, v512);
      REG(state, ZMM1, vec[1].zmm, v512);
      REG(state, ZMM2, vec[2].zmm, v512);
      REG(state, ZMM3, vec[3].zmm, v512);
      REG(state, ZMM4, vec[4].zmm, v512);
      REG(state, ZMM5, vec[5].zmm, v512);
      REG(state, ZMM6, vec[6].zmm, v512);
      REG(state, ZMM7, vec[7].zmm, v512);
      REG(state, ZMM8, vec[8].zmm, v512);
      REG(state, ZMM9, vec[9].zmm, v512);
      REG(state, ZMM10, vec[10].zmm, v512);
      REG(state, ZMM11, vec[11].zmm, v512);
      REG(state, ZMM12, vec[12].zmm, v512);
      REG(state, ZMM13, vec[13].zmm, v512);
      REG(state, ZMM14, vec[14].zmm, v512);
      REG(state, ZMM15, vec[15].zmm, v512);
      REG(state, ZMM16, vec[16].zmm, v512);
      REG(state, ZMM17, vec[17].zmm, v512);
      REG(state, ZMM18, vec[18].zmm, v512);
      REG(state, ZMM19, vec[19].zmm, v512);
      REG(state, ZMM20, vec[20].zmm, v512);
      REG(state, ZMM21, vec[21].zmm, v512);
      REG(state, ZMM22, vec[22].zmm, v512);
      REG(state, ZMM23, vec[23].zmm, v512);
      REG(state, ZMM24, vec[24].zmm, v512);
      REG(state, ZMM25, vec[25].zmm, v512);
      REG(state, ZMM26, vec[26].zmm, v512);
      REG(state, ZMM27, vec[27].zmm, v512);
      REG(state, ZMM28, vec[28].zmm, v512);
      REG(state, ZMM29, vec[29].zmm, v512);
      REG(state, ZMM30, vec[30].zmm, v512);
      REG(state, ZMM31, vec[31].zmm, v512);
    }

    SUB_REGAVX512(state, YMM0, vec[0].ymm, v256, ZMM0);
    SUB_REGAVX512(state, YMM1, vec[1].ymm, v256, ZMM1);
    SUB_REGAVX512(state, YMM2, vec[2].ymm, v256, ZMM2);
    SUB_REGAVX512(state, YMM3, vec[3].ymm, v256, ZMM3);
    SUB_REGAVX512(state, YMM4, vec[4].ymm, v256, ZMM4);
    SUB_REGAVX512(state, YMM5, vec[5].ymm, v256, ZMM5);
    SUB_REGAVX512(state, YMM6, vec[6].ymm, v256, ZMM6);
    SUB_REGAVX512(state, YMM7, vec[7].ymm, v256, ZMM7);

    if (64 == address_size || has_avx512) {
      SUB_REGAVX512(state, YMM8, vec[8].ymm, v256, ZMM8);
      SUB_REGAVX512(state, YMM9, vec[9].ymm, v256, ZMM9);
      SUB_REGAVX512(state, YMM10, vec[10].ymm, v256, ZMM10);
      SUB_REGAVX512(state, YMM11, vec[11].ymm, v256, ZMM11);
      SUB_REGAVX512(state, YMM12, vec[12].ymm, v256, ZMM12);
      SUB_REGAVX512(state, YMM13, vec[13].ymm, v256, ZMM13);
      SUB_REGAVX512(state, YMM14, vec[14].ymm, v256, ZMM14);
      SUB_REGAVX512(state, YMM15, vec[15].ymm, v256, ZMM15);
    }

    if (has_avx512) {
      SUB_REGAVX512(state, YMM16, vec[16].ymm, v256, ZMM16);
      SUB_REGAVX512(state, YMM17, vec[17].ymm, v256, ZMM17);
      SUB_REGAVX512(state, YMM18, vec[18].ymm, v256, ZMM18);
      SUB_REGAVX512(state, YMM19, vec[19].ymm, v256, ZMM19);
      SUB_REGAVX512(state, YMM20, vec[20].ymm, v256, ZMM20);
      SUB_REGAVX512(state, YMM21, vec[21].ymm, v256, ZMM21);
      SUB_REGAVX512(state, YMM22, vec[22].ymm, v256, ZMM22);
      SUB_REGAVX512(state, YMM23, vec[23].ymm, v256, ZMM23);
      SUB_REGAVX512(state, YMM24, vec[24].ymm, v256, ZMM24);
      SUB_REGAVX512(state, YMM25, vec[25].ymm, v256, ZMM25);
      SUB_REGAVX512(state, YMM26, vec[26].ymm, v256, ZMM26);
      SUB_REGAVX512(state, YMM27, vec[27].ymm, v256, ZMM27);
      SUB_REGAVX512(state, YMM28, vec[28].ymm, v256, ZMM28);
      SUB_REGAVX512(state, YMM29, vec[29].ymm, v256, ZMM29);
      SUB_REGAVX512(state, YMM30, vec[30].ymm, v256, ZMM30);
      SUB_REGAVX512(state, YMM31, vec[31].ymm, v256, ZMM31);
    }
  }

  SUB_REGAVX(state, XMM0, vec[0].xmm, v128, YMM0);
  SUB_REGAVX(state, XMM1, vec[1].xmm, v128, YMM1);
  SUB_REGAVX(state, XMM2, vec[2].xmm, v128, YMM2);
  SUB_REGAVX(state, XMM3, vec[3].xmm, v128, YMM3);
  SUB_REGAVX(state, XMM4, vec[4].xmm, v128, YMM4);
  SUB_REGAVX(state, XMM5, vec[5].xmm, v128, YMM5);
  SUB_REGAVX(state, XMM6, vec[6].xmm, v128, YMM6);
  SUB_REGAVX(state, XMM7, vec[7].xmm, v128, YMM7);

  if (has_avx || 64 == address_size) {
    SUB_REGAVX(state, XMM8, vec[8].xmm, v128, YMM8);
    SUB_REGAVX(state, XMM9, vec[9].xmm, v128, YMM9);
    SUB_REGAVX(state, XMM10, vec[10].xmm, v128, YMM10);
    SUB_REGAVX(state, XMM11, vec[11].xmm, v128, YMM11);
    SUB_REGAVX(state, XMM12, vec[12].xmm, v128, YMM12);
    SUB_REGAVX(state, XMM13, vec[13].xmm, v128, YMM13);
    SUB_REGAVX(state, XMM14, vec[14].xmm, v128, YMM14);
    SUB_REGAVX(state, XMM15, vec[15].xmm, v128, YMM15);
  }

  if (has_avx512) {
    SUB_REG(state, XMM16, vec[16].xmm, v128, YMM16);
    SUB_REG(state, XMM17, vec[17].xmm, v128, YMM17);
    SUB_REG(state, XMM18, vec[18].xmm, v128, YMM18);
    SUB_REG(state, XMM19, vec[19].xmm, v128, YMM19);
    SUB_REG(state, XMM20, vec[20].xmm, v128, YMM20);
    SUB_REG(state, XMM21, vec[21].xmm, v128, YMM21);
    SUB_REG(state, XMM22, vec[22].xmm, v128, YMM22);
    SUB_REG(state, XMM23, vec[23].xmm, v128, YMM23);
    SUB_REG(state, XMM24, vec[24].xmm, v128, YMM24);
    SUB_REG(state, XMM25, vec[25].xmm, v128, YMM25);
    SUB_REG(state, XMM26, vec[26].xmm, v128, YMM26);
    SUB_REG(state, XMM27, vec[27].xmm, v128, YMM27);
    SUB_REG(state, XMM28, vec[28].xmm, v128, YMM28);
    SUB_REG(state, XMM29, vec[29].xmm, v128, YMM29);
    SUB_REG(state, XMM30, vec[30].xmm, v128, YMM30);
    SUB_REG(state, XMM31, vec[31].xmm, v128, YMM31);
  }

  REG(state, ST0, st.elems[0].val, f80);
  REG(state, ST1, st.elems[1].val, f80);
  REG(state, ST2, st.elems[2].val, f80);
  REG(state, ST3, st.elems[3].val, f80);
  REG(state, ST4, st.elems[4].val, f80);
  REG(state, ST5, st.elems[5].val, f80);
  REG(state, ST6, st.elems[6].val, f80);
  REG(state, ST7, st.elems[7].val, f80);

#if 0  // TODO(pag): Don't emulate directly for now.
  if (32 == address_size) {
    REG(FPU_LASTIP, fpu.u.x86.ip);
    REG(FPU_LASTIP, fpu.u.x86.ip);
    REG(FPU_LASTCS, fpu.u.x86.cs);
    REG(FPU_LASTCS, fpu.u.x86.cs);
    REG(FPU_LASTDP, fpu.u.x86.dp);
    REG(FPU_LASTDP, fpu.u.x86.dp);
    REG(FPU_LASTDS, fpu.u.x86.ds);
    REG(FPU_LASTDS, fpu.u.x86.ds);
  } else {
    REG(FPU_LASTIP, fpu.u.amd64.ip);
    REG(FPU_LASTIP, fpu.u.amd64.ip);
    REG(FPU_LASTDP, fpu.u.amd64.dp);
    REG(FPU_LASTDP, fpu.u.amd64.dp);
  }
#endif

  // MMX technology registers. For simplicity, these are implemented separately
  // from the FPU stack, and so they do not alias. This makes some things
  // easier and some things harder. Marshaling native/lifted state becomes
  // harder, but generating and optimizing bitcode becomes simpler. The trade-
  // off is that analysis and native states will diverge in strange ways
  // with code that mixes the two (X87 FPU ops, MMX ops).
  REG(state, MM0, mmx.elems[0].val.qwords.elems[0], u64);
  REG(state, MM1, mmx.elems[1].val.qwords.elems[0], u64);
  REG(state, MM2, mmx.elems[2].val.qwords.elems[0], u64);
  REG(state, MM3, mmx.elems[3].val.qwords.elems[0], u64);
  REG(state, MM4, mmx.elems[4].val.qwords.elems[0], u64);
  REG(state, MM5, mmx.elems[5].val.qwords.elems[0], u64);
  REG(state, MM6, mmx.elems[6].val.qwords.elems[0], u64);
  REG(state, MM7, mmx.elems[7].val.qwords.elems[0], u64);

  if (has_avx512) {
    REG(state, K0, k_reg.elems[0].val, u64);
    REG(state, K1, k_reg.elems[1].val, u64);
    REG(state, K2, k_reg.elems[2].val, u64);
    REG(state, K3, k_reg.elems[3].val, u64);
    REG(state, K4, k_reg.elems[4].val, u64);
    REG(state, K5, k_reg.elems[5].val, u64);
    REG(state, K6, k_reg.elems[6].val, u64);
    REG(state, K7, k_reg.elems[7].val, u64);
  }

  // Arithmetic flags. Data-flow analyses will clear these out ;-)
  REG(state, AF, aflag.af, u8);
  REG(state, CF, aflag.cf, u8);
  REG(state, DF, aflag.df, u8);
  REG(state, OF, aflag.of, u8);
  REG(state, PF, aflag.pf, u8);
  REG(state, SF, aflag.sf, u8);
  REG(state, ZF, aflag.zf, u8);

  //  // Debug registers. No-ops keep them from being stripped off the module.
  //  DR0
  //  DR1
  //  DR2
  //  DR3
  //  DR4
  //  DR5
  //  DR6
  //  DR7

  //  REG(CR0, lat);
  //  REG(CR1, lat);
  //  REG(CR2, lat);
  //  REG(CR3, lat);
  //  REG(CR4, lat);
  //#if 64 == ADDRESS_SIZE_BITS
  //  REG(CR8, lat);
  //#endif
}

// Populate a just-initialized lifted function function with architecture-
// specific variables.
void X86ArchBase::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {
  const auto &dl = module->getDataLayout();
  CHECK_EQ(sizeof(State), dl.getTypeAllocSize(StateStructType()))
      << "Mismatch between size of State type for x86/amd64 and what is in "
      << "the bitcode module";

  auto &context = module->getContext();
  auto addr = llvm::Type::getIntNTy(context, address_size);
  auto zero_addr_val = llvm::Constant::getNullValue(addr);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);
  ir.CreateStore(pc_arg, ir.CreateAlloca(addr, nullptr, "NEXT_PC"));

  (void) this->RegisterByName("PC")->AddressOf(state_ptr_arg, ir);

  if (64 == address_size) {
    ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "CSBASE"));
    ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "SSBASE"));
    ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "ESBASE"));
    ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "DSBASE"));
  }
}
}  // namespace remill
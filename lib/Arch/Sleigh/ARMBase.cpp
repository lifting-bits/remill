#include <glog/logging.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/TargetParser/Triple.h>
#include <remill/Arch/AArch32/AArch32Base.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

namespace remill {
// Default calling convention for this architecture.
llvm::CallingConv::ID AArch32ArchBase::DefaultCallingConv(void) const {
  return llvm::CallingConv::C;  // cdecl.
}

// Get the LLVM triple for this architecture.
llvm::Triple AArch32ArchBase::Triple(void) const {
  auto triple = BasicTriple();
  switch (arch_name) {
    case kArchAArch32LittleEndian: triple.setArch(llvm::Triple::arm); break;
    case kArchThumb2LittleEndian: triple.setArch(llvm::Triple::thumb); break;
    default:
      LOG(FATAL) << "Cannot get triple for non-aarch32 architecture "
                 << GetArchName(arch_name);
  }

  return triple;
}

// Get the LLVM DataLayout for a module.
llvm::DataLayout AArch32ArchBase::DataLayout(void) const {
  std::string dl;
  switch (os_name) {
    case kOSInvalid:
      LOG(FATAL) << "Cannot convert module for an unrecognized OS.";
      break;

    case kOSLinux:
    case kOSSolaris:
    case kOSmacOS:
    case kOSWindows:
      dl = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64";
      break;
  }

  return llvm::DataLayout(dl);
}

// Returns the name of the stack pointer register.
std::string_view AArch32ArchBase::StackPointerRegisterName(void) const {
  return "SP";
}

// Returns the name of the program counter register.
std::string_view AArch32ArchBase::ProgramCounterRegisterName(void) const {
  return "PC";
}

// Populate the table of register information.
void AArch32ArchBase::PopulateRegisterTable(void) const {
  CHECK_NOTNULL(context);

  reg_by_offset.resize(sizeof(AArch32State));

  auto u8 = llvm::Type::getInt8Ty(*context);

  auto u32 = llvm::Type::getInt32Ty(*context);

  auto u64 = llvm::Type::getInt64Ty(*context);

  auto u128 = llvm::Type::getInt128Ty(*context);


#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(AArch32State, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(AArch32State, access), #parent_reg_name)

  REG(R0, gpr.r0.dword, u32);
  REG(R1, gpr.r1.dword, u32);
  REG(R2, gpr.r2.dword, u32);
  REG(R3, gpr.r3.dword, u32);
  REG(R4, gpr.r4.dword, u32);
  REG(R5, gpr.r5.dword, u32);
  REG(R6, gpr.r6.dword, u32);
  REG(R7, gpr.r7.dword, u32);
  REG(R8, gpr.r8.dword, u32);
  REG(R9, gpr.r9.dword, u32);
  REG(R10, gpr.r10.dword, u32);
  REG(R11, gpr.r11.dword, u32);
  REG(R12, gpr.r12.dword, u32);
  REG(R13, gpr.r13.dword, u32);
  REG(R14, gpr.r14.dword, u32);
  REG(R15, gpr.r15.dword, u32);

  SUB_REG(SP, gpr.r13.dword, u32, R13);
  SUB_REG(LR, gpr.r14.dword, u32, R14);
  SUB_REG(PC, gpr.r15.dword, u32, R15);

  REG(Q0, neon.q0, u128);
  REG(Q1, neon.q1, u128);
  REG(Q2, neon.q2, u128);
  REG(Q3, neon.q3, u128);
  REG(Q4, neon.q4, u128);
  REG(Q5, neon.q5, u128);
  REG(Q6, neon.q6, u128);
  REG(Q7, neon.q7, u128);
  REG(Q8, neon.q8, u128);
  REG(Q9, neon.q9, u128);
  REG(Q10, neon.q10, u128);
  REG(Q11, neon.q11, u128);
  REG(Q12, neon.q12, u128);
  REG(Q13, neon.q13, u128);
  REG(Q14, neon.q14, u128);
  REG(Q15, neon.q15, u128);

  REG(FPSCR, fpscr.value, u32);

  SUB_REG(D0, neon.q0.dwords.low_dword, u64, Q0);
  SUB_REG(D1, neon.q0.dwords.high_dword, u64, Q0);
  SUB_REG(D2, neon.q1.dwords.low_dword, u64, Q1);
  SUB_REG(D3, neon.q1.dwords.high_dword, u64, Q1);
  SUB_REG(D4, neon.q2.dwords.low_dword, u64, Q2);
  SUB_REG(D5, neon.q2.dwords.high_dword, u64, Q2);
  SUB_REG(D6, neon.q3.dwords.low_dword, u64, Q3);
  SUB_REG(D7, neon.q3.dwords.high_dword, u64, Q3);
  SUB_REG(D8, neon.q4.dwords.low_dword, u64, Q4);
  SUB_REG(D9, neon.q4.dwords.high_dword, u64, Q4);
  SUB_REG(D10, neon.q5.dwords.low_dword, u64, Q5);
  SUB_REG(D11, neon.q5.dwords.high_dword, u64, Q5);
  SUB_REG(D12, neon.q6.dwords.low_dword, u64, Q6);
  SUB_REG(D13, neon.q6.dwords.high_dword, u64, Q6);
  SUB_REG(D14, neon.q7.dwords.low_dword, u64, Q7);
  SUB_REG(D15, neon.q7.dwords.high_dword, u64, Q7);
  SUB_REG(D16, neon.q8.dwords.low_dword, u64, Q8);
  SUB_REG(D17, neon.q8.dwords.high_dword, u64, Q8);
  SUB_REG(D18, neon.q9.dwords.low_dword, u64, Q9);
  SUB_REG(D19, neon.q9.dwords.high_dword, u64, Q9);
  SUB_REG(D20, neon.q10.dwords.low_dword, u64, Q10);
  SUB_REG(D21, neon.q10.dwords.high_dword, u64, Q10);
  SUB_REG(D22, neon.q11.dwords.low_dword, u64, Q11);
  SUB_REG(D23, neon.q11.dwords.high_dword, u64, Q11);
  SUB_REG(D24, neon.q12.dwords.low_dword, u64, Q12);
  SUB_REG(D25, neon.q12.dwords.high_dword, u64, Q12);
  SUB_REG(D26, neon.q13.dwords.low_dword, u64, Q13);
  SUB_REG(D27, neon.q13.dwords.high_dword, u64, Q13);
  SUB_REG(D28, neon.q14.dwords.low_dword, u64, Q14);
  SUB_REG(D29, neon.q14.dwords.high_dword, u64, Q14);
  SUB_REG(D30, neon.q15.dwords.low_dword, u64, Q15);
  SUB_REG(D31, neon.q15.dwords.high_dword, u64, Q15);

  SUB_REG(S0, neon.q0.words.ll_word, u32, D0);
  SUB_REG(S1, neon.q0.words.lh_word, u32, D0);
  SUB_REG(S2, neon.q0.words.hl_word, u32, D1);
  SUB_REG(S3, neon.q0.words.hh_word, u32, D1);
  SUB_REG(S4, neon.q1.words.ll_word, u32, D2);
  SUB_REG(S5, neon.q1.words.lh_word, u32, D2);
  SUB_REG(S6, neon.q1.words.hl_word, u32, D3);
  SUB_REG(S7, neon.q1.words.hh_word, u32, D3);
  SUB_REG(S8, neon.q2.words.ll_word, u32, D4);
  SUB_REG(S9, neon.q2.words.lh_word, u32, D4);
  SUB_REG(S10, neon.q2.words.hl_word, u32, D5);
  SUB_REG(S11, neon.q2.words.hh_word, u32, D5);
  SUB_REG(S12, neon.q3.words.ll_word, u32, D6);
  SUB_REG(S13, neon.q3.words.lh_word, u32, D6);
  SUB_REG(S14, neon.q3.words.hl_word, u32, D7);
  SUB_REG(S15, neon.q3.words.hh_word, u32, D7);
  SUB_REG(S16, neon.q4.words.ll_word, u32, D8);
  SUB_REG(S17, neon.q4.words.lh_word, u32, D8);
  SUB_REG(S18, neon.q4.words.hl_word, u32, D9);
  SUB_REG(S19, neon.q4.words.hh_word, u32, D9);
  SUB_REG(S20, neon.q5.words.ll_word, u32, D10);
  SUB_REG(S21, neon.q5.words.lh_word, u32, D10);
  SUB_REG(S22, neon.q5.words.hl_word, u32, D11);
  SUB_REG(S23, neon.q5.words.hh_word, u32, D11);
  SUB_REG(S24, neon.q6.words.ll_word, u32, D12);
  SUB_REG(S25, neon.q6.words.lh_word, u32, D12);
  SUB_REG(S26, neon.q6.words.hl_word, u32, D13);
  SUB_REG(S27, neon.q6.words.hh_word, u32, D13);
  SUB_REG(S28, neon.q7.words.ll_word, u32, D14);
  SUB_REG(S29, neon.q7.words.lh_word, u32, D14);
  SUB_REG(S30, neon.q7.words.hl_word, u32, D15);
  SUB_REG(S31, neon.q7.words.hh_word, u32, D15);


  REG(N, sr.n, u8);
  REG(C, sr.c, u8);
  REG(Z, sr.z, u8);
  REG(V, sr.v, u8);
}


// Populate a just-initialized lifted function function with architecture-
// specific variables.
void AArch32ArchBase::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {
  const auto &dl = module->getDataLayout();
  CHECK_EQ(sizeof(State), dl.getTypeAllocSize(StateStructType()))
      << "Mismatch between size of State type for aarch32 and what is in "
      << "the bitcode module";

  auto &context = module->getContext();
  auto u8 = llvm::Type::getInt8Ty(context);

  //  auto u16 = llvm::Type::getInt16Ty(context);
  auto u32 = llvm::Type::getInt32Ty(context);
  auto addr = llvm::Type::getIntNTy(context, address_size);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);
  ir.CreateStore(pc_arg,
                 ir.CreateAlloca(addr, nullptr, kNextPCVariableName.data()));
  ir.CreateStore(
      pc_arg, ir.CreateAlloca(addr, nullptr, kIgnoreNextPCVariableName.data()));

  auto zero_c = ir.CreateAlloca(u8, nullptr, "ZERO_C");
  ir.CreateStore(llvm::Constant::getNullValue(u8), zero_c);
  ir.CreateAlloca(u32, nullptr, "SUPPRESS_WRITEBACK");
  (void) this->RegisterByName("PC")->AddressOf(state_ptr_arg, ir);
}
}  // namespace remill
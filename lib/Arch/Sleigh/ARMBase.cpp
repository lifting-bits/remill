#include <glog/logging.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
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

#define OFFSET_OF(state, access) \
  (reinterpret_cast<uintptr_t>(&state.access) \
    - reinterpret_cast<uintptr_t>(&state))

#define REG(state, name, access, type) \
  AddRegister(#name, type, OFFSET_OF(state, access), nullptr)

#define SUB_REG(state, name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(state, access), #parent_reg_name)

  AArch32State state;

  REG(state, R0, gpr.r0.dword, u32);
  REG(state, R1, gpr.r1.dword, u32);
  REG(state, R2, gpr.r2.dword, u32);
  REG(state, R3, gpr.r3.dword, u32);
  REG(state, R4, gpr.r4.dword, u32);
  REG(state, R5, gpr.r5.dword, u32);
  REG(state, R6, gpr.r6.dword, u32);
  REG(state, R7, gpr.r7.dword, u32);
  REG(state, R8, gpr.r8.dword, u32);
  REG(state, R9, gpr.r9.dword, u32);
  REG(state, R10, gpr.r10.dword, u32);
  REG(state, R11, gpr.r11.dword, u32);
  REG(state, R12, gpr.r12.dword, u32);
  REG(state, R13, gpr.r13.dword, u32);
  REG(state, R14, gpr.r14.dword, u32);
  REG(state, R15, gpr.r15.dword, u32);

  SUB_REG(state, SP, gpr.r13.dword, u32, R13);
  SUB_REG(state, LR, gpr.r14.dword, u32, R14);
  SUB_REG(state, PC, gpr.r15.dword, u32, R15);

  REG(state, Q0, neon.q0, u128);
  REG(state, Q1, neon.q1, u128);
  REG(state, Q2, neon.q2, u128);
  REG(state, Q3, neon.q3, u128);
  REG(state, Q4, neon.q4, u128);
  REG(state, Q5, neon.q5, u128);
  REG(state, Q6, neon.q6, u128);
  REG(state, Q7, neon.q7, u128);
  REG(state, Q8, neon.q8, u128);
  REG(state, Q9, neon.q9, u128);
  REG(state, Q10, neon.q10, u128);
  REG(state, Q11, neon.q11, u128);
  REG(state, Q12, neon.q12, u128);
  REG(state, Q13, neon.q13, u128);
  REG(state, Q14, neon.q14, u128);
  REG(state, Q15, neon.q15, u128);

  REG(state, FPSCR, fpscr.value, u32);

  SUB_REG(state, D0, neon.q0.dwords.low_dword, u64, Q0);
  SUB_REG(state, D1, neon.q0.dwords.high_dword, u64, Q0);
  SUB_REG(state, D2, neon.q1.dwords.low_dword, u64, Q1);
  SUB_REG(state, D3, neon.q1.dwords.high_dword, u64, Q1);
  SUB_REG(state, D4, neon.q2.dwords.low_dword, u64, Q2);
  SUB_REG(state, D5, neon.q2.dwords.high_dword, u64, Q2);
  SUB_REG(state, D6, neon.q3.dwords.low_dword, u64, Q3);
  SUB_REG(state, D7, neon.q3.dwords.high_dword, u64, Q3);
  SUB_REG(state, D8, neon.q4.dwords.low_dword, u64, Q4);
  SUB_REG(state, D9, neon.q4.dwords.high_dword, u64, Q4);
  SUB_REG(state, D10, neon.q5.dwords.low_dword, u64, Q5);
  SUB_REG(state, D11, neon.q5.dwords.high_dword, u64, Q5);
  SUB_REG(state, D12, neon.q6.dwords.low_dword, u64, Q6);
  SUB_REG(state, D13, neon.q6.dwords.high_dword, u64, Q6);
  SUB_REG(state, D14, neon.q7.dwords.low_dword, u64, Q7);
  SUB_REG(state, D15, neon.q7.dwords.high_dword, u64, Q7);
  SUB_REG(state, D16, neon.q8.dwords.low_dword, u64, Q8);
  SUB_REG(state, D17, neon.q8.dwords.high_dword, u64, Q8);
  SUB_REG(state, D18, neon.q9.dwords.low_dword, u64, Q9);
  SUB_REG(state, D19, neon.q9.dwords.high_dword, u64, Q9);
  SUB_REG(state, D20, neon.q10.dwords.low_dword, u64, Q10);
  SUB_REG(state, D21, neon.q10.dwords.high_dword, u64, Q10);
  SUB_REG(state, D22, neon.q11.dwords.low_dword, u64, Q11);
  SUB_REG(state, D23, neon.q11.dwords.high_dword, u64, Q11);
  SUB_REG(state, D24, neon.q12.dwords.low_dword, u64, Q12);
  SUB_REG(state, D25, neon.q12.dwords.high_dword, u64, Q12);
  SUB_REG(state, D26, neon.q13.dwords.low_dword, u64, Q13);
  SUB_REG(state, D27, neon.q13.dwords.high_dword, u64, Q13);
  SUB_REG(state, D28, neon.q14.dwords.low_dword, u64, Q14);
  SUB_REG(state, D29, neon.q14.dwords.high_dword, u64, Q14);
  SUB_REG(state, D30, neon.q15.dwords.low_dword, u64, Q15);
  SUB_REG(state, D31, neon.q15.dwords.high_dword, u64, Q15);

  SUB_REG(state, S0, neon.q0.words.ll_word, u32, D0);
  SUB_REG(state, S1, neon.q0.words.lh_word, u32, D0);
  SUB_REG(state, S2, neon.q0.words.hl_word, u32, D1);
  SUB_REG(state, S3, neon.q0.words.hh_word, u32, D1);
  SUB_REG(state, S4, neon.q1.words.ll_word, u32, D2);
  SUB_REG(state, S5, neon.q1.words.lh_word, u32, D2);
  SUB_REG(state, S6, neon.q1.words.hl_word, u32, D3);
  SUB_REG(state, S7, neon.q1.words.hh_word, u32, D3);
  SUB_REG(state, S8, neon.q2.words.ll_word, u32, D4);
  SUB_REG(state, S9, neon.q2.words.lh_word, u32, D4);
  SUB_REG(state, S10, neon.q2.words.hl_word, u32, D5);
  SUB_REG(state, S11, neon.q2.words.hh_word, u32, D5);
  SUB_REG(state, S12, neon.q3.words.ll_word, u32, D6);
  SUB_REG(state, S13, neon.q3.words.lh_word, u32, D6);
  SUB_REG(state, S14, neon.q3.words.hl_word, u32, D7);
  SUB_REG(state, S15, neon.q3.words.hh_word, u32, D7);
  SUB_REG(state, S16, neon.q4.words.ll_word, u32, D8);
  SUB_REG(state, S17, neon.q4.words.lh_word, u32, D8);
  SUB_REG(state, S18, neon.q4.words.hl_word, u32, D9);
  SUB_REG(state, S19, neon.q4.words.hh_word, u32, D9);
  SUB_REG(state, S20, neon.q5.words.ll_word, u32, D10);
  SUB_REG(state, S21, neon.q5.words.lh_word, u32, D10);
  SUB_REG(state, S22, neon.q5.words.hl_word, u32, D11);
  SUB_REG(state, S23, neon.q5.words.hh_word, u32, D11);
  SUB_REG(state, S24, neon.q6.words.ll_word, u32, D12);
  SUB_REG(state, S25, neon.q6.words.lh_word, u32, D12);
  SUB_REG(state, S26, neon.q6.words.hl_word, u32, D13);
  SUB_REG(state, S27, neon.q6.words.hh_word, u32, D13);
  SUB_REG(state, S28, neon.q7.words.ll_word, u32, D14);
  SUB_REG(state, S29, neon.q7.words.lh_word, u32, D14);
  SUB_REG(state, S30, neon.q7.words.hl_word, u32, D15);
  SUB_REG(state, S31, neon.q7.words.hh_word, u32, D15);


  REG(state, N, sr.n, u8);
  REG(state, C, sr.c, u8);
  REG(state, Z, sr.z, u8);
  REG(state, V, sr.v, u8);
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
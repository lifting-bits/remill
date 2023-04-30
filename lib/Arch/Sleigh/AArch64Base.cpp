#include <glog/logging.h>
#include <remill/Arch/AArch64/AArch64Base.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

namespace remill {
// Returns the name of the stack pointer register.
std::string_view AArch64ArchBase::StackPointerRegisterName(void) const {
  return "SP";
}

// Returns the name of the program counter register.
std::string_view AArch64ArchBase::ProgramCounterRegisterName(void) const {
  return "PC";
}

uint64_t AArch64ArchBase::MinInstructionAlign(const DecodingContext &) const {
  return 4;
}

uint64_t AArch64ArchBase::MinInstructionSize(const DecodingContext &) const {
  return 4;
}

// Maximum number of bytes in an instruction for this particular architecture.
uint64_t AArch64ArchBase::MaxInstructionSize(const DecodingContext &,
                                             bool) const {
  return 4;
}


// Populate a just-initialized lifted function function with architecture-
// specific variables.
void AArch64ArchBase::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {

  auto &context = module->getContext();
  auto u32 = llvm::Type::getInt32Ty(context);
  auto u64 = llvm::Type::getInt64Ty(context);

  auto addr = u64;
  auto zero_u32 = llvm::Constant::getNullValue(u32);
  auto zero_u64 = llvm::Constant::getNullValue(u64);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);
  llvm::StringRef next_pc_name(kNextPCVariableName.data(),
                               kNextPCVariableName.size());
  ir.CreateStore(pc_arg, ir.CreateAlloca(addr, nullptr, next_pc_name));

  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "WZR"));
  ir.CreateStore(zero_u64, ir.CreateAlloca(u64, nullptr, "XZR"));
  ir.CreateAlloca(u32, nullptr, "IGNORE_WRITE_TO_WZR");
  ir.CreateAlloca(u64, nullptr, "IGNORE_WRITE_TO_XZR");
  ir.CreateAlloca(u64, nullptr, "SUPPRESS_WRITEBACK");

  (void) this->RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir);
}

llvm::Triple AArch64ArchBase::Triple(void) const {
  auto triple = BasicTriple();
  switch (arch_name) {
    case kArchAArch64LittleEndian_SLEIGH:
    case kArchAArch64LittleEndian: triple.setArch(llvm::Triple::aarch64); break;

    default:
      LOG(FATAL) << "Cannot get triple for non-AArch64 architecture "
                 << GetArchName(arch_name);
      break;
  }
  return triple;
}

llvm::DataLayout AArch64ArchBase::DataLayout(void) const {
  std::string dl;
  switch (arch_name) {
    case kArchAArch64LittleEndian:
    case kArchAArch64LittleEndian_SLEIGH:
      dl = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128";
      break;

    default:
      LOG(FATAL) << "Cannot get data layout for non-AArch64 architecture "
                 << GetArchName(arch_name);
      break;
  }
  return llvm::DataLayout(dl);
}

// Default calling convention for this architecture.
llvm::CallingConv::ID AArch64ArchBase::DefaultCallingConv(void) const {
  return llvm::CallingConv::C;
}

// Populate the table of register information.
void AArch64ArchBase::PopulateRegisterTable(void) const {

  reg_by_offset.resize(sizeof(AArch64State));

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(AArch64State, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(AArch64State, access), #parent_reg_name)

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u16 = llvm::Type::getInt16Ty(*context);
  auto u32 = llvm::Type::getInt32Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto u128 = llvm::Type::getInt128Ty(*context);

  auto v128u8 = llvm::ArrayType::get(u8, 128u / 8u);
  auto v128u16 = llvm::ArrayType::get(u16, 128u / 16u);
  auto v128u32 = llvm::ArrayType::get(u32, 128u / 32u);
  auto v128u64 = llvm::ArrayType::get(u64, 128u / 64u);
  auto v128u128 = llvm::ArrayType::get(u128, 128u / 128u);

  REG(X0, gpr.x0.qword, u64);
  REG(X1, gpr.x1.qword, u64);
  REG(X2, gpr.x2.qword, u64);
  REG(X3, gpr.x3.qword, u64);
  REG(X4, gpr.x4.qword, u64);
  REG(X5, gpr.x5.qword, u64);
  REG(X6, gpr.x6.qword, u64);
  REG(X7, gpr.x7.qword, u64);
  REG(X8, gpr.x8.qword, u64);
  REG(X9, gpr.x9.qword, u64);
  REG(X10, gpr.x10.qword, u64);
  REG(X11, gpr.x11.qword, u64);
  REG(X12, gpr.x12.qword, u64);
  REG(X13, gpr.x13.qword, u64);
  REG(X14, gpr.x14.qword, u64);
  REG(X15, gpr.x15.qword, u64);
  REG(X16, gpr.x16.qword, u64);
  REG(X17, gpr.x17.qword, u64);
  REG(X18, gpr.x18.qword, u64);
  REG(X19, gpr.x19.qword, u64);
  REG(X20, gpr.x20.qword, u64);
  REG(X21, gpr.x21.qword, u64);
  REG(X22, gpr.x22.qword, u64);
  REG(X23, gpr.x23.qword, u64);
  REG(X24, gpr.x24.qword, u64);
  REG(X25, gpr.x25.qword, u64);
  REG(X26, gpr.x26.qword, u64);
  REG(X27, gpr.x27.qword, u64);
  REG(X28, gpr.x28.qword, u64);
  REG(X29, gpr.x29.qword, u64);
  REG(X30, gpr.x30.qword, u64);

  SUB_REG(W0, gpr.x0.dword, u32, X0);
  SUB_REG(W1, gpr.x1.dword, u32, X1);
  SUB_REG(W2, gpr.x2.dword, u32, X2);
  SUB_REG(W3, gpr.x3.dword, u32, X3);
  SUB_REG(W4, gpr.x4.dword, u32, X4);
  SUB_REG(W5, gpr.x5.dword, u32, X5);
  SUB_REG(W6, gpr.x6.dword, u32, X6);
  SUB_REG(W7, gpr.x7.dword, u32, X7);
  SUB_REG(W8, gpr.x8.dword, u32, X8);
  SUB_REG(W9, gpr.x9.dword, u32, X9);
  SUB_REG(W10, gpr.x10.dword, u32, X10);
  SUB_REG(W11, gpr.x11.dword, u32, X11);
  SUB_REG(W12, gpr.x12.dword, u32, X12);
  SUB_REG(W13, gpr.x13.dword, u32, X13);
  SUB_REG(W14, gpr.x14.dword, u32, X14);
  SUB_REG(W15, gpr.x15.dword, u32, X15);
  SUB_REG(W16, gpr.x16.dword, u32, X16);
  SUB_REG(W17, gpr.x17.dword, u32, X17);
  SUB_REG(W18, gpr.x18.dword, u32, X18);
  SUB_REG(W19, gpr.x19.dword, u32, X19);
  SUB_REG(W20, gpr.x20.dword, u32, X20);
  SUB_REG(W21, gpr.x21.dword, u32, X21);
  SUB_REG(W22, gpr.x22.dword, u32, X22);
  SUB_REG(W23, gpr.x23.dword, u32, X23);
  SUB_REG(W24, gpr.x24.dword, u32, X24);
  SUB_REG(W25, gpr.x25.dword, u32, X25);
  SUB_REG(W26, gpr.x26.dword, u32, X26);
  SUB_REG(W27, gpr.x27.dword, u32, X27);
  SUB_REG(W28, gpr.x28.dword, u32, X28);
  SUB_REG(W29, gpr.x29.dword, u32, X29);
  SUB_REG(W30, gpr.x30.dword, u32, X30);

  REG(PC, gpr.pc.qword, u64);
  SUB_REG(WPC, gpr.pc.dword, u32, PC);

  REG(SP, gpr.sp.qword, u64);
  SUB_REG(WSP, gpr.sp.dword, u32, SP);

  SUB_REG(LP, gpr.x30.qword, u64, X30);
  SUB_REG(WLP, gpr.x30.dword, u32, LP);

  REG(V0, simd.v[0].bytes.elems[0], v128u8);
  REG(V1, simd.v[1].bytes.elems[0], v128u8);
  REG(V2, simd.v[2].bytes.elems[0], v128u8);
  REG(V3, simd.v[3].bytes.elems[0], v128u8);
  REG(V4, simd.v[4].bytes.elems[0], v128u8);
  REG(V5, simd.v[5].bytes.elems[0], v128u8);
  REG(V6, simd.v[6].bytes.elems[0], v128u8);
  REG(V7, simd.v[7].bytes.elems[0], v128u8);
  REG(V8, simd.v[8].bytes.elems[0], v128u8);
  REG(V9, simd.v[9].bytes.elems[0], v128u8);
  REG(V10, simd.v[10].bytes.elems[0], v128u8);
  REG(V11, simd.v[11].bytes.elems[0], v128u8);
  REG(V12, simd.v[12].bytes.elems[0], v128u8);
  REG(V13, simd.v[13].bytes.elems[0], v128u8);
  REG(V14, simd.v[14].bytes.elems[0], v128u8);
  REG(V15, simd.v[15].bytes.elems[0], v128u8);
  REG(V16, simd.v[16].bytes.elems[0], v128u8);
  REG(V17, simd.v[17].bytes.elems[0], v128u8);
  REG(V18, simd.v[18].bytes.elems[0], v128u8);
  REG(V19, simd.v[19].bytes.elems[0], v128u8);
  REG(V20, simd.v[20].bytes.elems[0], v128u8);
  REG(V21, simd.v[21].bytes.elems[0], v128u8);
  REG(V22, simd.v[22].bytes.elems[0], v128u8);
  REG(V23, simd.v[23].bytes.elems[0], v128u8);
  REG(V24, simd.v[24].bytes.elems[0], v128u8);
  REG(V25, simd.v[25].bytes.elems[0], v128u8);
  REG(V26, simd.v[26].bytes.elems[0], v128u8);
  REG(V27, simd.v[27].bytes.elems[0], v128u8);
  REG(V28, simd.v[28].bytes.elems[0], v128u8);
  REG(V29, simd.v[29].bytes.elems[0], v128u8);
  REG(V30, simd.v[30].bytes.elems[0], v128u8);
  REG(V31, simd.v[31].bytes.elems[0], v128u8);

  SUB_REG(B0, simd.v[0].bytes.elems[0], v128u8, V0);
  SUB_REG(B1, simd.v[1].bytes.elems[0], v128u8, V1);
  SUB_REG(B2, simd.v[2].bytes.elems[0], v128u8, V2);
  SUB_REG(B3, simd.v[3].bytes.elems[0], v128u8, V3);
  SUB_REG(B4, simd.v[4].bytes.elems[0], v128u8, V4);
  SUB_REG(B5, simd.v[5].bytes.elems[0], v128u8, V5);
  SUB_REG(B6, simd.v[6].bytes.elems[0], v128u8, V6);
  SUB_REG(B7, simd.v[7].bytes.elems[0], v128u8, V7);
  SUB_REG(B8, simd.v[8].bytes.elems[0], v128u8, V8);
  SUB_REG(B9, simd.v[9].bytes.elems[0], v128u8, V9);
  SUB_REG(B10, simd.v[10].bytes.elems[0], v128u8, V10);
  SUB_REG(B11, simd.v[11].bytes.elems[0], v128u8, V11);
  SUB_REG(B12, simd.v[12].bytes.elems[0], v128u8, V12);
  SUB_REG(B13, simd.v[13].bytes.elems[0], v128u8, V13);
  SUB_REG(B14, simd.v[14].bytes.elems[0], v128u8, V14);
  SUB_REG(B15, simd.v[15].bytes.elems[0], v128u8, V15);
  SUB_REG(B16, simd.v[16].bytes.elems[0], v128u8, V16);
  SUB_REG(B17, simd.v[17].bytes.elems[0], v128u8, V17);
  SUB_REG(B18, simd.v[18].bytes.elems[0], v128u8, V18);
  SUB_REG(B19, simd.v[19].bytes.elems[0], v128u8, V19);
  SUB_REG(B20, simd.v[20].bytes.elems[0], v128u8, V20);
  SUB_REG(B21, simd.v[21].bytes.elems[0], v128u8, V21);
  SUB_REG(B22, simd.v[22].bytes.elems[0], v128u8, V22);
  SUB_REG(B23, simd.v[23].bytes.elems[0], v128u8, V23);
  SUB_REG(B24, simd.v[24].bytes.elems[0], v128u8, V24);
  SUB_REG(B25, simd.v[25].bytes.elems[0], v128u8, V25);
  SUB_REG(B26, simd.v[26].bytes.elems[0], v128u8, V26);
  SUB_REG(B27, simd.v[27].bytes.elems[0], v128u8, V27);
  SUB_REG(B28, simd.v[28].bytes.elems[0], v128u8, V28);
  SUB_REG(B29, simd.v[29].bytes.elems[0], v128u8, V29);
  SUB_REG(B30, simd.v[30].bytes.elems[0], v128u8, V30);
  SUB_REG(B31, simd.v[31].bytes.elems[0], v128u8, V31);

  SUB_REG(H0, simd.v[0].words.elems[0], v128u16, V0);
  SUB_REG(H1, simd.v[1].words.elems[0], v128u16, V1);
  SUB_REG(H2, simd.v[2].words.elems[0], v128u16, V2);
  SUB_REG(H3, simd.v[3].words.elems[0], v128u16, V3);
  SUB_REG(H4, simd.v[4].words.elems[0], v128u16, V4);
  SUB_REG(H5, simd.v[5].words.elems[0], v128u16, V5);
  SUB_REG(H6, simd.v[6].words.elems[0], v128u16, V6);
  SUB_REG(H7, simd.v[7].words.elems[0], v128u16, V7);
  SUB_REG(H8, simd.v[8].words.elems[0], v128u16, V8);
  SUB_REG(H9, simd.v[9].words.elems[0], v128u16, V9);
  SUB_REG(H10, simd.v[10].words.elems[0], v128u16, V10);
  SUB_REG(H11, simd.v[11].words.elems[0], v128u16, V11);
  SUB_REG(H12, simd.v[12].words.elems[0], v128u16, V12);
  SUB_REG(H13, simd.v[13].words.elems[0], v128u16, V13);
  SUB_REG(H14, simd.v[14].words.elems[0], v128u16, V14);
  SUB_REG(H15, simd.v[15].words.elems[0], v128u16, V15);
  SUB_REG(H16, simd.v[16].words.elems[0], v128u16, V16);
  SUB_REG(H17, simd.v[17].words.elems[0], v128u16, V17);
  SUB_REG(H18, simd.v[18].words.elems[0], v128u16, V18);
  SUB_REG(H19, simd.v[19].words.elems[0], v128u16, V19);
  SUB_REG(H20, simd.v[20].words.elems[0], v128u16, V20);
  SUB_REG(H21, simd.v[21].words.elems[0], v128u16, V21);
  SUB_REG(H22, simd.v[22].words.elems[0], v128u16, V22);
  SUB_REG(H23, simd.v[23].words.elems[0], v128u16, V23);
  SUB_REG(H24, simd.v[24].words.elems[0], v128u16, V24);
  SUB_REG(H25, simd.v[25].words.elems[0], v128u16, V25);
  SUB_REG(H26, simd.v[26].words.elems[0], v128u16, V26);
  SUB_REG(H27, simd.v[27].words.elems[0], v128u16, V27);
  SUB_REG(H28, simd.v[28].words.elems[0], v128u16, V28);
  SUB_REG(H29, simd.v[29].words.elems[0], v128u16, V29);
  SUB_REG(H30, simd.v[30].words.elems[0], v128u16, V30);
  SUB_REG(H31, simd.v[31].words.elems[0], v128u16, V31);

  SUB_REG(S0, simd.v[0].dwords.elems[0], v128u32, V0);
  SUB_REG(S1, simd.v[1].dwords.elems[0], v128u32, V1);
  SUB_REG(S2, simd.v[2].dwords.elems[0], v128u32, V2);
  SUB_REG(S3, simd.v[3].dwords.elems[0], v128u32, V3);
  SUB_REG(S4, simd.v[4].dwords.elems[0], v128u32, V4);
  SUB_REG(S5, simd.v[5].dwords.elems[0], v128u32, V5);
  SUB_REG(S6, simd.v[6].dwords.elems[0], v128u32, V6);
  SUB_REG(S7, simd.v[7].dwords.elems[0], v128u32, V7);
  SUB_REG(S8, simd.v[8].dwords.elems[0], v128u32, V8);
  SUB_REG(S9, simd.v[9].dwords.elems[0], v128u32, V9);
  SUB_REG(S10, simd.v[10].dwords.elems[0], v128u32, V10);
  SUB_REG(S11, simd.v[11].dwords.elems[0], v128u32, V11);
  SUB_REG(S12, simd.v[12].dwords.elems[0], v128u32, V12);
  SUB_REG(S13, simd.v[13].dwords.elems[0], v128u32, V13);
  SUB_REG(S14, simd.v[14].dwords.elems[0], v128u32, V14);
  SUB_REG(S15, simd.v[15].dwords.elems[0], v128u32, V15);
  SUB_REG(S16, simd.v[16].dwords.elems[0], v128u32, V16);
  SUB_REG(S17, simd.v[17].dwords.elems[0], v128u32, V17);
  SUB_REG(S18, simd.v[18].dwords.elems[0], v128u32, V18);
  SUB_REG(S19, simd.v[19].dwords.elems[0], v128u32, V19);
  SUB_REG(S20, simd.v[20].dwords.elems[0], v128u32, V20);
  SUB_REG(S21, simd.v[21].dwords.elems[0], v128u32, V21);
  SUB_REG(S22, simd.v[22].dwords.elems[0], v128u32, V22);
  SUB_REG(S23, simd.v[23].dwords.elems[0], v128u32, V23);
  SUB_REG(S24, simd.v[24].dwords.elems[0], v128u32, V24);
  SUB_REG(S25, simd.v[25].dwords.elems[0], v128u32, V25);
  SUB_REG(S26, simd.v[26].dwords.elems[0], v128u32, V26);
  SUB_REG(S27, simd.v[27].dwords.elems[0], v128u32, V27);
  SUB_REG(S28, simd.v[28].dwords.elems[0], v128u32, V28);
  SUB_REG(S29, simd.v[29].dwords.elems[0], v128u32, V29);
  SUB_REG(S30, simd.v[30].dwords.elems[0], v128u32, V30);
  SUB_REG(S31, simd.v[31].dwords.elems[0], v128u32, V31);

  SUB_REG(D0, simd.v[0].qwords.elems[0], v128u64, V0);
  SUB_REG(D1, simd.v[1].qwords.elems[0], v128u64, V1);
  SUB_REG(D2, simd.v[2].qwords.elems[0], v128u64, V2);
  SUB_REG(D3, simd.v[3].qwords.elems[0], v128u64, V3);
  SUB_REG(D4, simd.v[4].qwords.elems[0], v128u64, V4);
  SUB_REG(D5, simd.v[5].qwords.elems[0], v128u64, V5);
  SUB_REG(D6, simd.v[6].qwords.elems[0], v128u64, V6);
  SUB_REG(D7, simd.v[7].qwords.elems[0], v128u64, V7);
  SUB_REG(D8, simd.v[8].qwords.elems[0], v128u64, V8);
  SUB_REG(D9, simd.v[9].qwords.elems[0], v128u64, V9);
  SUB_REG(D10, simd.v[10].qwords.elems[0], v128u64, V10);
  SUB_REG(D11, simd.v[11].qwords.elems[0], v128u64, V11);
  SUB_REG(D12, simd.v[12].qwords.elems[0], v128u64, V12);
  SUB_REG(D13, simd.v[13].qwords.elems[0], v128u64, V13);
  SUB_REG(D14, simd.v[14].qwords.elems[0], v128u64, V14);
  SUB_REG(D15, simd.v[15].qwords.elems[0], v128u64, V15);
  SUB_REG(D16, simd.v[16].qwords.elems[0], v128u64, V16);
  SUB_REG(D17, simd.v[17].qwords.elems[0], v128u64, V17);
  SUB_REG(D18, simd.v[18].qwords.elems[0], v128u64, V18);
  SUB_REG(D19, simd.v[19].qwords.elems[0], v128u64, V19);
  SUB_REG(D20, simd.v[20].qwords.elems[0], v128u64, V20);
  SUB_REG(D21, simd.v[21].qwords.elems[0], v128u64, V21);
  SUB_REG(D22, simd.v[22].qwords.elems[0], v128u64, V22);
  SUB_REG(D23, simd.v[23].qwords.elems[0], v128u64, V23);
  SUB_REG(D24, simd.v[24].qwords.elems[0], v128u64, V24);
  SUB_REG(D25, simd.v[25].qwords.elems[0], v128u64, V25);
  SUB_REG(D26, simd.v[26].qwords.elems[0], v128u64, V26);
  SUB_REG(D27, simd.v[27].qwords.elems[0], v128u64, V27);
  SUB_REG(D28, simd.v[28].qwords.elems[0], v128u64, V28);
  SUB_REG(D29, simd.v[29].qwords.elems[0], v128u64, V29);
  SUB_REG(D30, simd.v[30].qwords.elems[0], v128u64, V30);
  SUB_REG(D31, simd.v[31].qwords.elems[0], v128u64, V31);

  SUB_REG(Q0, simd.v[0].dqwords.elems[0], v128u128, V0);
  SUB_REG(Q1, simd.v[1].dqwords.elems[0], v128u128, V1);
  SUB_REG(Q2, simd.v[2].dqwords.elems[0], v128u128, V2);
  SUB_REG(Q3, simd.v[3].dqwords.elems[0], v128u128, V3);
  SUB_REG(Q4, simd.v[4].dqwords.elems[0], v128u128, V4);
  SUB_REG(Q5, simd.v[5].dqwords.elems[0], v128u128, V5);
  SUB_REG(Q6, simd.v[6].dqwords.elems[0], v128u128, V6);
  SUB_REG(Q7, simd.v[7].dqwords.elems[0], v128u128, V7);
  SUB_REG(Q8, simd.v[8].dqwords.elems[0], v128u128, V8);
  SUB_REG(Q9, simd.v[9].dqwords.elems[0], v128u128, V9);
  SUB_REG(Q10, simd.v[10].dqwords.elems[0], v128u128, V10);
  SUB_REG(Q11, simd.v[11].dqwords.elems[0], v128u128, V11);
  SUB_REG(Q12, simd.v[12].dqwords.elems[0], v128u128, V12);
  SUB_REG(Q13, simd.v[13].dqwords.elems[0], v128u128, V13);
  SUB_REG(Q14, simd.v[14].dqwords.elems[0], v128u128, V14);
  SUB_REG(Q15, simd.v[15].dqwords.elems[0], v128u128, V15);
  SUB_REG(Q16, simd.v[16].dqwords.elems[0], v128u128, V16);
  SUB_REG(Q17, simd.v[17].dqwords.elems[0], v128u128, V17);
  SUB_REG(Q18, simd.v[18].dqwords.elems[0], v128u128, V18);
  SUB_REG(Q19, simd.v[19].dqwords.elems[0], v128u128, V19);
  SUB_REG(Q20, simd.v[20].dqwords.elems[0], v128u128, V20);
  SUB_REG(Q21, simd.v[21].dqwords.elems[0], v128u128, V21);
  SUB_REG(Q22, simd.v[22].dqwords.elems[0], v128u128, V22);
  SUB_REG(Q23, simd.v[23].dqwords.elems[0], v128u128, V23);
  SUB_REG(Q24, simd.v[24].dqwords.elems[0], v128u128, V24);
  SUB_REG(Q25, simd.v[25].dqwords.elems[0], v128u128, V25);
  SUB_REG(Q26, simd.v[26].dqwords.elems[0], v128u128, V26);
  SUB_REG(Q27, simd.v[27].dqwords.elems[0], v128u128, V27);
  SUB_REG(Q28, simd.v[28].dqwords.elems[0], v128u128, V28);
  SUB_REG(Q29, simd.v[29].dqwords.elems[0], v128u128, V29);
  SUB_REG(Q30, simd.v[30].dqwords.elems[0], v128u128, V30);
  SUB_REG(Q31, simd.v[31].dqwords.elems[0], v128u128, V31);

  REG(TPIDR_EL0, sr.tpidr_el0.qword, u64);
  REG(TPIDRRO_EL0, sr.tpidrro_el0.qword, u64);
}
}  // namespace remill
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

#define OFFSET_OF(state, access) \
  (reinterpret_cast<uintptr_t>(&state.access) \
    - reinterpret_cast<uintptr_t>(&state))

#define REG(state, name, access, type) \
  AddRegister(#name, type, OFFSET_OF(state, access), nullptr)

#define SUB_REG(state, name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(state, access), #parent_reg_name)

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

  AArch64State state;

  REG(state, X0, gpr.x0.qword, u64);
  REG(state, X1, gpr.x1.qword, u64);
  REG(state, X2, gpr.x2.qword, u64);
  REG(state, X3, gpr.x3.qword, u64);
  REG(state, X4, gpr.x4.qword, u64);
  REG(state, X5, gpr.x5.qword, u64);
  REG(state, X6, gpr.x6.qword, u64);
  REG(state, X7, gpr.x7.qword, u64);
  REG(state, X8, gpr.x8.qword, u64);
  REG(state, X9, gpr.x9.qword, u64);
  REG(state, X10, gpr.x10.qword, u64);
  REG(state, X11, gpr.x11.qword, u64);
  REG(state, X12, gpr.x12.qword, u64);
  REG(state, X13, gpr.x13.qword, u64);
  REG(state, X14, gpr.x14.qword, u64);
  REG(state, X15, gpr.x15.qword, u64);
  REG(state, X16, gpr.x16.qword, u64);
  REG(state, X17, gpr.x17.qword, u64);
  REG(state, X18, gpr.x18.qword, u64);
  REG(state, X19, gpr.x19.qword, u64);
  REG(state, X20, gpr.x20.qword, u64);
  REG(state, X21, gpr.x21.qword, u64);
  REG(state, X22, gpr.x22.qword, u64);
  REG(state, X23, gpr.x23.qword, u64);
  REG(state, X24, gpr.x24.qword, u64);
  REG(state, X25, gpr.x25.qword, u64);
  REG(state, X26, gpr.x26.qword, u64);
  REG(state, X27, gpr.x27.qword, u64);
  REG(state, X28, gpr.x28.qword, u64);
  REG(state, X29, gpr.x29.qword, u64);
  REG(state, X30, gpr.x30.qword, u64);

  SUB_REG(state, W0, gpr.x0.dword, u32, X0);
  SUB_REG(state, W1, gpr.x1.dword, u32, X1);
  SUB_REG(state, W2, gpr.x2.dword, u32, X2);
  SUB_REG(state, W3, gpr.x3.dword, u32, X3);
  SUB_REG(state, W4, gpr.x4.dword, u32, X4);
  SUB_REG(state, W5, gpr.x5.dword, u32, X5);
  SUB_REG(state, W6, gpr.x6.dword, u32, X6);
  SUB_REG(state, W7, gpr.x7.dword, u32, X7);
  SUB_REG(state, W8, gpr.x8.dword, u32, X8);
  SUB_REG(state, W9, gpr.x9.dword, u32, X9);
  SUB_REG(state, W10, gpr.x10.dword, u32, X10);
  SUB_REG(state, W11, gpr.x11.dword, u32, X11);
  SUB_REG(state, W12, gpr.x12.dword, u32, X12);
  SUB_REG(state, W13, gpr.x13.dword, u32, X13);
  SUB_REG(state, W14, gpr.x14.dword, u32, X14);
  SUB_REG(state, W15, gpr.x15.dword, u32, X15);
  SUB_REG(state, W16, gpr.x16.dword, u32, X16);
  SUB_REG(state, W17, gpr.x17.dword, u32, X17);
  SUB_REG(state, W18, gpr.x18.dword, u32, X18);
  SUB_REG(state, W19, gpr.x19.dword, u32, X19);
  SUB_REG(state, W20, gpr.x20.dword, u32, X20);
  SUB_REG(state, W21, gpr.x21.dword, u32, X21);
  SUB_REG(state, W22, gpr.x22.dword, u32, X22);
  SUB_REG(state, W23, gpr.x23.dword, u32, X23);
  SUB_REG(state, W24, gpr.x24.dword, u32, X24);
  SUB_REG(state, W25, gpr.x25.dword, u32, X25);
  SUB_REG(state, W26, gpr.x26.dword, u32, X26);
  SUB_REG(state, W27, gpr.x27.dword, u32, X27);
  SUB_REG(state, W28, gpr.x28.dword, u32, X28);
  SUB_REG(state, W29, gpr.x29.dword, u32, X29);
  SUB_REG(state, W30, gpr.x30.dword, u32, X30);

  REG(state, PC, gpr.pc.qword, u64);
  SUB_REG(state, WPC, gpr.pc.dword, u32, PC);

  REG(state, SP, gpr.sp.qword, u64);
  SUB_REG(state, WSP, gpr.sp.dword, u32, SP);

  SUB_REG(state, LP, gpr.x30.qword, u64, X30);
  SUB_REG(state, WLP, gpr.x30.dword, u32, LP);

  REG(state, V0, simd.v[0].bytes.elems[0], v128u8);
  REG(state, V1, simd.v[1].bytes.elems[0], v128u8);
  REG(state, V2, simd.v[2].bytes.elems[0], v128u8);
  REG(state, V3, simd.v[3].bytes.elems[0], v128u8);
  REG(state, V4, simd.v[4].bytes.elems[0], v128u8);
  REG(state, V5, simd.v[5].bytes.elems[0], v128u8);
  REG(state, V6, simd.v[6].bytes.elems[0], v128u8);
  REG(state, V7, simd.v[7].bytes.elems[0], v128u8);
  REG(state, V8, simd.v[8].bytes.elems[0], v128u8);
  REG(state, V9, simd.v[9].bytes.elems[0], v128u8);
  REG(state, V10, simd.v[10].bytes.elems[0], v128u8);
  REG(state, V11, simd.v[11].bytes.elems[0], v128u8);
  REG(state, V12, simd.v[12].bytes.elems[0], v128u8);
  REG(state, V13, simd.v[13].bytes.elems[0], v128u8);
  REG(state, V14, simd.v[14].bytes.elems[0], v128u8);
  REG(state, V15, simd.v[15].bytes.elems[0], v128u8);
  REG(state, V16, simd.v[16].bytes.elems[0], v128u8);
  REG(state, V17, simd.v[17].bytes.elems[0], v128u8);
  REG(state, V18, simd.v[18].bytes.elems[0], v128u8);
  REG(state, V19, simd.v[19].bytes.elems[0], v128u8);
  REG(state, V20, simd.v[20].bytes.elems[0], v128u8);
  REG(state, V21, simd.v[21].bytes.elems[0], v128u8);
  REG(state, V22, simd.v[22].bytes.elems[0], v128u8);
  REG(state, V23, simd.v[23].bytes.elems[0], v128u8);
  REG(state, V24, simd.v[24].bytes.elems[0], v128u8);
  REG(state, V25, simd.v[25].bytes.elems[0], v128u8);
  REG(state, V26, simd.v[26].bytes.elems[0], v128u8);
  REG(state, V27, simd.v[27].bytes.elems[0], v128u8);
  REG(state, V28, simd.v[28].bytes.elems[0], v128u8);
  REG(state, V29, simd.v[29].bytes.elems[0], v128u8);
  REG(state, V30, simd.v[30].bytes.elems[0], v128u8);
  REG(state, V31, simd.v[31].bytes.elems[0], v128u8);

  SUB_REG(state, B0, simd.v[0].bytes.elems[0], v128u8, V0);
  SUB_REG(state, B1, simd.v[1].bytes.elems[0], v128u8, V1);
  SUB_REG(state, B2, simd.v[2].bytes.elems[0], v128u8, V2);
  SUB_REG(state, B3, simd.v[3].bytes.elems[0], v128u8, V3);
  SUB_REG(state, B4, simd.v[4].bytes.elems[0], v128u8, V4);
  SUB_REG(state, B5, simd.v[5].bytes.elems[0], v128u8, V5);
  SUB_REG(state, B6, simd.v[6].bytes.elems[0], v128u8, V6);
  SUB_REG(state, B7, simd.v[7].bytes.elems[0], v128u8, V7);
  SUB_REG(state, B8, simd.v[8].bytes.elems[0], v128u8, V8);
  SUB_REG(state, B9, simd.v[9].bytes.elems[0], v128u8, V9);
  SUB_REG(state, B10, simd.v[10].bytes.elems[0], v128u8, V10);
  SUB_REG(state, B11, simd.v[11].bytes.elems[0], v128u8, V11);
  SUB_REG(state, B12, simd.v[12].bytes.elems[0], v128u8, V12);
  SUB_REG(state, B13, simd.v[13].bytes.elems[0], v128u8, V13);
  SUB_REG(state, B14, simd.v[14].bytes.elems[0], v128u8, V14);
  SUB_REG(state, B15, simd.v[15].bytes.elems[0], v128u8, V15);
  SUB_REG(state, B16, simd.v[16].bytes.elems[0], v128u8, V16);
  SUB_REG(state, B17, simd.v[17].bytes.elems[0], v128u8, V17);
  SUB_REG(state, B18, simd.v[18].bytes.elems[0], v128u8, V18);
  SUB_REG(state, B19, simd.v[19].bytes.elems[0], v128u8, V19);
  SUB_REG(state, B20, simd.v[20].bytes.elems[0], v128u8, V20);
  SUB_REG(state, B21, simd.v[21].bytes.elems[0], v128u8, V21);
  SUB_REG(state, B22, simd.v[22].bytes.elems[0], v128u8, V22);
  SUB_REG(state, B23, simd.v[23].bytes.elems[0], v128u8, V23);
  SUB_REG(state, B24, simd.v[24].bytes.elems[0], v128u8, V24);
  SUB_REG(state, B25, simd.v[25].bytes.elems[0], v128u8, V25);
  SUB_REG(state, B26, simd.v[26].bytes.elems[0], v128u8, V26);
  SUB_REG(state, B27, simd.v[27].bytes.elems[0], v128u8, V27);
  SUB_REG(state, B28, simd.v[28].bytes.elems[0], v128u8, V28);
  SUB_REG(state, B29, simd.v[29].bytes.elems[0], v128u8, V29);
  SUB_REG(state, B30, simd.v[30].bytes.elems[0], v128u8, V30);
  SUB_REG(state, B31, simd.v[31].bytes.elems[0], v128u8, V31);

  SUB_REG(state, H0, simd.v[0].words.elems[0], v128u16, V0);
  SUB_REG(state, H1, simd.v[1].words.elems[0], v128u16, V1);
  SUB_REG(state, H2, simd.v[2].words.elems[0], v128u16, V2);
  SUB_REG(state, H3, simd.v[3].words.elems[0], v128u16, V3);
  SUB_REG(state, H4, simd.v[4].words.elems[0], v128u16, V4);
  SUB_REG(state, H5, simd.v[5].words.elems[0], v128u16, V5);
  SUB_REG(state, H6, simd.v[6].words.elems[0], v128u16, V6);
  SUB_REG(state, H7, simd.v[7].words.elems[0], v128u16, V7);
  SUB_REG(state, H8, simd.v[8].words.elems[0], v128u16, V8);
  SUB_REG(state, H9, simd.v[9].words.elems[0], v128u16, V9);
  SUB_REG(state, H10, simd.v[10].words.elems[0], v128u16, V10);
  SUB_REG(state, H11, simd.v[11].words.elems[0], v128u16, V11);
  SUB_REG(state, H12, simd.v[12].words.elems[0], v128u16, V12);
  SUB_REG(state, H13, simd.v[13].words.elems[0], v128u16, V13);
  SUB_REG(state, H14, simd.v[14].words.elems[0], v128u16, V14);
  SUB_REG(state, H15, simd.v[15].words.elems[0], v128u16, V15);
  SUB_REG(state, H16, simd.v[16].words.elems[0], v128u16, V16);
  SUB_REG(state, H17, simd.v[17].words.elems[0], v128u16, V17);
  SUB_REG(state, H18, simd.v[18].words.elems[0], v128u16, V18);
  SUB_REG(state, H19, simd.v[19].words.elems[0], v128u16, V19);
  SUB_REG(state, H20, simd.v[20].words.elems[0], v128u16, V20);
  SUB_REG(state, H21, simd.v[21].words.elems[0], v128u16, V21);
  SUB_REG(state, H22, simd.v[22].words.elems[0], v128u16, V22);
  SUB_REG(state, H23, simd.v[23].words.elems[0], v128u16, V23);
  SUB_REG(state, H24, simd.v[24].words.elems[0], v128u16, V24);
  SUB_REG(state, H25, simd.v[25].words.elems[0], v128u16, V25);
  SUB_REG(state, H26, simd.v[26].words.elems[0], v128u16, V26);
  SUB_REG(state, H27, simd.v[27].words.elems[0], v128u16, V27);
  SUB_REG(state, H28, simd.v[28].words.elems[0], v128u16, V28);
  SUB_REG(state, H29, simd.v[29].words.elems[0], v128u16, V29);
  SUB_REG(state, H30, simd.v[30].words.elems[0], v128u16, V30);
  SUB_REG(state, H31, simd.v[31].words.elems[0], v128u16, V31);

  SUB_REG(state, S0, simd.v[0].dwords.elems[0], v128u32, V0);
  SUB_REG(state, S1, simd.v[1].dwords.elems[0], v128u32, V1);
  SUB_REG(state, S2, simd.v[2].dwords.elems[0], v128u32, V2);
  SUB_REG(state, S3, simd.v[3].dwords.elems[0], v128u32, V3);
  SUB_REG(state, S4, simd.v[4].dwords.elems[0], v128u32, V4);
  SUB_REG(state, S5, simd.v[5].dwords.elems[0], v128u32, V5);
  SUB_REG(state, S6, simd.v[6].dwords.elems[0], v128u32, V6);
  SUB_REG(state, S7, simd.v[7].dwords.elems[0], v128u32, V7);
  SUB_REG(state, S8, simd.v[8].dwords.elems[0], v128u32, V8);
  SUB_REG(state, S9, simd.v[9].dwords.elems[0], v128u32, V9);
  SUB_REG(state, S10, simd.v[10].dwords.elems[0], v128u32, V10);
  SUB_REG(state, S11, simd.v[11].dwords.elems[0], v128u32, V11);
  SUB_REG(state, S12, simd.v[12].dwords.elems[0], v128u32, V12);
  SUB_REG(state, S13, simd.v[13].dwords.elems[0], v128u32, V13);
  SUB_REG(state, S14, simd.v[14].dwords.elems[0], v128u32, V14);
  SUB_REG(state, S15, simd.v[15].dwords.elems[0], v128u32, V15);
  SUB_REG(state, S16, simd.v[16].dwords.elems[0], v128u32, V16);
  SUB_REG(state, S17, simd.v[17].dwords.elems[0], v128u32, V17);
  SUB_REG(state, S18, simd.v[18].dwords.elems[0], v128u32, V18);
  SUB_REG(state, S19, simd.v[19].dwords.elems[0], v128u32, V19);
  SUB_REG(state, S20, simd.v[20].dwords.elems[0], v128u32, V20);
  SUB_REG(state, S21, simd.v[21].dwords.elems[0], v128u32, V21);
  SUB_REG(state, S22, simd.v[22].dwords.elems[0], v128u32, V22);
  SUB_REG(state, S23, simd.v[23].dwords.elems[0], v128u32, V23);
  SUB_REG(state, S24, simd.v[24].dwords.elems[0], v128u32, V24);
  SUB_REG(state, S25, simd.v[25].dwords.elems[0], v128u32, V25);
  SUB_REG(state, S26, simd.v[26].dwords.elems[0], v128u32, V26);
  SUB_REG(state, S27, simd.v[27].dwords.elems[0], v128u32, V27);
  SUB_REG(state, S28, simd.v[28].dwords.elems[0], v128u32, V28);
  SUB_REG(state, S29, simd.v[29].dwords.elems[0], v128u32, V29);
  SUB_REG(state, S30, simd.v[30].dwords.elems[0], v128u32, V30);
  SUB_REG(state, S31, simd.v[31].dwords.elems[0], v128u32, V31);

  SUB_REG(state, D0, simd.v[0].qwords.elems[0], v128u64, V0);
  SUB_REG(state, D1, simd.v[1].qwords.elems[0], v128u64, V1);
  SUB_REG(state, D2, simd.v[2].qwords.elems[0], v128u64, V2);
  SUB_REG(state, D3, simd.v[3].qwords.elems[0], v128u64, V3);
  SUB_REG(state, D4, simd.v[4].qwords.elems[0], v128u64, V4);
  SUB_REG(state, D5, simd.v[5].qwords.elems[0], v128u64, V5);
  SUB_REG(state, D6, simd.v[6].qwords.elems[0], v128u64, V6);
  SUB_REG(state, D7, simd.v[7].qwords.elems[0], v128u64, V7);
  SUB_REG(state, D8, simd.v[8].qwords.elems[0], v128u64, V8);
  SUB_REG(state, D9, simd.v[9].qwords.elems[0], v128u64, V9);
  SUB_REG(state, D10, simd.v[10].qwords.elems[0], v128u64, V10);
  SUB_REG(state, D11, simd.v[11].qwords.elems[0], v128u64, V11);
  SUB_REG(state, D12, simd.v[12].qwords.elems[0], v128u64, V12);
  SUB_REG(state, D13, simd.v[13].qwords.elems[0], v128u64, V13);
  SUB_REG(state, D14, simd.v[14].qwords.elems[0], v128u64, V14);
  SUB_REG(state, D15, simd.v[15].qwords.elems[0], v128u64, V15);
  SUB_REG(state, D16, simd.v[16].qwords.elems[0], v128u64, V16);
  SUB_REG(state, D17, simd.v[17].qwords.elems[0], v128u64, V17);
  SUB_REG(state, D18, simd.v[18].qwords.elems[0], v128u64, V18);
  SUB_REG(state, D19, simd.v[19].qwords.elems[0], v128u64, V19);
  SUB_REG(state, D20, simd.v[20].qwords.elems[0], v128u64, V20);
  SUB_REG(state, D21, simd.v[21].qwords.elems[0], v128u64, V21);
  SUB_REG(state, D22, simd.v[22].qwords.elems[0], v128u64, V22);
  SUB_REG(state, D23, simd.v[23].qwords.elems[0], v128u64, V23);
  SUB_REG(state, D24, simd.v[24].qwords.elems[0], v128u64, V24);
  SUB_REG(state, D25, simd.v[25].qwords.elems[0], v128u64, V25);
  SUB_REG(state, D26, simd.v[26].qwords.elems[0], v128u64, V26);
  SUB_REG(state, D27, simd.v[27].qwords.elems[0], v128u64, V27);
  SUB_REG(state, D28, simd.v[28].qwords.elems[0], v128u64, V28);
  SUB_REG(state, D29, simd.v[29].qwords.elems[0], v128u64, V29);
  SUB_REG(state, D30, simd.v[30].qwords.elems[0], v128u64, V30);
  SUB_REG(state, D31, simd.v[31].qwords.elems[0], v128u64, V31);

  SUB_REG(state, Q0, simd.v[0].dqwords.elems[0], v128u128, V0);
  SUB_REG(state, Q1, simd.v[1].dqwords.elems[0], v128u128, V1);
  SUB_REG(state, Q2, simd.v[2].dqwords.elems[0], v128u128, V2);
  SUB_REG(state, Q3, simd.v[3].dqwords.elems[0], v128u128, V3);
  SUB_REG(state, Q4, simd.v[4].dqwords.elems[0], v128u128, V4);
  SUB_REG(state, Q5, simd.v[5].dqwords.elems[0], v128u128, V5);
  SUB_REG(state, Q6, simd.v[6].dqwords.elems[0], v128u128, V6);
  SUB_REG(state, Q7, simd.v[7].dqwords.elems[0], v128u128, V7);
  SUB_REG(state, Q8, simd.v[8].dqwords.elems[0], v128u128, V8);
  SUB_REG(state, Q9, simd.v[9].dqwords.elems[0], v128u128, V9);
  SUB_REG(state, Q10, simd.v[10].dqwords.elems[0], v128u128, V10);
  SUB_REG(state, Q11, simd.v[11].dqwords.elems[0], v128u128, V11);
  SUB_REG(state, Q12, simd.v[12].dqwords.elems[0], v128u128, V12);
  SUB_REG(state, Q13, simd.v[13].dqwords.elems[0], v128u128, V13);
  SUB_REG(state, Q14, simd.v[14].dqwords.elems[0], v128u128, V14);
  SUB_REG(state, Q15, simd.v[15].dqwords.elems[0], v128u128, V15);
  SUB_REG(state, Q16, simd.v[16].dqwords.elems[0], v128u128, V16);
  SUB_REG(state, Q17, simd.v[17].dqwords.elems[0], v128u128, V17);
  SUB_REG(state, Q18, simd.v[18].dqwords.elems[0], v128u128, V18);
  SUB_REG(state, Q19, simd.v[19].dqwords.elems[0], v128u128, V19);
  SUB_REG(state, Q20, simd.v[20].dqwords.elems[0], v128u128, V20);
  SUB_REG(state, Q21, simd.v[21].dqwords.elems[0], v128u128, V21);
  SUB_REG(state, Q22, simd.v[22].dqwords.elems[0], v128u128, V22);
  SUB_REG(state, Q23, simd.v[23].dqwords.elems[0], v128u128, V23);
  SUB_REG(state, Q24, simd.v[24].dqwords.elems[0], v128u128, V24);
  SUB_REG(state, Q25, simd.v[25].dqwords.elems[0], v128u128, V25);
  SUB_REG(state, Q26, simd.v[26].dqwords.elems[0], v128u128, V26);
  SUB_REG(state, Q27, simd.v[27].dqwords.elems[0], v128u128, V27);
  SUB_REG(state, Q28, simd.v[28].dqwords.elems[0], v128u128, V28);
  SUB_REG(state, Q29, simd.v[29].dqwords.elems[0], v128u128, V29);
  SUB_REG(state, Q30, simd.v[30].dqwords.elems[0], v128u128, V30);
  SUB_REG(state, Q31, simd.v[31].dqwords.elems[0], v128u128, V31);

  REG(state, TPIDR_EL0, sr.tpidr_el0.qword, u64);
  REG(state, TPIDRRO_EL0, sr.tpidrro_el0.qword, u64);
}
}  // namespace remill
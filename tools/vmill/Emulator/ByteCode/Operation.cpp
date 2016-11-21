/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <sstream>

#include "tools/vmill/Emulator/ByteCode/Operation.h"
#include "remill/Arch/Runtime/HyperCall.h"

namespace remill {
namespace vmill {

// Relative size of each pseudo-operand structure.
const uint64_t OpCode::OpCode::kNumOpSlots[] = {
#define OP(name, num_op_slots, bytes_read, bytes_written) \
  [OpCode::k ## name] = num_op_slots,
#include "tools/vmill/Emulator/ByteCode/Operation.inc"
#undef OP
};

const uint64_t OpCode::OpCode::kNumBytesRead[] = {
#define OP(name, num_op_slots, bytes_read, bytes_written) \
  [OpCode::k ## name] = bytes_read,
#include "tools/vmill/Emulator/ByteCode/Operation.inc"
};

const uint64_t OpCode::OpCode::kNumBitsRead[] = {
#define OP(name, num_op_slots, bytes_read, bytes_written) \
  [OpCode::k ## name] = bytes_read * 8,
#include "tools/vmill/Emulator/ByteCode/Operation.inc"
};

const uint64_t OpCode::OpCode::kNumBytesWritten[] = {
#define OP(name, num_op_slots, bytes_read, bytes_written) \
  [OpCode::k ## name] = bytes_written,
#include "tools/vmill/Emulator/ByteCode/Operation.inc"
};

const uint64_t OpCode::OpCode::kNumBitsWritten[] = {
#define OP(name, num_op_slots, bytes_read, bytes_written) \
  [OpCode::k ## name] = bytes_written * 8,
#include "tools/vmill/Emulator/ByteCode/Operation.inc"
};


const char * const OpCode::kName[] = {
#define OP(name, num_op_slots, bytes_read, bytes_written) \
    [OpCode::k ## name] = #name,
#include "tools/vmill/Emulator/ByteCode/Operation.inc"
    [(OpCode::kInvalid + 1) ... 255] = "!UNDEFINED!"
};

const char * const Intrinsic::kName[] = {
    [Intrinsic::kPopCount] = "popcount",
    [Intrinsic::kNumLeadingZeros] = "clz",
    [Intrinsic::kNumTrailingZeros] = "ctz",
    [Intrinsic::kByteSwap] = "bswap",
    [Intrinsic::kInvalid] = "INVALID",
    [(Intrinsic::kInvalid + 1) ... 255] = "!UNDEFINED!",
};

const char * const FPIntrinsic::kName[] = {
    [FPIntrinsic::kSin] = "sin",
    [FPIntrinsic::kCos] = "cos",
    [FPIntrinsic::kTan] = "tan",
    [FPIntrinsic::kArcTan] = "arctan",
    [FPIntrinsic::kRoundToNearestInt] = "nearbyint",
    [FPIntrinsic::kTruncToNearestInt] = "trunc",
    [FPIntrinsic::kInvalid] = "INVALID",
    [(FPIntrinsic::kInvalid + 1) ... 255] = "!UNDEFINED!",
};

namespace {
template <typename T>
const T &O(const Operation *op) {
  return *reinterpret_cast<const T *>(op);
}

inline int I(VarId val) {
  return static_cast<int>(val);
}

static const char * const kHyperCallName[] = {
  [SyncHyperCall::kInvalid] = "INVALID!",
  [SyncHyperCall::kX86CPUID] = "X86:CPUID",
  [SyncHyperCall::kX86ReadTSC] = "X86:RDTSC",
  [SyncHyperCall::kX86ReadTSCP] = "X86:RDTSCP",
  [SyncHyperCall::kX86EmulateInstruction] = "X86:MICROX",
  [SyncHyperCall::kAMD64EmulateInstruction] = "AMD64:MICROX",
};

}  // namespace

// Serialize the operation into a string (for debugging).
std::string Operation::Serialize(void) const {
  std::stringstream ss;
  switch (op_code) {
    case OpCode::kConstant:
      ss << "constant @ pool[" << O<Constant>(this).offset << "]";
      break;
    case OpCode::kAllocOverflowData:
      ss << "alloc slot";
      break;
    case OpCode::kEnter32:
      ss << "enter32 " << std::hex << O<Enter32>(this).pc;
      break;
    case OpCode::kEnter64:
      ss << "enter64 " << std::hex << O<Enter64>(this).pc;
      break;
    case OpCode::kExitCall:
      ss << "exit call %" << I(O<Exit>(this).pc_var);
      break;
    case OpCode::kExitRet:
      ss << "exit ret %" << I(O<Exit>(this).pc_var);
      break;
    case OpCode::kExitJump:
      ss << "exit jmp %" << I(O<Exit>(this).pc_var);
      break;
    case OpCode::kExitAsyncHyperCall:
      ss << "exit async hypercall";
      break;
    case OpCode::kExitError:
      ss << "exit error %" << I(O<Exit>(this).pc_var);
      break;
    case OpCode::kGoTo:
      ss << "goto %" << I(O<GoTo>(this).true_var);
      break;
    case OpCode::kCondGoTo:
      ss << "goto %" << I(O<GoTo>(this).true_var)
         << " if %" << I(O<GoTo>(this).cond_var)
         << " else %" << I(O<GoTo>(this).false_var);
      break;

    case OpCode::kJumpFarBackward:
      ss << "jmp rel far @ cache[here - " << O<JumpFar>(this).rel_offset << "]";
      break;

    case OpCode::kJumpFarForward:
      ss << "jmp rel far @ cache[here + " << O<JumpFar>(this).rel_offset << "";
      break;

    case OpCode::kJump: {
      auto disp = O<Jump>(this).rel_offset;
      if (disp < 0) {
        ss << "jmp rel short @ cache[here - " << disp << "]";
      } else {
        ss << "jmp rel short @ cache[here + " << disp << "]";
      }
      break;
    }

    case OpCode::kSyncHyperCall:
      ss << "sync hypercall " << kHyperCallName[O<HyperCall>(this).call];
      break;
    case OpCode::kIntrinsic8:
    case OpCode::kIntrinsic16:
    case OpCode::kIntrinsic32:
    case OpCode::kIntrinsic64:
    case OpCode::kIntrinsic128:
      ss << "i" << OpCode::kNumBitsRead[op_code] << " intrinsic "
         << Intrinsic::kName[O<IntrinsicCall>(this).call]
         << "(%" << I(O<IntrinsicCall>(this).src1_var) << ")";
      break;
    case OpCode::kFPIntrinsic32:
    case OpCode::kFPIntrinsic64:
      ss << "f" << OpCode::kNumBitsRead[op_code] << " intrinsic "
         << Intrinsic::kName[O<FPIntrinsicCall>(this).call]
         << "(%" << I(O<FPIntrinsicCall>(this).src1_var) << ")";
      break;
    case OpCode::kRead8:
    case OpCode::kRead16:
    case OpCode::kRead32:
    case OpCode::kRead64:
    case OpCode::kRead128:
      ss << "read i" << OpCode::kNumBitsRead[op_code] << " state["
         << O<State>(this).offset << "]";
      break;
    case OpCode::kWrite8:
    case OpCode::kWrite16:
    case OpCode::kWrite32:
    case OpCode::kWrite64:
    case OpCode::kWrite128:
      ss << "write i" << OpCode::kNumBitsRead[op_code] << " %"
         << I(O<State>(this).src_var) << " to state["
         << O<State>(this).offset << "]";
      break;

    case OpCode::kReadStack8:
    case OpCode::kReadStack16:
    case OpCode::kReadStack32:
    case OpCode::kReadStack64:
    case OpCode::kReadStack128:
      ss << "read i" << OpCode::kNumBitsRead[op_code] << " stack["
         << O<State>(this).offset << "]";
      break;
    case OpCode::kWriteStack8:
    case OpCode::kWriteStack16:
    case OpCode::kWriteStack32:
    case OpCode::kWriteStack64:
    case OpCode::kWriteStack128:
      ss << "write i" << OpCode::kNumBitsRead[op_code] << " %"
         << I(O<State>(this).src_var) << " to stack["
         << O<State>(this).offset << "]";
      break;

    case OpCode::kReadMem8:
    case OpCode::kReadMem16:
    case OpCode::kReadMem32:
    case OpCode::kReadMem64:
      ss << "read i" << OpCode::kNumBitsRead[op_code] << " memory[%"
         << I(O<Mem>(this).addr_var) << "]";
      break;
    case OpCode::kWriteMem8:
    case OpCode::kWriteMem16:
    case OpCode::kWriteMem32:
    case OpCode::kWriteMem64:
      ss << "write i" << OpCode::kNumBitsRead[op_code] << " %"
         << I(O<Mem>(this).src_var) << " to memory[%"
         << I(O<Mem>(this).addr_var) << "]";
      break;
    case OpCode::kZero:
      ss << "0";
      break;
    case OpCode::kOne:
      ss << "1";
      break;
    case OpCode::kPositive16:
      ss << O<PositiveInteger>(this).val;
      break;
    case OpCode::kNegative16:
      ss << O<NegativeInteger>(this).val;
      break;
    case OpCode::kPow2:
      ss << (1UL << O<Pow2>(this).shift);
      break;
    case OpCode::kNegPow2:
      ss << -static_cast<int32_t>(1UL << O<Pow2>(this).shift);
      break;
    case OpCode::kITE8:
    case OpCode::kITE16:
    case OpCode::kITE32:
    case OpCode::kITE64:
    case OpCode::kITE128:
      ss << "select i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<ITE>(this).true_var)
         << " if %" << I(O<ITE>(this).cond_var)
         << " else %" << I(O<ITE>(this).false_var);
      break;
    case OpCode::kAdd8:
    case OpCode::kAdd16:
    case OpCode::kAdd32:
    case OpCode::kAdd64:
    case OpCode::kAdd128:
      ss << "add i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kSub8:
    case OpCode::kSub16:
    case OpCode::kSub32:
    case OpCode::kSub64:
    case OpCode::kSub128:
      ss << "sub i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kMul8:
    case OpCode::kMul16:
    case OpCode::kMul32:
    case OpCode::kMul64:
    case OpCode::kMul128:
      ss << "mul i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kUDiv8:
    case OpCode::kUDiv16:
    case OpCode::kUDiv32:
    case OpCode::kUDiv64:
    case OpCode::kUDiv128:
      ss << "udiv i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kSDiv8:
    case OpCode::kSDiv16:
    case OpCode::kSDiv32:
    case OpCode::kSDiv64:
    case OpCode::kSDiv128:
      ss << "sdiv i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kURem8:
    case OpCode::kURem16:
    case OpCode::kURem32:
    case OpCode::kURem64:
    case OpCode::kURem128:
      ss << "urem i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kSRem8:
    case OpCode::kSRem16:
    case OpCode::kSRem32:
    case OpCode::kSRem64:
    case OpCode::kSRem128:
      ss << "srem i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kShl8:
    case OpCode::kShl16:
    case OpCode::kShl32:
    case OpCode::kShl64:
    case OpCode::kShl128:
      ss << "shl i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kLShr8:
    case OpCode::kLShr16:
    case OpCode::kLShr32:
    case OpCode::kLShr64:
    case OpCode::kLShr128:
      ss << "lshr i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kAShr8:
    case OpCode::kAShr16:
    case OpCode::kAShr32:
    case OpCode::kAShr64:
    case OpCode::kAShr128:
      ss << "ashr i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kAnd8:
    case OpCode::kAnd16:
    case OpCode::kAnd32:
    case OpCode::kAnd64:
    case OpCode::kAnd128:
      ss << "and i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kOr8:
    case OpCode::kOr16:
    case OpCode::kOr32:
    case OpCode::kOr64:
    case OpCode::kOr128:
      ss << "or i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kXor8:
    case OpCode::kXor16:
    case OpCode::kXor32:
    case OpCode::kXor64:
    case OpCode::kXor128:
      ss << "xor i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kNeg8:
    case OpCode::kNeg16:
    case OpCode::kNeg32:
    case OpCode::kNeg64:
    case OpCode::kNeg128:
      ss << "neg i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Unary>(this).src_var);
      break;
    case OpCode::kNot8:
    case OpCode::kNot16:
    case OpCode::kNot32:
    case OpCode::kNot64:
    case OpCode::kNot128:
      ss << "not i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Unary>(this).src_var);
      break;
    case OpCode::kFAdd32:
    case OpCode::kFAdd64:
      ss << "add f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFSub32:
    case OpCode::kFSub64:
      ss << "sub f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFMul32:
    case OpCode::kFMul64:
      ss << "mul f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFDiv32:
    case OpCode::kFDiv64:
      ss << "div f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFRem32:
    case OpCode::kFRem64:
      ss << "rem f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kTruncTo8:
    case OpCode::kTruncTo16:
    case OpCode::kTruncTo32:
    case OpCode::kTruncTo64:
      ss << "trunc %" << I(O<Unary>(this).src_var)
         << " to i" << OpCode::kNumBitsWritten[op_code];
      break;
    case OpCode::kZExtFrom8:
    case OpCode::kZExtFrom16:
    case OpCode::kZExtFrom32:
    case OpCode::kZExtFrom64:
      ss << "zext %" << I(O<Unary>(this).src_var)
         << " to i" << OpCode::kNumBitsWritten[op_code];
      break;
    case OpCode::kSExtFrom8:
    case OpCode::kSExtFrom16:
    case OpCode::kSExtFrom32:
    case OpCode::kSExtFrom64:
      ss << "sext %" << I(O<Unary>(this).src_var)
         << " to i" << OpCode::kNumBitsWritten[op_code];
      break;
    case OpCode::kFPTrunc64To32:
      ss << "convert f64 %" << I(O<Unary>(this).src_var)
         << " to f32";
      break;
    case OpCode::kFPExt32To64:
      ss << "convert f32 %" << I(O<Unary>(this).src_var)
         << " to f64";
      break;
    case OpCode::kFP64ToUI64:
      ss << "convert f64 %" << I(O<Unary>(this).src_var)
         << " to i64";
      break;
    case OpCode::kFP64ToUI32:
      ss << "convert f64 %" << I(O<Unary>(this).src_var)
         << " to i32";
      break;
    case OpCode::kFP32ToUI64:
      ss << "convert f32 %" << I(O<Unary>(this).src_var)
         << " to i64";
      break;
    case OpCode::kFP32ToUI32:
      ss << "convert f32 %" << I(O<Unary>(this).src_var)
         << " to i32";
      break;
    case OpCode::kFP64ToSI64:
      ss << "convert f64 %" << I(O<Unary>(this).src_var)
         << " to signed i64";
      break;
    case OpCode::kFP64ToSI32:
      ss << "convert f64 %" << I(O<Unary>(this).src_var)
         << " to signed i32";
      break;
    case OpCode::kFP32ToSI64:
      ss << "convert f32 %" << I(O<Unary>(this).src_var)
         << " to signed i64";
      break;
    case OpCode::kFP32ToSI32:
      ss << "convert f32 %" << I(O<Unary>(this).src_var)
         << " to signed i32";
      break;
    case OpCode::kUI64ToFP64:
      ss << "convert i64 %" << I(O<Unary>(this).src_var)
         << " to f64";
      break;
    case OpCode::kUI32ToFP64:
      ss << "convert i32 %" << I(O<Unary>(this).src_var)
         << " to f64";
      break;
    case OpCode::kUI64ToFP32:
      ss << "convert i64 %" << I(O<Unary>(this).src_var)
         << " to f32";
      break;
    case OpCode::kUI32ToFP32:
      ss << "convert i32 %" << I(O<Unary>(this).src_var)
         << " to f32";
      break;
    case OpCode::kSI64ToFP64:
      ss << "convert signed i64 %" << I(O<Unary>(this).src_var)
         << " to f64";
      break;
    case OpCode::kSI32ToFP64:
      ss << "convert signed i32 %" << I(O<Unary>(this).src_var)
         << " to f64";
      break;
    case OpCode::kSI64ToFP32:
      ss << "convert signed i64 %" << I(O<Unary>(this).src_var)
         << " to f32";
      break;
    case OpCode::kSI32ToFP32:
      ss << "convert signed i32 %" << I(O<Unary>(this).src_var)
         << " to f32";
      break;
    case OpCode::kFCmpEq32:
    case OpCode::kFCmpEq64:
      ss << "cmp eq f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFCmpGt32:
    case OpCode::kFCmpGt64:
      ss << "cmp gt f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFCmpGe32:
    case OpCode::kFCmpGe64:
      ss << "cmp ge f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFCmpLt32:
    case OpCode::kFCmpLt64:
      ss << "cmp lt f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFCmpLe32:
    case OpCode::kFCmpLe64:
      ss << "cmp le f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kFCmpNe32:
    case OpCode::kFCmpNe64:
      ss << "cmp ne f" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpEq8:
    case OpCode::kICmpEq16:
    case OpCode::kICmpEq32:
    case OpCode::kICmpEq64:
    case OpCode::kICmpEq128:
      ss << "cmp eq i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpNe8:
    case OpCode::kICmpNe16:
    case OpCode::kICmpNe32:
    case OpCode::kICmpNe64:
    case OpCode::kICmpNe128:
      ss << "cmp ne i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpUgt8:
    case OpCode::kICmpUgt16:
    case OpCode::kICmpUgt32:
    case OpCode::kICmpUgt64:
    case OpCode::kICmpUgt128:
      ss << "cmp ugt i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpUge8:
    case OpCode::kICmpUge16:
    case OpCode::kICmpUge32:
    case OpCode::kICmpUge64:
    case OpCode::kICmpUge128:
      ss << "cmp uge i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpUlt8:
    case OpCode::kICmpUlt16:
    case OpCode::kICmpUlt32:
    case OpCode::kICmpUlt64:
    case OpCode::kICmpUlt128:
      ss << "cmp ult i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpUle8:
    case OpCode::kICmpUle16:
    case OpCode::kICmpUle32:
    case OpCode::kICmpUle64:
    case OpCode::kICmpUle128:
      ss << "cmp ule i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpSgt8:
    case OpCode::kICmpSgt16:
    case OpCode::kICmpSgt32:
    case OpCode::kICmpSgt64:
    case OpCode::kICmpSgt128:
      ss << "cmp signed gt i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpSge8:
    case OpCode::kICmpSge16:
    case OpCode::kICmpSge32:
    case OpCode::kICmpSge64:
    case OpCode::kICmpSge128:
      ss << "cmp signed ge i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpSlt8:
    case OpCode::kICmpSlt16:
    case OpCode::kICmpSlt32:
    case OpCode::kICmpSlt64:
    case OpCode::kICmpSlt128:
      ss << "cmp signed lt i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kICmpSle8:
    case OpCode::kICmpSle16:
    case OpCode::kICmpSle32:
    case OpCode::kICmpSle64:
    case OpCode::kICmpSle128:
      ss << "cmp signed le i" << OpCode::kNumBitsRead[op_code]
         << " %" << I(O<Binary>(this).src1_var)
         << ", %" << I(O<Binary>(this).src2_var);
      break;
    case OpCode::kSafePoint:
      ss << "safepoint";
      break;
    case OpCode::kInvalid:
      ss << "invalid";
      break;
    default:
      break;
  }
  return ss.str();
}

}  // namespace vmill
}  // namespace remill

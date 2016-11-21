/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cmath>
#include <cstddef>

#include <iostream>

#include "remill/Arch/Runtime/Types.h"

#include "tools/vmill/Emulator/ByteCode/Cache.h"
#include "tools/vmill/Emulator/ByteCode/Interpreter.h"
#include "tools/vmill/OS/System32.h"

namespace remill {
namespace vmill {
namespace {

template <typename T>
inline const T &O(const Operation *op) {
  return *reinterpret_cast<const T *>(op);
}

static uint64_t DoIntrinsic32(
    Intrinsic::Name call, uint64_t arg1, uint64_t arg2) {
  switch (call) {
    case Intrinsic::kPopCount:
      return __builtin_popcount(static_cast<uint32_t>(arg1));
    case Intrinsic::kNumLeadingZeros:
      return __builtin_clz(static_cast<uint32_t>(arg1));
    case Intrinsic::kNumTrailingZeros:
      return __builtin_ctz(static_cast<uint32_t>(arg1));
    case Intrinsic::kByteSwap:
      return __builtin_bswap32(static_cast<uint32_t>(arg1));
    default:
      LOG(FATAL)
          << "Unsupported 32-bit intrinsic call " << static_cast<int>(call);
  }
}

}  // namespace

ByteCodeInterpreter::~ByteCodeInterpreter(void) {}

ByteCodeInterpreter::ByteCodeInterpreter(uint64_t code_version_)
    : ByteCodeVM(code_version_) {}

Emulator::Status ByteCodeInterpreter::Emulate(Process32 *process,
                                              Thread32 *thread) {
  Operation *op = nullptr;
  Emulator::Status status = Emulator::kPaused;
  do {
    const auto pc = thread->ProgramCounter();
    op = index->TryFind(pc);
    if (!op) {
      Compile(process, pc);
      op = index->MustFind(pc);
    }
    status = Interpret(process->memory, thread->MachineState(), op);
  } while (Emulator::kPaused == status);

  return status;
}

#define DO_OP(op_type, op_size, ...) \
    do { \
      typedef uint ## op_size ## _t uintn_t; \
      typedef int ## op_size ## _t intn_t; \
      auto curr = reinterpret_cast<Operation::op_type *>(op); \
      (void) curr; \
      __VA_ARGS__ ; \
    } while (false)

#define DO_OPS_8_TO_64(op_type, opcode, ...) \
    case OpCode::k ## opcode ## 8: DO_OP(op_type, 8, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 16: DO_OP(op_type, 16, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 32: DO_OP(op_type, 32, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 64: DO_OP(op_type, 64, __VA_ARGS__); break;

#define DO_OPS_8_TO_128(op_type, opcode, ...) \
    case OpCode::k ## opcode ## 8: DO_OP(op_type, 8, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 16: DO_OP(op_type, 16, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 32: DO_OP(op_type, 32, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 64: DO_OP(op_type, 64, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 128: DO_OP(op_type, 128, __VA_ARGS__); break;

#define DO_FOP(op_type, op_size, ...) \
    do { \
      typedef uint ## op_size ## _t uintn_t; \
      typedef int ## op_size ## _t intn_t; \
      typedef float ## op_size ## _t floatn_t; \
      auto curr = reinterpret_cast<Operation::op_type *>(op); \
      (void) curr; \
      __VA_ARGS__ ; \
    } while (false)

#define DO_FOPS(op_type, opcode, ...) \
    case OpCode::k ## opcode ## 32: DO_FOP(op_type, 32, __VA_ARGS__); break; \
    case OpCode::k ## opcode ## 64: DO_FOP(op_type, 64, __VA_ARGS__); break;

Emulator::Status ByteCodeInterpreter::Interpret(
    Memory32 *memory, uint8_t *state, Operation *op) {

  uint64_t pc = 0;
  Operation *next_op = nullptr;
  Operation *block_entry_op = op;
  auto last_op = cache->end();
  auto pool = constants->begin();
  for (ptrdiff_t i = 0; op < last_op; op = next_op) {
    i = op - block_entry_op;
    next_op = op + OpCode::kNumOpSlots[op->op_code];

    std::cout << "%" << i << " = " << op->Serialize() << std::endl;
    // Clear out the data slot before we use it.
    if (OpCode::kAllocOverflowData != op->op_code) {
      data.data[i] = 0;
    }
    switch (op->op_code) {
      case OpCode::kConstant:
        DO_OP(Constant, 64, data.data[i] = pool[curr->offset]);
        break;

      case OpCode::kAllocOverflowData:
        break;

      case OpCode::kEnter32:
        DO_OP(Enter32, 64,
            block_entry_op = op;
            pc = curr->pc);
        break;

      case OpCode::kEnter64:
        DO_OP(Enter64, 64,
            block_entry_op = op;
            pc = curr->pc);
        break;

      case OpCode::kExitCall:
      case OpCode::kExitRet:
      case OpCode::kExitJump:
        return Emulator::kPaused;

      case OpCode::kExitAsyncHyperCall:
        return Emulator::kStoppedAtAsyncHyperCall;

      case OpCode::kExitError:
        return Emulator::kStoppedAtError;

      case OpCode::kGoTo:
        DO_OP(GoTo, 64, next_op = &(block_entry_op[curr->true_var]));
        break;

      case OpCode::kCondGoTo: {
        auto goto_op = reinterpret_cast<Operation::GoTo *>(op);
        if (data.data[goto_op->cond_var]) {
          next_op = &(block_entry_op[goto_op->true_var]);
        } else {
          next_op = &(block_entry_op[goto_op->false_var]);
        }
        break;
      }

      case OpCode::kJumpFarForward: {
        next_op = &(op[O<Operation::JumpFar>(op).rel_offset]);
        block_entry_op = next_op;
        break;
      }

      case OpCode::kJumpFarBackward: {
        auto offset = static_cast<int32_t>(
            O<Operation::JumpFar>(op).rel_offset);
        next_op = &(op[-offset]);;
        block_entry_op = next_op;
        break;
      }

      case OpCode::kJump: {
        next_op = &(op[O<Operation::Jump>(op).rel_offset]);;
        block_entry_op = next_op;
        break;
      }
      case OpCode::kSyncHyperCall:
        return Emulator::kStoppedAtSyncHyperCall;

//        break;
//      case OpCode::kIntrinsic8:
//      case OpCode::kIntrinsic16:
      case OpCode::kIntrinsic32:
        DO_OP(IntrinsicCall, 32,
            data.data[i] = DoIntrinsic32(curr->call, data.data[curr->src1_var],
                                         data.data[curr->src2_var]));
        break;

//      case OpCode::kIntrinsic64:
//      case OpCode::kIntrinsic128:
//        break;
//      case OpCode::kFPIntrinsic32:
//      case OpCode::kFPIntrinsic64:
//        break;

      DO_OPS_8_TO_128(State, Read,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              *(reinterpret_cast<uintn_t *>(&(state[curr->offset]))));

      DO_OPS_8_TO_128(State, Write,
          *(reinterpret_cast<uintn_t *>(&(state[curr->offset]))) =
              reinterpret_cast<uintn_t &>(data.data[curr->src_var]));

      DO_OPS_8_TO_128(State, ReadStack,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              *(reinterpret_cast<uintn_t *>(&(stack.data[curr->offset]))));

      DO_OPS_8_TO_128(State, WriteStack,
          *(reinterpret_cast<uintn_t *>(&(stack.data[curr->offset]))) =
              reinterpret_cast<uintn_t &>(data.data[curr->src_var]));

      case OpCode::kReadMem8:
        DO_OP(Mem, 8,
            reinterpret_cast<uintn_t &>(data.data[i]) =
                *(memory->RawByteAddress(data.data[curr->addr_var])));
        break;

      case OpCode::kReadMem16:
        DO_OP(Mem, 16,
            reinterpret_cast<uintn_t &>(data.data[i]) =
                *(memory->RawWordAddress(data.data[curr->addr_var])));
        break;

      case OpCode::kReadMem32:
        DO_OP(Mem, 32,
            reinterpret_cast<uintn_t &>(data.data[i]) =
                *(memory->RawDwordAddress(data.data[curr->addr_var])));
        break;

      case OpCode::kReadMem64:
        DO_OP(Mem, 64,
            reinterpret_cast<uintn_t &>(data.data[i]) =
                *(memory->RawQwordAddress(data.data[curr->addr_var])));
        break;

      case OpCode::kWriteMem8:
        DO_OP(Mem, 8,
            *(memory->RawByteAddress(data.data[curr->addr_var])) =
                reinterpret_cast<uintn_t &>(data.data[curr->src_var]));
        break;

      case OpCode::kWriteMem16:
        DO_OP(Mem, 16,
            *(memory->RawWordAddress(data.data[curr->addr_var])) =
                reinterpret_cast<uintn_t &>(data.data[curr->src_var]));
        break;

      case OpCode::kWriteMem32:
        DO_OP(Mem, 32,
            *(memory->RawDwordAddress(data.data[curr->addr_var])) =
                reinterpret_cast<uintn_t &>(data.data[curr->src_var]));
        break;

      case OpCode::kWriteMem64:
        DO_OP(Mem, 64,
            *(memory->RawQwordAddress(data.data[curr->addr_var])) =
                reinterpret_cast<uintn_t &>(data.data[curr->src_var]));
        break;

      case OpCode::kZero:
        DO_OP(Constant, 64, data.data[i] = 0);
        break;

      case OpCode::kOne:
        DO_OP(Constant, 64, data.data[i] = 1);
        break;

      case OpCode::kPositive16:
        DO_OP(PositiveInteger, 64, data.data[i] = curr->val);
        break;

      case OpCode::kNegative16:
        DO_OP(NegativeInteger, 64, data.data[i] =
            static_cast<uint64_t>(static_cast<int64_t>(curr->val)));
        break;

      case OpCode::kPow2:
        DO_OP(Pow2, 64, data.data[i] = 1ULL << uint64_t(curr->shift));
        break;

      case OpCode::kNegPow2:
        DO_OP(Pow2, 64, data.data[i] = ~(1ULL << uint64_t(curr->shift)) + 1ULL);
        break;

      DO_OPS_8_TO_128(ITE, ITE,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<bool &>(data.data[curr->cond_var]) ?
                  reinterpret_cast<uintn_t &>(data.data[curr->true_var]) :
                  reinterpret_cast<uintn_t &>(data.data[curr->false_var]));

      DO_OPS_8_TO_128(Binary, Add,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) +
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, Sub,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) -
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, Mul,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) *
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, UDiv,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) /
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, SDiv,
          reinterpret_cast<intn_t &>(data.data[i]) =
              reinterpret_cast<intn_t &>(data.data[curr->src1_var]) /
              reinterpret_cast<intn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, URem,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) %
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, SRem,
          reinterpret_cast<intn_t &>(data.data[i]) =
              reinterpret_cast<intn_t &>(data.data[curr->src1_var]) %
              reinterpret_cast<intn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, Shl,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) <<
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, LShr,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) >>
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, AShr,
          reinterpret_cast<intn_t &>(data.data[i]) =
              reinterpret_cast<intn_t &>(data.data[curr->src1_var]) >>
              reinterpret_cast<intn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, And,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) &
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, Or,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) |
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Binary, Xor,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) ^
              reinterpret_cast<uintn_t &>(data.data[curr->src2_var]));

      DO_OPS_8_TO_128(Unary, Neg,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              ~reinterpret_cast<uintn_t &>(data.data[curr->src_var]) +
              uintn_t(1));

      DO_OPS_8_TO_128(Unary, Not,
          reinterpret_cast<uintn_t &>(data.data[i]) =
              ~reinterpret_cast<uintn_t &>(data.data[curr->src_var]));

      DO_FOPS(Binary, FAdd,
          reinterpret_cast<floatn_t &>(data.data[i]) =
              reinterpret_cast<floatn_t &>(data.data[curr->src1_var]) +
              reinterpret_cast<floatn_t &>(data.data[curr->src2_var]));

      DO_FOPS(Binary, FSub,
          reinterpret_cast<floatn_t &>(data.data[i]) =
              reinterpret_cast<floatn_t &>(data.data[curr->src1_var]) -
              reinterpret_cast<floatn_t &>(data.data[curr->src2_var]));

      DO_FOPS(Binary, FMul,
          reinterpret_cast<floatn_t &>(data.data[i]) =
              reinterpret_cast<floatn_t &>(data.data[curr->src1_var]) *
              reinterpret_cast<floatn_t &>(data.data[curr->src2_var]));

      DO_FOPS(Binary, FDiv,
          reinterpret_cast<floatn_t &>(data.data[i]) =
              reinterpret_cast<floatn_t &>(data.data[curr->src1_var]) /
              reinterpret_cast<floatn_t &>(data.data[curr->src2_var]));

      DO_FOPS(Binary, FRem,
          reinterpret_cast<floatn_t &>(data.data[i]) = fmod(
              reinterpret_cast<floatn_t &>(data.data[curr->src1_var]),
              reinterpret_cast<floatn_t &>(data.data[curr->src2_var])));

      DO_OPS_8_TO_64(Unary, TruncTo,
          data.data[i] = reinterpret_cast<uintn_t &>(data.data[curr->src_var]));

      case OpCode::kZExtFrom8:
        DO_OP(Unary, 8, data.data[i] =
            reinterpret_cast<uintn_t &>(data.data[curr->src_var]));
        break;

      case OpCode::kZExtFrom16:
        DO_OP(Unary, 16, data.data[i] =
            reinterpret_cast<uintn_t &>(data.data[curr->src_var]));
        break;

      case OpCode::kZExtFrom32:
        DO_OP(Unary, 32, data.data[i] =
            reinterpret_cast<uintn_t &>(data.data[curr->src_var]));
        break;

      case OpCode::kZExtFrom64:
        DO_OP(Unary, 64,
            data.data[i] = data.data[curr->src_var];
            data.data[i + 1] = 0;);
        break;

      case OpCode::kSExtFrom8:
        DO_OP(Unary, 8,
            data.data[i] = static_cast<uint64_t>(static_cast<int64_t>(
                reinterpret_cast<intn_t &>(data.data[curr->src_var]))));
        break;

      case OpCode::kSExtFrom16:
        DO_OP(Unary, 16,
            data.data[i] = static_cast<uint64_t>(static_cast<int64_t>(
                reinterpret_cast<intn_t &>(data.data[curr->src_var]))));
        break;

      case OpCode::kSExtFrom32:
        DO_OP(Unary, 32,
            data.data[i] = static_cast<uint64_t>(static_cast<int64_t>(
                reinterpret_cast<intn_t &>(data.data[curr->src_var]))));
        break;

      case OpCode::kSExtFrom64:
        DO_OP(Unary, 64,
            reinterpret_cast<uint128_t &>(data.data[i]) =
                static_cast<uint128_t>(static_cast<int128_t>(
                    reinterpret_cast<intn_t &>(data.data[curr->src_var]))));
        break;
//
//      case OpCode::kFPTrunc64To32:
//        ss << "convert f64 %" << I(O<Unary>(this).src_var)
//           << " to f32";
//        break;
//      case OpCode::kFPExt32To64:
//        ss << "convert f32 %" << I(O<Unary>(this).src_var)
//           << " to f64";
//        break;
//      case OpCode::kFP64ToUI64:
//        ss << "convert f64 %" << I(O<Unary>(this).src_var)
//           << " to i64";
//        break;
//      case OpCode::kFP64ToUI32:
//        ss << "convert f64 %" << I(O<Unary>(this).src_var)
//           << " to i32";
//        break;
//      case OpCode::kFP32ToUI64:
//        ss << "convert f32 %" << I(O<Unary>(this).src_var)
//           << " to i64";
//        break;
//      case OpCode::kFP32ToUI32:
//        ss << "convert f32 %" << I(O<Unary>(this).src_var)
//           << " to i32";
//        break;
//      case OpCode::kFP64ToSI64:
//        ss << "convert f64 %" << I(O<Unary>(this).src_var)
//           << " to signed i64";
//        break;
//      case OpCode::kFP64ToSI32:
//        ss << "convert f64 %" << I(O<Unary>(this).src_var)
//           << " to signed i32";
//        break;
//      case OpCode::kFP32ToSI64:
//        ss << "convert f32 %" << I(O<Unary>(this).src_var)
//           << " to signed i64";
//        break;
//      case OpCode::kFP32ToSI32:
//        ss << "convert f32 %" << I(O<Unary>(this).src_var)
//           << " to signed i32";
//        break;
//      case OpCode::kUI64ToFP64:
//        ss << "convert i64 %" << I(O<Unary>(this).src_var)
//           << " to f64";
//        break;
//      case OpCode::kUI32ToFP64:
//        ss << "convert i32 %" << I(O<Unary>(this).src_var)
//           << " to f64";
//        break;
//      case OpCode::kUI64ToFP32:
//        ss << "convert i64 %" << I(O<Unary>(this).src_var)
//           << " to f32";
//        break;
//      case OpCode::kUI32ToFP32:
//        ss << "convert i32 %" << I(O<Unary>(this).src_var)
//           << " to f32";
//        break;
//      case OpCode::kSI64ToFP64:
//        ss << "convert signed i64 %" << I(O<Unary>(this).src_var)
//           << " to f64";
//        break;
//      case OpCode::kSI32ToFP64:
//        ss << "convert signed i32 %" << I(O<Unary>(this).src_var)
//           << " to f64";
//        break;
//      case OpCode::kSI64ToFP32:
//        ss << "convert signed i64 %" << I(O<Unary>(this).src_var)
//           << " to f32";
//        break;
//      case OpCode::kSI32ToFP32:
//        ss << "convert signed i32 %" << I(O<Unary>(this).src_var)
//           << " to f32";
//        break;
//      case OpCode::kFCmpEq32:
//      case OpCode::kFCmpEq64:
//        ss << "cmp eq f" << OpCode::kNumBitsRead[op_code]
//           << " %" << I(O<Binary>(this).src1_var)
//           << ", %" << I(O<Binary>(this).src2_var);
//        break;
//      case OpCode::kFCmpGt32:
//      case OpCode::kFCmpGt64:
//        ss << "cmp gt f" << OpCode::kNumBitsRead[op_code]
//           << " %" << I(O<Binary>(this).src1_var)
//           << ", %" << I(O<Binary>(this).src2_var);
//        break;
//      case OpCode::kFCmpGe32:
//      case OpCode::kFCmpGe64:
//        ss << "cmp ge f" << OpCode::kNumBitsRead[op_code]
//           << " %" << I(O<Binary>(this).src1_var)
//           << ", %" << I(O<Binary>(this).src2_var);
//        break;
//      case OpCode::kFCmpLt32:
//      case OpCode::kFCmpLt64:
//        ss << "cmp lt f" << OpCode::kNumBitsRead[op_code]
//           << " %" << I(O<Binary>(this).src1_var)
//           << ", %" << I(O<Binary>(this).src2_var);
//        break;
//      case OpCode::kFCmpLe32:
//      case OpCode::kFCmpLe64:
//        ss << "cmp le f" << OpCode::kNumBitsRead[op_code]
//           << " %" << I(O<Binary>(this).src1_var)
//           << ", %" << I(O<Binary>(this).src2_var);
//        break;
//      case OpCode::kFCmpNe32:
//      case OpCode::kFCmpNe64:
//        ss << "cmp ne f" << OpCode::kNumBitsRead[op_code]
//           << " %" << I(O<Binary>(this).src1_var)
//           << ", %" << I(O<Binary>(this).src2_var);
//        break;


        DO_OPS_8_TO_128(Binary, ICmpEq,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) ==
                reinterpret_cast<uintn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpNe,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) !=
                reinterpret_cast<uintn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpUgt,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) >
                reinterpret_cast<uintn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpUge,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) >=
                reinterpret_cast<uintn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpUlt,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) <
                reinterpret_cast<uintn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpUle,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<uintn_t &>(data.data[curr->src1_var]) <=
                reinterpret_cast<uintn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpSgt,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<intn_t &>(data.data[curr->src1_var]) >
                reinterpret_cast<intn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpSge,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<intn_t &>(data.data[curr->src1_var]) >=
                reinterpret_cast<intn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpSlt,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<intn_t &>(data.data[curr->src1_var]) <
                reinterpret_cast<intn_t &>(data.data[curr->src2_var])));

        DO_OPS_8_TO_128(Binary, ICmpSle,
            data.data[i] = static_cast<uint64_t>(
                reinterpret_cast<intn_t &>(data.data[curr->src1_var]) <=
                reinterpret_cast<intn_t &>(data.data[curr->src2_var])));

      case OpCode::kSafePoint:
        break;

      default:
        std::cout << "not handled! " << std::endl;
        return Emulator::kCannotContinue;
    }
  }
  return Emulator::kCannotContinue;
}

}  // namespace vmill
}  // namespace remill

/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// Disable the "loop not unrolled warnings"
#pragma clang diagnostic ignored "-Wpass-failed"

namespace {

template <typename D, typename S, typename DestType>
DEF_SEM(LEA, D dst, S src) {
  WriteZExt(dst, static_cast<DestType>(AddressOf(src)));
  return memory;
}

DEF_SEM(LEAVE_16BIT) {
  addr_t op_size = 2;
  addr_t link_pointer = Read(REG_XBP);
  addr_t base_pointer =
      Read(ReadPtr<addr_t>(link_pointer _IF_32BIT(REG_SS_BASE)));
  Write(REG_XBP, base_pointer);
  Write(REG_XSP, UAdd(link_pointer, op_size));
  return memory;
}

template <typename T>
DEF_SEM(LEAVE_FULL) {
  addr_t op_size = TruncTo<addr_t>(sizeof(T));
  addr_t link_pointer = Read(REG_XBP);
  addr_t base_pointer =
      Read(ReadPtr<addr_t>(link_pointer _IF_32BIT(REG_SS_BASE)));
  Write(REG_XBP, base_pointer);
  Write(REG_XSP, UAdd(link_pointer, op_size));
  return memory;
}

}  // namespace

DEF_ISEL(LEA_GPRv_AGEN_16) = LEA<R16W, M8, uint16_t>;
DEF_ISEL(LEA_GPRv_AGEN_32) = LEA<R32W, M8, uint32_t>;
IF_64BIT(DEF_ISEL(LEA_GPRv_AGEN_64) = LEA<R64W, M8, uint64_t>;)

DEF_ISEL(LEAVE_16) = LEAVE_16BIT;
DEF_ISEL_RI32or64(LEAVE, LEAVE_FULL);

namespace {

// TODO(pag): Handle the case where the operand size and address size disagree.
//            This can happen when using the 66H or 67H prefixes to override the
//            operand or address sizes. For example, and operand size of 32 with
//            an address size of 16 will read `[BP]` instead of `[EBP]`, but the
//            stack pointer will decrement by `4`.
template <typename T>
DEF_SEM(ENTER, I16 src1, I8 src2) {
  addr_t op_size = sizeof(T);
  addr_t alloc_size = ZExtTo<addr_t>(Read(src1));
  addr_t nesting_level = ZExtTo<addr_t>(URem(Read(src2), 32_u8));
  addr_t xsp_temp = Read(REG_XSP);
  addr_t frame_temp = USub(xsp_temp, op_size);
  addr_t next_xsp =
      USub(USub(frame_temp, UMul(op_size, nesting_level)), alloc_size);

  // Detect failure. This should really happen at the end of `ENTER` but we
  // do it here. This is why `frame_temp` is created before the `PUSH` of
  // `RBP`, but displaced to mimic the `PUSH`.
  Write(WritePtr<T>(next_xsp _IF_32BIT(REG_SS_BASE)),
        Read(ReadPtr<T>(next_xsp _IF_32BIT(REG_SS_BASE))));

  // Push `XBP`.
  addr_t xbp_temp = Read(REG_XBP);
  addr_t xsp_after_push = USub(xsp_temp, op_size);
  Write(REG_XSP, xsp_after_push);
  Write(WritePtr<T>(xsp_after_push _IF_32BIT(REG_SS_BASE)),
        TruncTo<T>(xbp_temp));
  xsp_temp = xsp_after_push;

  if (nesting_level) {
    if (1 < nesting_level) {
      _Pragma("unroll") for (addr_t i = 1; i <= (nesting_level - 1); ++i) {
        xbp_temp = USub(xbp_temp, op_size);  // TODO(pag): Handle 67H prefix.

        // Copy the display entry to the stack.
        xsp_after_push = USub(xsp_temp, op_size);
        Write(WritePtr<T>(xsp_after_push _IF_32BIT(REG_SS_BASE)),
              Read(ReadPtr<T>(xbp_temp _IF_32BIT(REG_SS_BASE))));
        xsp_temp = xsp_after_push;
      }
    }

    xsp_temp = xsp_after_push;
    xsp_after_push = USub(xsp_temp, op_size);
    Write(WritePtr<addr_t>(xsp_after_push _IF_32BIT(REG_SS_BASE)), frame_temp);
    xsp_temp = xsp_after_push;
  }

  Write(REG_XBP, frame_temp);
  Write(REG_XSP, USub(xsp_temp, alloc_size));
  return memory;
}

DEF_SEM(DoNothing) {
  return memory;
}

template <typename... Args>
DEF_SEM(DoNothingWithParam, Args...) {
  return memory;
}

DEF_SEM(DoCLFLUSH_MEMmprefetch, M8) {
  return memory;
}


// Good reference for memory barriers and their relationships to instructions:
// http://g.oswego.edu/dl/jmm/cookbook.html

DEF_SEM(DoMFENCE) {
  BarrierStoreLoad();
  return memory;
}

DEF_SEM(DoSFENCE) {
  BarrierStoreStore();
  return memory;
}

DEF_SEM(DoLFENCE) {
  BarrierLoadLoad();
  return memory;
}

DEF_SEM(DoXLAT) {
  addr_t base = Read(REG_XBX);
  addr_t offset = ZExtTo<addr_t>(Read(REG_AL));
  Write(REG_AL,
        Read(ReadPtr<uint8_t>(UAdd(base, offset) _IF_32BIT(REG_DS_BASE))));
  return memory;
}

DEF_SEM(DoCPUID) {
  return __remill_sync_hyper_call(state, memory, SyncHyperCall::kX86CPUID);
}
}  // namespace

DEF_ISEL(ENTER_IMMw_IMMb_16) = ENTER<uint16_t>;
IF_32BIT(DEF_ISEL(ENTER_IMMw_IMMb_32) = ENTER<uint32_t>;)
IF_64BIT(DEF_ISEL(ENTER_IMMw_IMMb_64) = ENTER<uint64_t>;)

// A `NOP` with a `REP` prefix for hinting. Used for busy-wait loops.
DEF_ISEL(PAUSE) = DoNothing;

// A kind of NOP.
DEF_ISEL(CLFLUSH_MEMmprefetch) = DoCLFLUSH_MEMmprefetch;

DEF_ISEL(MFENCE) = DoMFENCE;

DEF_ISEL(SFENCE) = DoSFENCE;

DEF_ISEL(LFENCE) = DoLFENCE;

DEF_ISEL(XLAT) = DoXLAT;

DEF_ISEL(CPUID) = DoCPUID;

DEF_ISEL(UD0_GPR32_MEMd) =
    DoNothingWithParam<R32, M32, IF_32BIT_ELSE(R32W, R64W)>;

DEF_ISEL(UD1_GPR32_MEMd) =
    DoNothingWithParam<R32, M32, IF_32BIT_ELSE(R32W, R64W)>;

DEF_ISEL(UD2) = DoNothingWithParam<IF_32BIT_ELSE(R32W, R64W)>;

DEF_ISEL(HLT) = DoNothingWithParam<IF_32BIT_ELSE(R32W, R64W)>;

/*
230 INVPCID INVPCID_GPR64_MEMdq MISC INVPCID INVPCID ATTRIBUTES: NOTSX RING0
231 INVPCID INVPCID_GPR32_MEMdq MISC INVPCID INVPCID ATTRIBUTES: NOTSX RING0
639 MONITOR MONITOR MISC SSE3 SSE3 ATTRIBUTES: NOTSX RING0
1924 MWAIT MWAIT MISC SSE3 SSE3 ATTRIBUTES: NOTSX RING0
 */

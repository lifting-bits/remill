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

#include "Int.h"

class SyncHyperCall {
 public:
  enum Name : uint32_t {
    kInvalid,
    kAssertPrivileged,

    kX86EmulateInstruction = 0x100U,
    kAMD64EmulateInstruction,

    kX86CPUID,
    kX86ReadTSC,
    kX86ReadTSCP,
    kX86LoadGlobalDescriptorTable,
    kX86LoadInterruptDescriptorTable,
    kX86ReadModelSpecificRegister,
    kX86WriteModelSpecificRegister,
    kX86WriteBackInvalidate,

    kX86SetSegmentES,
    kX86SetSegmentSS,
    kX86SetSegmentDS,
    kX86SetSegmentFS,
    kX86SetSegmentGS,

    kX86SetDebugReg,
    kAMD64SetDebugReg,

    kX86SetControlReg0,
    kX86SetControlReg1,
    kX86SetControlReg2,
    kX86SetControlReg3,
    kX86SetControlReg4,
    kAMD64SetControlReg0,
    kAMD64SetControlReg1,
    kAMD64SetControlReg2,
    kAMD64SetControlReg3,
    kAMD64SetControlReg4,
    kAMD64SetControlReg8,

    kX86SysCall,
    kX86SysEnter,
    kX86SysExit,

    // TODO(pag): How to distinguish little- and big-endian?
    kAArch64EmulateInstruction = 0x200U,
    kAArch64Breakpoint,
    kAArch32EmulateInstruction = 0x300U,

    kAArch32CheckNotEL2,

    kSPARC32EmulateInstruction = 0x400U,
    kSPARC64EmulateInstruction,
    kSPARCSetAsiRegister,
    kSPARCTagOverflow,

    kSPARCUnimplementedInstruction,
    kSPARCUnhandledDCTI,  // A CTI in a delay slot.
    kSPARCWindowUnderflow,  // Underflow when RESTOREing a register window.

    kSPARCTrapCondA,
    kSPARCTrapCondN,
    kSPARCTrapCondNE,
    kSPARCTrapCondE,
    kSPARCTrapCondG,
    kSPARCTrapCondLE,
    kSPARCTrapCondGE,
    kSPARCTrapCondL,
    kSPARCTrapCondGU,
    kSPARCTrapCondLEU,
    kSPARCTrapCondCC,
    kSPARCTrapCondCS,
    kSPARCTrapCondPOS,
    kSPARCTrapCondNEG,
    kSPARCTrapCondVC,
    kSPARCTrapCondVS,

    kPPCEmulateInstruction,
    kPPCSysCall,

    kMIPSEmulateInstruction,
    kMIPSSysCall,
  };
} __attribute__((packed));

class AsyncHyperCall {
 public:
  enum Name : uint32_t {
    kInvalid,

    // Interrupts calls.
    kX86Int1,
    kX86Int3,
    kX86IntO,
    kX86IntN,
    kX86Bound,

    // Interrupt returns.
    kX86IRet,

    // System calls.
    kX86SysCall,
    kX86SysRet,

    kX86SysEnter,
    kX86SysExit,

    // Far jumps: CS should be updated.
    kX86JmpFar,

    kAArch64SupervisorCall,

    kSPARCTagOverflowAdd,
    kSPARCTagOverflowSub,

    kSPARCUnimplementedInstruction,

    kSPARCTrapCondA,
    kSPARCTrapCondN,
    kSPARCTrapCondNE,
    kSPARCTrapCondE,
    kSPARCTrapCondG,
    kSPARCTrapCondLE,
    kSPARCTrapCondGE,
    kSPARCTrapCondL,
    kSPARCTrapCondGU,
    kSPARCTrapCondLEU,
    kSPARCTrapCondCC,
    kSPARCTrapCondCS,
    kSPARCTrapCondPOS,
    kSPARCTrapCondNEG,
    kSPARCTrapCondVC,
    kSPARCTrapCondVS,

    // Invalid instruction.
    kInvalidInstruction
  };
} __attribute__((packed));

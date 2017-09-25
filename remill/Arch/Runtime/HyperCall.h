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

#ifndef REMILL_ARCH_RUNTIME_HYPERCALL_H_
#define REMILL_ARCH_RUNTIME_HYPERCALL_H_

#include <cstdint>

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

    kX86SetSegmentES,
    kX86SetSegmentSS,
    kX86SetSegmentDS,
    kX86SetSegmentFS,
    kX86SetSegmentGS,

    // TODO(pag): How to distinguish little- and big-endian?
    kAArch64EmulateInstruction = 0x200U,
    kAArch64Breakpoint,

    kMipsEmulateInstruction = 0x300U,
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

    kAArch64SupervisorCall,

    // Invalid instruction.
    kInvalidInstruction
  };
} __attribute__((packed));

#endif  // REMILL_ARCH_RUNTIME_HYPERCALL_H_

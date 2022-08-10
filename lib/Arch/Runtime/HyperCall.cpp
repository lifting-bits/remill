/*
 * Copyright (c) 2022 Trail of Bits, Inc.
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

Memory *__remill_sync_hyper_call(State &state, Memory *mem,
                                 SyncHyperCall::Name call) {
  switch (call) {

#if REMILL_ON_X86 || REMILL_ON_AMD64

    case SyncHyperCall::kX86CPUID:
      asm volatile("cpuid"
                   : "=a"(state.gpr.rax.aword), "=b"(state.gpr.rbx.aword),
                     "=c"(state.gpr.rcx.aword), "=d"(state.gpr.rdx.aword)
                   : "a"(state.gpr.rax.aword), "b"(state.gpr.rbx.aword),
                     "c"(state.gpr.rcx.aword), "d"(state.gpr.rdx.aword));
      break;

    case SyncHyperCall::kX86ReadTSC:
      asm volatile("rdtsc"
                   : "=a"(state.gpr.rax.dword), "=d"(state.gpr.rdx.dword));
      break;

    case SyncHyperCall::kX86ReadTSCP:
      asm volatile("rdtscp"
                   : "=a"(state.gpr.rax.aword), "=c"(state.gpr.rcx.aword),
                     "=d"(state.gpr.rdx.aword)
                   : "a"(state.gpr.rax.aword), "c"(state.gpr.rcx.aword),
                     "d"(state.gpr.rdx.aword));
      break;

    case SyncHyperCall::kX86LoadGlobalDescriptorTable:
      auto read = __remill_read_memory_64(mem, state.addr_to_load);
      asm volatile("lgdt" : : "m"(read));
      break;

    case SyncHyperCall::kX86LoadInterruptDescriptorTable:
      auto read = __remill_write_memory_64(mem, state.addr_to_load);
      asm volatile("lidt" : : "m"(read));
      break;

    case SyncHyperCall::kX86ReadModelSpecificRegister:
      asm volatile("rdmsr"
                   : "=c"(state.gpr.rcx.dword)
                   : "a"(state.gpr.rax.dword), "d"(state.gpr.rdx.dword));
      break;

    case SyncHyperCall::kX86WriteModelSpecificRegister:
      asm volatile("wrmsr"
                   : "=c"(state.gpr.rcx.dword)
                   : "a"(state.gpr.rax.dword), "d"(state.gpr.rdx.dword));
      break;

    case SyncHyperCall::kX86WriteBackInvalidate:
      asm volatile("wbinvd" :);
      break;

    // TODO(alex): There doesn't seem to be a way to figure out what what value
    // gets written to these segment registers. Is there a reason we can't
    // just do a write to these registers in the semantic functions
    // themselves? I don't really get why these are sync hyper calls.
    case SyncHyperCall::kX86SetSegmentES: break;

    case SyncHyperCall::kX86SetSegmentSS: break;

    case SyncHyperCall::kX86SetSegmentDS: break;

    case SyncHyperCall::kX86SetSegmentFS: break;

    case SyncHyperCall::kX86SetSegmentGS: break;

#  if REMILL_ON_X86

    case SyncHyperCall::kX86SetDebugReg: break;

    case SyncHyperCall::kX86SetControlReg0: break;

    case SyncHyperCall::kX86SetControlReg1: break;

    case SyncHyperCall::kX86SetControlReg2: break;

    case SyncHyperCall::kX86SetControlReg3: break;

    case SyncHyperCall::kX86SetControlReg4: break;

#  elif REMILL_ON_AMD64

    case SyncHyperCall::kAMD64SetDebugReg: break;

    case SyncHyperCall::kAMD64SetControlReg0: break;

    case SyncHyperCall::kAMD64SetControlReg1: break;

    case SyncHyperCall::kAMD64SetControlReg2: break;

    case SyncHyperCall::kAMD64SetControlReg3: break;

    case SyncHyperCall::kAMD64SetControlReg4: break;

    case SyncHyperCall::kAMD64SetControlReg8: break;

#  endif

#elif REMILL_ON_AARCH64

    case SyncHyperCall::kAArch64EmulateInstruction:
      mem = __remill_aarch64_emulate_instruction(mem);
      break;

    case SyncHyperCall::kAArch64Breakpoint: asm volatile("bkpt" :); break;

    case SyncHyperCall::kAArch32EmulateInstruction:
      mem = __remill_aarch32_emulate_instruction(mem);
      break;

    case SyncHyperCall::kAArch32CheckNotEL2:
      mem = __remill_aarch32_check_not_el2(mem);
      break;

#elif REMILL_ON_SPARC32 || REMILL_ON_SPARC64

    case SyncHyperCall::kSPARCSetAsiRegister: break;

    case SyncHyperCall::kSPARCTagOverflow: break;

    case SyncHyperCall::kSPARCUnimplementedInstruction:
      mem = __remill_sparc_unimplemented_instruction(mem);
      break;

    case SyncHyperCall::kSPARCUnhandledDCTI: break;

    case SyncHyperCall::kSPARCWindowUnderflow: break;

    case SyncHyperCall::kSPARCTrapCondA: break;

    case SyncHyperCall::kSPARCTrapCondN: break;

    case SyncHyperCall::kSPARCTrapCondNE: break;

    case SyncHyperCall::kSPARCTrapCondE: break;

    case SyncHyperCall::kSPARCTrapCondG: break;

    case SyncHyperCall::kSPARCTrapCondLE: break;

    case SyncHyperCall::kSPARCTrapCondGE: break;

    case SyncHyperCall::kSPARCTrapCondL: break;

    case SyncHyperCall::kSPARCTrapCondGU: break;

    case SyncHyperCall::kSPARCTrapCondLEU: break;

    case SyncHyperCall::kSPARCTrapCondCC: break;

    case SyncHyperCall::kSPARCTrapCondCS: break;

    case SyncHyperCall::kSPARCTrapCondPOS: break;

    case SyncHyperCall::kSPARCTrapCondNEG: break;

    case SyncHyperCall::kSPARCTrapCondVC: break;

    case SyncHyperCall::kSPARCTrapCondVS: break;

#  if defined(REMILL_ON_SPARC32)

    case SyncHyperCall::kSPARC32EmulateInstruction:
      mem = __remill_sparc32_emulate_instruction(mem);
      break;

#  elif defined(REMILL_ON_SPARC64)

    case SyncHyperCall::kSPARC64EmulateInstruction:
      mem = __remill_sparc64_emulate_instruction(mem);
      break;

#  endif

#endif

    default: abort();
  }

  return mem;
}

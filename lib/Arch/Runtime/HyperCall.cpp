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
      const auto read = __remill_read_memory_64(mem, state.addr_to_load);
      asm volatile("lgdt" : : "m"(read));
      break;

    case SyncHyperCall::kX86LoadInterruptDescriptorTable:
      const auto read = __remill_read_memory_64(mem, state.addr_to_load);
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

    case SyncHyperCall::kX86SetSegmentES:
      mem = __remill_x86_set_segment_es(mem);
      break;

    case SyncHyperCall::kX86SetSegmentSS:
      mem = __remill_x86_set_segment_ss(mem);
      break;

    case SyncHyperCall::kX86SetSegmentDS:
      mem = __remill_x86_set_segment_ds(mem);
      break;

    case SyncHyperCall::kX86SetSegmentFS:
      mem = __remill_x86_set_segment_fs(mem);
      break;

    case SyncHyperCall::kX86SetSegmentGS:
      mem = __remill_x86_set_segment_gs(mem);
      break;

#  if REMILL_ON_X86

    case SyncHyperCall::kX86SetDebugReg:
      mem = __remill_x86_set_debug_reg(mem);
      break;

    case SyncHyperCall::kX86SetControlReg0:
      mem = __remill_x86_set_control_reg_0(mem);
      break;

    case SyncHyperCall::kX86SetControlReg1:
      mem = __remill_x86_set_control_reg_1(mem);
      break;

    case SyncHyperCall::kX86SetControlReg2:
      mem = __remill_x86_set_control_reg_2(mem);
      break;

    case SyncHyperCall::kX86SetControlReg3:
      mem = __remill_x86_set_control_reg_3(mem);
      break;

    case SyncHyperCall::kX86SetControlReg4:
      mem = __remill_x86_set_control_reg_4(mem);
      break;

#  elif REMILL_ON_AMD64

    case SyncHyperCall::kAMD64SetDebugReg:
      mem = __remill_amd64_set_debug_reg(mem);
      break;

    case SyncHyperCall::kAMD64SetControlReg0:
      mem = __remill_amd64_set_control_reg_0(mem);
      break;

    case SyncHyperCall::kAMD64SetControlReg1:
      mem = __remill_amd64_set_control_reg_1(mem);
      break;

    case SyncHyperCall::kAMD64SetControlReg2:
      mem = __remill_amd64_set_control_reg_2(mem);
      break;

    case SyncHyperCall::kAMD64SetControlReg3:
      mem = __remill_amd64_set_control_reg_3(mem);
      break;

    case SyncHyperCall::kAMD64SetControlReg4:
      mem = __remill_amd64_set_control_reg_4(mem);
      break;

    case SyncHyperCall::kAMD64SetControlReg8:
      mem = __remill_amd64_set_control_reg_8(mem);
      break;

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

    case SyncHyperCall::kSPARCSetAsiRegister:
      mem = __remill_sparc_set_asi_register(mem);
      break;

    case SyncHyperCall::kSPARCUnimplementedInstruction:
      mem = __remill_sparc_unimplemented_instruction(mem);
      break;

    case SyncHyperCall::kSPARCUnhandledDCTI:
      mem = __remill_sparc_unhandled_dcti(mem);
      break;

    case SyncHyperCall::kSPARCWindowUnderflow:
      mem = __remill_sparc_window_underflow(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondA:
      mem = __remill_sparc_trap_cond_a(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondN:
      mem = __remill_sparc_trap_cond_n(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondNE:
      mem = __remill_sparc_trap_cond_ne(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondE:
      mem = __remill_sparc_trap_cond_e(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondG:
      mem = __remill_sparc_trap_cond_g(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondLE:
      mem = __remill_sparc_trap_cond_le(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondGE:
      mem = __remill_sparc_trap_cond_ge(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondL:
      mem = __remill_sparc_trap_cond_l(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondGU:
      mem = __remill_sparc_trap_cond_gu(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondLEU:
      mem = __remill_sparc_trap_cond_leu(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondCC:
      mem = __remill_sparc_trap_cond_cc(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondCS:
      mem = __remill_sparc_trap_cond_cs(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondPOS:
      mem = __remill_sparc_trap_cond_pos(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondNEG:
      mem = __remill_sparc_trap_cond_neg(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondVC:
      mem = __remill_sparc_trap_cond_vc(mem);
      break;

    case SyncHyperCall::kSPARCTrapCondVS:
      mem = __remill_sparc_trap_cond_vs(mem);
      break;

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

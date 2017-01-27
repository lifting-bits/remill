# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import idautils
import idaapi
import idc

import log
import program


_PREFIX_ITYPES = (idaapi.NN_lock, idaapi.NN_rep,
                  idaapi.NN_repe, idaapi.NN_repne)


def decode_instruction(ea):
  """Read the bytes of an x86/amd64 instruction. This handles things like
  combining the bytes of an instruction with its prefix. IDA Pro sometimes
  treats these as separate."""
  global _PREFIX_ITYPES

  decoded_inst = idautils.DecodeInstruction(ea)
  if not decoded_inst:
    return None, tuple()

  assert decoded_inst.ea == ea
  end_ea = ea + decoded_inst.size
  decoded_bytes = [chr(idc.Byte(byte_ea)) for byte_ea in range(ea, end_ea)]

  # We've got an instruction with a prefix, but the prefix is treated as
  # independent.
  if 1 == decoded_inst.size and decoded_inst.itype in _PREFIX_ITYPES:
    decoded_inst, extra_bytes = decode_instruction(end_ea)
    log.debug("Extended instruction at {:08x} by {} bytes".format(
        ea, len(extra_bytes)))
    decoded_bytes.extend(extra_bytes)

  return decoded_inst, decoded_bytes


_PERSONALITIES = {
  idaapi.NN_call: program.Instruction.PERSONALITY_DIRECT_CALL,
  idaapi.NN_callfi: program.Instruction.PERSONALITY_INDIRECT_CALL,
  idaapi.NN_callni: program.Instruction.PERSONALITY_INDIRECT_CALL,

  idaapi.NN_retf: program.Instruction.PERSONALITY_RETURN,
  idaapi.NN_retfd: program.Instruction.PERSONALITY_RETURN,
  idaapi.NN_retfq: program.Instruction.PERSONALITY_RETURN,
  idaapi.NN_retfw: program.Instruction.PERSONALITY_RETURN,
  idaapi.NN_retn: program.Instruction.PERSONALITY_RETURN,
  idaapi.NN_retnd: program.Instruction.PERSONALITY_RETURN,
  idaapi.NN_retnq: program.Instruction.PERSONALITY_RETURN,
  idaapi.NN_retnw: program.Instruction.PERSONALITY_RETURN,

  idaapi.NN_jmp: program.Instruction.PERSONALITY_DIRECT_JUMP,
  idaapi.NN_jmpshort: program.Instruction.PERSONALITY_DIRECT_JUMP,
  idaapi.NN_jmpfi: program.Instruction.PERSONALITY_INDIRECT_JUMP,
  idaapi.NN_jmpni: program.Instruction.PERSONALITY_INDIRECT_JUMP,

  idaapi.NN_int: program.Instruction.PERSONALITY_SYSTEM_CALL,
  idaapi.NN_into: program.Instruction.PERSONALITY_SYSTEM_CALL,
  idaapi.NN_int3: program.Instruction.PERSONALITY_SYSTEM_CALL,
  idaapi.NN_bound: program.Instruction.PERSONALITY_SYSTEM_CALL,
  idaapi.NN_syscall: program.Instruction.PERSONALITY_SYSTEM_CALL,
  idaapi.NN_sysenter: program.Instruction.PERSONALITY_SYSTEM_CALL,

  idaapi.NN_iretw: program.Instruction.PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_iret: program.Instruction.PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_iretd: program.Instruction.PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_iretq: program.Instruction.PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_sysret: program.Instruction.PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_sysexit: program.Instruction.PERSONALITY_SYSTEM_RETURN,

  idaapi.NN_hlt: program.Instruction.PERSONALITY_TERMINATOR,
  idaapi.NN_ud2: program.Instruction.PERSONALITY_TERMINATOR,
  idaapi.NN_icebp: program.Instruction.PERSONALITY_TERMINATOR,

  idaapi.NN_ja: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jae: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jb: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jbe: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jc: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jcxz: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_je: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jecxz: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jg: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jge: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jl: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jle: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jna: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnae: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnb: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnbe: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnc: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jne: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jng: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnge: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnl: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnle: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jno: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnp: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jns: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnz: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jo: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jp: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jpe: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jpo: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jrcxz: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_js: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jz: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_xbegin: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,

  idaapi.NN_loopw: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loop: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopd: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopq: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopwe: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loope: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopde: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopqe: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopwne: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopne: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopdne: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopqne: program.Instruction.PERSONALITY_CONDITIONAL_BRANCH,
}


def get_instruction_personality(decoded_inst):
  """Return the 'personality' of an instruction. This categorizes the control-
  flow behaviour of the instruction."""
  global _PERSONALITIES
  if decoded_inst.itype in _PERSONALITIES:
    return _PERSONALITIES[decoded_inst.itype]
  else:
    return program.Instruction.PERSONALITY_FALL_THROUGH

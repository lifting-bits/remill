#!/usr/bin/env python
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import argparse
import collections
import os
import subprocess
import sys
import traceback

import log
import program


# If we're in the IDA script, then we can use the IDA Python APIs.
try:
  import idautils
  import idaapi
  import idc
except:
  pass


POSSIBLE_CODE_REFS = set()


# Architecture-specific functions.
decode_instruction = None
get_instruction_personality = None


def init_for_arch(arch):
  """Initialize the program analyser for the architecture named by `arch`."""
  global decode_instruction, get_instruction_personality

  log.info("Initialising for architecture {}.".format(arch))
  if arch in ('x86', 'amd64'):
    import x86
    decode_instruction = x86.decode_instruction
    get_instruction_personality = x86.get_instruction_personality
  else:
    raise Exception("Unsupported architecture {}".format(arch))


def get_instruction(ea):
  """Gets the instruction located at `ea`. If we haven't initialized an
  `Instruction` data structure for the instruction at `ea`, then we decode
  the instruction and fill in the missing data."""
  inst = program.get_instruction(ea)
  if inst.is_valid():
    return inst

  decoded_inst, decoded_bytes = decode_instruction(ea)
  if not decoded_inst:
    log.error("Unable to decode instruction at {:08x}".format(ea))
    inst.personality = program.Instruction.PERSONALITY_TERMINATOR
    return inst

  inst.bytes = decoded_bytes
  inst.personality = get_instruction_personality(decoded_inst)
  return inst


def instruction_is_referenced(ea):
  """Returns `True` if it appears that there's a non-fall-through reference
  to the instruction at `ea`."""
  global POSSIBLE_CODE_REFS
  if len(tuple(idautils.CodeRefsTo(ea, False))):
    return True
  if len(tuple(idautils.DataRefsTo(ea))):
    return True
  return ea in POSSIBLE_CODE_REFS


def find_linear_terminator(ea, max_num=256):
  """Find the terminating instruction of a basic block, without actually
  associating the instructions with the block. This scans linearly until
  we find something that is definitely a basic block terminator. This does
  not consider the case of intermediate blocks."""
  for i in xrange(max_num):
    term_inst = get_instruction(ea)
    if term_inst.is_block_terminator() or not term_inst.is_valid():
      break

    ea = term_inst.next_ea

    # The next instruction was already processed as part of some other scan.
    if program.instruction_is_valid(ea) or instruction_is_referenced(ea):
      break

  term_inst.mark_as_terminator()
  return term_inst


def get_direct_branch_target(branch_inst_ea):
  """Tries to 'force' get the target of a direct or conditional branch.
  IDA can't always get code refs for flows from an instruction that appears
  inside another instruction (and so even seen by IDA in the first place)."""
  try:
    branch_flows = tuple(idautils.CodeRefsFrom(branch_inst_ea, False))
    return branch_flows[0]
  except:
    decoded_inst = idautils.DecodeInstruction(branch_inst_ea)
    target_ea = decoded_inst.Op1.addr
    log.warning("Determined target of {:08x} to be {:08x}".format(
        branch_inst_ea, target_ea))
    return target_ea


def get_static_successors(inst):
  """Returns the statically known successors of an instruction."""
  branch_flows = tuple(idautils.CodeRefsFrom(inst.ea, False))

  # Direct function call. The successor will be the fall-through instruction
  # unless the target of the function call looks like a `noreturn` function.
  if inst.is_direct_function_call():
    called_ea = get_direct_branch_target(inst.ea)
    flags = idc.GetFunctionFlags(called_ea)

    if 0 < flags and (flags & idaapi.FUNC_NORET):
      log.debug("Call to noreturn function {:08x} at {:08x}".format(
          called_ea, inst.ea))
    else:
      yield inst.next_ea  # Not recognised as a `noreturn` function.

  if inst.is_call():  # Indirect function call, system call.
    yield inst.next_ea

  elif inst.is_conditional_branch():
    yield inst.next_ea
    yield get_direct_branch_target(inst.ea)

  elif inst.is_direct_jump():
    yield get_direct_branch_target(inst.ea)

  elif inst.is_indirect_jump():
    si = idaapi.get_switch_info_ex(inst.ea)
    if si:
      for case_ea in idautils.CodeRefsFrom(inst.ea, True):
        yield case_ea

  elif inst.is_fall_through():
    yield inst.next_ea

  else:
    log.debug("No static successors of {:08x}".format(inst.ea))


def analyse_block(sub, block):
  """Find the instructions of a basic block."""
  log.info("Analysing basic block {:08x} of subroutine {:08x}".format(
      block.ea, sub.ea))

  if block.terminator:
    return block.terminator  # Already analysed.

  inst = block.get_instruction(block.ea)
  while not inst.is_block_terminator():
    assert inst.is_valid()
    inst = block.get_instruction(inst.next_ea)

  inst.mark_as_terminator()  # Just in case!
  block.terminator = inst
  block.successor_eas.update(get_static_successors(inst))


def analyse_subroutine(sub):
  """Goes through the basic blocks of an identified function."""
  if len(sub.blocks):
    return  # We've already processed this subroutine.

  log.info("Analysing subroutine {} at {:08x}".format(sub.name, sub.ea))
  block_head_eas = set()
  block_head_eas.add(sub.ea)

  # Try to get IDA to give us function information.
  f = idaapi.get_func(sub.ea)
  if f:
    for b in idaapi.FlowChart(f):
      block_head_eas.add(b.startEA)

    for chunk_start_ea, chunk_end_ea in idautils.Chunks(sub.ea):
      block_head_eas.add(chunk_start_ea)
  else:
    log.warning("IDA does not recognise subroutine at {:08x}".format(sub.ea))

  # Iteratively scan for block heads. This will do linear sweeps looking for
  # block terminators. These linear sweeps do not consider flows incoming
  # flows from existing blocks that logically split a block into two.
  found_block_eas = set()
  while len(block_head_eas):
    block_head_ea = block_head_eas.pop()
    if block_head_ea in found_block_eas:
      continue

    found_block_eas.add(block_head_ea)

    # Try to make sure that analysis will terminate if we accidentally 
    # walk through a noreturn call.
    if block_head_ea != sub.ea and program.has_subroutine(block_head_ea):
      continue

    log.debug("Found block head at {:08x}".format(block_head_ea))
    
    if program.has_basic_block(block_head_ea):
      existing_block = program.get_basic_block(block_head_ea)
      term_inst = existing_block.terminator
      assert term_inst is not None
    else:
      term_inst = find_linear_terminator(block_head_ea)

    log.debug("Linear terminator of {:08x} is {:08x}".format(
        block_head_ea, term_inst.ea))
    
    succ_eas = tuple(get_static_successors(term_inst))
    if succ_eas:
      log.debug("Static successors of {:08x} are {}".format(
          term_inst.ea, ", ".join("{:08x}".format(sea) for sea in succ_eas)))
      block_head_eas.update(succ_eas)

  # Create blocks associated with this subroutine for each block
  # head that the prior analysis discovered.
  blocks = []
  for block_head_ea in found_block_eas:
    if block_head_ea != sub.ea and program.has_subroutine(block_head_ea):
      continue
    block = sub.get_block(block_head_ea)
    blocks.append(block)

  log.debug("Subroutine {:08x} has {} blocks".format(sub.ea, len(blocks)))

  # Analyse the blocks
  blocks.sort(key=lambda b: b.ea)
  for block in blocks:
    analyse_block(sub, block)
    log.debug("Block at {:08x} has {} instructions".format(
        block.ea, len(block.instructions)))


def find_exported_eas():
  """Find the address of all exported functions. Exported functions are
  entrypoints into this program that external code can execute."""
  exported_eas = set()
  for index, ordinal, ea, name in idautils.Entries():
    if idc.hasName(ea):
      exported_eas.add(ea)
    else:
      log.error("Exported subroutine {:08x} has no name.".format(ea))
  return exported_eas


def find_imported_eas():
  """Find the address of all imported functions."""
  num_imports = idaapi.get_import_module_qty()
  imported_eas = set()
  named_imported_eas = set()

  for i in xrange(num_imports):
    idaapi.enum_import_names(i, lambda ea, name, ord: imported_eas.add(ea))

  for ea in imported_eas:
    if idc.hasName(ea):
      named_imported_eas.add(ea)
    else:
      log.error("Imported subroutine {:08x} has no name.".format(ea))

  # TODO(pag):  This is not finding most thunks. Perhaps go over all identified
  #             functions and test them.

  return named_imported_eas


def get_called_subroutines(sub):
  """Finds all functions directly called by `sub`."""
  called_sub_eas = set()
  for block in sub:
    term_inst = block.terminator
    assert term_inst
    if term_inst.is_direct_function_call():
      called_sub_eas.add(get_direct_branch_target(term_inst.ea))
  return called_sub_eas


def analyse_subroutines():
  """Goes through all the subroutines that IDA's initial auto analysis
  discovers."""

  log.info("Analysing initial subroutines identified by IDA")
 
  exported_eas = find_exported_eas()
  log.info("IDA identified {} exported functions".format(len(exported_eas)))

  imported_eas = find_imported_eas()
  log.info("IDA identified {} imported functions".format(len(imported_eas)))

  subs = set()
  sub_eas = set()  # Work list.
  sub_eas.update(exported_eas)
  sub_eas.update(imported_eas)

  # Get all subroutines that IDA recognised.
  for seg_ea in idautils.Segments():
    min_ea, max_ea = idc.SegStart(seg_ea), idc.SegEnd(seg_ea)
    sub_eas.update(idautils.Functions(min_ea, max_ea))

  log.info("IDA identified {} functions".format(len(sub_eas)))

  for sub_ea in sub_eas:
    sub = program.get_subroutine(sub_ea)  # Mark `ea` as a subroutine.

  while len(sub_eas):
    sub_ea = sub_eas.pop()
    sub = program.get_subroutine(sub_ea)
    if sub in subs:
      log.debug("Skipping {:08x}; already analysed.".format(sub_ea))
      continue

    subs.add(sub)

    if idc.hasName(sub_ea):
      sub.name = idc.GetFunctionName(sub_ea)
    
    # Mark this subroutine as exported.
    if sub_ea in exported_eas:
      sub.visibility = program.Subroutine.VISIBILITY_EXPORTED

    # Mark this subroutine as imported.
    elif sub_ea in imported_eas:
      sub.visibility = program.Subroutine.VISIBILITY_IMPORTED
      continue  # Don't analyse subroutine (e.g. PLT table entry).

    analyse_subroutine(sub)
    sub_eas.update(get_called_subroutines(sub))

  return subs


def scan_data_for_code_refs(begin_ea, end_ea, read_func, read_size):
  """Read in 4- or 8-byte chunks of data, and try to see if they look like
  pointers into the code."""
  global POSSIBLE_CODE_REFS
  for ea in xrange(begin_ea, end_ea, read_size):
    qword = read_func(ea)
    if idc.isCode(idc.GetFlags(qword)):
      POSSIBLE_CODE_REFS.add(qword)


def analyse_data(pointer_size):
  """Go through the data sections and look for possible tables of
  code pointers."""
  log.info("Analysing the data section for simple code refs.")
  for seg_ea in idautils.Segments():
    seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
    if seg_type != idc.SEG_DATA:
      continue

    min_ea, max_ea = idc.SegStart(seg_ea), idc.SegEnd(seg_ea)
    if 8 == pointer_size:
      scan_data_for_code_refs(min_ea, max_ea, idc.Qword, 8)
    scan_data_for_code_refs(min_ea, max_ea, idc.Dword, 4)


def analyse_indirect_jump(block, jump_inst, blocks):
  """Analyse an indirect jump and try to determine its targets."""
  log.info("Analysing indirect jump at {:08x}".format(jump_inst.ea))
  si = idaapi.get_switch_info_ex(jump_inst.ea)
  target_eas = set()
  if si:
    num_targets = si.get_jtable_size()
    log.info("IDA identified a jump table at {:08x} with {} targets".format(
        jump_inst.ea, num_targets))
    target_eas.update(idautils.CodeRefsFrom(jump_inst.ea, True))


def analyse_indirect_jumps():
  """Scan through the code looking for jump tables."""
  log.info("Analysing indirect jump instructions.")
  blocks = set(program.basic_blocks())
  seen = set()
  while len(blocks):
    block = blocks.pop()
    if block in seen:
      continue

    seen.add(block)
    term_inst = block.terminator
    if term_inst.is_indirect_jump():
      analyse_indirect_jump(block, term_inst, blocks)


def execute(args, command_args):
  """Execute IDA Pro as a subprocess, passing this file in as a batch-mode
  script for IDA to run. This forwards along arguments passed to `remill-lift`
  down into the IDA script. `command_args` contains unparsed arguments passed
  to `remill-lift`. This script may handle extra arguments."""

  ida_disass_path = os.path.abspath(__file__)
  ida_dir = os.path.dirname(ida_disass_path)

  env = {}
  env["IDALOG"] = os.devnull
  env["TVHEADLESS"] = "1"
  env["HOME"] = os.path.expanduser('~')
  env["IDA_PATH"] = os.path.dirname(args.disassembler)
  env["PYTHONPATH"] = os.path.dirname(ida_dir)

  script_cmd = []
  script_cmd.append(ida_disass_path.rstrip("c"))  # (This) script file name.
  script_cmd.append("--output")
  script_cmd.append(args.output)
  script_cmd.append("--log_file")
  script_cmd.append(args.log_file)
  script_cmd.append("--log_level")
  script_cmd.append(str(args.log_level))
  script_cmd.append("--arch")
  script_cmd.append(args.arch)
  script_cmd.extend(command_args)  # Extra, script-specific arguments.

  cmd = []
  cmd.append(args.disassembler)  # Path to IDA.
  cmd.append("-B")  # Batch mode.
  cmd.append("-S\"{}\"".format(" ".join(script_cmd)))
  cmd.append(args.binary)

  log.init(output_file=args.log_file, log_level=args.log_level)

  log.info("Executing {} {}".format(
      " ".join("{}={}".format(*e) for e in env.items()),
      " ".join(cmd)))

  try:
    with open(os.devnull, "w") as devnull:
      return subprocess.check_call(
          " ".join(cmd),
          env=env, 
          stdin=None, 
          stdout=devnull,  # Necessary.
          stderr=sys.stderr,  # For enabling `--log_file /dev/stderr`.
          shell=True,  # Necessary.
          cwd=os.path.dirname(__file__))

  except subprocess.CalledProcessError as e:
    sys.stderr.write(traceback.format_exc())
    return 1


ADDRESS_SIZE = {
  "amd64": 8,
  "x86": 4
}


if "__main__" == __name__:
  arg_parser = argparse.ArgumentParser()
  arg_parser.add_argument(
      '--log_file', type=argparse.FileType('w'), required=True)

  arg_parser.add_argument(
      '--log_level', type=int, required=True)

  arg_parser.add_argument(
      '--arch', required=True)

  arg_parser.add_argument(
      '--output', type=argparse.FileType('w'), required=True)

  try:
    args = arg_parser.parse_args(args=idc.ARGV[1:])
    log.init(output_stream=args.log_file, log_level=args.log_level)

    if args.arch not in ADDRESS_SIZE:
      arg_parser.error("{} is not recognized by `--arch`.".format(args.arch))

    init_for_arch(args.arch)

    log.info("Analysing {}.".format(idc.GetInputFile()))

    # Wait for auto-analysis to finish.
    log.info("Waiting for IDA to finish its auto-analysis.")
    idaapi.autoWait()

    analyse_data(ADDRESS_SIZE[args.arch])
    analyse_subroutines()
    analyse_indirect_jumps()

    log.info("Done.")
    idc.Exit(0)

  except SystemExit as e:
    idc.Exit(e.code)

  except:
    log.error(traceback.format_exc())
    idc.Exit(1)

# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

import idautils
import idaapi
import idc

import argparse
import os
import sys
import syslog
import traceback

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MCSEMA_DIR = os.path.dirname(SCRIPT_DIR)

sys.path.append(MCSEMA_DIR)
sys.path.append('/usr/lib/python2.7/dist-packages')
sys.path.append('/usr/local/lib/python2.7/site-packages/protobuf-2.6.1-py2.7.egg')
from generated.CFG import CFG_pb2

CALL_ITYPES = frozenset([idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni])
JMP_ITYPES = frozenset([idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni])
SYSCALL_ITYPES = frozenset([idaapi.NN_int, idaapi.NN_syscall,
                            idaapi.NN_sysenter])
PREFIX_ITYPES = frozenset([idaapi.NN_lock, idaapi.NN_rep, idaapi.NN_repe,
                           idaapi.NN_repne])

# Print out debugging information to the system log.
def debug(*args):
  if True:
    syslog.syslog(" ".join(str(a) for a in args))


# Returns True if some address represents executable code.
def address_is_code(address):
  pf = idc.GetFlags(address)
  return idc.isCode(pf) and not idc.isData(pf)


# Returns True if some address represents executable code.
def control_flows_to_address(address):
  pf = idc.GetFlags(address)
  return idc.isFlow(pf)


# Returns True if some address is not code and is data.
def address_is_data(address):
  pf = idc.GetFlags(address)
  return not idc.isCode(pf) and idc.isData(pf)


# Returns true if some address is alignment.
def address_is_alignment(address):
  flags = idc.GetFlags(address)
  return idc.isAlign(flags)


# Mark an address as containing code.
def try_mark_as_code(address, end_address=0):
  flags = idc.GetFlags(address)
  if idc.isAlign(flags):
    return False

  if idc.isCode(flags):
    return True

  if idc.MakeCode(address):
    idaapi.autoWait()
    return True

  end_address = max(end_address, address + 1)
  idc.MakeUnknown(address, end_address - address + 1, idc.DOUNK_SIMPLE)
  
  if idc.MakeCode(address):
    idaapi.autoWait()
    return True

  return False

# Mark an address as being the beginning of a function.
def try_mark_as_function(ea):
  if not idc.MakeFunction(ea, idc.BADADDR):
    idc.MakeUnknown(ea, 1, idc.DOUNK_SIMPLE)
    if not idc.MakeFunction(ea, idc.BADADDR):
      debug("Unable to convert code to function:", hex(ea))
      return False
  idaapi.autoWait()
  return True


# Get a function.
def try_get_function(address):
  func = idaapi.get_func(address)
  if not func:
    debug("Error: couldn't find function for", hex(address))
    if not try_mark_as_function(address):
      return None
    func = idaapi.get_func(address)
  return func


# Try to decode an instruction and return both the protobuf (CFG) and IDA
# representation of the instruction. In some cases, we merge two or more
# IDA instructions into a logical CFG instruction.
def try_decode_instruction(block, ea):
  global PREFIX_ITYPES
  instr_t = idautils.DecodeInstruction(ea)
  if not instr_t:
    debug("Unable to decode instruction at", hex(ea))
    return None, None

  bs = [chr(idc.Byte(bea)) for bea in range(ea, ea+instr_t.size)]

  # The following pattern exists in glibc, and IDA handles it in an annoying
  # but understandable way:
  #
  #                   cmp ...
  #                   jz unsynchronized
  #                   lock
  #   unsynchronized: cmpxchg ...
  #
  # Here we have a prefix that's split across two blocks, and we want to merge the
  # prefix and the prefixed instruction.
  instr_t2 = instr_t
  orig_ea = ea
  while 1 == instr_t2.size and instr_t2.itype in PREFIX_ITYPES:
    debug("Found prefix-only instruction at", hex(ea))
    ea += 1
    instr_t2 = idautils.DecodeInstruction(ea)
    if not instr_t2:
      debug("Unable to decode instruction tail at", hex(ea))
      return None, instr_t

    debug("Merging instruction", hex(ea), "into", hex(orig_ea))
    bs.extend([chr(idc.Byte(bea)) for bea in range(ea, ea+instr_t2.size)])

  instr = block.instructions.add()
  instr.address = orig_ea
  instr.bytes = "".join(bs)
  instr.size = len(bs)
  return instr, instr_t2


# Get the ending effective address of the next block.
def block_end_ea(ea):
  for begin, end in get_blocks(ea):
    if begin <= ea < end:
      return end
  return idc.BADADDR


# Visit an instruction. We handle function calls specially. We want to split code
# after a function call into a separate basic block, regardless of what IDA thinks.
# This is because code following a CALL is potentially reachable via indirect JMPs
# (e.g. in the `longjmp` case).
def visit_instruction(block, ea, end_ea, new_blocks, addressable_blocks):
  global CALL_ITYPES, SYSCALL_ITYPES
  instr, instr_t = try_decode_instruction(block, ea)
  if not instr:
    return idc.BADADDR

  # If there's a data reference to this instruction then we'll consider it a block
  # head and split the block (as long as this ins't the first instruction).
  if len(tuple(idautils.DataRefsTo(ea))):
    addressable_blocks.add(ea)
    if block.address < ea:
      debug("Splitting block at", hex(ea), "to", hex(end_ea), "(reason: data ref)")
      new_blocks.add((ea, end_ea))
      return idc.BADADDR

  ea += instr.size

  # Split this block at a calls, and mark the blocks following the calls as
  # being addressed. Only do this if the `call` isn't the last instruction in
  # the block.
  if instr_t.itype in CALL_ITYPES or instr_t.itype in SYSCALL_ITYPES:
    addressable_blocks.add(ea)
    if ea < end_ea:
      debug("Splitting block at", hex(ea), "to", hex(end_ea), "(reason: call)")
      new_blocks.add((ea, end_ea))
      return idc.BADADDR

  # Instruction is split over two blocks and was merged by our script, try to split the
  # block to handle this. This is seen in glibc where code conditionally jumps after
  # the `LOCK` prefix of a `cmpxchg`, or falls through to the `lock cmpxchg`.
  if instr.size > instr_t.size:
    if ea > end_ea:
      end_ea = block_end_ea(ea)
    if idc.BADADDR != end_ea:
      new_blocks.add((ea, end_ea))
      debug("Splitting block at", hex(ea), "to", hex(end_ea), "(reason: cross)")
    else:
      debug("Unable to find next block end for merged instruction at", hex(instr.address))
    return idc.BADADDR

  return ea


# Visit a basic block and add it to the control-flow graph.
def visit_block(cfg, ea, end_ea, new_blocks, addressable_blocks):
  debug("Found basic block at", hex(ea), "to", hex(end_ea))
  block = cfg.blocks.add()
  block.address = ea

  while ea < end_ea and idc.BADADDR != ea:
    assert address_is_code(ea)
    ea = visit_instruction(block, ea, end_ea, new_blocks, addressable_blocks)


# Scan for blocks of code.
def scan_blocks(ea):
  blocks = set()
  # TODO(pag): Implement me.
  # Try using idautils.Heads and stop when we come across a head that is also
  # a function, or when heads stops working. Limit the search to the end of
  # the current segment.
  return blocks


# Walk the blocks of code within a function. Sometimes we find a function via
# and internal label `ea`. In this case, we want to ensure that we find that
# `ea` is the beginning of a block, so we will sometimes split it.
def function_blocks(ea, func):
  blocks = set()
  for block in idaapi.FlowChart(func):
    if block.startEA < block.endEA:
      if block.startEA < ea < block.endEA:
        blocks.add((block.startEA, ea))
        blocks.add((ea, block.endEA))
      else:
        blocks.add((block.startEA, block.endEA))
  return blocks


# Get a list of [begin, end) program counter pairs representing the bounds of
# basic blocks within a function, likely beginning at `ea`.
def get_blocks(ea):
  func = try_get_function(ea)
  if not func:
    if not try_mark_as_function(ea):
      return scan_blocks(ea)
    func = try_get_function(ea)
    assert func
  return function_blocks(ea, func)


# Visit all the basic block reachable from a given location.
def visit_blocks(cfg, ea, seen_blocks, addressable_blocks):
  blocks = get_blocks(ea)
  while len(blocks):
    ea, end_ea = blocks.pop()
    if ea in seen_blocks:
      continue
    seen_blocks.add(ea)
    visit_block(cfg, ea, end_ea, blocks, addressable_blocks)


# Find functions that this code exports to the outside world.
def find_exported_functions(cfg, exclude_blocks):
  for idx, ord, ea, name in idautils.Entries():
    if address_is_code(ea):
      func = cfg.functions.add()
      func.name = name
      func.address = ea
      func.is_imported = False
      func.is_exported = True
      func.is_weak = False

      debug("Found export:", name, "at", hex(ea))
      visit_blocks(cfg, ea, exclude_blocks, set([ea]))

    elif address_is_data(ea):
      # TODO(pag): Implement this!
      pass


# Find functions that this code imports from the outside world.
def find_imported_functions(cfg, exclude_blocks):

  # Try to pattern-match an imported function against an ELF GOT/PLT entry.
  # 
  # Example:
  #   malloc@plt:
  #   0x402640 <+0>:  jmp   QWORD PTR [rip+0x217c22] # 0x61a268 <malloc@got.plt>
  #   0x402646 <+6>:  push  0x4a
  #   0x40264b <+11>: jmp   0x402190
  #
  # Produces:
  #   plt_offset = 0x402646   <-- what we get in IDA.
  #   got_entry_ea = 0x61a268          
  #   plt_jmp_ea = 0x402640
  def visit_elf_import(plt_offset, name):
    exclude_blocks.add(plt_offset)

    ea = 0
    for got_entry_ea in idautils.DataRefsTo(plt_offset):
      seg_name = idc.SegName(got_entry_ea)
      if ".got.plt" == seg_name:
        for plt_jmp_ea in idautils.DataRefsTo(got_entry_ea):
          if ".plt" != idc.SegName(plt_jmp_ea):
            continue
          plt_jmp = idautils.DecodeInstruction(plt_jmp_ea)
          if plt_jmp and "jmp" == plt_jmp.get_canon_mnem():
            ea = plt_jmp_ea

      elif ".got" == seg_name:
        assert idaapi.is_weak_name(plt_offset)

    if ea:
      func = cfg.functions.add()
      func.name = name
      func.address = ea
      func.is_imported = True
      func.is_exported = False
      func.is_weak = idaapi.is_weak_name(plt_offset)

      exclude_blocks.add(ea)
      debug("Found import:", name, "at", hex(ea))
    else:
      debug("Didn't find import", name)
  
  # Visit an imported function name.
  def visit_import(ea, name, ord):
    visit_elf_import(ea, name)
    return True

  num_imports = idaapi.get_import_module_qty()
  for i in range(num_imports):
    idaapi.enum_import_names(i, visit_import)


# Find functions that are internal to the executable / library.
def find_internal_functions(cfg, seen_blocks, addressable_blocks):
  for seg_ea in idautils.Segments():
    seg_start, seg_end = idc.SegStart(seg_ea), idc.SegEnd(seg_ea)
    for func_ea in idautils.Functions(seg_start, seg_end):
      if func_ea in seen_blocks:
        continue

      func = cfg.functions.add()
      func.name = idc.GetTrueNameEx(func_ea, func_ea) or ""
      func.address = func_ea
      func.is_imported = False
      func.is_exported = False
      func.is_weak = False

      debug("Found function:", func.name, "at", hex(func_ea))
      
      visit_blocks(cfg, func_ea, seen_blocks, addressable_blocks)


# Adds a list of blocks that might be targeted by indirect jumps/calls to a
# set of entrypoints.
def find_indirect_entrypoints(cfg, addressable_blocks):
  for ea in addressable_blocks:
    block = cfg.indirect_blocks.add()
    block.address = ea


# This is a 'fudge' factor when we find that two blocks are separated by data
# and we think we should merge them. We use the maximum length of an x86
# instruction as our fudge.
MAX_INSTRUCTION_LENGTH = 15


# Return the next (assumed) block head that is actually code.
def next_code_head_ea(heads, i):
  while i < len(heads):
    if address_is_code(heads[i]):
      return heads[i]
    i = i+1
  return idc.BADADDR


# Collect function call targets.
def collect_function_call_target(heads, ea):
  global CALL_ITYPES
  instr_t = idautils.DecodeInstruction(ea)
  if not instr_t or instr_t.itype not in CALL_ITYPES:
    return
  target_ea = instr_t.Operands[0].addr
  if target_ea and idc.BADADDR != target_ea:
    heads.add(target_ea)


# Clean up a segment of code by trying to make sure that basic blocks connect.
# We need to be careful during our cleanup because it might introduce new block
# heads, so we always move in a forward direction and "restart" from intermediate
# positions.
def clean_up_segment(seg_start, seg_end, function_heads):
  head_ea = seg_start
  while head_ea < seg_end:
    blocks = list(idautils.Heads(head_ea, seg_end))
    if not blocks:
      break

    blocks.append(seg_end)

    for i, head_ea in enumerate(blocks):
      if head_ea == seg_end:
        break

      actual_end_ea = blocks[i+1]
      if not address_is_code(head_ea):
        continue

      # Try to find called functions.
      collect_function_call_target(function_heads, head_ea)

      if address_is_code(actual_end_ea):
        continue

      expected_end_ea = next_code_head_ea(blocks, i+1)
      if idc.BADADDR == expected_end_ea:
        continue

      # Looks like there some non-code between two basic blocks. If control
      # flows from the last instruction to the non-code, and as long as the
      # non-code stuff isn't too long, then we'll try to mark it as code.
      if 0 < (expected_end_ea - actual_end_ea) <= MAX_INSTRUCTION_LENGTH:
        if control_flows_to_address(actual_end_ea):
          if try_mark_as_code(actual_end_ea, expected_end_ea):
            debug("Cleanup: marked", hex(actual_end_ea), "as a block head")
            break


# Clean up the code that IDA sees. This is sometimes necessary with code that
# has no symbols, and so requires more of IDA's heuristics to kick in. We
# apply some "anti"-heuristics where IDA makes strange choices. These special
# cases are geared toward "nice" code, as produced by a typical compiler.
def find_functions():
  function_heads = set()
  for seg_ea in idautils.Segments():
    clean_up_segment(idc.SegStart(seg_ea), idc.SegEnd(seg_ea),
                     function_heads)
  
  # Try to mark known "good" procedure heads.
  for func_ea in function_heads:
    try_mark_as_function(func_ea)

  # Mark all remaining things as procedures.
  for seg_ea in idautils.Segments():
    for head_ea in idautils.Heads(idc.SegStart(seg_ea), idc.SegEnd(seg_ea)):
      if address_is_code(head_ea) \
      and not address_is_alignment(head_ea) \
      and not idc.GetFunctionName(head_ea):
        debug("Not part of function:", hex(head_ea))
        try_mark_as_function(head_ea)


# Wait for IDA to finish its analysis.
def init_analysis():
  analysis_flags = idc.GetShortPrm(idc.INF_START_AF)
  analysis_flags &= ~idc.AF_IMMOFF  
  idc.SetShortPrm(idc.INF_START_AF, analysis_flags)
  idaapi.autoWait()


# Close IDA now that we're done.
def exit_analysis():
  idc.Exit(0)


# Analyze a binary.
def main(args):
  init_analysis()
  
  try:
    cfg = CFG_pb2.Module()
    cfg.binary_path = idc.GetInputFile()
    exclude_blocks = set()

    debug("Finding functions...")
    find_functions()

    debug("Analyzing exports...")
    find_exported_functions(cfg, exclude_blocks)

    debug("Analyzing imports...")
    find_imported_functions(cfg, exclude_blocks)

    debug("Analyzing functions...")
    addressable_blocks = set(exclude_blocks)
    find_internal_functions(cfg, exclude_blocks, addressable_blocks)

    debug("Analyzing indirect entrypoints...")
    find_indirect_entrypoints(cfg, addressable_blocks)

    debug("Saving CFG to", args.output)
    with open(args.output, "wb") as output:
      output.write(cfg.SerializeToString())

    debug("Done.")
  except:
    debug(traceback.format_exc())
  
  exit_analysis()


if "__main__" == __name__:
  parser = argparse.ArgumentParser()
  parser.add_argument("-o", "--output",
      type=str,
      default=None,
      help="The output control flow graph recovered from this file")

  main(parser.parse_args(args=idc.ARGV[1:]))

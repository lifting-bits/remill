# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import log
import os
import program
import sys

sys.path.append('/usr/lib/python2.7/dist-packages')
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import CFG_pb2


def save_to_stream(output_stream):
  mod = CFG_pb2.Module()
  num_subs, num_blocks, num_insts = 0, 0, 0

  exclude_blocks = set()
  for sub in program.subroutines():
    num_subs += 1
    if program.Subroutine.VISIBILITY_IMPORTED == sub.visibility:
      exclude_blocks.update(sub.blocks)

  log.debug("Not serializing {} blocks".format(len(exclude_blocks)))

  for block in program.basic_blocks():
    if block in exclude_blocks:
      continue

    if not len(block.instructions):
      log.error("Block {:08x} has no instructions.".format(block.ea))
      continue

    num_blocks += 1

    log.info("Serializing block {:08x}.".format(block.ea))
    b = mod.blocks.add()
    b.address = block.ea

    if program.has_subroutine(block.ea):
      func_of_block = program.get_subroutine(block.ea)
      if func_of_block.name:
        b.name = func_of_block.name

    for inst in block:
      i = b.instructions.add()
      i.address = inst.ea
      i.bytes = inst.bytes
      num_insts += 1

  log.info("Serializing {} blocks".format(num_blocks))
  log.info("Serializing {} instructions".format(num_insts))
  output_stream.write(mod.SerializeToString())

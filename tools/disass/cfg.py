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

  referenced_blocks = set()
  addressed_blocks = set()
  for block in program.basic_blocks():
    if block in exclude_blocks:
      continue

    if not len(block.instructions):
      referenced_blocks.add(block)
      log.error("Block {:08x} has no instructions.".format(block.ea))
      continue

    num_blocks += 1

    log.info("Serializing block {:08x}.".format(block.ea))
    b = mod.blocks.add()
    b.address = block.ea
    
    if block.address_is_taken:
      addressed_blocks.add(block)

    for inst in block:
      i = b.instructions.add()
      i.address = inst.ea
      i.bytes = inst.bytes
      num_insts += 1

  for block in addressed_blocks:
    mod.addressed_blocks.append(block.ea)

  for block in referenced_blocks:
    mod.referenced_blocks.append(block.ea)

  for sub in program.subroutines():
    if not sub.name:
      continue

    if program.Subroutine.VISIBILITY_INTERNAL == sub.visibility:
      continue

    nb = mod.named_blocks.add()
    nb.name = sub.name
    nb.address = sub.ea

    if program.Subroutine.VISIBILITY_IMPORTED == sub.visibility:
      nb.visibility = CFG_pb2.IMPORTED
    elif program.Subroutine.VISIBILITY_EXPORTED == sub.visibility:
      nb.visibility = CFG_pb2.EXPORTED

  log.info("Serializing {} subroutines".format(num_subs))
  log.info("Serializing {} blocks".format(num_blocks))
  log.info("Serializing {} instructions".format(num_insts))
  output_stream.write(mod.SerializeToString())

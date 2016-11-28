# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.


import collections


class _AddressedDictionary(collections.defaultdict):
  """A defaultdict, where all constructed values are assumed to have an
  `ea` field, which will be supplied via the key to the dict."""
  def __getitem__(self, ea):
    value = super(_AddressedDictionary, self).__getitem__(ea)
    value.ea = ea
    return value



class Subroutine(object):
  __slots__ = ('name', 'ea', 'blocks', 'visibility')

  VISIBILITY_INTERNAL = 0
  VISIBILITY_EXPORTED = 1
  VISIBILITY_IMPORTED = 2

  def __init__(self):
    self.name = ""
    self.ea = 0
    self.blocks = set()
    self.visibility = Subroutine.VISIBILITY_INTERNAL

  def get_basic_block(self, block_ea):
    block = get_basic_block(block_ea)
    block.subroutines.add(self)
    self.blocks.add(block)
    return block

  def __iter__(self):
    return iter(self.blocks)


class BasicBlock(object):
  __slots__ = ('ea', 'end_ea', 'instructions', 'is_addressable',
               'subroutines', 'terminator', 'successor_eas',
               'address_is_taken')
  
  def __init__(self):
    self.ea = 0
    self.end_ea = 0
    self.instructions = set()
    self.is_addressable = False
    self.subroutines = set()
    self.terminator = None  # Last instruction of this block.
    self.successor_eas = set()
    self.address_is_taken = False

  def get_instruction(self, inst_ea):
    global _INSTRUCTIONS
    inst = _INSTRUCTIONS[inst_ea]
    self.instructions.add(inst)
    return inst

  def __iter__(self):
    insts = list(self.instructions)
    insts.sort(key=lambda i: i.ea)
    return iter(insts)


class Instruction(object):
  __slots__ = ('ea', 'bytes', 'personality')

  PERSONALITY_INVALID = 0
  PERSONALITY_DIRECT_JUMP = 1
  PERSONALITY_INDIRECT_JUMP = 2
  PERSONALITY_DIRECT_CALL = 3
  PERSONALITY_INDIRECT_CALL = 4
  PERSONALITY_RETURN = 5
  PERSONALITY_SYSTEM_CALL = 6
  PERSONALITY_SYSTEM_RETURN = 7
  PERSONALITY_CONDITIONAL_BRANCH = 8
  PERSONALITY_TERMINATOR = 9
  PERSONALITY_FALL_THROUGH = 10
  PERSONALITY_FALL_THROUGH_TERMINATOR = 11

  def __init__(self):
    self.ea = 0
    self.bytes = ""
    self.personality = Instruction.PERSONALITY_INVALID

  @property
  def next_ea(self):
    return self.ea + len(self.bytes)

  def is_valid(self):
    return Instruction.PERSONALITY_INVALID != self.personality

  def is_indirect_function_call(self):
    return Instruction.PERSONALITY_INDIRECT_CALL == self.personality
  
  def is_direct_function_call(self):
    return Instruction.PERSONALITY_DIRECT_CALL == self.personality

  def is_function_call(self):
    return self.is_direct_function_call() or self.is_indirect_function_call()

  def is_function_return(self):
    return Instruction.PERSONALITY_RETURN == self.personality

  def is_conditional_branch(self):
    return Instruction.PERSONALITY_CONDITIONAL_BRANCH == self.personality

  def is_system_call(self):
    return Instruction.PERSONALITY_SYSTEM_CALL == self.personality

  def is_system_return(self):
    return Instruction.PERSONALITY_SYSTEM_RETURN == self.personality

  def is_call(self):
    return self.is_function_call() or self.is_system_call()

  def is_return(self):
    return self.is_function_return() or self.is_system_return()

  def is_indirect_jump(self):
    return Instruction.PERSONALITY_INDIRECT_JUMP == self.personality
  
  def is_direct_jump(self):
    return Instruction.PERSONALITY_DIRECT_JUMP == self.personality

  def is_jump(self):
    return self.is_indirect_jump() or self.is_direct_jump()

  def is_fall_through(self):
    return self.personality in (Instruction.PERSONALITY_FALL_THROUGH,
                                Instruction.PERSONALITY_FALL_THROUGH_TERMINATOR)

  def mark_as_terminator(self):
    if self.is_block_terminator():
      return

    if Instruction.PERSONALITY_FALL_THROUGH == self.personality:
      self.personality = Instruction.PERSONALITY_FALL_THROUGH_TERMINATOR
      return

    raise Exception(
        "Unable to convert instruction at {:08x} into a terminator.".format(
            self.ea))

  def is_block_terminator(self):
    return self.personality not in (Instruction.PERSONALITY_FALL_THROUGH,
                                    Instruction.PERSONALITY_INVALID)


_SUBROUTINES = _AddressedDictionary(Subroutine)
_BASIC_BLOCKS = _AddressedDictionary(BasicBlock)
_INSTRUCTIONS = _AddressedDictionary(Instruction)


def get_subroutine(ea):
  global _SUBROUTINES
  return _SUBROUTINES[ea]


def has_subroutine(ea):
  global _SUBROUTINES
  return ea in _SUBROUTINES


def get_basic_block(ea):
  global _BASIC_BLOCKS
  return _BASIC_BLOCKS[ea]


def has_basic_block(ea):
  global _BASIC_BLOCKS
  return ea in _BASIC_BLOCKS


def get_instruction(ea):
  global _INSTRUCTIONS
  return _INSTRUCTIONS[ea]


def has_instruction(ea):
  global _INSTRUCTIONS
  return ea in _INSTRUCTIONS


def instruction_is_valid(ea):
  global _INSTRUCTIONS
  if ea not in _INSTRUCTIONS:
    return False
  inst = _INSTRUCTIONS[ea]
  return inst.is_valid()


def basic_blocks():
  global _BASIC_BLOCKS
  return iter(_BASIC_BLOCKS.values())


def subroutines():
  global _BASIC_BLOCKS
  return iter(_SUBROUTINES.values())

# class JumpTable(object):
#   __slots__ = ('ea', 'personality', 'targets')

#   PERSONALITY_UNKNOWN = 0
#   ENTRIES = _AddressedDictionary(JumpTable)

#   def __init__(self):
#     self.ea = 0
#     self.personality = JumpTable.PERSONALITY_UNKNOWN
#     self.targets = set()

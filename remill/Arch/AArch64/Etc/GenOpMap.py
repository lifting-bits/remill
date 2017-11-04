#!/usr/bin/env python
# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# How to use:
#
# Step 1:
#   Download https://developer.arm.com/-/media/developer/products/architecture/armv8-a-architecture/A64_v82A_ISA_xml_00bet3.2.tar.gz
#
# Step 2:
#   Extract the `ISA_v82A_A64_xml_00bet3.1_OPT` directory.
#
# Step 3:
#   Run this program, passing in the path to the
#   `ISA_v82A_A64_xml_00bet3.1_OPT` directory.

import collections
import itertools
import math
import os
import sys

try:
  import xml.etree.cElementTree as ET
except:
  import xml.etree.ElementTree as ET


# <instructionsection id="ADD_addsub_imm" title="ADD (immediate) -- A64" type="instruction">
#   ...
#   <classes>
#     <iclass name="Not setting the condition flags" oneof="1" id="no_s" no_encodings="2" isa="A64">
#       ...
#       <regdiagram form="32" psname="..." tworows="1">
#         <box hibit="31" name="sf" usename="1">
#           <c></c>
#         </box>
#         ...
#         <box hibit="28" width="5" settings="5">
#           <c>1</c>
#           ...
#         </box>

NAMES = set()
ENCODINGS = []
UNALIASED_ENCODINGS = []
BITS = {}
BIT_BASE = {}
USED_FIELD_NAMES = set()

class BaseDiagram(object):
  def __init__(self):
    self.bits = ['x'] * 32
    # self.simp_names = [None] * 32
    self.names = [None] * 32
    self.iclass = ""
    self.iform = ""
    self.constraints = {}
    self.asm_string = ""
    self.hints = {}

def print_diag(diag, out):
  out.write("// {} {}:\n".format(diag.iclass, diag.iform))
  for i in xrange(32):
    out.write("//  {:2} {}".format(i, diag.bits[i]))
    if diag.names[i]:
      out.write(" {:8} {}".format(diag.names[i][0], diag.names[i][1]))
    out.write("\n")

# REGS = ('Ra', 'Rd', 'Rm', 'Rn', 'Rs', 'Rt', 'Rt2',)
# REGS_32 = ('Wa', 'Wd', 'Wm', 'Wn', 'Ws', 'Wt', 'Wt2',)
# REGS_64 = ('Xa', 'Xd', 'Xm', 'Xn', 'Xs', 'Xt', 'Xt2',)

# REGS_32 = {
#   'Wa': 'Ra',
#   'Wd': 'Rd',
#   'Wm': 'Rm',
#   'Wn': 'Rn',
#   'Ws': 'Rs',
#   'Wt': 'Rt',
#   'Wt2': 'Rt2',
# }

# REGS_64 = {
#   'Xa': 'Ra',
#   'Xd': 'Rd',
#   'Xm': 'Rm',
#   'Xn': 'Rn',
#   'Xs': 'Rs',
#   'Xt': 'Rt',
#   'Xt2': 'Rt2',
# }

# REGS_128 = {
#   'Va': 'Ra',
#   'Vd': 'Rd',
#   'Vm': 'Rm',
#   'Vn': 'Rn',
#   'Vs': 'Rs',
#   'Vt': 'Rt',
#   'Vt2': 'Rt2',
# }

# REGS_FP16_BIT_SIMD = {  # Half precision.
#   'Ha': 'Ra',
#   'Hd': 'Rd',
#   'Hm': 'Rm',
#   'Hn': 'Rn',
#   'Hs': 'Rs',
#   'Ht': 'Rt',
#   'Ht2': 'Rt2',
# }

# REGS_FP32_BIT_SIMD = {  # Single precision.
#   'Sa': 'Ra',
#   'Sd': 'Rd',
#   'Sm': 'Rm',
#   'Sn': 'Rn',
#   'Ss': 'Rs',
#   'St': 'Rt',
#   'St2': 'Rt2',
# }

# REGS_FP64_BIT_SIMD = {  # Double precision.
#   'Da': 'Ra',
#   'Dd': 'Rd',
#   'Dm': 'Rm',
#   'Dn': 'Rn',
#   'Ds': 'Rs',
#   'Dt': 'Rt',
#   'Dt2': 'Rt2',
# }

# def _parse_reg(text, reg_map, size):
#   for reg in reg_map:
#     if reg in text:
#       return AsmReg(text, reg, reg_map[reg], size)
#   return None

# def parse_reg(text):
#   return _parse_reg(text, REGS_32, 32) \
#       or _parse_reg(text, REGS_64, 64) \
#       or _parse_reg(text, REGS_128, 128) \
#       or _parse_reg(text, REGS_FP16_BIT_SIMD, 16) \
#       or _parse_reg(text, REGS_FP32_BIT_SIMD, 32) \
#       or _parse_reg(text, REGS_FP64_BIT_SIMD, 64)

# class AsmExpr(object):
#   pass

# class AsmReg(AsmExpr):
#   def __init__(self, name, reg_name, field_name, reg_size):
#     self.name = name.replace('|', "_").strip('<').strip('>')
#     self.reg_name = reg_name
#     self.field_name = field_name
#     self.reg_size = reg_size

# ASM_TREE = {}

def parse_asm(enc, base):
  asm_string = []
  parts = []
  for elem in enc.iterfind('asmtemplate/*'):
    assert elem.tag == 'text' or elem.tag == 'a'
    asm_string.append(elem.text)
    text = elem.text.strip(",").strip()
    if not text:
      continue
    parts.append(text)

  return "".join(asm_string)

  # names = set()
  # for n in base.names:
  #   if n:
  #     name, bit = n
  #     names.add(name)

  # print "".join(asm_string)
  # print parts

  # with open("/dev/stderr", "w") as f:
  #   print_diag(base, f)

  # for i, text in enumerate(parts):
  #   part = text
  #   if text.startswith('<'):
  #     # This sucks. So, in something like `FRECPX  <V><d>, <V><n>`, what we
  #     # should really have is `Sd` or `Dd`, where a different `<encoding>` tag
  #     # is used to differentiate the two. Unfortunately, the creator(s) of the
  #     # XML file decided against this.. WHYYY???? So, we'll punt on this
  #     # for some later stage.
  #     if text == '<V>':
  #       return

  #     elif text[1] in "XRWVHSD":
  #       reg = parse_reg(text)
  #       assert reg
  #       parts[i] = reg

  #     elif text[1] in "T":
  #       print text
  #       assert False

  #     else:
  #       print text
  #       assert False

  #     continue
      

  #     # assert part == text
  #     # if '(field '
  #     # # if text == '<shift>':
  #     # #   if 'shift' in names:

  #     # #   print base.names
  #     # #   exit()
  #     # #   print "shift!"
  #     # #   print elem.attrib
  #     # # elif text == '<extend>':
  #     # #   print "extend!"
  #     # #   print elem.attrib

  # print parts
  # print 

def parse_diagram_impl(diagram, base):

  # # Figure out the number of bits in a combined `immhi` or `immlo` pair.
  # immlo_size = collections.defaultdict(int)
  # for box in diagram.iterfind('box'):
  #   if 'name' in box.attrib:
  #     name = box.attrib['name']
  #     if 'imm' in name and 'lo' in name:
  #       immlo_size[name[:-2]] += int(box.attrib['width'])

  # Decompose the boxes into the basic diagram. This doesn't include
  for box in diagram.iterfind('box'):
    high_bit = int(box.attrib['hibit'])
    curr_bit = high_bit

    # How many bits in this box?
    num_cols = 1
    if 'width' in box.attrib:
      num_cols = int(box.attrib['width'])

    # Name the bits of the box
    base_index = 0
    limit_index = num_cols - 1

    if 'name' in box.attrib:
      name = box.attrib['name'].strip()
      # simp_name = name
      # use_name = 'usename' in box.attrib and box.attrib['usename'] == '1'

      # Extract the sub-range of the logical bitfield being accessed.
      if '[' in name or '<' in name:
        name = name.replace('<', '[')
        name = name.replace('>', '')
        name = name.replace(']', '')
        name = name.replace(':', '[')
        parts = name.split('[')
        name = parts[0].strip()
        # simp_name = name

        # assert not name.endswith('hi')
        # assert not name.endswith('lo')

        base_index = int(parts[1])
        limit_index = base_index
        assert len(parts) <= 3
        if len(parts) == 3:
          base_index, limit_index = int(parts[2]), base_index

        assert num_cols == (limit_index - base_index + 1)
      
      # # If this is the high component of an immediate, then add it in as if
      # # part of the immediate was being indexed.
      # elif 'imm' in name and 'hi' in name:
      #   simp_name = "{}_hilo".format(name[:-2])
      #   base_index = immlo_size[name]
      #   limit_index = num_cols - 1

      # # If this is the low component of an immediate, then add it in as if
      # # part of the immediate was being indexed.
      # elif 'imm' in name and 'lo' in name:
      #   simp_name = "{}_hilo".format(name[:-2])
      #   base_index = 0
      #   limit_index = num_cols - 1

      for i in xrange(num_cols):
        # if use_name:
        #   base.simp_names[curr_bit - num_cols + 1 + i] = (simp_name, base_index)
        base.names[curr_bit - num_cols + 1 + i] = (name, base_index)
        base_index += 1

      NAMES.add(name)

    seen_other_bits = False
    for c in box.iterfind('c'):
      col_span = 1
      if 'colspan' in c.attrib:
        col_span = int(c.attrib['colspan'])

      # None of these bits are set.
      if not c.text:
        curr_bit -= col_span
        continue

      text = c.text

      if 'constraint' in box.attrib:
        assert not seen_other_bits
        assert name
        cs = c.text.strip()
        assert cs.startswith('!= ')
        cs = cs[3:]
        base.constraints[name] = cs
        if 'psbits' not in box:
          text = "x" * col_span
        else:
          start = high_bit - curr_bit
          text = box.attrib['psbits'][start:][-col_span]
      
      seen_other_bits = True

      # `HINT` uses `Z`.
      # `LDEORAL` uses `N`.
      # `FCMPE` uses 'z'.
      #
      # Things like the `HINT` instruction are super annoying. They use `Z`
      # and those things need to magically need to be figured out by parsing
      # out stuff from the 'structured' comments. I have no idea what `N` is,
      # but it comes up with things like `LDEORAL`.
      if 1 == col_span:
        val = str(eval(text, {}, {'x': 'x', 'z': 'x', 'Z': 'x', 'N': 'x'}))
        assert len(val) == 1
        base.bits[curr_bit] = val
        curr_bit -= 1

      else:
        for i in xrange(col_span):
          val = text[i]
          base.bits[curr_bit] = val
          curr_bit -= 1

ALIASES = collections.defaultdict(set)
ASM = {}

def adapt_diagram(base, enc):
  new_base = BaseDiagram()
  new_base.iform = enc.attrib['name']
  new_base.iclass = base.iclass
  new_base.bits = list(base.bits)
  new_base.names = list(base.names)
  new_base.constraints = dict(base.constraints)
  # new_base.simp_names = list(base.simp_names)
  parse_diagram_impl(enc, new_base)
  ASM[new_base.iform] = parse_asm(enc, new_base)
  
  alias_iclass = None
  for docvar in enc.iterfind('docvars/docvar'):
    if docvar.attrib['key'] == 'mnemonic':
      new_base.iclass = docvar.attrib['value']

    elif docvar.attrib['key'] == 'alias_mnemonic':
      alias_iclass = docvar.attrib['value']

  if alias_iclass:
    alias_iform = "_".join(new_base.iform.split("_")[1:])
    ALIASES[alias_iform].add(new_base)
    print new_base.iform, 'is an alias of', alias_iform

  return new_base, alias_iclass

def parse_diagram(diagram):
  global NAMES
  base = BaseDiagram()
  base.iform = diagram.attrib['psname'].split("/")[-1]
  base.iclass = base.iform.split("_")[0]
  parse_diagram_impl(diagram, base)
  return base

def parse_xml(doc):
  for iclass in doc.iterfind("classes/iclass"):
    for diagram in iclass.iterfind('regdiagram'):
      base = parse_diagram(diagram)
      for enc in iclass.iterfind('encoding'):
        new_base, is_alias = adapt_diagram(base, enc)
        ENCODINGS.append(new_base)
        if is_alias:
          continue

        bits = "".join(new_base.bits)
        assert bits not in BITS
        BITS[bits] = new_base
        BIT_BASE[bits] = base
        UNALIASED_ENCODINGS.append(new_base)

def chosen_to_string(num, chosen_list):
  pr = ["-"] * 32
  for i, v in enumerate(reversed(chosen_list)):
    if num & (1 << i):
      pr[v] = '1'
    else:
      pr[v] = '0'
  return "".join(reversed(pr))

# def get_bits(group, num_bits):
#   group = set(group)
#   count = [0] * 32
#   diff = [0] * 32
#   static = collections.defaultdict(set)
#   for base in group:
#     for i, bit in enumerate(base.bits):
#       if bit == 'x':
#         count[i] += 1
#       elif bit == '0':
#         diff[i] -= 1
#         static[i].add(base)
#       elif bit == '1':
#         diff[i] += 1
#         static[i].add(base)

#   # Minimize by the number of diagrams with variable bits in each position,
#   # and where the number matches, order by absolute difference between the
#   # number of zero- and one-bits in each base at that position.
#   poss = [(i, count[i], abs(diff[i])) for i in xrange(32)]
#   poss.sort(key=lambda p: (p[1], p[2]))

#   indexes = [poss[0][0]]
#   bases = static[poss[0][0]]
#   for i in xrange(1, 32):
#     if len(bases) == len(group):
#       break

#     next_bases = set()

#   for p in poss:
#     print p[0], p[1], p[2]

#   # for i in xrange(32):
#   #   print i, len(variadic[i])

# def get_static_bits(group, num_bits):
#   count = [0] * 32
#   for base in group:
#     for i, bit in enumerate(base.bits):
#       if bit == 'x':
#         count[i] += 1

#   count = list(enumerate(count))
#   count.sort(key=lambda p: p[1])
#   res = []
#   for i in xrange(num_bits):
#     res.append(count[i][0])
#   return res

dir_name = sys.argv[1]
for file_name in os.listdir(dir_name):
  if file_name.endswith(".xml"):
    print "Parsing {}".format(file_name)
    parse_xml(ET.parse(os.path.join(dir_name, file_name)))

fixed_zero = collections.defaultdict(set)
fixed_one = collections.defaultdict(set)
variadic = collections.defaultdict(set)
# at_bit = collections.defaultdict(set)

# get_bits(BITS.values(), 8)

for bits, base in BITS.items():
  for i, bit in enumerate(bits):
    # at_bit[i].add(base)
    if bit == 'x':
      variadic[i].add(base)
    elif bit == '1':
      fixed_one[i].add(base)
    elif bit == '0':
      fixed_zero[i].add(base)
    else:
      assert False

for i in xrange(32):
  print i, len(variadic[i]), len(fixed_one[i]), len(fixed_zero[i]), abs(len(fixed_one[i]) - len(fixed_zero[i]))

# 21 204
# 24 2
# 25 2
# 26 0
# 27 0
# 28 0
# 29 2
# 31 2

decl = open("/tmp/Decode.h", "w")
impl = open("/tmp/Extract.cpp", "w") 

iform_names = set()
iclass_names = set()
field_names = set()
field_name_example = {}

field_name_size = collections.defaultdict(int)
field_name_intsize = {}
field_name_bitsize = {}

max_names_per_inst = 0

for base in ENCODINGS:
  iform_names.add(base.iform)
  iclass_names.add(base.iclass)
  base.name_size = collections.defaultdict(int)

  for n in base.names:
    if not n:
      continue
    name, index = n
    base.name_size[name] += 1
    field_names.add(name)
    field_name_example[name] = base.iform

  for name, size in base.name_size.items():
    field_name_size[name] = max(field_name_size[name], size)

  max_names_per_inst = max(max_names_per_inst, len(base.name_size))

iform_names = list(iform_names)
iform_names.sort()

iclass_names = list(iclass_names)
iclass_names.sort()

field_names = list(field_names)
field_names.sort()

decl.write("""/*
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

#ifndef REMILL_ARCH_AARCH64_DECODE_H_
#define REMILL_ARCH_AARCH64_DECODE_H_

#include <cstdint>

namespace remill {

class Instruction;

namespace aarch64 {

""")

decl.write('enum class InstName : uint16_t {\n')
decl.write('  INVALID,\n')
for iclass in iclass_names:
  decl.write('  {},\n'.format(iclass.upper()))
decl.write('};\n\n')

decl.write('enum class InstForm : uint16_t {\n')
decl.write('  INVALID,\n')
for iform in iform_names:
  decl.write('  {},\n'.format(iform.upper()))
decl.write('};\n\n')

# Sort by size (in descending order) and name in ascending order
field_names = list(field_name_size.items())
field_names.sort(key=lambda p: (-p[1], p[0]))

decl.write("union InstImm {\n")
decl.write("  uint64_t uimm;\n")

for i in xrange(1, 32):
  decl.write("  union {\n")
  decl.write("    int64_t simm{}:{};\n".format(i, i))
  decl.write("    uint64_t _{}:{};\n".format(i, 32 - i))
  decl.write("  } __attribute__((packed));\n")

# decl.write('enum class OpName : uint8_t {\n')
# decl.write('  INVALID,\n')
# for field_name, size in field_names:
#   decl.write('  {},\n'.format(field_name.upper()))
# decl.write('};\n\n')

# Make a data structure that can hold any particular field that can be
# present in any instruction.

decl.write("""
} __attribute__((packed));
static_assert(sizeof(InstImm) == 8, "");

struct InstData {
  InstForm iform;
  InstName iclass;
  InstImm immhi_immlo;
""")

# decl.write("  OpName ops[{}];\n".format(max_names_per_inst))

fields = []

for field_name, size in field_names:
  num_bits = int(2 ** math.ceil(math.log(max(8, size)) / math.log(2)))
  if 'imm' in field_name:
    num_bits = 64

  fields.append((field_name, num_bits))
  field_name_intsize[field_name] = num_bits

fields.sort(key=lambda x: -x[1])

for field_name, num_bits in fields:
  if "imm" in field_name:
    decl.write("  InstImm {};  // {}, ...\n".format(
        field_name, field_name_example[field_name]))
  else:
    decl.write("  uint{}_t {};  // {}, ...\n".format(
        num_bits, field_name, field_name_example[field_name]))

# decl.write("\n")
# decl.write("  inline uint32_t GetOp(OpName name) const {\n")
# decl.write("    switch (name) {\n")
# decl.write("      case OpName::INVALID: return 0;\n")
# for field_name, size in field_names:
#   decl.write("      case OpName::{}: return static_cast<uint32_t>({});\n".format(
#       field_name.upper(), field_name))
# decl.write("    }\n")
# decl.write("  }\n")
decl.write("};\n\n")

# Forward declarations.
for base in ENCODINGS:
  decl.write('// {}\n'.format(ASM[base.iform]))
  decl.write('bool TryDecode{}(const InstData &data, Instruction &inst);\n\n'.format(
      base.iform.upper()))

decl.write("""

const char *InstNameToString(InstName iclass);
const char *InstFormToString(InstForm iform);

bool TryExtract(const uint8_t *bytes, InstData &data);
bool TryDecode(const InstData &data, Instruction &inst);

}  // namespace aarch64
}  // namespace remill

#endif  // REMILL_ARCH_AARCH64_DECODE_H_
""")

# 0 1374 84 21 63
# 1 1374 84 21 63
# 2 1374 80 25 55
# 3 1374 86 19 67
# 4 1359 89 31 58
# 5 1462 7 10 3
# 6 1461 7 11 4
# 7 1461 8 10 2
# 8 1464 2 13 11
# 9 1464 5 10 5
# 10 295 378 806 428
# 11 360 447 672 225
# 12 425 446 608 162
# 13 356 515 608 93
# 14 352 494 633 139
# 15 317 418 744 326
# 16 995 263 221 42
# 17 995 147 337 190
# 18 995 126 358 232
# 19 976 180 323 143
# 20 975 196 308 112
# 21 204 846 429 417
# 22 394 576 509 67
# 23 227 506 746 240
# 24 2 338 1139 801
# 25 2 825 652 173
# 26 0 970 509 461
# 27 0 1405 74 1331
# 28 0 860 619 241
# 29 2 654 823 169
# 30 469 467 543 76
# 31 2 364 1113 749

chosen = (26, 27, 28)
#chosen = (31, 29, 28, 27, 26, 25, 24, 21)
# chosen = (31, 30, 29, 28, 27, 26, 25, 24)
#chosen = (30, 22, 16, 13)
# chosen = (
#     31,  # unbalanced to zero, very little variadic
#     30,  # close across the board
#     29,  # close zero/ones, very little variadic
#     28,  # close zero/ones, no variadic
#     27,  # unbalanced to one, no variadic
#     22,  # close zero/ones
#     16,  # close zero/ones
#     13)  # close zero/ones

# chosen_set = set()
# for i in chosen:
#   chosen_set.update(at_bit[i])

# assert len(chosen_set) == len(BITS)

impl.write("""/*
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

#include "remill/Arch/AArch64/Decode.h"

namespace remill {
namespace aarch64 {
namespace {

""")
# for i in xrange(32):
#   print i, len(variadic[i])

impl.write('const char * const kIClassName[] = {\n')
impl.write('  nullptr,\n')
for iclass in iclass_names:
  impl.write('  "{}",\n'.format(iclass.upper()))
impl.write('};\n\n')

impl.write('const char * const kIFormName[] = {\n')
impl.write('  nullptr,\n')
for iform in iform_names:
  impl.write('  "{}",\n'.format(iform.upper()))
impl.write('};\n\n')

# Forward declare
for base in ENCODINGS:
  impl.write('static bool TryExtract{}(InstData &inst, uint32_t bits);\n'.format(
      base.iform.upper()))

for base in ENCODINGS:
  #print_diag(base, impl)
  impl.write('static bool TryExtract{}(InstData &inst, uint32_t bits) {{\n'.format(
      base.iform.upper()))

  # Deal with aliases.
  #
  # NOTE(pag): Added in `false` to always disable aliases for now...
  if base.iform in ALIASES:
    aliases = list(ALIASES[base.iform])
    aliases.sort(key=lambda base: base.bits.count('x')-32)
    for alias_base in aliases:
      impl.write('  if (false && TryExtract{}(inst, bits)) return true;\n'.format(
          alias_base.iform.upper()))

  # Decide whether or not the bits of the instruction are an encoding
  # represented by `base`.
  mask = ["0"] * 32
  accept = ["0"] * 32
  for i, bit in enumerate(reversed(base.bits)):
    if bit != 'x':
      mask[i] = '1'
      accept[i] = bit

  mask = "".join(mask)
  accept = "".join(accept)

  impl.write('  //   bits\n')
  impl.write('  // & {}\n'.format(mask))
  impl.write('  //   {}\n'.format("-" * 32))
  impl.write('  //   {}\n'.format(accept))
  impl.write('  if ((bits & 0x{:x}U) != 0x{:x}U) {{\n'.format(int(mask, 2), int(accept, 2)))
  impl.write('    return false;\n')
  impl.write('  }\n')

  # Make a structure that has the parts of the encoding.
  impl.write('  union {\n');
  impl.write('    uint32_t flat;\n')
  impl.write('    struct {\n')
  last_name = ""
  last_name_count = 0
  struct_names = set()
  for bit, n in enumerate(base.names):
    if not n:
      if last_name_count:
        impl.write('{};\n'.format(last_name_count))
        last_name_count = 0
        last_name = ""
      comment = ""
      if base.bits[bit] != 'x':
        comment = "  // {}".format(base.bits[bit])
      impl.write('      uint32_t _{}:1;{}\n'.format(bit, comment))
    else:
      name, index = n
      struct_names.add(name)
      if name != last_name and last_name_count:
        impl.write('{};\n'.format(last_name_count))
        last_name_count = 0
        last_name = ""

      if not last_name_count:
        impl.write('      uint32_t {}:'.format(name))
        last_name_count = 1
        last_name = name
      else:
        assert last_name
        last_name_count += 1

  if last_name_count:
    impl.write('{};\n'.format(last_name_count))

  impl.write('    } __attribute__((packed));\n')
  impl.write('  } __attribute__((packed)) enc;\n')
  impl.write('  static_assert(sizeof(enc) == 4, " ");\n')
  impl.write("  enc.flat = bits;\n")

  has_imm_hilo = False
  for field_name in struct_names:
    suffix = ""
    if "imm" in field_name:
      suffix = ".uimm"

    impl.write('  inst.{}{} = static_cast<uint{}_t>(enc.{});\n'.format(
        field_name, suffix, field_name_intsize[field_name], field_name))
    
    if field_name in ('immhi', 'immlo'):
      has_imm_hilo = True

    if field_name in base.constraints:
      # print base.iform, base.constraints
      neq_bits = base.constraints[field_name]
      for i in xrange(2**neq_bits.count('x')):
        our_bits = neq_bits
        sel = bin(i)[2:]
        for b in sel:
          our_bits = our_bits.replace('x', b, 1)
        neq_num = int(our_bits, 2)

        impl.write('  if (!(inst.{}{} != 0x{:x})) return false;\n'.format(
            field_name, suffix, neq_num))
  
  if has_imm_hilo:
    lo_size = field_name_size['immlo']
    impl.write('  inst.immhi_immlo.uimm = static_cast<uint64_t>(inst.immhi.uimm);\n')
    impl.write('  inst.immhi_immlo.uimm <<= static_cast<uint64_t>({}U);\n'.format(
        base.name_size['immlo']))
    impl.write('  inst.immhi_immlo.uimm |= static_cast<uint64_t>(inst.immlo.uimm);\n')
  
  # # # Fill in in the `ops` array with op names that are present in
  # # # the instruction.
  # seen_field_names = set()
  # hilo_name = ""
  # for n in base.names:
  #   if not n:
  #     continue
  #   name, index = n
  #   if name not in field_names:

  #     field_names.append(name)
  #     if name.endswith('hi') or name.endswith('lo'):
  #       hilo_name = name[:-2]

  # for field_name in field_names:


  # for i, field_name in enumerate(field_names):
  #   impl.write('  inst.ops[{}] = OpName::{};\n'.format(i, field_name.upper()))

  # Only fill in this info once we know that we've decoded the instruction
  # and satisfied all of the constraints.
  impl.write('  inst.iform = InstForm::{};\n'.format(base.iform.upper()))
  impl.write('  inst.iclass = InstName::{};\n'.format(base.iclass.upper()))

  impl.write('  return true;\n')
  impl.write('}\n\n')

# for iform in iform_names:
#   decl.write('  {},\n'.format(iform.upper()))

mask_str = chosen_to_string(0xFFFFFFFF, chosen).replace('0', '1').replace('-', '0')
mask = int(mask_str, 2)
all_bases = set()

for i in xrange(int(2**len(chosen))):

  # Get a bitmask of what bits to select.
  sel_mask = 0
  for k, bit in enumerate(chosen):
    if 0 != (i & (1 << k)):
      sel_mask = sel_mask | (1 << bit)

  sel_mask_str = "{:032b}".format(sel_mask)
  # print "{:4} {:08x} {}".format(i, sel_mask, sel_mask_str)
  # assert sel_mask == int(sel_mask_str, 2)

  bases = set()
  num_var_bits = {}
  for base in UNALIASED_ENCODINGS:
    # base_bits = "".join(reversed(base.bits)).replace('x');
    base_mask_str = "".join(reversed(base.bits)).replace('x', '0')
    base_mask = int(base_mask_str, 2)

    # print "({} & {}) == {}".format(mask_str, base_mask_str, sel_mask_str)
    if (mask & base_mask) == sel_mask:
      bases.add(base)
      all_bases.add(base)

      # Get the number of variable bits per encoding
      num_var = 0
      for bit in base.bits:
        if bit == 'x':
          num_var += 1
      num_var_bits[base] = num_var

  # Sort the bases in ascending order of variable bits, so that we try to
  # extract the most constraints bases first
  bases = list(bases)
  bases.sort(key=lambda b: num_var_bits[b])

  # exit()
  impl.write("// {}\n".format(sel_mask_str))
  impl.write('static bool TryExtract{}(InstData &inst, uint32_t bits) {{\n'.format(i))
  impl.write('  return false')
  for base in bases:
    impl.write(' ||\n         TryExtract{}(inst, bits)'.format(
        base.iform.upper()))
  impl.write(';\n')
  impl.write('}\n\n')

impl.write('static bool (* const kFirstLevel[])(InstData &, uint32_t) = {\n')
for i in xrange(int(2**len(chosen))):
  impl.write('  TryExtract{},  // {}\n'.format(i, chosen_to_string(i, chosen)))
impl.write('};\n\n')

impl.write("}  // namespace\n")

impl.write("""
const char *InstNameToString(InstName iclass) {{
  auto num = static_cast<uint16_t>(iclass);
  if (iclass == InstName::INVALID) {{
    return nullptr;
  }} else if (static_cast<uint16_t>(InstName::{}) < num) {{
    return nullptr;
  }} else {{
    return kIClassName[num];
  }}
}}

const char *InstFormToString(InstForm iform) {{
  auto num = static_cast<uint16_t>(iform);
  if (iform == InstForm::INVALID) {{
    return nullptr;
  }} else if (static_cast<uint16_t>(InstForm::{}) < num) {{
    return nullptr;
  }} else {{
    return kIFormName[num];
  }}
}}

""".format(iclass_names[-1].upper(), iform_names[-1].upper()))

impl.write("""
bool TryExtract(const uint8_t *bytes, InstData &inst) {
  uint32_t bits = 0;
  bits = (bits << 8) | static_cast<uint32_t>(bytes[3]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[2]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[1]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[0]);
  uint32_t index = 0;
""")

# impl.write('  union {\n')
# impl.write('    uint32_t flat;\n')
# impl.write('    struct {\n')
# for i in xrange(32):
#   impl.write('      uint32_t _{}:1;\n'.format(i))
# impl.write('    } __attribute__((packed)); \n')
# impl.write('  } __attribute__((packed)) x; \n')
# impl.write('  x.flat = bits;\n')
for i, bit in enumerate(reversed(chosen)):
  impl.write('  index |= ((bits >> {}U) & 1U) << {}U;\n'.format(bit, len(chosen) - i - 1))
impl.write('  return kFirstLevel[index](inst, bits);\n')
impl.write('}\n\n')


impl.write("}  // namespace aarch64\n")
impl.write("}  // namespace remill\n\n")
# best_combo = None
# best = -1

# fixed_one = list(fixed_one.items())
# fixed_zero = list(fixed_zero.items())

# fixed_one.sort(key=lambda i_sb: -len(i_sb[1]))
# fixed_zero.sort(key=lambda i_sb: -len(i_sb[1]))

assert len(BITS) == len(all_bases)

# for seq in itertools.combinations(range(32), 8):
#   total = set()
#   for i in seq:
#     total.update(fixed[i])
#   if len(total) > best:
#     print "Found new best", seq, "matching", len(total), "encodings"
#     best = len(total)
#     best_combo = seq

impl = open("/tmp/Decode.cpp", "w")

impl.write("""/*
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

#include "remill/Arch/AArch64/Decode.h"

namespace remill {
namespace aarch64 {
""");

# Temporary implementations.
for base in ENCODINGS:
  print_diag(base, impl)
  impl.write('// {}\n'.format(ASM[base.iform]))
  impl.write('bool TryDecode{}(const InstData &, Instruction &) {{\n'.format(base.iform.upper()))
  impl.write('  return false;\n');
  impl.write('}\n\n');

impl.write("""
namespace {
""")

impl.write("""
static bool (* const kDecoder[])(const InstData &data, Instruction &inst) = {
""")

impl.write("\n")
for iform in iform_names:
  impl.write("  TryDecode{},\n".format(iform.upper()))
impl.write("};\n\n")
impl.write("}  // namespace\n")

impl.write("""

bool TryDecode(const InstData &data, Instruction &inst) {
  auto iform_num = static_cast<unsigned>(data.iform);
  return kDecoder[iform_num - 1](data, inst);
}

}  // namespace aarch64
}  // namespace remill
""")
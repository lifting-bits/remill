#!/usr/bin/env python
import argparse
import os
import sys

import binaryninja as binja
import magic  # pip install python-magic

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REMILL_DIR = os.path.dirname(SCRIPT_DIR)

sys.path.append(REMILL_DIR)
from generated.CFG import CFG_pb2

DEBUG = False

INDIRECT_TERMINATORS = [
    binja.core.LLIL_CALL,
    binja.core.LLIL_SYSCALL,
    binja.core.LLIL_TRAP,
    binja.core.LLIL_BP
]

UNKNOWN_IL = [
    binja.core.LLIL_UNDEF,
    binja.core.LLIL_UNIMPL,
    binja.core.LLIL_UNIMPL_MEM
]


def debug(s):
    if DEBUG:
        sys.stdout.write('{}\n'.format(str(s)))


def is_cpuid(bv, il):
    # type: (binja.BinaryView, binja.LowLevelILInstruction) -> bool
    txt = get_inst_text(bv, il.address)
    return 'cpuid' == txt[0].text.strip()


def is_interrupt(bv, il):
    # type: (binja.BinaryView, binja.LowLevelILInstruction) -> bool
    txt = get_inst_text(bv, il.address)
    return 'int' == txt[0].text.strip()


def get_inst_text(bv, addr):
    # type: (binja.BinaryView, int) -> list
    data = bv.read(addr, 16)
    return bv.arch.get_instruction_text(data, addr)[0]


def read_inst_bytes(bv, il):
    # type: (binja.BinaryView, binja.LowLevelILInstruction) -> str
    inst_data = bv.read(il.address, 16)
    inst_info = bv.arch.get_instruction_info(inst_data, il.address)
    return inst_data[:inst_info.length]


def process_inst(bv, pb_block, il):
    # type: (binja.BinaryView, CFG_pb2.Block, binja.LowLevelILInstruction) -> (CFG_pb2.Instr, int)
    pb_inst = pb_block.instructions.add()
    pb_inst.address = il.address
    pb_inst.bytes = read_inst_bytes(bv, il)
    pb_inst.size = len(pb_inst.bytes)

    op = il.operation
    if op in INDIRECT_TERMINATORS:
        debug('Found indirect terminator: {} @ {:x}'.format(il.operation_name, il.address))
        return pb_inst, True

    elif op in UNKNOWN_IL:
        if is_cpuid(bv, il):
            debug('Found cpuid @ {:x}'.format(il.address))
            return pb_inst, True
        if is_interrupt(bv, il):
            debug('Found int @ {:x}'.format(il.address))
            return pb_inst, True

    return pb_inst, False


def create_block(pb_mod, addr):
    # type: (CFG_pb2.Module, int) -> CFG_pb2.Block
    pb_block = pb_mod.blocks.add()
    pb_block.address = addr
    return pb_block


def create_indirect_block(pb_mod, addr):
    # type: (CFG_pb2.Module, int) -> CFG_pb2.Block
    """Creates a new Block and IndirectBlock at an address, returns the Block"""
    debug('Creating indirect block @ {:x}'.format(addr))
    pb_iblock = pb_mod.indirect_blocks.add()
    pb_iblock.address = addr
    return create_block(pb_mod, addr)


def process_blocks(bv, pb_mod, func):
    # type: (binja.BinaryView, CFG_pb2.Module, binja.Function) -> None
    ilfunc = func.lifted_il

    for block in func:
        pb_block = create_block(pb_mod, block.start)

        # Keep track of the current address in the block
        inst_idx = block.start
        end_block = False
        while inst_idx < block.end:
            # Check if the block should be split early
            if end_block:
                pb_block = create_indirect_block(pb_mod, inst_idx)

            # Get the IL at the current address
            il = ilfunc[func.get_lifted_il_at(bv.arch, inst_idx)]

            # Add the instruction data
            pb_inst, end_block = process_inst(bv, pb_block, il)
            inst_idx += pb_inst.size


def is_export(func):
    # type: (binja.Function) -> bool
    sym_type = binja.core.BNSymbolType_by_name[func.symbol.type]
    return sym_type == binja.core.FunctionSymbol and not func.auto


def is_import(func):
    # type: (binja.Function) -> bool
    sym_type = binja.core.BNSymbolType_by_name[func.symbol.type]
    return sym_type == binja.core.ImportedFunctionSymbol


def is_internal(func):
    # type: (binja.Function) -> bool
    sym_type = binja.core.BNSymbolType_by_name[func.symbol.type]
    return sym_type == binja.core.FunctionSymbol and func.auto


def analyze_exports(bv, pb_mod):
    # type: (binja.BinaryView, CFG_pb2.Module) -> None
    for func in bv.functions:
        if is_export(func):
            pb_func = pb_mod.functions.add()
            pb_func.name = func.symbol.short_name
            pb_func.address = func.start
            pb_func.is_imported = False
            pb_func.is_exported = True
            pb_func.is_weak = False

            debug('Adding export: {} @ {:x}'.format(pb_func.name, pb_func.address))
            process_blocks(bv, pb_mod, func)


def analyze_imports(bv, pb_mod):
    # type: (binja.BinaryView, CFG_pb2.Module) -> None
    for func in bv.functions:
        if is_import(func):
            pb_func = pb_mod.functions.add()
            pb_func.name = func.symbol.short_name
            pb_func.address = func.start
            pb_func.is_imported = True
            pb_func.is_exported = False
            pb_func.is_weak = False  # TODO: see if this can be figured out

            debug('Adding import: {} @ {:x}'.format(pb_func.name, pb_func.address))


def analyze_internal_functions(bv, pb_mod):
    # type: (binja.BinaryView, CFG_pb2.Module) -> None
    for func in bv.functions:
        if is_internal(func):
            pb_func = pb_mod.functions.add()
            pb_func.name = func.symbol.short_name  # TODO: should this be different?
            pb_func.address = func.start
            pb_func.is_imported = False
            pb_func.is_exported = False
            pb_func.is_weak = False

            debug('Adding function: {} @ {:x}'.format(pb_func.name, pb_func.address))
            process_blocks(bv, pb_mod, func)


def recover_cfg(bv, outf):
    # type: (binja.BinaryView, file) -> None
    pb_mod = CFG_pb2.Module()
    pb_mod.binary_path = bv.file.filename

    debug('Analyzing exports...')
    analyze_exports(bv, pb_mod)

    debug('Analyzing imports...')
    analyze_imports(bv, pb_mod)

    debug('Analyzing internal functions...')
    analyze_internal_functions(bv, pb_mod)

    debug('Saving CFG to {}'.format(outf.name))
    outf.write(pb_mod.SerializeToString())
    outf.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable verbose debugging mode')

    parser.add_argument('-o', '--output',
                        type=str, default=None,
                        help='The output control flow graph recovered from this file')

    parser.add_argument('file', help='Binary to recover control flow graph from')

    args = parser.parse_args(sys.argv[1:])

    # Enable debugging
    if args.debug:
        global DEBUG
        DEBUG = True

    # Get path to input file
    fpath = os.path.abspath(args.file)
    fdir = os.path.dirname(fpath)

    # Resolve path to output file
    if args.output:
        # Attempt to create directories to the output file
        try:
            os.mkdir(os.path.dirname(args.output))
        except OSError:
            pass

        outf = open(args.output, 'wb')
    else:
        # Default output file is "{basename}.cfg"
        outpath = os.path.join(fdir, '{}.cfg'.format(os.path.basename(fpath)))
        outf = open(outpath, 'wb')

    # Look at magic bytes to choose the right BinaryViewType
    magic_type = magic.from_file(fpath)
    if 'ELF' in magic_type:
        bv_type = binja.BinaryViewType['ELF']
    elif 'PE32' in magic_type:
        bv_type = binja.BinaryViewType['PE']
    elif 'Mach-O' in magic_type:
        bv_type = binja.BinaryViewType['Mach-O']
    else:
        # "Raw" type, can't be used for anything, quitting
        debug('Unknown binary type: "{}"'.format(magic_type))
        return 1

    # Load and analyze the binary
    bv = bv_type.open(fpath)
    bv.update_analysis_and_wait()

    # Binja will not load a binary with no entry point
    if len(bv) == 0:
        debug('Binary could not be loaded in binja, is it linked?')
        return 1

    recover_cfg(bv, outf)


if __name__ == '__main__':
    exit(main())

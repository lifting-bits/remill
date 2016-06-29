#!/usr/bin/env python
import argparse
import os
import sys
import time

import binaryninja as binja
import magic  # pip install python-magic

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REMILL_DIR = os.path.dirname(SCRIPT_DIR)

sys.path.append(REMILL_DIR)
from generated.CFG import CFG_pb2

DEBUG = False


def debug(s):
    if DEBUG:
        sys.stdout.write('{}\n'.format(str(s)))


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
    bv.update_analysis()
    time.sleep(0.1)

    # Binja will not load a binary with no entry point
    if len(bv) == 0:
        debug('Binary could not be loaded in binja, is it linked?')
        return 1

    recover_cfg(bv, outf)


if __name__ == '__main__':
    exit(main())

#!/usr/bin/env python
import argparse
import os
import sys
import time

import binaryninja as binja
import magic  # pip install python-magic

DEBUG = False


def debug(s):
    if DEBUG:
        sys.stdout.write('{}\n'.format(str(s)))


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


if __name__ == '__main__':
    exit(main())

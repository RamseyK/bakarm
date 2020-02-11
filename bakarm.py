#!/usr/bin/env python3

import os
import sys
import argparse
import signal
from capstone import *


def hexstring(s):
    return ''.join('{:02x}'.format(x) for x in s)


ARM64_GRP_BRANCH_RELATIVE = 7


def main():

    parser = argparse.ArgumentParser(description='Disassemble a stream of bytes in a file as ARM/ARM64 instructions')
    parser.add_argument('-a', '--arch', required=False, type=str, default='arm', help='Architecture to disassemble as: [arm, arm64]')
    parser.add_argument('-b', '--base', required=False, type=str, default="0", help='Virtual base address to use')
    parser.add_argument('-o', '--offset', required=False, type=str, default="0", help='Offset in the file to start at')
    parser.add_argument('-thumb', '--thumb', required=False, action='store_true', help="Treat all ARM32 bit code as THUMB")
    parser.add_argument('file')

    args = parser.parse_args()

    if not args.file or not os.path.exists(args.file):
        print("Source file must exist")
        parser.print_help()
        return -1

    # parse arch
    if args.arch and args.arch == 'arm64':
        arch = CS_ARCH_ARM64
        mode = CS_MODE_ARM
    else:
        arch = CS_ARCH_ARM

        if args.thumb:
            mode = CS_MODE_THUMB
        else:
            mode = CS_MODE_ARM

    # convert base to integer
    base = 0
    if args.base.startswith("0x"):
        base_address = int(args.base, 16)
    else:
        base_address = int(args.base)

    # convert offset to integer
    offset = 0
    if args.offset.startswith("0x"):
        offset = int(args.offset, 16)
    else:
        offset = int(args.offset)

    # Exit the program if the output is being piped somewhere, and that pipe has been closed
    # Usecase: bakarm.py test.bin | less
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    with open(args.file, 'rb') as fh:
        # Skip offset number of bytes if specified
        if offset > 0:
            fh.seek(offset)

        code = fh.read()

    # Setup capstone
    md = Cs(arch, mode)
    md.detail = True  # Needed for semantic group info

    # Skip bad instructions (will be transformed to a .byte <instr bytes>)
    md.skipdata = True

    # Dictionary of label sources keyed by source address
    source_labels = {}

    # Dictionary of label targets keyed by target address
    target_labels = {}

    # First pass: find all branch targets to make labels for
    for instr in md.disasm(code, 0):
        try:
            if CS_GRP_JUMP in instr.groups and ARM64_GRP_BRANCH_RELATIVE not in instr.groups:
                # Branch and link / branch register val
                pass
            elif ARM64_GRP_BRANCH_RELATIVE in instr.groups:
                # Transform the op_str (which is the offset in form of #0x14) to the actual target addr
                target_off = int(instr.op_str.replace('#', ''), 16)
                target_addr = base_address + target_off
                source_labels.update({base_address + instr.address: "loc_{:08x}".format(target_addr)})
                target_labels.update({target_addr: "loc_{:08x}".format(target_addr)})
            else:
                pass
        except Exception as e:
            # will be thrown on invalid instrs. Ignore.
            # print(e)
            pass

    # Second pass: print instructions and labels
    for instr in md.disasm(code, 0):
        out = ""

        # Check for target labels and add with a new line
        tl = target_labels.get(base_address + instr.address)
        if tl:
            out += "{}:\n".format(tl)

        out += "0x{:08x}:\t\t0x{}\t\t{}\t{}".format(base_address + instr.address, hexstring(instr.bytes), instr.mnemonic, instr.op_str)

        # Check for source labels and add as a comment
        sl = source_labels.get(base_address + instr.address)
        if sl:
            out += "  // {}".format(sl)

        print(out)

    return 0


if __name__ == '__main__':
    sys.exit(main())

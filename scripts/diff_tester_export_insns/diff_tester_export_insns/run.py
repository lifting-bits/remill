import binaryninja
import argparse
import json


def main():
    parser = argparse.ArgumentParser("JSON Insn Exporter")
    parser.add_argument("target_binary")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    target_bin = args.target_binary
    target_bin_view = binaryninja.BinaryViewType.get_view_of_file(target_bin)
    arch = target_bin_view.arch
    mx_insn_len = arch.max_instr_length
    insn_testcase_list = []
    seen_bytes = set()
    for func in target_bin_view.functions:
        for (_, start_addr) in func.instructions:
            buff = target_bin_view[start_addr: start_addr+mx_insn_len]
            insn_size = arch.get_instruction_info(buff, start_addr).length
            final_bytes = buff[:insn_size]
            if final_bytes not in seen_bytes:
                insn_testcase_list.append((start_addr, final_bytes.hex()))
            seen_bytes.add(final_bytes)

    with open(args.out, "w") as f:
        json.dump(insn_testcase_list, f, indent=4)


if __name__ == "__main__":
    main()

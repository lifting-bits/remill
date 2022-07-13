import binaryninja
import argparse
import json
import os
from Crypto.Random.random import shuffle
import tqdm
import multiprocessing
from functools import partial


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def lift_bin(tgt_list, target_bin):
    target_bin_view = binaryninja.BinaryViewType.get_view_of_file(
        target_bin)
    arch = target_bin_view.arch
    mx_insn_len = arch.max_instr_length
    seen_bytes = set()
    internal_list = []
    for func in target_bin_view.functions:
        for (_, start_addr) in func.instructions:
            buff = target_bin_view[start_addr: start_addr+mx_insn_len]
            insn_size = arch.get_instruction_info(buff, start_addr).length
            final_bytes = buff[:insn_size]
            if final_bytes not in seen_bytes:
                internal_list.append(final_bytes.hex())
            seen_bytes.add(final_bytes)

    tgt_list.extend(internal_list)
    return 1


def main():
    parser = argparse.ArgumentParser("JSON Insn Exporter")
    parser.add_argument("target_directory")
    parser.add_argument("--num_shards", type=int, default=1)
    parser.add_argument("--out_name", required=True)
    parser.add_argument("--out_dir", required=True)
    args = parser.parse_args()

    man = multiprocessing.Manager()
    tot_list = man.list()
    f = partial(lift_bin, tot_list)
    chals = [os.path.join(
        args.target_directory, f) for f in os.listdir(args.target_directory)]
    shuffle(chals)
    with multiprocessing.Pool() as p:
        for _ in tqdm.tqdm(p.imap_unordered(f, chals), total=len(chals)):
            pass

    insn_testcase_list = list(set(tot_list))
    shuffle(insn_testcase_list)

    for i, insns in enumerate(chunks(insn_testcase_list, len(insn_testcase_list)//args.num_shards)):
        with open(os.path.join(args.out_dir, f"{args.out_name}_{i}.json"), "w") as f:
            json.dump(insns, f, indent=4)


if __name__ == "__main__":
    main()

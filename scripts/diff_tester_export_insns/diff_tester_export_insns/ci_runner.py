import multiprocessing
import argparse
import glob
from functools import partial
from pathlib import Path
import os
import json
import subprocess
import tqdm
import sys

# paralellism for CI


class TestResults:
    def __init__(self, num_run: int, num_failed: int) -> None:
        self.num_run = num_run
        self.num_failed = num_failed

    def merge(self, other):
        self.num_run += other.num_run
        self.num_failed += other.num_failed


class DiffTesterInfo:
    def __init__(self, path: str, workdir: str, whitelist_path: str, num_iters: int) -> None:
        self.path = path
        self.workdir = workdir
        self.num_iters = num_iters
        self.whitelist_path = whitelist_path

    def run(self, json_file_path: str) -> TestResults:

        with open(json_file_path, "r") as f:
            num_tests = len(json.load(f))

        fname = Path(json_file_path).stem
        repro_file = f"{fname}_repro.json"
        repro_path = os.path.join(self.workdir, repro_file)
        command_args = [self.path, "-num_iterations",
                        str(self.num_iters), "-target_insn_file", json_file_path, "-whitelist", self.whitelist_path, "-repro_file", repro_path]
        exit_stat = subprocess.run(command_args)
        if exit_stat.returncode == 0:
            return TestResults(num_tests, 0)

        if exit_stat != 2:
            return TestResults(num_tests, num_tests)

        if not os.path.exists(repro_path):
            return TestResults(num_tests, num_tests)

        with open(repro_path, "r") as f:
            num_failed = len(json.load(f))
            return TestResults(num_tests, num_failed)


def test_single_json(tester: DiffTesterInfo, json_file: str):
    return tester.run(json_file)


def main():
    prsr = argparse.ArgumentParser("CI runner for difftester")
    prsr.add_argument("target_dir", type=str)
    prsr.add_argument("--workdir", required=True, type=str)
    prsr.add_argument("--num_iters", type=int, default=2)
    prsr.add_argument("--whitelist_file", type=str, required=True)
    prsr.add_argument("--difftester_bin", required=True, type=str)
    prsr.add_argument("--required_success_rate", default=0.0, type=float)
    args = prsr.parse_args()
    diff_tester = DiffTesterInfo(args.difftester_bin, args.workdir,
                                 args.whitelist_file, args.num_iters)
    f = partial(test_single_json, diff_tester)
    target_jsons = glob.glob(f"{args.target_dir}/*.json")

    with multiprocessing.Pool() as p:
        beginning_test_res = TestResults(0, 0)
        for test_res in tqdm.tqdm(p.imap_unordered(f, target_jsons), total=len(target_jsons)):
            beginning_test_res.merge(test_res)

    success_rate = round(float(beginning_test_res.num_run -
                         beginning_test_res.num_failed)/float(beginning_test_res.num_run), 2)

    print(f"Ran {beginning_test_res.num_run} with {beginning_test_res.num_failed} failing. Success rate of: {success_rate}")

    if success_rate >= args.required_success_rate:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()

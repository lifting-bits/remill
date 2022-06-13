import argparse


def main():
    prsr = argparse.ArgumentParser("Disassembly action replacer")
    prsr.add_argument("target_file")
    prsr.add_argument("--out", required=True)

    args = prsr.parse_args()

    with open(args.target_file, 'r') as target_f:
        with open(args.out, 'w') as output_f:
            pass


if __name__ == "__main__":
    main()

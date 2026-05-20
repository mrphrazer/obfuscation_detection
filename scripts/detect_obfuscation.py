#!/usr/bin/python
import argparse
import json
import sys

from obfuscation_detection import run_heuristics_and_utils
from obfuscation_detection.reports import collect_heuristics_and_utils_reports


def parse_args(argv):
    parser = argparse.ArgumentParser(
        usage="%(prog)s [--json] <path to binary>",
        description="Detect obfuscated code and interesting code constructs.",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("file_name", nargs="?")
    return parser.parse_args(argv)


def load_binary(file_name):
    import binaryninja

    return binaryninja.load(file_name)


def run_text(bv):
    run_heuristics_and_utils(bv)


def run_json(bv, file_name):
    return {
        "binary": file_name,
        "detections": collect_heuristics_and_utils_reports(bv),
    }


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)
    if args.file_name is None:
        print("[*] Syntax: {} [--json] <path to binary>".format(sys.argv[0]))
        return 0

    bv = load_binary(args.file_name)

    if args.json_output:
        print(json.dumps(run_json(bv, args.file_name), sort_keys=True))
    else:
        run_text(bv)

    return 0


if __name__ == "__main__":
    sys.exit(main())

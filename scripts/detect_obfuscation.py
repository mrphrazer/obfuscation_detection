#!/usr/bin/python
import sys

from binaryninja import BinaryViewType
from obfuscation_detection import detect_obfuscation


# check file arguments
if len(sys.argv) < 2:
    print("[*] Syntax: {} <path to binary>".format(sys.argv[0]))
    exit(0)

# parse arguments
file_name = sys.argv[1]

# init binary ninja
bv = BinaryViewType.get_view_of_file(file_name)
if not file_name.endswith(".bndb"):
    bv.update_analysis_and_wait()

# look for obfuscation heuristics
detect_obfuscation(bv)

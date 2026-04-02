#!/usr/bin/python
import sys

import binaryninja
from obfuscation_detection import detect_obfuscation


# check file arguments
if len(sys.argv) < 2:
    print("[*] Syntax: {} <path to binary>".format(sys.argv[0]))
    exit(0)

# parse arguments
file_name = sys.argv[1]

# init binary ninja
bv = binaryninja.load(file_name)

# look for obfuscation heuristics
detect_obfuscation(bv)

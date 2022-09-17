#!/usr/bin/python
import glob
import sys
from collections import Counter
from pprint import pformat

from binaryninja import BinaryViewType

from obfuscation_detection.utils import calc_global_ngrams

# check file arguments
if len(sys.argv) < 3:
    print("[*] Syntax: {} <path to analysis directory> <output file>".format(sys.argv[0]))
    exit(0)

# parse arguments
analysis_directory = sys.argv[1]
output_file_path = sys.argv[2]

# global ngrams counter
ngrams = Counter()
# set n as default to 3
n = 3

# walk over all binaries in the provided directory
for binary_file_path in glob.glob(f"{analysis_directory}/*"):
    print(f"Analyzing file {binary_file_path}.")
    # init binary ninja
    bv = BinaryViewType.get_view_of_file(binary_file_path)
    # wait until analysis finishes
    bv.update_analysis_and_wait()
    # count ngrams
    ngrams.update(calc_global_ngrams(bv, n))


# prepare output string -- the most common 1k ngrams in a set
output_string = pformat({k for k, v in ngrams.most_common(1000)})

# write output file
with open(output_file_path, 'w') as output_file:
    output_file.write(output_string)
    output_file.close()

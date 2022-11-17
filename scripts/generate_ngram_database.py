#!/usr/bin/python
import glob
import sys
from collections import Counter
from pprint import pformat
import multiprocessing

from binaryninja import BinaryViewType

from obfuscation_detection.utils import calc_global_ngrams


def analyze(binary_file_path):
    print(f"Analyzing file {binary_file_path}.")
    # init binary ninja
    bv = BinaryViewType.get_view_of_file(binary_file_path)
    # wait until analysis finishes
    bv.update_analysis_and_wait()
    # count 3-grams
    return calc_global_ngrams(bv, 3, use_llil=True)


if __name__ == '__main__':
    # check file arguments
    if len(sys.argv) < 3:
        print("[*] Syntax: {} <path to analysis directory> <output file>".format(sys.argv[0]))
        exit(0)

    # parse arguments
    analysis_directory = sys.argv[1]
    output_file_path = sys.argv[2]

    # global ngrams counter
    ngrams = Counter()

    # calculate ngrams in parallel
    with multiprocessing.Pool() as pool:
        mapping = pool.map(analyze, glob.glob(f"{analysis_directory}/*"))

        # walk over all binaries in the provided directory
        for grams in mapping:
            ngrams.update(grams)

    # prepare output string -- the most common 1k ngrams in a set
    output_string = pformat({k for k, v in ngrams.most_common(1000)})

    # write output file
    with open(output_file_path, 'w') as output_file:
        output_file.write(output_string)
        output_file.close()

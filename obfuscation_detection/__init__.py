from .heuristics import *


def detect_obfuscation(bv):
    # find flattened functions
    find_flattened_functions(bv)

    # find complex functions
    find_complex_functions(bv)

    # find large basic blocks
    find_large_basic_blocks(bv)

    # find uncommon instruction sequences
    find_uncommon_instruction_sequences(bv)

    # find overlapping instructions
    find_instruction_overlapping(bv)

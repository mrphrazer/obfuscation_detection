from binaryninja import highlight

from .utils import *


def find_flattened_functions(bv):
    print("=" * 80)
    print("Control Flow Flattening")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, calc_flattening_score):
        # skip bad scores
        if score == 0.0:
            continue
        print(
            f"Function {hex(f.start)} ({f.name}) has a flattening score of {score}.")


def find_complex_functions(bv):
    print("=" * 80)
    print("Cyclomatic Complexity")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, calc_cyclomatic_complexity):
        print(
            f"Function {hex(f.start)} ({f.name}) has a cyclomatic complexity of {score}.")


def find_large_basic_blocks(bv):
    print("=" * 80)
    print("Large Basic Blocks")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, calc_average_instructions_per_block):
        print(
            f"Basic blocks in function {hex(f.start)} ({f.name}) contain on average {ceil(score)} instructions.")


def find_instruction_overlapping(bv):
    print("=" * 80)
    print("Instruction Overlapping")

    # sets of addresses
    seen = {}
    overlapping_addresses = set()
    functions_with_overlapping = set()

    # walk over all instructions
    for instruction in bv.instructions:
        # parse address
        address = instruction[-1]

        # seen for the first time
        if address not in seen:
            # mark as instruction beginning
            seen[address] = 1
        # seen before and not marked as instruction beginning
        elif seen[address] == 0:
            overlapping_addresses.add(address)

        # walk over instruction length and mark bytes as seen
        for _ in range(1, bv.get_instruction_length(address)):
            address += 1
            # if seen before and marked as instruction beginning
            if address in seen and seen[address] == 1:
                overlapping_addresses.add(address)
            else:
                seen[address] = 0

    # walk over all overlapping addresses
    for address in overlapping_addresses:
        # walk over all functions containing the address
        for function in bv.get_functions_containing(address):
            # highlight overlapping instruction
            function.set_user_instr_highlight(
                address, highlight.HighlightColor(red=0xff, blue=0xff, green=0))
            # add to set of overlapping functions
            functions_with_overlapping.add(function.start)

    for address in sorted(functions_with_overlapping):
        print(
            f"Overlapping instructions in function {hex(address)} ({bv.get_function_at(address).name}).")


def find_uncommon_instruction_sequences(bv):
    print("=" * 80)
    print("Uncommon Instruction Sequences")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, calc_uncommon_instruction_sequences_score):
        print(
            f"Function {hex(f.start)} ({f.name}) has an uncommon instruction sequences score of {score}.")


def find_most_called_functions(bv):
    print("=" * 80)
    print("Most Called Functions")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, lambda f: len(f.callers)):
        print(
            f"Function {hex(f.start)} ({f.name}) is called from {score} different functions.")


def find_xor_decryption_loops(bv):
    print("=" * 80)
    print("XOR Decryption Loops")

    for f in bv.functions:
        if contains_xor_decryption_loop(bv, f):
            print(
                f"Function {hex(f.start)} ({f.name}) contains a XOR decryption loop with a constant.")


def find_complex_arithmetic_expressions(bv):
    """
    Heuristic to identify complex (mixed) boolean expressions inspired by gooMBA:
    https://github.com/HexRaysSA/goomba
    """
    print("=" * 80)
    print("Functions with complex arithmetic expressions:")

    for f, score in get_top_10_functions(bv.functions, lambda f: calculate_complex_arithmetic_expressions(f)):
        if score != 0:
            print(
                f"Function {hex(f.start)} ({(f.name)}) has {score} instructions that use complex arithmetic expressions.")


def find_entry_functions(bv):
    print("=" * 80)
    print("Functions without callers:")

    for f in bv.functions:
        if len(f.callers) != 0:
            continue

        print(
            f"Function {hex(f.start)} ({(f.name)}) has no known callers.")


def find_leaf_functions(bv):
    print("=" * 80)
    print("Functions without callees:")

    for f in bv.functions:
        # no callees and at least two instructions
        if len(f.callees) == 0 and sum(1 for _ in f.instructions) > 1:
            print(
                f"Function {hex(f.start)} ({(f.name)}) has no known callees.")

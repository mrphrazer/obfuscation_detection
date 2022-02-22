from math import ceil
from binaryninja import highlight
from obfuscation_detection.utils import *


def find_flattened_functions(bv):
    print("=" * 80)
    print("Control Flow Flattening")
    # walk over all functions
    for function in bv.functions:
        # calculate flattening score
        score = calc_flattening_score(function)
        # skip if score is too low
        if score < 0.9:
            # print(f"Function {hex(function.start)} has a flattening score of {score}.")
            continue

        # print function and score
        print(
            f"Function {hex(function.start)} ({function.name}) has a flattening score of {score}.")


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

    # set of addresses
    seen = {}

    functions_with_overlapping = set()

    # walk over all functions
    for function in bv.functions:
        # walk over all instructions
        for instruction in function.instructions:
            # parse address
            address = instruction[-1]

            # seen for the first time
            if address not in seen:
                # mark as instruction beginning
                seen[address] = 1
            # seen before and not marked as instruction beginning
            elif seen[address] == 0:
                functions_with_overlapping.add(function.start)
                function.set_user_instr_highlight(
                    address, highlight.HighlightColor(red=0xff, blue=0xff, green=0))

            # walk over instruction length and mark bytes as seen
            for _ in range(1, bv.get_instruction_length(address)):
                address += 1
                # if seen before and marked as instruction beginning
                if address in seen and seen[address] == 1:
                    functions_with_overlapping.add(function.start)
                    function.set_user_instr_highlight(
                        address, highlight.HighlightColor(red=0xff, blue=0xff, green=0))
                else:
                    seen[address] = 0

    for address in sorted(functions_with_overlapping):
        print(
            f"Overlapping instructions in function {hex(address)} ({bv.get_function_at(address).name}).")

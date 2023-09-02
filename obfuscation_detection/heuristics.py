from binaryninja import highlight

from .utils import *


def find_flattened_functions(bv):
    print("=" * 80)
    print("Control Flow Flattening")

    # set of (function, score) tuples
    flattening_results = set()

    # walk over all functions
    for function in bv.functions:
        # calculate flattening score
        score = calc_flattening_score(function)
        # skip if score is too low
        if score < 0.9:
            # print(f"Function {hex(function.start)} has a flattening score of {score}.")
            continue

        # add to set
        flattening_results.add((function, score))

    # print function and scores in descending order
    for function, score in reversed(sorted(flattening_results, key=lambda x: x[1])):
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

arithmetic_op = [HighLevelILOperation.HLIL_ADD, HighLevelILOperation.HLIL_NEG, HighLevelILOperation.HLIL_SUB, HighLevelILOperation.HLIL_MUL, HighLevelILOperation.HLIL_DIVS, HighLevelILOperation.HLIL_MODS]
boolean_op = [HighLevelILOperation.HLIL_NOT, HighLevelILOperation.HLIL_AND, HighLevelILOperation.HLIL_OR, HighLevelILOperation.HLIL_XOR]
arithmetic_counter = 0
boolean_counter = 0

def traverse_HLIL(il, ident):
    global arithmetic_counter, boolean_counter
    if isinstance(il, highlevelil.HighLevelILInstruction):
        if il.operation in arithmetic_op:
            arithmetic_counter += 1

        if il.operation in boolean_op:
            boolean_counter += 1

        for o in il.operands:
            traverse_HLIL(o, ident+1)

def find_mba_expressions(bv):
    print("=" * 80)
    print("Functions that might have MBA expressions:")
    global boolean_counter, arithmetic_counter
    # iterate through functions 
    for f in bv.functions:
        instr_mba = 0
        if f.hlil is not None:
            # iterate through HIL instructions via AST
            for ins in f.hlil.root:
                # reset the counters per each instruction
                boolean_counter = 0
                arithmetic_counter = 0
                traverse_HLIL(ins, 0)
                # if an expression has a boolean operation and a arithmetic operation, it's probably an MBA expression
                if boolean_counter >= 1 and arithmetic_counter >= 1:
                    instr_mba += 1
            
            if instr_mba != 0:
                print(f"Function {hex(f.start)} ({f.name}) has {instr_mba} instructions that resemble MBA expressions")

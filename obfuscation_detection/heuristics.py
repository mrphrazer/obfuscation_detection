from math import ceil

from binaryninja import highlight

from .helpers import (
    calc_average_instructions_per_block,
    calc_cyclomatic_complexity,
    calc_flattening_score,
    calc_uncommon_instruction_sequences_score,
    calculate_complex_arithmetic_expressions,
    clear_heuristic_tags,
    contains_xor_decryption_loop,
    count_context_signature_duplicates,
    find_rc4_ksa,
    find_rc4_prga,
    get_top_10_functions,
    tag_function,
)
from .loop_analysis import compute_irreducible_loops, compute_number_of_natural_loops


def find_flattened_functions(bv):
    print("=" * 80)
    print("Control Flow Flattening")
    clear_heuristic_tags(bv, "Heuristic: Control Flow Flattening")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, calc_flattening_score):
        # skip bad scores
        if score == 0.0:
            continue
        print(f"Function {hex(f.start)} ({f.name}) has a flattening score of {score}.")
        tag_function(
            bv,
            f,
            "Heuristic: Control Flow Flattening",
            f"flattening_score: {score:.2f} | may indicate: control-flow flattening, state machines, C&C dispatching",
        )


def find_complex_functions(bv):
    print("=" * 80)
    print("Cyclomatic Complexity")
    clear_heuristic_tags(bv, "Heuristic: Complex Function")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, calc_cyclomatic_complexity):
        print(
            f"Function {hex(f.start)} ({f.name}) has a cyclomatic complexity of {score}."
        )
        tag_function(
            bv,
            f,
            "Heuristic: Complex Function",
            f"cyclomatic_complexity: {score} | may indicate: complex protocols, state machines, opaque predicates",
        )


def find_large_basic_blocks(bv):
    print("=" * 80)
    print("Large Basic Blocks")
    clear_heuristic_tags(bv, "Heuristic: Large Basic Blocks")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(
        bv.functions, calc_average_instructions_per_block
    ):
        print(
            f"Basic blocks in function {hex(f.start)} ({f.name}) contain on average {ceil(score)} instructions."
        )
        tag_function(
            bv,
            f,
            "Heuristic: Large Basic Blocks",
            f"avg_instructions_per_block: {ceil(score)} | may indicate: unrolled code, crypto, arithmetic obfuscation",
        )


def find_duplicated_subgraphs(bv):
    print("=" * 80)
    print("Duplicate Subgraphs")
    clear_heuristic_tags(bv, "Heuristic: Duplicate Subgraphs")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(
        bv.functions, count_context_signature_duplicates
    ):
        if score != 0:
            print(
                f"Function {hex(f.start)} ({f.name}) contains {score} duplicate subgraphs."
            )
            tag_function(
                bv,
                f,
                "Heuristic: Duplicate Subgraphs",
                f"num_duplicate_subgraphs: {score} | may indicate: cloned obfuscation stubs, unrolled loops, decision trees",
            )


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
                address, highlight.HighlightColor(red=0xFF, blue=0xFF, green=0)
            )
            # add to set of overlapping functions
            functions_with_overlapping.add(function.start)

    clear_heuristic_tags(bv, "Heuristic: Instruction Overlapping")
    for address in sorted(functions_with_overlapping):
        f = bv.get_function_at(address)
        print(f"Overlapping instructions in function {hex(address)} ({f.name}).")
        tag_function(
            bv,
            f,
            "Heuristic: Instruction Overlapping",
            "may indicate: broken disassembly, opaque predicates",
        )


def find_uncommon_instruction_sequences(bv):
    print("=" * 80)
    print("Uncommon Instruction Sequences")
    clear_heuristic_tags(bv, "Heuristic: Uncommon Instruction Sequences")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(
        bv.functions, calc_uncommon_instruction_sequences_score
    ):
        print(
            f"Function {hex(f.start)} ({f.name}) has an uncommon instruction sequences score of {score}."
        )
        tag_function(
            bv,
            f,
            "Heuristic: Uncommon Instruction Sequences",
            f"uncommon_sequences_score: {score} | may indicate: crypto, arithmetic obfuscation, floating point arithmetic",
        )


def find_most_called_functions(bv):
    print("=" * 80)
    print("Most Called Functions")
    clear_heuristic_tags(bv, "Heuristic: Most Called Function")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, lambda f: len(f.callers)):
        print(
            f"Function {hex(f.start)} ({f.name}) is called from {score} different functions."
        )
        tag_function(
            bv,
            f,
            "Heuristic: Most Called Function",
            f"num_callers: {score} | may indicate: string decryption routines, statically linked library functions",
        )


def find_xor_decryption_loops(bv):
    print("=" * 80)
    print("XOR Decryption Loops")
    clear_heuristic_tags(bv, "Heuristic: XOR Decryption Loop")

    for f in bv.functions:
        if contains_xor_decryption_loop(bv, f):
            print(
                f"Function {hex(f.start)} ({f.name}) contains a XOR decryption loop with a constant."
            )
            tag_function(
                bv,
                f,
                "Heuristic: XOR Decryption Loop",
                "potential: string decryption, code decryption stubs, crypto",
            )


def find_complex_arithmetic_expressions(bv):
    """
    Heuristic to identify complex (mixed) boolean expressions inspired by gooMBA:
    https://github.com/HexRaysSA/goomba
    """
    print("=" * 80)
    print("Functions with complex arithmetic expressions:")
    clear_heuristic_tags(bv, "Heuristic: Complex Arithmetic Expressions")

    for f, score in get_top_10_functions(
        bv.functions, lambda f: calculate_complex_arithmetic_expressions(f)
    ):
        if score != 0:
            print(
                f"Function {hex(f.start)} ({(f.name)}) has {score} instructions that use complex arithmetic expressions."
            )
            tag_function(
                bv,
                f,
                "Heuristic: Complex Arithmetic Expressions",
                f"num_mba_instructions: {score} | may indicate: mixed-boolean-arithmetic obfuscation, crypto",
            )


def find_entry_functions(bv):
    print("=" * 80)
    print("Functions without callers:")
    clear_heuristic_tags(bv, "Heuristic: Entry Function")

    for f in bv.functions:
        if len(f.callers) != 0:
            continue

        print(f"Function {hex(f.start)} ({(f.name)}) has no known callers.")
        tag_function(
            bv,
            f,
            "Heuristic: Entry Function",
            "no known callers | may indicate: entry point, indirect jump target",
        )


def find_leaf_functions(bv):
    print("=" * 80)
    print("Functions without callees:")
    clear_heuristic_tags(bv, "Heuristic: Leaf Function")

    for f in bv.functions:
        # no callees and at least two instructions
        if len(f.callees) == 0 and sum(1 for _ in f.instructions) > 1:
            print(f"Function {hex(f.start)} ({(f.name)}) has no known callees.")
            tag_function(
                bv,
                f,
                "Heuristic: Leaf Function",
                "no known callees | may indicate: outlined functions, trampolines, obfuscation",
            )


def find_rc4(bv):
    print("=" * 80)
    print("Potential RC4 Implementations:")
    clear_heuristic_tags(bv, "Heuristic: RC4-KSA")
    clear_heuristic_tags(bv, "Heuristic: RC4-PRGA")

    for f in bv.functions:
        if find_rc4_ksa(bv, f):
            print(f"Function {f.name} ({hex(f.start)}) might implement RC4-KSA.")
            tag_function(bv, f, "Heuristic: RC4-KSA", "potential RC4 key scheduling")
        if find_rc4_prga(bv, f):
            print(f"Function {f.name} ({hex(f.start)}) might implement RC4-PRGA.")
            tag_function(bv, f, "Heuristic: RC4-PRGA", "potential RC4 PRGA")


def find_loop_frequency_functions(bv):
    print("=" * 80)
    print("Loop Frequency")
    clear_heuristic_tags(bv, "Heuristic: Loop Frequency")

    # print top 10% (iterate in descending order)
    for f, score in get_top_10_functions(bv.functions, compute_number_of_natural_loops):
        print(f"Function {hex(f.start)} ({f.name}) contains {score} loops.")
        tag_function(
            bv,
            f,
            "Heuristic: Loop Frequency",
            f"num_loops: {score} | may indicate: complex parsing, intensive algorithms",
        )


def find_irreducible_loops(bv):
    print("=" * 80)
    print("Irreducible Loops")
    clear_heuristic_tags(bv, "Heuristic: Irreducible Loops")

    # print top 10% (iterate in descending order)
    for f, score in filter(
        lambda x: x[1] > 0,
        get_top_10_functions(bv.functions, lambda x: len(compute_irreducible_loops(x))),
    ):
        print(f"Function {hex(f.start)} ({f.name}) contains {score} irreducible loops.")
        tag_function(
            bv,
            f,
            "Heuristic: Irreducible Loops",
            f"num_irreducible_loops: {score} | may indicate: hand-written assembly, aggressive compiler optimizations, obfuscation",
        )

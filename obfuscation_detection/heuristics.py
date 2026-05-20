from binaryninja import highlight

from .reports import (
    compute_overlapping_instruction_addresses,
    find_complex_arithmetic_expression_reports,
    find_complex_function_reports,
    find_duplicate_subgraph_reports,
    find_state_machine_reports,
    find_instruction_overlapping_reports,
    find_irreducible_loop_reports,
    find_large_basic_block_reports,
    find_loop_frequency_reports,
    find_most_called_function_reports,
    find_uncommon_instruction_sequence_reports,
    find_xor_decryption_loop_reports,
    get_function_for_finding,
)
from .tagging import (
    clear_heuristic_tags,
    TAG_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_COMPLEX_FUNCTION,
    TAG_STATE_MACHINE,
    TAG_DUPLICATE_SUBGRAPH,
    TAG_IRREDUCIBLE_LOOP,
    TAG_LARGE_BASIC_BLOCK,
    TAG_LOOP_FREQUENCY,
    TAG_MOST_CALLED_FUNCTION,
    TAG_OVERLAPPING_INSTRUCTION,
    TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
    TAG_XOR_DECRYPTION_LOOP,
    tag_function,
)


def find_state_machines(bv):
    print("=" * 80)
    print("State Machine")
    clear_heuristic_tags(bv, TAG_STATE_MACHINE)

    # print top 10% (iterate in descending order)
    for finding in find_state_machine_reports(bv):
        score = finding["state_machine_score"]
        f = get_function_for_finding(bv, finding)
        print(
            f"Function {hex(f.start)} ({f.name}) has a state machine score of {score}."
        )
        tag_function(
            bv,
            f,
            TAG_STATE_MACHINE,
            finding["description"],
        )


def find_complex_functions(bv):
    print("=" * 80)
    print("Complex Function")
    clear_heuristic_tags(bv, TAG_COMPLEX_FUNCTION)

    # print top 10% (iterate in descending order)
    for finding in find_complex_function_reports(bv):
        score = finding["cyclomatic_complexity"]
        f = get_function_for_finding(bv, finding)
        print(
            f"Function {hex(f.start)} ({f.name}) has a cyclomatic complexity of {score}."
        )
        tag_function(
            bv,
            f,
            TAG_COMPLEX_FUNCTION,
            finding["description"],
        )


def find_large_basic_blocks(bv):
    print("=" * 80)
    print("Large Basic Block")
    clear_heuristic_tags(bv, TAG_LARGE_BASIC_BLOCK)

    # print top 10% (iterate in descending order)
    for finding in find_large_basic_block_reports(bv):
        score = finding["avg_instructions_per_block"]
        f = get_function_for_finding(bv, finding)
        print(
            f"Basic blocks in function {hex(f.start)} ({f.name}) contain on average {score} instructions."
        )
        tag_function(
            bv,
            f,
            TAG_LARGE_BASIC_BLOCK,
            finding["description"],
        )


def find_duplicated_subgraphs(bv):
    print("=" * 80)
    print("Duplicate Subgraph")
    clear_heuristic_tags(bv, TAG_DUPLICATE_SUBGRAPH)

    # print top 10% (iterate in descending order)
    for finding in find_duplicate_subgraph_reports(bv):
        score = finding["num_duplicate_subgraphs"]
        f = get_function_for_finding(bv, finding)
        print(
            f"Function {hex(f.start)} ({f.name}) contains {score} duplicate subgraphs."
        )
        tag_function(
            bv,
            f,
            TAG_DUPLICATE_SUBGRAPH,
            finding["description"],
        )


def find_instruction_overlapping(bv):
    print("=" * 80)
    print("Overlapping Instruction")

    # walk over all overlapping addresses
    for address in compute_overlapping_instruction_addresses(bv):
        # walk over all functions containing the address
        for function in bv.get_functions_containing(address):
            # highlight overlapping instruction
            function.set_user_instr_highlight(
                address, highlight.HighlightColor(red=0xFF, blue=0xFF, green=0)
            )

    clear_heuristic_tags(bv, TAG_OVERLAPPING_INSTRUCTION)
    for finding in find_instruction_overlapping_reports(bv):
        f = get_function_for_finding(bv, finding)
        print(f"Overlapping instructions in function {finding['address']} ({f.name}).")
        tag_function(
            bv,
            f,
            TAG_OVERLAPPING_INSTRUCTION,
            finding["description"],
        )


def find_uncommon_instruction_sequences(bv):
    print("=" * 80)
    print("Uncommon Instruction Sequence")
    clear_heuristic_tags(bv, TAG_UNCOMMON_INSTRUCTION_SEQUENCE)

    # print top 10% (iterate in descending order)
    for finding in find_uncommon_instruction_sequence_reports(bv):
        score = finding["uncommon_sequences_score"]
        f = get_function_for_finding(bv, finding)
        print(
            f"Function {hex(f.start)} ({f.name}) has an uncommon instruction sequences score of {score}."
        )
        tag_function(
            bv,
            f,
            TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
            finding["description"],
        )


def find_most_called_functions(bv):
    print("=" * 80)
    print("Most Called Function")
    clear_heuristic_tags(bv, TAG_MOST_CALLED_FUNCTION)

    # print top 10% (iterate in descending order)
    for finding in find_most_called_function_reports(bv):
        score = finding["num_callers"]
        f = get_function_for_finding(bv, finding)
        print(
            f"Function {hex(f.start)} ({f.name}) is called from {score} different functions."
        )
        tag_function(
            bv,
            f,
            TAG_MOST_CALLED_FUNCTION,
            finding["description"],
        )


def find_xor_decryption_loops(bv):
    print("=" * 80)
    print("XOR Decryption Loop")
    clear_heuristic_tags(bv, TAG_XOR_DECRYPTION_LOOP)

    for finding in find_xor_decryption_loop_reports(bv):
        f = get_function_for_finding(bv, finding)
        print(
            f"Function {hex(f.start)} ({f.name}) contains a XOR decryption loop with a constant."
        )
        tag_function(
            bv,
            f,
            TAG_XOR_DECRYPTION_LOOP,
            finding["description"],
        )


def find_complex_arithmetic_expressions(bv):
    """
    Heuristic to identify complex (mixed) boolean expressions inspired by gooMBA:
    https://github.com/HexRaysSA/goomba
    """
    print("=" * 80)
    print("Complex Arithmetic Expression")
    clear_heuristic_tags(bv, TAG_COMPLEX_ARITHMETIC_EXPRESSION)

    for finding in find_complex_arithmetic_expression_reports(bv):
        score = finding["num_mba_instructions"]
        f = get_function_for_finding(bv, finding)
        print(
            f"Function {hex(f.start)} ({(f.name)}) has {score} instructions that use complex arithmetic expressions."
        )
        tag_function(
            bv,
            f,
            TAG_COMPLEX_ARITHMETIC_EXPRESSION,
            finding["description"],
        )


def find_loop_frequency_functions(bv):
    print("=" * 80)
    print("Loop Frequency")
    clear_heuristic_tags(bv, TAG_LOOP_FREQUENCY)

    # print top 10% (iterate in descending order)
    for finding in find_loop_frequency_reports(bv):
        score = finding["num_loops"]
        f = get_function_for_finding(bv, finding)
        print(f"Function {hex(f.start)} ({f.name}) contains {score} loops.")
        tag_function(
            bv,
            f,
            TAG_LOOP_FREQUENCY,
            finding["description"],
        )


def find_irreducible_loops(bv):
    print("=" * 80)
    print("Irreducible Loop")
    clear_heuristic_tags(bv, TAG_IRREDUCIBLE_LOOP)

    # print top 10% (iterate in descending order)
    for finding in find_irreducible_loop_reports(bv):
        score = finding["num_irreducible_loops"]
        f = get_function_for_finding(bv, finding)
        print(f"Function {hex(f.start)} ({f.name}) contains {score} irreducible loops.")
        tag_function(
            bv,
            f,
            TAG_IRREDUCIBLE_LOOP,
            finding["description"],
        )

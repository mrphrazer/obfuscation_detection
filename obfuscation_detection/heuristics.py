from math import ceil

from binaryninja import highlight

from .helpers import (
    calc_average_instructions_per_block,
    calc_cyclomatic_complexity,
    calc_flattening_score,
    calc_uncommon_instruction_sequences_score,
    calculate_complex_arithmetic_expressions,
    contains_xor_decryption_loop,
    count_context_signature_duplicates,
    get_top_10_functions,
)
from .loop_analysis import compute_irreducible_loops, compute_number_of_natural_loops
from .tagging import (
    clear_heuristic_tags,
    TAG_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_COMPLEX_FUNCTION,
    TAG_CONTROL_FLOW_FLATTENING,
    TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_DESC_COMPLEX_FUNCTION,
    TAG_DESC_CONTROL_FLOW_FLATTENING,
    TAG_DESC_DUPLICATE_SUBGRAPH,
    TAG_DESC_IRREDUCIBLE_LOOP,
    TAG_DESC_LARGE_BASIC_BLOCK,
    TAG_DESC_LOOP_FREQUENCY,
    TAG_DESC_MOST_CALLED_FUNCTION,
    TAG_DESC_OVERLAPPING_INSTRUCTION,
    TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE,
    TAG_DESC_XOR_DECRYPTION_LOOP,
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


def function_finding(function, **fields):
    finding = {
        "address": hex(function.start),
        "name": function.name,
    }
    finding.update(fields)
    return finding


def get_function_for_finding(bv, finding):
    return bv.get_function_at(int(finding["address"], 16))


def compute_overlapping_instruction_addresses(bv):
    seen = {}
    overlapping_addresses = set()

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

    return overlapping_addresses


def find_flattened_function_reports(bv):
    reports = []
    for f, score in get_top_10_functions(bv.functions, calc_flattening_score):
        if score != 0.0:
            reports.append(function_finding(f, flattening_score=score))
    return reports


def find_complex_function_reports(bv):
    return [
        function_finding(f, cyclomatic_complexity=score)
        for f, score in get_top_10_functions(bv.functions, calc_cyclomatic_complexity)
    ]


def find_large_basic_block_reports(bv):
    return [
        function_finding(f, avg_instructions_per_block=ceil(score))
        for f, score in get_top_10_functions(
            bv.functions, calc_average_instructions_per_block
        )
    ]


def find_duplicate_subgraph_reports(bv):
    return [
        function_finding(f, num_duplicate_subgraphs=score)
        for f, score in get_top_10_functions(
            bv.functions, count_context_signature_duplicates
        )
        if score != 0
    ]


def find_instruction_overlapping_reports(bv):
    reports_by_function = {}
    for address in sorted(compute_overlapping_instruction_addresses(bv)):
        for function in bv.get_functions_containing(address):
            report = reports_by_function.setdefault(
                function.start,
                function_finding(function, overlapping_instruction_addresses=[]),
            )
            report["overlapping_instruction_addresses"].append(hex(address))
    return [reports_by_function[address] for address in sorted(reports_by_function)]


def find_uncommon_instruction_sequence_reports(bv):
    return [
        function_finding(f, uncommon_sequences_score=score)
        for f, score in get_top_10_functions(
            bv.functions, calc_uncommon_instruction_sequences_score
        )
    ]


def find_most_called_function_reports(bv):
    return [
        function_finding(f, num_callers=score)
        for f, score in get_top_10_functions(bv.functions, lambda f: len(f.callers))
    ]


def find_xor_decryption_loop_reports(bv):
    return [
        function_finding(f) for f in bv.functions if contains_xor_decryption_loop(bv, f)
    ]


def find_complex_arithmetic_expression_reports(bv):
    return [
        function_finding(f, num_mba_instructions=score)
        for f, score in get_top_10_functions(
            bv.functions, lambda f: calculate_complex_arithmetic_expressions(f)
        )
        if score != 0
    ]


def find_loop_frequency_reports(bv):
    return [
        function_finding(f, num_loops=score)
        for f, score in get_top_10_functions(
            bv.functions, compute_number_of_natural_loops
        )
    ]


def find_irreducible_loop_reports(bv):
    return [
        function_finding(f, num_irreducible_loops=score)
        for f, score in filter(
            lambda x: x[1] > 0,
            get_top_10_functions(
                bv.functions, lambda x: len(compute_irreducible_loops(x))
            ),
        )
    ]


def collect_obfuscation_reports(bv):
    return [
        {
            "name": "Control Flow Flattening",
            "findings": find_flattened_function_reports(bv),
        },
        {
            "name": "Cyclomatic Complexity",
            "findings": find_complex_function_reports(bv),
        },
        {
            "name": "Large Basic Blocks",
            "findings": find_large_basic_block_reports(bv),
        },
        {
            "name": "Uncommon Instruction Sequences",
            "findings": find_uncommon_instruction_sequence_reports(bv),
        },
        {
            "name": "Instruction Overlapping",
            "findings": find_instruction_overlapping_reports(bv),
        },
        {
            "name": "Most Called Functions",
            "findings": find_most_called_function_reports(bv),
        },
        {
            "name": "Loop Frequency",
            "findings": find_loop_frequency_reports(bv),
        },
        {
            "name": "Irreducible Loops",
            "findings": find_irreducible_loop_reports(bv),
        },
        {
            "name": "XOR Decryption Loops",
            "findings": find_xor_decryption_loop_reports(bv),
        },
        {
            "name": "Functions with complex arithmetic expressions:",
            "findings": find_complex_arithmetic_expression_reports(bv),
        },
        {
            "name": "Duplicate Subgraphs",
            "findings": find_duplicate_subgraph_reports(bv),
        },
    ]


def find_flattened_functions(bv):
    print("=" * 80)
    print("Control Flow Flattening")
    clear_heuristic_tags(bv, TAG_CONTROL_FLOW_FLATTENING)

    # print top 10% (iterate in descending order)
    for finding in find_flattened_function_reports(bv):
        score = finding["flattening_score"]
        f = get_function_for_finding(bv, finding)
        print(f"Function {hex(f.start)} ({f.name}) has a flattening score of {score}.")
        tag_function(
            bv,
            f,
            TAG_CONTROL_FLOW_FLATTENING,
            TAG_DESC_CONTROL_FLOW_FLATTENING.format(score=score),
        )


def find_complex_functions(bv):
    print("=" * 80)
    print("Cyclomatic Complexity")
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
            TAG_DESC_COMPLEX_FUNCTION.format(score=score),
        )


def find_large_basic_blocks(bv):
    print("=" * 80)
    print("Large Basic Blocks")
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
            TAG_DESC_LARGE_BASIC_BLOCK.format(score=score),
        )


def find_duplicated_subgraphs(bv):
    print("=" * 80)
    print("Duplicate Subgraphs")
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
            TAG_DESC_DUPLICATE_SUBGRAPH.format(score=score),
        )


def find_instruction_overlapping(bv):
    print("=" * 80)
    print("Instruction Overlapping")

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
            TAG_DESC_OVERLAPPING_INSTRUCTION,
        )


def find_uncommon_instruction_sequences(bv):
    print("=" * 80)
    print("Uncommon Instruction Sequences")
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
            TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE.format(score=score),
        )


def find_most_called_functions(bv):
    print("=" * 80)
    print("Most Called Functions")
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
            TAG_DESC_MOST_CALLED_FUNCTION.format(score=score),
        )


def find_xor_decryption_loops(bv):
    print("=" * 80)
    print("XOR Decryption Loops")
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
            TAG_DESC_XOR_DECRYPTION_LOOP,
        )


def find_complex_arithmetic_expressions(bv):
    """
    Heuristic to identify complex (mixed) boolean expressions inspired by gooMBA:
    https://github.com/HexRaysSA/goomba
    """
    print("=" * 80)
    print("Functions with complex arithmetic expressions:")
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
            TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION.format(score=score),
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
            TAG_DESC_LOOP_FREQUENCY.format(score=score),
        )


def find_irreducible_loops(bv):
    print("=" * 80)
    print("Irreducible Loops")
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
            TAG_DESC_IRREDUCIBLE_LOOP.format(score=score),
        )

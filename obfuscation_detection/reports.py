from math import ceil

from .helpers import (
    calc_average_instructions_per_block,
    calc_cyclomatic_complexity,
    calc_flattening_score,
    calc_uncommon_instruction_sequences_score,
    calculate_entropy,
    calculate_complex_arithmetic_expressions,
    contains_xor_decryption_loop,
    count_context_signature_duplicates,
    find_rc4_ksa,
    find_rc4_prga,
    get_top_10_functions,
)
from .loop_analysis import compute_irreducible_loops, compute_number_of_natural_loops
from .tagging import (
    TAG_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_COMPLEX_FUNCTION,
    TAG_CONTROL_FLOW_FLATTENING,
    TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION,
    TAG_DESC_COMPLEX_FUNCTION,
    TAG_DESC_CONTROL_FLOW_FLATTENING,
    TAG_DESC_DUPLICATE_SUBGRAPH,
    TAG_DESC_ENTRY_FUNCTION,
    TAG_DESC_IRREDUCIBLE_LOOP,
    TAG_DESC_LARGE_BASIC_BLOCK,
    TAG_DESC_LEAF_FUNCTION,
    TAG_DESC_LOOP_FREQUENCY,
    TAG_DESC_MOST_CALLED_FUNCTION,
    TAG_DESC_OVERLAPPING_INSTRUCTION,
    TAG_DESC_RC4_KSA,
    TAG_DESC_RC4_PRGA,
    TAG_DESC_RECURSIVE_FUNCTION,
    TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE,
    TAG_DESC_XOR_DECRYPTION_LOOP,
    TAG_DUPLICATE_SUBGRAPH,
    TAG_ENTRY_FUNCTION,
    TAG_IRREDUCIBLE_LOOP,
    TAG_LARGE_BASIC_BLOCK,
    TAG_LEAF_FUNCTION,
    TAG_LOOP_FREQUENCY,
    TAG_MOST_CALLED_FUNCTION,
    TAG_OVERLAPPING_INSTRUCTION,
    TAG_RC4_KSA,
    TAG_RC4_PRGA,
    TAG_RECURSIVE_FUNCTION,
    TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
    TAG_XOR_DECRYPTION_LOOP,
)


def function_finding(function, tag_type, description, **fields):
    finding = {
        "address": hex(function.start),
        "name": function.name,
        "tag_type": tag_type,
        "description": description,
    }
    finding.update(fields)
    return finding


def section_finding(section, entropy):
    return {
        "name": section.name,
        "address": hex(section.start),
        "length": section.length,
        "entropy": entropy,
    }


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
            reports.append(
                function_finding(
                    f,
                    TAG_CONTROL_FLOW_FLATTENING,
                    TAG_DESC_CONTROL_FLOW_FLATTENING.format(score=score),
                    flattening_score=score,
                )
            )
    return reports


def find_complex_function_reports(bv):
    return [
        function_finding(
            f,
            TAG_COMPLEX_FUNCTION,
            TAG_DESC_COMPLEX_FUNCTION.format(score=score),
            cyclomatic_complexity=score,
        )
        for f, score in get_top_10_functions(bv.functions, calc_cyclomatic_complexity)
    ]


def find_large_basic_block_reports(bv):
    return [
        function_finding(
            f,
            TAG_LARGE_BASIC_BLOCK,
            TAG_DESC_LARGE_BASIC_BLOCK.format(score=ceil(score)),
            avg_instructions_per_block=ceil(score),
        )
        for f, score in get_top_10_functions(
            bv.functions, calc_average_instructions_per_block
        )
    ]


def find_duplicate_subgraph_reports(bv):
    return [
        function_finding(
            f,
            TAG_DUPLICATE_SUBGRAPH,
            TAG_DESC_DUPLICATE_SUBGRAPH.format(score=score),
            num_duplicate_subgraphs=score,
        )
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
                function_finding(
                    function,
                    TAG_OVERLAPPING_INSTRUCTION,
                    TAG_DESC_OVERLAPPING_INSTRUCTION,
                    overlapping_instruction_addresses=[],
                ),
            )
            report["overlapping_instruction_addresses"].append(hex(address))
    return [reports_by_function[address] for address in sorted(reports_by_function)]


def find_uncommon_instruction_sequence_reports(bv):
    return [
        function_finding(
            f,
            TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
            TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE.format(score=score),
            uncommon_sequences_score=score,
        )
        for f, score in get_top_10_functions(
            bv.functions, calc_uncommon_instruction_sequences_score
        )
    ]


def find_most_called_function_reports(bv):
    return [
        function_finding(
            f,
            TAG_MOST_CALLED_FUNCTION,
            TAG_DESC_MOST_CALLED_FUNCTION.format(score=score),
            num_callers=score,
        )
        for f, score in get_top_10_functions(bv.functions, lambda f: len(f.callers))
    ]


def find_xor_decryption_loop_reports(bv):
    return [
        function_finding(f, TAG_XOR_DECRYPTION_LOOP, TAG_DESC_XOR_DECRYPTION_LOOP)
        for f in bv.functions
        if contains_xor_decryption_loop(bv, f)
    ]


def find_complex_arithmetic_expression_reports(bv):
    return [
        function_finding(
            f,
            TAG_COMPLEX_ARITHMETIC_EXPRESSION,
            TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION.format(score=score),
            num_mba_instructions=score,
        )
        for f, score in get_top_10_functions(
            bv.functions, lambda f: calculate_complex_arithmetic_expressions(f)
        )
        if score != 0
    ]


def find_loop_frequency_reports(bv):
    return [
        function_finding(
            f,
            TAG_LOOP_FREQUENCY,
            TAG_DESC_LOOP_FREQUENCY.format(score=score),
            num_loops=score,
        )
        for f, score in get_top_10_functions(
            bv.functions, compute_number_of_natural_loops
        )
    ]


def find_irreducible_loop_reports(bv):
    return [
        function_finding(
            f,
            TAG_IRREDUCIBLE_LOOP,
            TAG_DESC_IRREDUCIBLE_LOOP.format(score=score),
            num_irreducible_loops=score,
        )
        for f, score in filter(
            lambda x: x[1] > 0,
            get_top_10_functions(
                bv.functions, lambda x: len(compute_irreducible_loops(x))
            ),
        )
    ]


def find_entry_function_reports(bv):
    return [
        function_finding(f, TAG_ENTRY_FUNCTION, TAG_DESC_ENTRY_FUNCTION)
        for f in bv.functions
        if len(f.callers) == 0
    ]


def find_leaf_function_reports(bv):
    return [
        function_finding(f, TAG_LEAF_FUNCTION, TAG_DESC_LEAF_FUNCTION)
        for f in bv.functions
        if len(f.callees) == 0 and sum(1 for _ in f.instructions) > 1
    ]


def find_recursive_function_reports(bv):
    return [
        function_finding(f, TAG_RECURSIVE_FUNCTION, TAG_DESC_RECURSIVE_FUNCTION)
        for f in bv.functions
        if f in f.callees
    ]


def find_section_entropy_reports(bv):
    section_entropies = [
        (section, calculate_entropy(bv.read(section.start, section.length)))
        for section in bv.sections.values()
    ]
    return [
        section_finding(section, score)
        for section, score in sorted(
            section_entropies,
            key=lambda section_entropy: section_entropy[1],
            reverse=True,
        )
    ]


def find_rc4_reports(bv):
    reports = []
    for f in bv.functions:
        if find_rc4_ksa(bv, f):
            reports.append(function_finding(f, TAG_RC4_KSA, TAG_DESC_RC4_KSA))
        if find_rc4_prga(bv, f):
            reports.append(function_finding(f, TAG_RC4_PRGA, TAG_DESC_RC4_PRGA))
    return reports


def collect_heuristics_and_utils_reports(bv):
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
        {
            "name": "Entry Functions",
            "findings": find_entry_function_reports(bv),
        },
        {
            "name": "Leaf Functions",
            "findings": find_leaf_function_reports(bv),
        },
        {
            "name": "Recursive Functions",
            "findings": find_recursive_function_reports(bv),
        },
        {
            "name": "Section Entropy",
            "findings": find_section_entropy_reports(bv),
        },
        {
            "name": "RC4 Implementations",
            "findings": find_rc4_reports(bv),
        },
    ]

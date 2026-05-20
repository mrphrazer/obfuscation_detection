from binaryninja import PluginCommand

from .obfuscation_detection import (
    # heuristics
    find_complex_functions_bg,
    find_state_machines_bg,
    find_instruction_overlapping_bg,
    find_large_basic_blocks_bg,
    find_most_called_functions_bg,
    find_uncommon_instruction_sequences_bg,
    find_xor_decryption_loops_bg,
    find_irreducible_loops_bg,
    find_loop_frequency_functions_bg,
    find_complex_arithmetic_expressions_bg,
    find_duplicate_subgraphs_bg,
    run_heuristics_and_utils_bg,
    # utils
    find_entry_functions_bg,
    find_leaf_functions_bg,
    find_recursive_functions_bg,
    compute_section_entropy_bg,
    find_rc4_bg,
)

# Heuristics
PluginCommand.register(
    "Obfuscation Detection\\All",
    "Runs all detection heuristics and utility detections",
    run_heuristics_and_utils_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\State Machine",
    "Heuristic to detect state machines",
    find_state_machines_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Complex Function",
    "Heuristic to detect complex functions",
    find_complex_functions_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Large Basic Block",
    "Heuristic to detect functions with large basic blocks",
    find_large_basic_blocks_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Overlapping Instruction",
    "Heuristic to detect overlapping instructions",
    find_instruction_overlapping_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Uncommon Instruction Sequence",
    "Heuristic to detect uncommon instruction sequences",
    find_uncommon_instruction_sequences_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Most Called Function",
    "Detects the most called functions",
    find_most_called_functions_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Loop Frequency",
    "Detects functions with a high number of loops",
    find_loop_frequency_functions_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Irreducible Loop",
    "Detects functions with irreducible loops",
    find_irreducible_loops_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\XOR Decryption Loop",
    "Detects functions with XOR decryption loops",
    find_xor_decryption_loops_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Complex Arithmetic Expression",
    "Detects functions with complex arithmetic expressions",
    find_complex_arithmetic_expressions_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Duplicate Subgraph",
    "Detects functions with duplicate subgraphs",
    find_duplicate_subgraphs_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Utils\\Entry Function",
    "Detects functions without callers",
    find_entry_functions_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Utils\\Leaf Function",
    "Detects functions without callees",
    find_leaf_functions_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Utils\\Recursive Function",
    "Detects recursive functions",
    find_recursive_functions_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Utils\\Section Entropy",
    "Computes the entropy of all sections",
    compute_section_entropy_bg,
)

PluginCommand.register(
    "Obfuscation Detection\\Utils\\RC4",
    "Detects functions which potentially implement RC4 algorithms",
    find_rc4_bg,
)

from binaryninja import PluginCommand

from .obfuscation_detection import (detect_obfuscation_bg,
                                    find_complex_functions_bg,
                                    find_flattened_functions_bg,
                                    find_instruction_overlapping_bg,
                                    find_large_basic_blocks_bg,
                                    find_most_called_functions_bg,
                                    find_uncommon_instruction_sequences_bg,
                                    find_xor_decryption_loops_bg,
                                    find_complex_arithmetic_expressions_bg)

PluginCommand.register("Obfuscation Detection\\All",
                       "Detects obfuscated code via heuristics", detect_obfuscation_bg)

PluginCommand.register("Obfuscation Detection\\Flattened Functions",
                       "Heuristic to detect flattened functions", find_flattened_functions_bg)

PluginCommand.register("Obfuscation Detection\\Complex Functions",
                       "Heuristic to detect complex functions", find_complex_functions_bg)

PluginCommand.register("Obfuscation Detection\\Large Basic Blocks",
                       "Heuristic to detect functions with large basic blocks", find_large_basic_blocks_bg)

PluginCommand.register("Obfuscation Detection\\Instruction Overlapping",
                       "Heuristic to detect instruction overlapping", find_instruction_overlapping_bg)

PluginCommand.register("Obfuscation Detection\\Uncommon Instruction Sequences",
                       "Heuristic to detect uncommon instruction sequences", find_uncommon_instruction_sequences_bg)

PluginCommand.register("Obfuscation Detection\\Most Called Functions",
                       "Detects the most called functions", find_most_called_functions_bg)

PluginCommand.register("Obfuscation Detection\\XOR Decryption Loops",
                       "Detects functions with XOR decryption loops", find_xor_decryption_loops_bg)

PluginCommand.register("Obfuscation Detection\\Arithmetic Complexity",
                       "Detects functions with complex arithmetic expressions", find_complex_arithmetic_expressions_bg)
from binaryninja import PluginCommand

from obfuscation_detection import detect_obfuscation
from obfuscation_detection import heuristics

PluginCommand.register("Obfuscation Detection\\All",
                       "Detects obfuscated code via heuristics", detect_obfuscation)

PluginCommand.register("Obfuscation Detection\\Flattened Functions",
                       "Heuristic to detect flattened functions", heuristics.find_flattened_functions)

PluginCommand.register("Obfuscation Detection\\Complex Functions",
                       "Heuristic to detect complex functions", heuristics.find_complex_functions)

PluginCommand.register("Obfuscation Detection\\Large Basic Blocks",
                       "Heuristic to detect functions with large basic blocks", heuristics.find_large_basic_blocks)

PluginCommand.register("Obfuscation Detection\\Instruction Overlapping",
                       "Heuristic to detect instruction overlapping", heuristics.find_instruction_overlapping)

PluginCommand.register("Obfuscation Detection\\Uncommon Instruction Sequences",
                       "Heuristic to detect uncommon instruction sequences", heuristics.find_uncommon_instruction_sequences)
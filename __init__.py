from binaryninja import PluginCommand

from obfuscation_detection import detect_obfuscation

PluginCommand.register("Obfuscation Detection",
                       "Detects obfuscated code via heuristics", detect_obfuscation)

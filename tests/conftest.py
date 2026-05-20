import sys
import types


def pytest_configure():
    """Provide enough Binary Ninja surface for importing pure helper code."""
    if "binaryninja" in sys.modules:
        return

    binaryninja = types.ModuleType("binaryninja")
    binaryninja.highlevelil = types.SimpleNamespace(HighLevelILInstruction=object)
    binaryninja.highlight = types.SimpleNamespace(HighlightColor=object)

    enums = types.ModuleType("binaryninja.enums")
    plugin = types.ModuleType("binaryninja.plugin")

    class BackgroundTaskThread:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            pass

    plugin.BackgroundTaskThread = BackgroundTaskThread

    class HighLevelILOperation:
        HLIL_ADD = "HLIL_ADD"
        HLIL_NEG = "HLIL_NEG"
        HLIL_SUB = "HLIL_SUB"
        HLIL_MUL = "HLIL_MUL"
        HLIL_DIVS = "HLIL_DIVS"
        HLIL_MODS = "HLIL_MODS"
        HLIL_NOT = "HLIL_NOT"
        HLIL_AND = "HLIL_AND"
        HLIL_OR = "HLIL_OR"
        HLIL_XOR = "HLIL_XOR"
        HLIL_LSR = "HLIL_LSR"
        HLIL_LSL = "HLIL_LSL"

    class LowLevelILOperation:
        LLIL_CONST = "LLIL_CONST"
        LLIL_CONST_PTR = "LLIL_CONST_PTR"
        LLIL_REG = "LLIL_REG"
        LLIL_SET_REG = "LLIL_SET_REG"
        LLIL_XOR = "LLIL_XOR"

    enums.HighLevelILOperation = HighLevelILOperation
    enums.LowLevelILOperation = LowLevelILOperation

    sys.modules["binaryninja"] = binaryninja
    sys.modules["binaryninja.enums"] = enums
    sys.modules["binaryninja.plugin"] = plugin

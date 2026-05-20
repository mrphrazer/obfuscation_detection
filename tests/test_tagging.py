from dataclasses import dataclass, field

import pytest

import obfuscation_detection as plugin
from obfuscation_detection import heuristics, utils
from obfuscation_detection.tagging import (
    clear_heuristic_tags,
    tag_function,
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


@dataclass
class FakeFunction:
    start: int = 0x401000
    name: str = "function"
    callers: list = field(default_factory=list)
    callees: list = field(default_factory=list)
    instructions: list = field(default_factory=lambda: [("nop", 0), ("ret", 1)])
    tags: dict = field(default_factory=dict)
    highlights: list = field(default_factory=list)

    def add_tag(self, tag_type_name, data):
        self.tags.setdefault(tag_type_name, []).append(data)

    def remove_user_function_tags_of_type(self, tag_type_name):
        self.tags.pop(tag_type_name, None)

    def set_user_instr_highlight(self, address, color):
        self.highlights.append((address, color))


@dataclass
class FakeBV:
    functions: list
    tag_types: dict = field(default_factory=dict)
    created_tag_types: list = field(default_factory=list)
    instructions: list = field(default_factory=list)
    instruction_lengths: dict = field(default_factory=dict)

    def create_tag_type(self, name, icon):
        self.created_tag_types.append((name, icon))
        self.tag_types[name] = icon

    def get_instruction_length(self, address):
        return self.instruction_lengths.get(address, 1)

    def get_functions_containing(self, _address):
        return self.functions

    def get_function_at(self, _address):
        for function in self.functions:
            if function.start == _address:
                return function
        return self.functions[0]


def test_tag_function_creates_tag_type_once():
    function = FakeFunction()
    bv = FakeBV([function])

    tag_function(bv, function, TAG_COMPLEX_FUNCTION, "first")
    tag_function(bv, function, TAG_COMPLEX_FUNCTION, "second")

    assert [name for name, _icon in bv.created_tag_types] == [TAG_COMPLEX_FUNCTION]
    assert function.tags[TAG_COMPLEX_FUNCTION] == ["first", "second"]


def test_clear_heuristic_tags_removes_only_matching_tag_type():
    first = FakeFunction(
        tags={TAG_COMPLEX_FUNCTION: ["old"], TAG_ENTRY_FUNCTION: ["keep"]}
    )
    second = FakeFunction(tags={TAG_COMPLEX_FUNCTION: ["old"]})
    bv = FakeBV([first, second], tag_types={TAG_COMPLEX_FUNCTION: object()})

    clear_heuristic_tags(bv, TAG_COMPLEX_FUNCTION)

    assert first.tags == {TAG_ENTRY_FUNCTION: ["keep"]}
    assert second.tags == {}


@pytest.mark.parametrize(
    ("finder", "score", "tag_type", "expected_data"),
    [
        (
            heuristics.find_flattened_functions,
            0.753,
            TAG_CONTROL_FLOW_FLATTENING,
            TAG_DESC_CONTROL_FLOW_FLATTENING.format(score=0.753),
        ),
        (
            heuristics.find_complex_functions,
            7,
            TAG_COMPLEX_FUNCTION,
            TAG_DESC_COMPLEX_FUNCTION.format(score=7),
        ),
        (
            heuristics.find_large_basic_blocks,
            3.2,
            TAG_LARGE_BASIC_BLOCK,
            TAG_DESC_LARGE_BASIC_BLOCK.format(score=4),
        ),
        (
            heuristics.find_duplicated_subgraphs,
            2,
            TAG_DUPLICATE_SUBGRAPH,
            TAG_DESC_DUPLICATE_SUBGRAPH.format(score=2),
        ),
        (
            heuristics.find_uncommon_instruction_sequences,
            0.5,
            TAG_UNCOMMON_INSTRUCTION_SEQUENCE,
            TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE.format(score=0.5),
        ),
        (
            heuristics.find_most_called_functions,
            4,
            TAG_MOST_CALLED_FUNCTION,
            TAG_DESC_MOST_CALLED_FUNCTION.format(score=4),
        ),
        (
            heuristics.find_complex_arithmetic_expressions,
            3,
            TAG_COMPLEX_ARITHMETIC_EXPRESSION,
            TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION.format(score=3),
        ),
        (
            heuristics.find_loop_frequency_functions,
            5,
            TAG_LOOP_FREQUENCY,
            TAG_DESC_LOOP_FREQUENCY.format(score=5),
        ),
        (
            heuristics.find_irreducible_loops,
            2,
            TAG_IRREDUCIBLE_LOOP,
            TAG_DESC_IRREDUCIBLE_LOOP.format(score=2),
        ),
    ],
)
def test_ranked_heuristics_clear_and_apply_expected_tags(
    monkeypatch, finder, score, tag_type, expected_data
):
    function = FakeFunction(tags={tag_type: ["old"]})
    bv = FakeBV([function], tag_types={tag_type: object()})
    monkeypatch.setattr(
        heuristics,
        "get_top_10_functions",
        lambda _functions, _scoring: [(function, score)],
    )

    finder(bv)

    assert function.tags[tag_type] == [expected_data]


def test_xor_decryption_loop_applies_expected_tag(monkeypatch):
    function = FakeFunction(tags={TAG_XOR_DECRYPTION_LOOP: ["old"]})
    bv = FakeBV([function], tag_types={TAG_XOR_DECRYPTION_LOOP: object()})
    monkeypatch.setattr(
        heuristics, "contains_xor_decryption_loop", lambda _bv, _f: True
    )

    heuristics.find_xor_decryption_loops(bv)

    assert function.tags[TAG_XOR_DECRYPTION_LOOP] == [TAG_DESC_XOR_DECRYPTION_LOOP]


def test_instruction_overlapping_applies_expected_tag():
    function = FakeFunction(start=0x401000, tags={TAG_OVERLAPPING_INSTRUCTION: ["old"]})
    bv = FakeBV(
        [function],
        tag_types={TAG_OVERLAPPING_INSTRUCTION: object()},
        instructions=[("first", 0x1000), ("overlap", 0x1001)],
        instruction_lengths={0x1000: 2, 0x1001: 1},
    )

    heuristics.find_instruction_overlapping(bv)

    assert function.tags[TAG_OVERLAPPING_INSTRUCTION] == [
        TAG_DESC_OVERLAPPING_INSTRUCTION
    ]
    assert function.highlights


def test_utility_tags_are_applied(monkeypatch):
    recursive = FakeFunction(name="recursive")
    recursive.callees.append(recursive)
    functions = [
        FakeFunction(name="entry"),
        FakeFunction(name="leaf"),
        recursive,
        FakeFunction(name="rc4"),
    ]
    bv = FakeBV(functions)
    monkeypatch.setattr(
        utils, "find_rc4_ksa", lambda _bv, function: function.name == "rc4"
    )
    monkeypatch.setattr(
        utils, "find_rc4_prga", lambda _bv, function: function.name == "rc4"
    )

    utils.find_entry_functions(bv)
    utils.find_leaf_functions(bv)
    utils.find_recursive_functions(bv)
    utils.find_rc4(bv)

    assert functions[0].tags[TAG_ENTRY_FUNCTION] == [TAG_DESC_ENTRY_FUNCTION]
    assert functions[1].tags[TAG_LEAF_FUNCTION] == [TAG_DESC_LEAF_FUNCTION]
    assert recursive.tags[TAG_RECURSIVE_FUNCTION] == [TAG_DESC_RECURSIVE_FUNCTION]
    assert functions[3].tags[TAG_RC4_KSA] == [TAG_DESC_RC4_KSA]
    assert functions[3].tags[TAG_RC4_PRGA] == [TAG_DESC_RC4_PRGA]


def test_detect_obfuscation_calls_all_heuristics_synchronously(monkeypatch):
    calls = []
    expected_calls = [
        "find_flattened_functions",
        "find_complex_functions",
        "find_large_basic_blocks",
        "find_uncommon_instruction_sequences",
        "find_instruction_overlapping",
        "find_most_called_functions",
        "find_loop_frequency_functions",
        "find_irreducible_loops",
        "find_xor_decryption_loops",
        "find_complex_arithmetic_expressions",
        "find_duplicated_subgraphs",
    ]

    for name in expected_calls:
        monkeypatch.setattr(plugin, name, lambda _bv, name=name: calls.append(name))
    monkeypatch.setattr(
        plugin,
        "find_irreducible_loops_bg",
        lambda _bv: pytest.fail("detect_obfuscation should not start nested tasks"),
    )

    plugin.detect_obfuscation(FakeBV([]))

    assert calls == expected_calls

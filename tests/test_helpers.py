from dataclasses import dataclass, field

from obfuscation_detection.helpers import (
    calc_average_instructions_per_block,
    calc_cyclomatic_complexity,
    calc_state_machine_score,
    calculate_entropy,
    count_context_signature_duplicates,
    get_dominated_by,
    get_opcode_from_disassembly,
    get_top_10_functions,
    sliding_window,
    sort_elements,
)


@dataclass(eq=False)
class Block:
    name: str
    outgoing_edges: list = field(default_factory=list)
    incoming_edges: list = field(default_factory=list)
    dominator_tree_children: list = field(default_factory=list)
    dominance_frontier: set = field(default_factory=set)
    instruction_count: int = 1
    instructions: tuple = ()

    def __iter__(self):
        return iter(self.instructions)

    def __repr__(self):
        return self.name


@dataclass(frozen=True)
class Edge:
    source: Block
    target: Block
    back_edge: bool = False


@dataclass
class Function:
    basic_blocks: list


def connect(source, target, *, back_edge=False):
    edge = Edge(source, target, back_edge)
    source.outgoing_edges.append(edge)
    target.incoming_edges.append(edge)
    return edge


def test_basic_graph_scoring_helpers():
    entry = Block("entry", instruction_count=3)
    left = Block("left", instruction_count=5)
    right = Block("right", instruction_count=7)
    exit_block = Block("exit", instruction_count=1)

    connect(entry, left)
    connect(entry, right)
    connect(left, exit_block)
    connect(right, exit_block)

    function = Function([entry, left, right, exit_block])

    assert calc_cyclomatic_complexity(function) == 2
    assert calc_average_instructions_per_block(function) == 4


def test_state_machine_score_uses_dominator_tree_and_back_edges():
    dispatcher = Block("dispatcher")
    case_a = Block("case_a")
    case_b = Block("case_b")
    exit_block = Block("exit")

    dispatcher.dominator_tree_children = [case_a, case_b]
    connect(dispatcher, case_a)
    connect(dispatcher, case_b)
    connect(case_a, dispatcher, back_edge=True)
    connect(case_b, exit_block)

    function = Function([dispatcher, case_a, case_b, exit_block])

    assert get_dominated_by(dispatcher) == {dispatcher, case_a, case_b}
    assert calc_state_machine_score(function) == 0.75


def test_context_signature_duplicate_count_detects_repeated_blocks():
    block_a = Block("a", instructions=((["mov"], 0x1000),))
    block_b = Block("b", instructions=((["xor"], 0x1001),))
    block_c = Block("c", instructions=((["xor"], 0x1002),))

    function = Function([block_a, block_b, block_c])

    assert count_context_signature_duplicates(function, num_iterations=0) == 1


def test_sequence_and_sorting_helpers():
    assert list(sliding_window(["a", "b", "c"], 2)) == [["a", "b"], ["b", "c"]]
    assert get_opcode_from_disassembly(([" mov "], 0x1000)) == "mov"
    assert list(sort_elements([1, 3, 2], lambda item: item)) == [(3, 3), (2, 2), (1, 1)]


def test_get_top_10_functions_keeps_highest_scoring_items_first():
    functions = list(range(12))

    assert list(get_top_10_functions(functions, lambda item: item)) == [
        (11, 11),
        (10, 10),
        (9, 9),
        (8, 8),
        (7, 7),
        (6, 6),
        (5, 5),
        (4, 4),
        (3, 3),
        (2, 2),
    ]


def test_entropy_for_uniform_and_fixed_data():
    assert calculate_entropy(b"\x00" * 8) == 0.0
    assert calculate_entropy(bytes(range(256))) == 8.0

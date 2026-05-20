from dataclasses import dataclass, field

from obfuscation_detection.loop_analysis import (
    compute_blocks_in_natural_loops,
    compute_irreducible_loops,
    compute_natural_loop_body,
    compute_natural_loop_back_edges,
    compute_number_of_natural_loops,
    compute_strongly_connected_components,
)


@dataclass(eq=False)
class Block:
    name: str
    outgoing_edges: list = field(default_factory=list)
    incoming_edges: list = field(default_factory=list)
    dominance_frontier: set = field(default_factory=set)
    dominator_tree_children: list = field(default_factory=list)
    instruction_count: int = 1

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


def component_names(components):
    return {frozenset(block.name for block in component) for component in components}


def test_natural_loop_back_edges_and_body():
    entry = Block("entry")
    header = Block("header")
    body = Block("body")
    latch = Block("latch")
    exit_block = Block("exit")

    connect(entry, header)
    connect(header, body)
    connect(body, latch)
    back_edge = connect(latch, header, back_edge=True)
    connect(header, exit_block)
    header.dominance_frontier.add(header)

    function = Function([entry, header, body, latch, exit_block])

    assert list(compute_natural_loop_back_edges(function)) == [back_edge]
    assert compute_number_of_natural_loops(function) == 1
    assert compute_natural_loop_body(back_edge) == {header, body, latch}
    assert compute_blocks_in_natural_loops(function) == {header, body, latch}


def test_nested_natural_loops_include_inner_loop_in_outer_loop_body():
    entry = Block("entry")
    outer_header = Block("outer_header")
    inner_header = Block("inner_header")
    inner_body = Block("inner_body")
    inner_latch = Block("inner_latch")
    outer_latch = Block("outer_latch")
    exit_block = Block("exit")

    connect(entry, outer_header)
    connect(outer_header, inner_header)
    connect(inner_header, inner_body)
    connect(inner_body, inner_latch)
    inner_back_edge = connect(inner_latch, inner_header, back_edge=True)
    connect(inner_header, outer_latch)
    outer_back_edge = connect(outer_latch, outer_header, back_edge=True)
    connect(outer_header, exit_block)
    outer_header.dominance_frontier.add(outer_header)
    inner_header.dominance_frontier.add(inner_header)

    function = Function(
        [
            entry,
            outer_header,
            inner_header,
            inner_body,
            inner_latch,
            outer_latch,
            exit_block,
        ]
    )

    assert list(compute_natural_loop_back_edges(function)) == [
        outer_back_edge,
        inner_back_edge,
    ]
    assert compute_number_of_natural_loops(function) == 2
    assert compute_natural_loop_body(inner_back_edge) == {
        inner_header,
        inner_body,
        inner_latch,
    }
    assert compute_natural_loop_body(outer_back_edge) == {
        outer_header,
        inner_header,
        inner_body,
        inner_latch,
        outer_latch,
    }
    assert compute_blocks_in_natural_loops(function) == {
        outer_header,
        inner_header,
        inner_body,
        inner_latch,
        outer_latch,
    }


def test_multiple_independent_natural_loops_are_counted_and_unionized():
    entry = Block("entry")
    first_header = Block("first_header")
    first_body = Block("first_body")
    between = Block("between")
    second_header = Block("second_header")
    second_body = Block("second_body")
    exit_block = Block("exit")

    connect(entry, first_header)
    connect(first_header, first_body)
    first_back_edge = connect(first_body, first_header, back_edge=True)
    connect(first_header, between)
    connect(between, second_header)
    connect(second_header, second_body)
    second_back_edge = connect(second_body, second_header, back_edge=True)
    connect(second_header, exit_block)
    first_header.dominance_frontier.add(first_header)
    second_header.dominance_frontier.add(second_header)

    function = Function(
        [
            entry,
            first_header,
            first_body,
            between,
            second_header,
            second_body,
            exit_block,
        ]
    )

    assert list(compute_natural_loop_back_edges(function)) == [
        first_back_edge,
        second_back_edge,
    ]
    assert compute_number_of_natural_loops(function) == 2
    assert compute_natural_loop_body(first_back_edge) == {first_header, first_body}
    assert compute_natural_loop_body(second_back_edge) == {second_header, second_body}
    assert compute_blocks_in_natural_loops(function) == {
        first_header,
        first_body,
        second_header,
        second_body,
    }


def test_natural_loop_body_includes_branching_paths_to_the_latch():
    entry = Block("entry")
    header = Block("header")
    left = Block("left")
    right = Block("right")
    side = Block("side")
    latch = Block("latch")
    exit_block = Block("exit")

    connect(entry, header)
    connect(header, left)
    connect(left, right)
    connect(left, side)
    connect(right, latch)
    connect(side, latch)
    back_edge = connect(latch, header, back_edge=True)
    connect(header, exit_block)
    header.dominance_frontier.add(header)

    function = Function([entry, header, left, right, side, latch, exit_block])

    assert compute_natural_loop_body(back_edge) == {
        header,
        left,
        right,
        side,
        latch,
    }
    assert compute_blocks_in_natural_loops(function) == {
        header,
        left,
        right,
        side,
        latch,
    }


def test_self_loop_is_a_natural_loop_not_an_irreducible_loop():
    entry = Block("entry")
    header = Block("header")
    exit_block = Block("exit")

    back_edge = connect(header, header, back_edge=True)
    connect(entry, header)
    connect(header, exit_block)
    header.dominance_frontier.add(header)

    function = Function([entry, header, exit_block])

    assert list(compute_natural_loop_back_edges(function)) == [back_edge]
    assert compute_natural_loop_body(back_edge) == {header}
    assert component_names(compute_strongly_connected_components(function)) == {
        frozenset({"entry"}),
        frozenset({"header"}),
        frozenset({"exit"}),
    }
    assert compute_irreducible_loops(function) == []


def test_edge_marked_as_non_back_edge_is_not_treated_as_natural_loop():
    header = Block("header")
    body = Block("body")

    connect(header, body)
    connect(body, header, back_edge=False)
    header.dominance_frontier.add(header)

    function = Function([header, body])

    assert list(compute_natural_loop_back_edges(function)) == []
    assert compute_number_of_natural_loops(function) == 0
    assert compute_blocks_in_natural_loops(function) == set()


def test_strongly_connected_components_partitions_cyclic_and_acyclic_blocks():
    entry = Block("entry")
    left = Block("left")
    right = Block("right")
    exit_block = Block("exit")

    connect(entry, left)
    connect(left, right)
    connect(right, left)
    connect(right, exit_block)

    function = Function([entry, left, right, exit_block])

    assert component_names(compute_strongly_connected_components(function)) == {
        frozenset({"entry"}),
        frozenset({"left", "right"}),
        frozenset({"exit"}),
    }


def test_strongly_connected_components_handle_disconnected_graphs():
    entry = Block("entry")
    terminal = Block("terminal")
    isolated = Block("isolated")
    cycle_a = Block("cycle_a")
    cycle_b = Block("cycle_b")
    cycle_c = Block("cycle_c")

    connect(entry, terminal)
    connect(cycle_a, cycle_b)
    connect(cycle_b, cycle_c)
    connect(cycle_c, cycle_a)

    function = Function([entry, terminal, isolated, cycle_a, cycle_b, cycle_c])

    assert component_names(compute_strongly_connected_components(function)) == {
        frozenset({"entry"}),
        frozenset({"terminal"}),
        frozenset({"isolated"}),
        frozenset({"cycle_a", "cycle_b", "cycle_c"}),
    }


def test_irreducible_loop_is_scc_not_covered_by_natural_loop():
    entry = Block("entry")
    left = Block("left")
    right = Block("right")
    exit_block = Block("exit")

    connect(entry, left)
    connect(entry, right)
    connect(left, right)
    connect(right, left)
    connect(right, exit_block)

    function = Function([entry, left, right, exit_block])

    assert compute_irreducible_loops(function) == [{left, right}]


def test_three_block_multi_entry_scc_is_irreducible():
    entry = Block("entry")
    first = Block("first")
    second = Block("second")
    third = Block("third")
    exit_block = Block("exit")

    connect(entry, first)
    connect(entry, second)
    connect(first, second)
    connect(second, third)
    connect(third, first)
    connect(third, exit_block)

    function = Function([entry, first, second, third, exit_block])

    assert component_names(compute_irreducible_loops(function)) == {
        frozenset({"first", "second", "third"})
    }


def test_mixed_reducible_and_irreducible_loops_report_only_irreducible_scc():
    entry = Block("entry")
    natural_header = Block("natural_header")
    natural_body = Block("natural_body")
    join = Block("join")
    irreducible_a = Block("irreducible_a")
    irreducible_b = Block("irreducible_b")
    irreducible_c = Block("irreducible_c")
    exit_block = Block("exit")

    connect(entry, natural_header)
    connect(natural_header, natural_body)
    connect(natural_body, natural_header, back_edge=True)
    connect(natural_header, join)
    connect(join, irreducible_a)
    connect(join, irreducible_b)
    connect(irreducible_a, irreducible_b)
    connect(irreducible_b, irreducible_c)
    connect(irreducible_c, irreducible_a)
    connect(irreducible_c, exit_block)
    natural_header.dominance_frontier.add(natural_header)

    function = Function(
        [
            entry,
            natural_header,
            natural_body,
            join,
            irreducible_a,
            irreducible_b,
            irreducible_c,
            exit_block,
        ]
    )

    assert compute_blocks_in_natural_loops(function) == {natural_header, natural_body}
    assert component_names(compute_irreducible_loops(function)) == {
        frozenset({"irreducible_a", "irreducible_b", "irreducible_c"})
    }


def test_disconnected_cycle_without_natural_loop_metadata_is_irreducible():
    entry = Block("entry")
    terminal = Block("terminal")
    cycle_a = Block("cycle_a")
    cycle_b = Block("cycle_b")

    connect(entry, terminal)
    connect(cycle_a, cycle_b)
    connect(cycle_b, cycle_a)

    function = Function([entry, terminal, cycle_a, cycle_b])

    assert component_names(compute_irreducible_loops(function)) == {
        frozenset({"cycle_a", "cycle_b"})
    }


def test_reducible_natural_loop_is_not_irreducible():
    entry = Block("entry")
    header = Block("header")
    body = Block("body")
    exit_block = Block("exit")

    connect(entry, header)
    connect(header, body)
    connect(body, header, back_edge=True)
    connect(header, exit_block)
    header.dominance_frontier.add(header)

    function = Function([entry, header, body, exit_block])

    assert compute_irreducible_loops(function) == []

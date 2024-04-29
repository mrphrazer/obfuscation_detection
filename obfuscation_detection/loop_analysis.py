from collections import namedtuple
from functools import reduce


def compute_number_of_natural_loops(function):
    return sum((1 for _ in compute_natural_loop_back_edges(function)))


def compute_natural_loop_back_edges(function):
    for block in function.basic_blocks:
        # block in its own dominance frontier => loop entry
        if block not in block.dominance_frontier:
            continue
        # filter back edges
        for edge in block.incoming_edges:
            if edge.back_edge:
                yield edge


def compute_natural_loop_body(back_edge):
    # initialize loop body
    loop_body = set([back_edge.target, back_edge.source])
    # initialize worklist
    todo = [back_edge.source]
    while todo:
        block = todo.pop()
        # walk over edges
        for edge in block.incoming_edges:
            # don't walk beyond loop entry
            if edge.source == back_edge.target:
                continue
            # add to loop body
            if edge.source not in loop_body:
                loop_body.add(edge.source)
                todo.append(edge.source)
    return loop_body


def compute_natural_loops(function):
    return {back_edge: compute_natural_loop_body(back_edge)
            for back_edge in compute_natural_loop_back_edges(function)}


def compute_blocks_in_natural_loops(function):
    return reduce(
        lambda x, y: x | y, (v for v in compute_natural_loops(
            function).values()),
        set()
    )


def compute_strongly_connected_components(function):
    """
    Partitions the graph into strongly connected components.

    Iterative implementation of Gabow's path-based SCC algorithm.

    Algorithm adapted from the miasm reverse enginerring framework: 
    https://github.com/cea-sec/miasm/blob/master/miasm/core/graph.py
    """
    stack = []
    boundaries = []
    counter = len(function.basic_blocks)

    # init index with 0
    index = {b: 0 for b in function.basic_blocks}

    # state machine for worklist algorithm
    VISIT, HANDLE_RECURSION, MERGE = 0, 1, 2
    BlockState = namedtuple('BlockState', ['state', 'block'])

    for block in function.basic_blocks:
        # next block if block was already visited
        if index[block]:
            continue

        todo = [BlockState(VISIT, block)]
        done = set()

        while todo:
            current = todo.pop()

            if current.block in done:
                continue

            # block is unvisited
            if current.state == VISIT:
                stack.append(current.block)
                index[current.block] = len(stack)
                boundaries.append(index[current.block])

                todo.append(BlockState(MERGE, current.block))
                # follow successors
                for edge in current.block.outgoing_edges:
                    todo.append(BlockState(HANDLE_RECURSION, edge.target))

            # iterative handling of recursion algorithm
            elif current.state == HANDLE_RECURSION:
                # visit unvisited successor
                if index[current.block] == 0:
                    todo.append(BlockState(VISIT, current.block))
                else:
                    # contract cycle if necessary
                    while index[current.block] < boundaries[-1]:
                        boundaries.pop()

            # merge strongly connected component
            else:
                if index[current.block] == boundaries[-1]:
                    boundaries.pop()
                    counter += 1
                    scc = set()

                    while index[current.block] <= len(stack):
                        popped = stack.pop()
                        index[popped] = counter
                        scc.add(popped)

                        done.add(current.block)

                    yield scc


def scc_is_loop(scc):
    # strongly connected component is loop if it contains more than one element or an back edge
    return len(scc) > 1 or any(edge.target == block for block in scc for edge in block.outgoing_edges)


def compute_irreducible_loops(function):
    # get all basic blocks that are part of natural loops
    blocks_in_natural_loops = compute_blocks_in_natural_loops(function)
    # if an scc is a loop and a block in scc is not part of a natural loop => irreducible loop
    return [
        scc for scc in compute_strongly_connected_components(function)
        if scc_is_loop(scc) and not scc.issubset(blocks_in_natural_loops)
    ]

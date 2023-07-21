from functools import reduce


def compute_number_of_loops(function):
    return sum((1 for b in function.basic_blocks if b in b.dominance_frontier))


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


def compute_blocks_in_loops(function):
    return reduce(
        lambda x, y: x | y, (v for v in compute_natural_loops(function).values()), 
        set()
        )
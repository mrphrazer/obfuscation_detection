from collections import Counter
from math import ceil


def calc_flattening_score(function):
    score = 0.0
    # 1: walk over all basic blocks
    for block in function.basic_blocks:
        # 2: get all blocks that are dominated by the current block
        dominated = get_dominated_by(block)
        # 3: check for a back edge
        if not any((edge.source in dominated for edge in block.incoming_edges)):
            continue
        # 4: calculate relation of dominated blocks to the blocks in the graph
        score = max(score, len(dominated)/len(function.basic_blocks))
    return score


def get_dominated_by(dominator):
    # 1: initialize worklist
    result = set()
    # add to result
    worklist = [dominator]
    # 2: perform a depth-first search on the dominator tree
    while worklist:
        # get next block
        block = worklist.pop(0)
        result.add(block)
        # add children from dominator tree to worklist
        for child in block.dominator_tree_children:
            worklist.append(child)
    return result


def calc_cyclomatic_complexity(function):
    # number of basic blocks
    num_blocks = len(function.basic_blocks)
    # number of edges in the graph
    num_edges = sum((len(b.outgoing_edges) for b in function.basic_blocks))
    return num_edges - num_blocks + 2


def calc_average_instructions_per_block(function):
    # number of basic blocks
    num_blocks = len(function.basic_blocks)
    # number of instructions
    num_instructions = sum(
        (b.instruction_count for b in function.basic_blocks))
    return num_instructions / num_blocks


def get_top_10_functions(functions, scoring_function):
    # sort functions by scoring function
    sorted_functions = sorted(((f, scoring_function(f))
                              for f in functions), key=lambda x: x[1])
    # bound to locate the top 10%
    bound = bound = ceil(((len(functions) * 10) / 100))
    # yield top 10% (iterate in descending order)
    for function, score in list(reversed(sorted_functions))[:bound]:
        yield function, score

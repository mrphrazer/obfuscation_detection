from collections import Counter
from math import ceil

from .ngrams import MOST_COMMON_3GRAMS


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


def sliding_window(l, window_size):
    # yiels all sliding windows of size `window_size` for a given list
    for index in range(len(l) - window_size + 1):
        yield l[index:index + window_size]


def calc_ngrams(function, n):
    def get_opcode(instruction):
        # ensure instruction has opcode
        if len(instruction) == 0 or len(instruction[0]) == 0:
            return ""
        return str(instruction[0][0]).replace(" ", "")
    # fetch instruction opcodes sorted by the instructions' address
    opcodes_sorted = [get_opcode(instruction) for instruction in sorted(
        function.instructions, key=lambda x: int(x[1]))]
    # calculate all n-grams
    grams_n = Counter(["".join(w) for w in sliding_window(opcodes_sorted, n)])
    return grams_n


def calc_global_ngrams(bv, n):
    # compute instruction ngrams of all functions
    global_grams_n = Counter()
    for f in bv.functions:
        # join function ngrams in glocal Counter
        global_grams_n.update(calc_ngrams(f, n))
    return global_grams_n


def calc_uncommon_instruction_sequences_score(function):
    # calculate all 3-grams in the function
    function_ngrams = calc_ngrams(function, 3)
    # heuristic to avoid overfitting to small function stubs
    if function_ngrams.total() < 5:
        return 0.0
    # count the number of ngrams in the function which are not in MOST_COMMON_3GRAMS
    count = sum((value for gram, value in function_ngrams.items()
                if gram not in MOST_COMMON_3GRAMS))
    # average relative to the amount of ngrams in the functions
    score = count / function_ngrams.total()
    return score


def get_top_10_functions(functions, scoring_function):
    # sort functions by scoring function
    sorted_functions = sorted(((f, scoring_function(f))
                              for f in functions), key=lambda x: x[1])
    # bound to locate the top 10%
    bound = bound = ceil(((len(functions) * 10) / 100))
    # yield top 10% (iterate in descending order)
    for function, score in list(reversed(sorted_functions))[:bound]:
        yield function, score

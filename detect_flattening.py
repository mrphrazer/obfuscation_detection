#!/usr/bin/python
import sys
from binaryninja import BinaryViewType


def calc_flattening_score(function):
    score = 0.0
    # 1: walk over all basic blocks
    for block in function.basic_blocks:
        # 2: get all blocks that are dominated by the current block
        dominated = get_dominated_by(block)
        # 3: check for a back edge
        if not any([edge.source in dominated for edge in block.incoming_edges]):
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


def find_flattened_functions():
    # walk over all functions
    for function in bv.functions:
        # calculate flattening score
        score = calc_flattening_score(function)
        # skip if score is too low
        if score < 0.9:
            # print(f"Function {hex(function.start)} has a flattening score of {score}.")
            continue

        # print function and score
        print(
            f"Function {hex(function.start)} has a flattening score of {score}.")


# check file arguments
if len(sys.argv) < 2:
    print("[*] Syntax: {} <path to binary>".format(sys.argv[0]))
    exit(0)

# parse arguments
file_name = sys.argv[1]

# init binary ninja
bv = BinaryViewType.get_view_of_file(file_name)
if not file_name.endswith(".bndb"):
    bv.update_analysis_and_wait()

# find flattened functions
find_flattened_functions()

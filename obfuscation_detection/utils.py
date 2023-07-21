from collections import Counter
from math import ceil

from binaryninja.enums import LowLevelILOperation

from .ngrams import determine_ngram_database
from .loop_analysis import compute_blocks_in_loops, compute_number_of_loops


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
        score = max(score, len(dominated) / len(function.basic_blocks))
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
    # number of basic blocks -- set to 1 if 0
    num_blocks = max(1, len(function.basic_blocks))
    # number of instructions
    num_instructions = sum(
        (b.instruction_count for b in function.basic_blocks))
    return num_instructions / num_blocks




def computes_xor_const(llil_instr):
    """Checks an LLIL instruction for the pattern x ^ const"""
    # check for instruction pattern: dst := src ^ const
    # check for dst = <...>
    if len(llil_instr.operands) != 2:
        return False
    # check if rhs has attribute 'operation'
    if not hasattr(llil_instr.operands[1], 'operation'):
        return False
    # check for a xor operation
    if llil_instr.operands[1].operation == LowLevelILOperation.LLIL_XOR:
        # check if one operand is a constant
        if any((op.operation == LowLevelILOperation.LLIL_CONST for op in llil_instr.operands[1].operands)):
            return True
    return False


def contains_xor_decryption_loop(bv, function, xor_check=computes_xor_const):
    # walk over all blocks which are part of a loop
    for block in compute_blocks_in_loops(function):
        # walk over all instructions
        addr = block.start
        while addr < block.end:
            # get lifted IL
            llil_instr = function.arch.get_instruction_low_level_il_instruction(bv, addr)
            # checks for a specific xor characteristic
            if xor_check(llil_instr):
                return True
            # compute next address
            addr += bv.get_instruction_length(addr)
    return False


def find_rc4_ksa(bv, function):
    # function has two natural loops
    if not compute_number_of_loops(function) == 2:
        return False
    # contains at least once the constant 0x100
    for instr in function.instructions:
        llil_instr = function.arch.get_instruction_low_level_il_instruction(bv, instr[1])
        if any(c == 0x100 for c in get_llil_constants(llil_instr)):
            return True
    return False


def find_rc4_prga(bv, function):
    """
    Tries to identify RC4-based PRGA implementations 
    by checking for specific xor instructions in a loop
    """
    return contains_xor_decryption_loop(bv, function, xor_check=computes_rc4_xor)


def computes_rc4_xor(llil_instr):
    """
    Checks for XOR variants commonly found in RC4:
    1. bytewise xor
    2. no constants as operands
    3. different operands
    """
    # check for instruction pattern: dst := src ^ const
    # check for dst = <...>
    if len(llil_instr.operands) != 2:
        return False
    # check if rhs has attribute 'operation'
    if not hasattr(llil_instr.operands[1], 'operation'):
        return False
    # checks if its a byte operation
    if not llil_instr.size == 1:
        return False
    # check for a xor operation
    if llil_instr.operands[1].operation == LowLevelILOperation.LLIL_XOR:
        # does not use constants
        if any((op.operation == LowLevelILOperation.LLIL_CONST for op in llil_instr.operands[1].operands)):
            return False
        # operands are different (no initialization with 0)
        if llil_instr.operands[1].operands[0].src == llil_instr.operands[1].operands[1].src:
            return False
        return True
    return False


def get_llil_constants(llil_instr):
    """Yields all constants in LLIL expressions"""
    worklist = [llil_instr]
    # iteratively walk over all operands
    while len(worklist) != 0:
        # pop from worklist
        llil_instr = worklist.pop()
        if not hasattr(llil_instr, 'operation'):
            continue
        # check if constant
        if llil_instr.operation == LowLevelILOperation.LLIL_CONST:
            yield llil_instr.constant
        # add operands to worklist
        for op in llil_instr.operands:
            worklist.append(op)


def sliding_window(l, window_size):
    # yiels all sliding windows of size `window_size` for a given list
    for index in range(len(l) - window_size + 1):
        yield l[index:index + window_size]


def calc_ngrams(function, n, use_llil):
    def get_opcode_from_disassembly(instruction):
        """Return the opcode of an assembly instruction"""
        # ensure instruction has opcode
        if len(instruction) == 0 or len(instruction[0]) == 0:
            return ""
        # return instruction mnemomic
        return str(instruction[0][0]).replace(" ", "")

    def get_opcode_from_llil(instr):
        """Returns the opcode of an LLIL instruction"""
        # for register assignments, check opcode
        if instr.operation == LowLevelILOperation.LLIL_SET_REG:
            # return LLIL_SET_REG is RHS is a constant or register (terminal)
            if instr.src.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR,
                                       LowLevelILOperation.LLIL_REG]:
                return str(instr.operation)
            # return operator of RHS
            return str(instr.src.operation)
        return str(instr.operation)

    # if function too complex, return empty counter
    if function.analysis_skipped:
        return Counter()

    # count opcodes either on LLIL or assembly level
    if use_llil:
        # fetch llil opcodes sorted by the instructions' address
        opcodes_sorted = [get_opcode_from_llil(instruction) for instruction in sorted(
            function.llil_instructions, key=lambda x: int(x.address))]
    else:
        # fetch instruction opcodes sorted by the instructions' address
        opcodes_sorted = [get_opcode_from_disassembly(instruction) for instruction in sorted(
            function.instructions, key=lambda x: int(x[1]))]

    # calculate all n-grams
    grams_n = Counter(["".join(w) for w in sliding_window(opcodes_sorted, n)])
    return grams_n


def calc_global_ngrams(bv, n, use_llil):
    # compute instruction ngrams of all functions
    global_grams_n = Counter()
    for f in bv.functions:
        # join function ngrams in global Counter
        global_grams_n.update(calc_ngrams(f, n, use_llil=use_llil))
    return global_grams_n


def calc_uncommon_instruction_sequences_score(function):
    # determine ngram database based on function's architecture
    use_llil, ngram_database = determine_ngram_database(function.arch)
    # calculate all 3-grams in the function
    function_ngrams = calc_ngrams(function, 3, use_llil=use_llil)
    # heuristic to avoid overfitting to small function stubs
    if sum(function_ngrams.values()) < 5:
        return 0.0
    # count the number of ngrams in the function which are not in MOST_COMMON_3GRAMS
    count = sum((value for gram, value in function_ngrams.items()
                 if gram not in ngram_database))
    # average relative to the amount of ngrams in the functions
    score = count / sum(function_ngrams.values())
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

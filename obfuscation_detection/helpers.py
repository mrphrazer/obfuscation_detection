from collections import Counter
from hashlib import md5
from math import ceil, log2

from binaryninja import highlevelil
from binaryninja.enums import HighLevelILOperation, LowLevelILOperation

from .loop_analysis import (compute_blocks_in_natural_loops,
                            compute_number_of_natural_loops)
from .ngrams import determine_ngram_database

# initialize operations
ARITHMETIC_OPERATION = set([
    HighLevelILOperation.HLIL_ADD,
    HighLevelILOperation.HLIL_NEG,
    HighLevelILOperation.HLIL_SUB,
    HighLevelILOperation.HLIL_MUL,
    HighLevelILOperation.HLIL_DIVS,
    HighLevelILOperation.HLIL_MODS,
])

BOOLEAN_OPERATION = set([
    HighLevelILOperation.HLIL_NOT,
    HighLevelILOperation.HLIL_AND,
    HighLevelILOperation.HLIL_OR,
    HighLevelILOperation.HLIL_XOR,
    HighLevelILOperation.HLIL_LSR,
    HighLevelILOperation.HLIL_LSL
])


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


def block_is_in_loop(block):
    # a block is in a natural loop if it is in its own dominance frontier
    return block in block.dominance_frontier


def computes_xor_const(llil_instr):
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
    for block in compute_blocks_in_natural_loops(function):
        # walk over all instructions
        addr = block.start
        while addr < block.end:
            # get lifted IL
            llil_instr = function.arch.get_instruction_low_level_il_instruction(
                bv, addr)
            # checks for a specific xor characteristic
            if xor_check(llil_instr):
                return True
            # compute next address
            addr += bv.get_instruction_length(addr)
    return False


def find_rc4_ksa(bv, function):
    """
    Tries to identify implementations of RC4's key scheduling algorihm (KSA)

    It checks if a function 
    - has at two loops
    - contains the constant 0x100.
    """
    # function has at least two natural loops
    if compute_number_of_natural_loops(function) != 2:
        return False
    # contains at least once the constant 0x100
    for instr in function.instructions:
        llil_instr = function.arch.get_instruction_low_level_il_instruction(
            bv, instr[1])
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


def compute_local_signature(basic_block):
    """
    Compute a simple, opcode-based signature for a single basic block.

    In many real-world scenarios, this opcode-based approach is
    sufficiently effective and offers good performance. If needed, this step can 
    be extended with more advanced normalization techniques (e.g., fuzzy hashing,
    register renaming).
    """
    return "".join(get_opcode_from_disassembly(instr) for instr in basic_block)


def compute_context_signatures(function, num_iterations):
    """
    Iteratively compute 'context signatures' for each basic block in 'function'
    up to a specified depth (num_iterations).

    ALGORITHM OVERVIEW:
    -------------------
    1) Local Signatures (Iteration 0):
       - First, we compute a 'local signature' for each basic block by looking at
         that block's instructions alone. This can be done in any manner:
         e.g., naive opcode concatenation, fuzzy hashing, or IR-based hashing.

    2) Context Signatures (Iterations 1..n):
       - For each iteration i in [1..num_iterations]:
         - For each block b, gather the previous iteration's context signature of b,
           plus the context signatures of b's successors (sorted to avoid ordering
           differences).
         - Concatenate them into a single string, then optionally hash it (e.g., MD5).
         - This becomes the new context signature for iteration i.

       - Each round includes more of the CFG neighborhood, so after i iterations,
         a block's context signature reflects up to i levels of successors.

    3) Loops and Fixed Depth:
       - In the presence of loops, we do NOT attempt to keep iterating until a
         full fixpoint. Instead, we use a fixed num_iterations. Blocks thus describe
         their 'context' to a depth of n. For detecting stable signatures, one could
         iteratively check for convergence, but a fixed depth is often sufficient.

    4) Output:
       - Returns a dictionary mapping each basic block to its final context signature
         after num_iterations.

    Why it works:
    -------------
    - If two blocks share identical local code and identical structure (and code) of
      their successors up to depth n, they will end up with the same context signature.
    - This helps reveal repeated subgraphs or code patterns within the same function.
    """

    # compute local (base) signatures for all blocks
    local_signatures = {}
    for bb in function.basic_blocks:
        local_signatures[bb] = compute_local_signature(bb)

    # for iteration 0, the context signatures are just the local signatures
    context_signatures = local_signatures.copy()

    # iterative context hashing
    for _ in range(num_iterations):
        new_context_signatures = {}

        for bb in function.basic_blocks:
            # gather the (current) context signatures of all successors
            succ_sigs = [context_signatures[outgoing_edge.target]
                         for outgoing_edge in bb.outgoing_edges]
            # sort the successor signatures to ensure a canonical order
            succ_sigs.sort()

            # combine this block's context signature with its successors' signatures
            combined = context_signatures[bb] + "|" + "|".join(succ_sigs)

            # hash the combined string to produce the new signature
            new_sig = md5(combined.encode()).hexdigest()

            new_context_signatures[bb] = new_sig

        # update our context signatures for the next iteration
        context_signatures = new_context_signatures

    return context_signatures


def count_context_signature_duplicates(function, num_iterations=2):
    """
    Compute context signatures for each basic block after 'num_iterations' rounds,
    then count how many basic blocks/subgraphs share the same final signature.

    Duplicates indicate repeated substructures or patterns within the CFG.

    RETURN:
      An integer count of how many blocks are 'duplicates' — i.e., how many blocks
      do NOT have a unique signature. If 5 total blocks share only 3 unique signatures,
      then (5 - 3) = 2 blocks are duplicates of something else.
    """
    final_signatures = compute_context_signatures(function, num_iterations)

    # each block has exactly one final signature in this dict.
    num_blocks = len(final_signatures)

    # convert to a set to see how many distinct signatures we have
    unique_signatures = set(final_signatures.values())
    num_unique_signatures = len(unique_signatures)

    # the number of duplicates is the difference
    duplicates = num_blocks - num_unique_signatures
    return duplicates


def calc_ngrams(function, n, use_llil):
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


def uses_mixed_boolean_arithmetic(hlil_instruction):
    # initialize
    global ARITHMETIC_OPERATION, BOOLEAN_OPERATION
    uses_boolean = False
    uses_arithmetic = False
    ins_stack = [hlil_instruction]

    # worklist algorithm
    while len(ins_stack) != 0:
        instruction = ins_stack.pop()
        # check if boolean or arithmetic operation
        if isinstance(instruction, highlevelil.HighLevelILInstruction):
            # arithmetic operation
            if instruction.operation in ARITHMETIC_OPERATION:
                uses_arithmetic = True
            # boolean operation
            elif instruction.operation in BOOLEAN_OPERATION:
                uses_boolean = True
            # mixed boolean arithmetic
            if uses_boolean and uses_arithmetic:
                return True
            # add operands to worklist
            for op in instruction.operands:
                ins_stack.append(op)
    return False


def calculate_complex_arithmetic_expressions(function):
    # check if the hlil has been generated for the function
    if function.hlil_if_available == None:
        return 0
    # init mba counter
    instr_mba = 0
    # iterate hlil instructions
    for ins in function.hlil_if_available.instructions:
        # if an expression has a boolean and an arithmetic operation, the expression has some arithmetic complexity
        if uses_mixed_boolean_arithmetic(ins):
            instr_mba += 1
    return instr_mba


def calculate_entropy(data):
    # count byte occurrences and calculate total bytes
    byte_count = Counter(data)
    total_bytes = len(data)

    # calculate entropy using the counted byte occurrences
    entropy = 0.0
    for count in byte_count.values():
        # calculate byte probability and update entropy
        probability = count / total_bytes
        entropy -= probability * log2(probability)

    return entropy


def get_top_10_functions(functions, scoring_function):
    # sort functions by scoring function
    sorted_functions = sorted(((f, scoring_function(f))
                               for f in functions), key=lambda x: x[1])
    # bound to locate the top 10%, but 10 minimum, 1k maximum
    bound = max(min(ceil(((len(functions) * 10) / 100)), 1000), 10)
    # yield top 10% (iterate in descending order)
    for function, score in list(reversed(sorted_functions))[:bound]:
        yield function, score


def sort_elements(iterator, scoring_function):
    # sort elements by scoring function
    sorted_elements = sorted(((elem, scoring_function(elem))
                              for elem in iterator), key=lambda x: x[1])
    # yield in descending order
    for element, score in list(reversed(sorted_elements)):
        yield element, score

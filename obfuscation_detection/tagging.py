# consistent icon for all heuristic tag types
HEURISTIC_TAG_ICON = "🏷️"

TAG_COMPLEX_ARITHMETIC_EXPRESSION = "Heuristic: Complex Arithmetic Expression"
TAG_COMPLEX_FUNCTION = "Heuristic: Complex Function"
TAG_STATE_MACHINE = "Heuristic: State Machine"
TAG_DUPLICATE_SUBGRAPH = "Heuristic: Duplicate Subgraph"
TAG_ENTRY_FUNCTION = "Heuristic: Entry Function"
TAG_IRREDUCIBLE_LOOP = "Heuristic: Irreducible Loop"
TAG_LARGE_BASIC_BLOCK = "Heuristic: Large Basic Block"
TAG_LEAF_FUNCTION = "Heuristic: Leaf Function"
TAG_LOOP_FREQUENCY = "Heuristic: Loop Frequency"
TAG_MOST_CALLED_FUNCTION = "Heuristic: Most Called Function"
TAG_OVERLAPPING_INSTRUCTION = "Heuristic: Overlapping Instruction"
TAG_RC4_KSA = "Heuristic: RC4 KSA"
TAG_RC4_PRGA = "Heuristic: RC4 PRGA"
TAG_RECURSIVE_FUNCTION = "Heuristic: Recursive Function"
TAG_UNCOMMON_INSTRUCTION_SEQUENCE = "Heuristic: Uncommon Instruction Sequence"
TAG_XOR_DECRYPTION_LOOP = "Heuristic: XOR Decryption Loop"

TAG_DESC_COMPLEX_ARITHMETIC_EXPRESSION = "num_mba_instructions: {score} | may indicate: mixed-boolean-arithmetic obfuscation, crypto"
TAG_DESC_COMPLEX_FUNCTION = "cyclomatic_complexity: {score} | may indicate: complex protocols, state machines, opaque predicates"
TAG_DESC_STATE_MACHINE = "state_machine_score: {score:.2f} | may indicate: control-flow flattening, state machines, dispatcher loops, C&C dispatching"
TAG_DESC_DUPLICATE_SUBGRAPH = "num_duplicate_subgraphs: {score} | may indicate: cloned obfuscation stubs, unrolled loops, decision trees"
TAG_DESC_ENTRY_FUNCTION = (
    "no known callers | may indicate: entry point, indirect jump target"
)
TAG_DESC_IRREDUCIBLE_LOOP = "num_irreducible_loops: {score} | may indicate: hand-written assembly, aggressive compiler optimizations, obfuscation"
TAG_DESC_LARGE_BASIC_BLOCK = "avg_instructions_per_block: {score} | may indicate: unrolled code, crypto, arithmetic obfuscation"
TAG_DESC_LEAF_FUNCTION = (
    "no known callees | may indicate: outlined functions, trampolines, obfuscation"
)
TAG_DESC_LOOP_FREQUENCY = (
    "num_loops: {score} | may indicate: complex parsing, intensive algorithms"
)
TAG_DESC_MOST_CALLED_FUNCTION = "num_callers: {score} | may indicate: string decryption routines, statically linked library functions"
TAG_DESC_OVERLAPPING_INSTRUCTION = "may indicate: broken disassembly, opaque predicates"
TAG_DESC_RC4_KSA = "may indicate: RC4 key scheduling"
TAG_DESC_RC4_PRGA = "may indicate: RC4 pseudo-random generation"
TAG_DESC_RECURSIVE_FUNCTION = (
    "self-recursive | may indicate: recursion, graph/tree traversal, obfuscation"
)
TAG_DESC_UNCOMMON_INSTRUCTION_SEQUENCE = "uncommon_sequences_score: {score} | may indicate: crypto, arithmetic obfuscation, floating point arithmetic"
TAG_DESC_XOR_DECRYPTION_LOOP = (
    "may indicate: string decryption, code decryption stubs, crypto"
)

LEGACY_TAG_TYPE_NAMES = {
    TAG_STATE_MACHINE: ("Heuristic: Control Flow Flattening",),
    TAG_RC4_KSA: ("Heuristic: RC4-KSA",),
    TAG_RC4_PRGA: ("Heuristic: RC4-PRGA",),
}


def get_or_create_tag_type(bv, name):
    """Get existing tag type or create it."""
    if name not in bv.tag_types:
        bv.create_tag_type(name, HEURISTIC_TAG_ICON)


def tag_function(bv, function, tag_type_name, data=""):
    """Tag a function with a heuristic tag type."""
    get_or_create_tag_type(bv, tag_type_name)
    function.add_tag(tag_type_name, data)


def clear_heuristic_tags(bv, tag_type_name):
    """Remove all function tags of a given type before re-running."""
    tag_type_names = (tag_type_name, *LEGACY_TAG_TYPE_NAMES.get(tag_type_name, ()))
    for current_tag_type_name in tag_type_names:
        if current_tag_type_name not in bv.tag_types:
            continue
        for f in bv.functions:
            f.remove_user_function_tags_of_type(current_tag_type_name)

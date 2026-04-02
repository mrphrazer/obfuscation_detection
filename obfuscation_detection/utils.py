from .helpers import *


def find_entry_functions(bv):
    print("=" * 80)
    print("Functions without callers:")
    clear_heuristic_tags(bv, "Heuristic: Entry Function")

    for f in bv.functions:
        if len(f.callers) != 0:
            continue

        print(
            f"Function {hex(f.start)} ({(f.name)}) has no known callers.")
        tag_function(bv, f, "Heuristic: Entry Function", "no known callers | may indicate: entry point, indirect jump target")


def find_leaf_functions(bv):
    print("=" * 80)
    print("Functions without callees:")
    clear_heuristic_tags(bv, "Heuristic: Leaf Function")

    for f in bv.functions:
        # no callees and at least two instructions
        if len(f.callees) == 0 and sum(1 for _ in f.instructions) > 1:
            print(
                f"Function {hex(f.start)} ({(f.name)}) has no known callees.")
            tag_function(bv, f, "Heuristic: Leaf Function", "no known callees | may indicate: outlined functions, trampolines, obfuscation")


def find_recursive_functions(bv):
    print("=" * 80)
    print("Recursive functions:")
    clear_heuristic_tags(bv, "Heuristic: Recursive Function")

    for f in bv.functions:
        # no callees and at least two instructions
        if f in f.callees:
            print(
                f"Function {hex(f.start)} ({(f.name)}) is recursive.")
            tag_function(bv, f, "Heuristic: Recursive Function", "potential self-recursive")


def compute_section_entropy(bv):
    print("=" * 80)
    print("Sections and their entropy:")

    # compute section entropies
    section_entropies = {
        section: calculate_entropy(bv.read(section.start, section.length))
        for section in bv.sections.values()
    }
    for section, score in sort_elements(section_entropies.keys(), lambda x: section_entropies[x]):
        print(f"Section {section.name} has an entropy of {score:.2f}.")


def find_rc4(bv):
    print("=" * 80)
    print("Potential RC4 Implementations:")
    clear_heuristic_tags(bv, "Heuristic: RC4-KSA")
    clear_heuristic_tags(bv, "Heuristic: RC4-PRGA")

    for f in bv.functions:
        if find_rc4_ksa(bv, f):
            print(
                f"Function {f.name} ({hex(f.start)}) might implement RC4-KSA.")
            tag_function(bv, f, "Heuristic: RC4-KSA", "potential RC4 key scheduling")
        if find_rc4_prga(bv, f):
            print(
                f"Function {f.name} ({hex(f.start)}) might implement RC4-PRGA.")
            tag_function(bv, f, "Heuristic: RC4-PRGA", "potential RC4 PRGA")

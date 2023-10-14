from .helpers import *


def find_entry_functions(bv):
    print("=" * 80)
    print("Functions without callers:")

    for f in bv.functions:
        if len(f.callers) != 0:
            continue

        print(
            f"Function {hex(f.start)} ({(f.name)}) has no known callers.")


def find_leaf_functions(bv):
    print("=" * 80)
    print("Functions without callees:")

    for f in bv.functions:
        # no callees and at least two instructions
        if len(f.callees) == 0 and sum(1 for _ in f.instructions) > 1:
            print(
                f"Function {hex(f.start)} ({(f.name)}) has no known callees.")


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

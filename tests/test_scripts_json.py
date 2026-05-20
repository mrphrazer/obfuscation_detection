import json
from types import SimpleNamespace

import scripts.detect_state_machine as detect_state_machine
import scripts.detect_obfuscation as detect_obfuscation
from obfuscation_detection import reports
from obfuscation_detection.tagging import (
    TAG_COMPLEX_FUNCTION,
    TAG_STATE_MACHINE,
    TAG_DESC_ENTRY_FUNCTION,
    TAG_DESC_COMPLEX_FUNCTION,
    TAG_DESC_STATE_MACHINE,
    TAG_DESC_XOR_DECRYPTION_LOOP,
    TAG_ENTRY_FUNCTION,
    TAG_XOR_DECRYPTION_LOOP,
)


class BinaryView:
    pass


def test_collect_reports_uses_stable_detection_ids(monkeypatch):
    report_helpers = [
        "find_state_machine_reports",
        "find_complex_function_reports",
        "find_large_basic_block_reports",
        "find_uncommon_instruction_sequence_reports",
        "find_instruction_overlapping_reports",
        "find_most_called_function_reports",
        "find_loop_frequency_reports",
        "find_irreducible_loop_reports",
        "find_xor_decryption_loop_reports",
        "find_complex_arithmetic_expression_reports",
        "find_duplicate_subgraph_reports",
        "find_entry_function_reports",
        "find_leaf_function_reports",
        "find_recursive_function_reports",
        "find_section_entropy_reports",
        "find_rc4_ksa_reports",
        "find_rc4_prga_reports",
    ]
    for helper_name in report_helpers:
        monkeypatch.setattr(reports, helper_name, lambda _bv: [])

    detections = reports.collect_heuristics_and_utils_reports(BinaryView())

    assert [(detection["id"], detection["name"]) for detection in detections] == [
        ("state_machine", "State Machine"),
        ("complex_function", "Complex Function"),
        ("large_basic_block", "Large Basic Block"),
        ("uncommon_instruction_sequence", "Uncommon Instruction Sequence"),
        ("overlapping_instruction", "Overlapping Instruction"),
        ("most_called_function", "Most Called Function"),
        ("loop_frequency", "Loop Frequency"),
        ("irreducible_loop", "Irreducible Loop"),
        ("xor_decryption_loop", "XOR Decryption Loop"),
        ("complex_arithmetic_expression", "Complex Arithmetic Expression"),
        ("duplicate_subgraph", "Duplicate Subgraph"),
        ("entry_function", "Entry Function"),
        ("leaf_function", "Leaf Function"),
        ("recursive_function", "Recursive Function"),
        ("section_entropy", "Section Entropy"),
        ("rc4_ksa", "RC4 KSA"),
        ("rc4_prga", "RC4 PRGA"),
    ]


def test_detect_obfuscation_default_preserves_text_output(monkeypatch, capsys):
    bv = BinaryView()

    def fake_run_heuristics_and_utils(received_bv):
        assert received_bv is bv
        print("=" * 80)
        print("Complex Function")
        print("Function 0x1000 (main) has a cyclomatic complexity of 7.")

    monkeypatch.setattr(detect_obfuscation, "load_binary", lambda file_name: bv)
    monkeypatch.setattr(
        detect_obfuscation,
        "run_heuristics_and_utils",
        fake_run_heuristics_and_utils,
    )

    assert detect_obfuscation.main(["sample.bin"]) == 0

    assert capsys.readouterr().out == (
        "=" * 80
        + "\n"
        + "Complex Function\n"
        + "Function 0x1000 (main) has a cyclomatic complexity of 7.\n"
    )


def test_detect_obfuscation_json_emits_sectioned_findings(monkeypatch, capsys):
    bv = BinaryView()

    def fake_collect_heuristics_and_utils_reports(received_bv):
        assert received_bv is bv
        return [
            {
                "id": "complex_function",
                "name": "Complex Function",
                "findings": [
                    {
                        "address": "0x1000",
                        "name": "main",
                        "tag_type": TAG_COMPLEX_FUNCTION,
                        "description": TAG_DESC_COMPLEX_FUNCTION.format(score=7),
                        "cyclomatic_complexity": 7,
                    }
                ],
            },
            {
                "id": "xor_decryption_loop",
                "name": "XOR Decryption Loop",
                "findings": [
                    {
                        "address": "0x2000",
                        "name": "decode",
                        "tag_type": TAG_XOR_DECRYPTION_LOOP,
                        "description": TAG_DESC_XOR_DECRYPTION_LOOP,
                    }
                ],
            },
            {
                "id": "entry_function",
                "name": "Entry Function",
                "findings": [
                    {
                        "address": "0x3000",
                        "name": "start",
                        "tag_type": TAG_ENTRY_FUNCTION,
                        "description": TAG_DESC_ENTRY_FUNCTION,
                    }
                ],
            },
        ]

    monkeypatch.setattr(detect_obfuscation, "load_binary", lambda file_name: bv)
    monkeypatch.setattr(
        detect_obfuscation,
        "collect_heuristics_and_utils_reports",
        fake_collect_heuristics_and_utils_reports,
    )

    assert detect_obfuscation.main(["--json", "sample.bin"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "binary": "sample.bin",
        "detections": [
            {
                "id": "complex_function",
                "name": "Complex Function",
                "findings": [
                    {
                        "address": "0x1000",
                        "cyclomatic_complexity": 7,
                        "description": TAG_DESC_COMPLEX_FUNCTION.format(score=7),
                        "name": "main",
                        "tag_type": TAG_COMPLEX_FUNCTION,
                    }
                ],
            },
            {
                "id": "xor_decryption_loop",
                "name": "XOR Decryption Loop",
                "findings": [
                    {
                        "address": "0x2000",
                        "description": TAG_DESC_XOR_DECRYPTION_LOOP,
                        "name": "decode",
                        "tag_type": TAG_XOR_DECRYPTION_LOOP,
                    }
                ],
            },
            {
                "id": "entry_function",
                "name": "Entry Function",
                "findings": [
                    {
                        "address": "0x3000",
                        "description": TAG_DESC_ENTRY_FUNCTION,
                        "name": "start",
                        "tag_type": TAG_ENTRY_FUNCTION,
                    }
                ],
            },
        ],
    }


def test_detect_state_machine_json_emits_structured_function_fields(
    monkeypatch, capsys
):
    bv = BinaryView()

    def fake_find_state_machine_reports(received_bv):
        assert received_bv is bv
        return [
            {
                "address": "0x401000",
                "name": "dispatcher",
                "tag_type": TAG_STATE_MACHINE,
                "description": TAG_DESC_STATE_MACHINE.format(score=0.75),
                "state_machine_score": 0.75,
            }
        ]

    monkeypatch.setattr(detect_state_machine, "load_binary", lambda file_name: bv)
    monkeypatch.setattr(
        detect_state_machine,
        "find_state_machine_reports",
        fake_find_state_machine_reports,
    )

    assert detect_state_machine.main(["--json", "sample.bin"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "binary": "sample.bin",
        "heuristics": [
            {
                "id": "state_machine",
                "name": "State Machine",
                "findings": [
                    {
                        "address": "0x401000",
                        "name": "dispatcher",
                        "tag_type": TAG_STATE_MACHINE,
                        "description": TAG_DESC_STATE_MACHINE.format(score=0.75),
                        "state_machine_score": 0.75,
                    }
                ],
            }
        ],
    }


def test_detect_state_machine_help_uses_argparse(capsys):
    try:
        detect_state_machine.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

    assert "--json" in capsys.readouterr().out


def test_detect_state_machine_run_json_uses_real_report_helper(monkeypatch):
    function = SimpleNamespace(start=0x401000, name="dispatcher")
    bv = SimpleNamespace(functions=[function])
    monkeypatch.setattr(
        detect_state_machine,
        "find_state_machine_reports",
        lambda received_bv: (
            [
                {
                    "address": "0x401000",
                    "name": "dispatcher",
                    "tag_type": TAG_STATE_MACHINE,
                    "description": TAG_DESC_STATE_MACHINE.format(score=0.75),
                    "state_machine_score": 0.75,
                }
            ]
            if received_bv is bv
            else []
        ),
    )

    assert detect_state_machine.run_json(bv, "sample.bin")["heuristics"][0][
        "findings"
    ] == [
        {
            "address": "0x401000",
            "name": "dispatcher",
            "tag_type": TAG_STATE_MACHINE,
            "description": TAG_DESC_STATE_MACHINE.format(score=0.75),
            "state_machine_score": 0.75,
        }
    ]
    assert (
        detect_state_machine.run_json(bv, "sample.bin")["heuristics"][0]["id"]
        == "state_machine"
    )

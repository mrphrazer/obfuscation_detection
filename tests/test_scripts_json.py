import json
from types import SimpleNamespace

import scripts.detect_flattening as detect_flattening
import scripts.detect_obfuscation as detect_obfuscation


class BinaryView:
    pass


def test_detect_obfuscation_default_preserves_text_output(monkeypatch, capsys):
    bv = BinaryView()

    def fake_detect_obfuscation(received_bv):
        assert received_bv is bv
        print("=" * 80)
        print("Cyclomatic Complexity")
        print("Function 0x1000 (main) has a cyclomatic complexity of 7.")

    monkeypatch.setattr(detect_obfuscation, "load_binary", lambda file_name: bv)
    monkeypatch.setattr(
        detect_obfuscation, "detect_obfuscation", fake_detect_obfuscation
    )

    assert detect_obfuscation.main(["sample.bin"]) == 0

    assert capsys.readouterr().out == (
        "=" * 80
        + "\n"
        + "Cyclomatic Complexity\n"
        + "Function 0x1000 (main) has a cyclomatic complexity of 7.\n"
    )


def test_detect_obfuscation_json_emits_sectioned_findings(monkeypatch, capsys):
    bv = BinaryView()

    def fake_collect_obfuscation_reports(received_bv):
        assert received_bv is bv
        return [
            {
                "name": "Cyclomatic Complexity",
                "findings": [
                    {
                        "address": "0x1000",
                        "name": "main",
                        "cyclomatic_complexity": 7,
                    }
                ],
            },
            {
                "name": "XOR Decryption Loops",
                "findings": [{"address": "0x2000", "name": "decode"}],
            },
        ]

    monkeypatch.setattr(detect_obfuscation, "load_binary", lambda file_name: bv)
    monkeypatch.setattr(
        detect_obfuscation,
        "collect_obfuscation_reports",
        fake_collect_obfuscation_reports,
    )

    assert detect_obfuscation.main(["--json", "sample.bin"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "binary": "sample.bin",
        "heuristics": [
            {
                "name": "Cyclomatic Complexity",
                "findings": [
                    {
                        "address": "0x1000",
                        "cyclomatic_complexity": 7,
                        "name": "main",
                    }
                ],
            },
            {
                "name": "XOR Decryption Loops",
                "findings": [
                    {
                        "address": "0x2000",
                        "name": "decode",
                    }
                ],
            },
        ],
    }


def test_detect_flattening_json_emits_structured_function_fields(monkeypatch, capsys):
    bv = BinaryView()

    def fake_find_flattened_function_reports(received_bv):
        assert received_bv is bv
        return [
            {
                "address": "0x401000",
                "name": "dispatcher",
                "flattening_score": 0.75,
            }
        ]

    monkeypatch.setattr(detect_flattening, "load_binary", lambda file_name: bv)
    monkeypatch.setattr(
        detect_flattening,
        "find_flattened_function_reports",
        fake_find_flattened_function_reports,
    )

    assert detect_flattening.main(["--json", "sample.bin"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "binary": "sample.bin",
        "heuristics": [
            {
                "name": "Control Flow Flattening",
                "findings": [
                    {
                        "address": "0x401000",
                        "name": "dispatcher",
                        "flattening_score": 0.75,
                    }
                ],
            }
        ],
    }


def test_detect_flattening_help_uses_argparse(capsys):
    try:
        detect_flattening.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

    assert "--json" in capsys.readouterr().out


def test_detect_flattening_run_json_uses_real_report_helper(monkeypatch):
    function = SimpleNamespace(start=0x401000, name="dispatcher")
    bv = SimpleNamespace(functions=[function])
    monkeypatch.setattr(
        detect_flattening,
        "find_flattened_function_reports",
        lambda received_bv: (
            [
                {
                    "address": "0x401000",
                    "name": "dispatcher",
                    "flattening_score": 0.75,
                }
            ]
            if received_bv is bv
            else []
        ),
    )

    assert detect_flattening.run_json(bv, "sample.bin")["heuristics"][0][
        "findings"
    ] == [{"address": "0x401000", "name": "dispatcher", "flattening_score": 0.75}]

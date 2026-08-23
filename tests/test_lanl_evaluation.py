from pathlib import Path

from evaluate_lanl import evaluate


def test_streaming_lanl_evaluation_recovers_known_pair(tmp_path: Path) -> None:
    auth = tmp_path / "auth.txt"
    redteam = tmp_path / "redteam.txt"
    auth.write_text(
        "10,U1@DOM,C1$@DOM,C1,C2,Kerberos,Network,LogOn,Success\n"
        "20,U1@DOM,C1$@DOM,C9,C3,Kerberos,Network,LogOn,Success\n",
        encoding="utf-8",
    )
    redteam.write_text("20,U1@DOM,C9,C3\n", encoding="utf-8")

    result = evaluate(auth, redteam)

    assert result["ground_truth_events"] == 1
    assert result["exact_ground_truth_events_present"] == 1
    assert result["detected_ground_truth_pairs"] == 1
    assert result["ground_truth_pair_recall"] == 1.0

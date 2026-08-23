import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


class SyntheticEvalTests(unittest.TestCase):
    def test_eval_script_produces_metrics_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            generated = tmp_path / "synthetic.csv"
            metrics = tmp_path / "metrics.json"

            subprocess.run(
                [
                    sys.executable,
                    "generate_auth_logs.py",
                    "--rows",
                    "600",
                    "--seed",
                    "42",
                    "--output",
                    str(generated),
                ],
                cwd=PROJECT_DIR,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "evaluate_synthetic_logs.py",
                    "--input",
                    str(generated),
                    "--output",
                    str(metrics),
                ],
                cwd=PROJECT_DIR,
                check=True,
            )

            payload = json.loads(metrics.read_text(encoding="utf-8"))
            self.assertIn("brute_force_recall", payload)
            self.assertIn("success_after_failures_recall", payload)
            self.assertGreaterEqual(payload["brute_force_recall"], 0.0)
            self.assertLessEqual(payload["brute_force_recall"], 1.0)


if __name__ == "__main__":
    unittest.main()

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


class ThreatHuntingSmokeTests(unittest.TestCase):
    """End-to-end runs that exercise the CLI on the bundled sample data.

    These spawn the *same* interpreter running the tests (sys.executable) rather
    than a bare "python", which on some machines resolves to a different
    environment that lacks the project dependencies.
    """

    def _run(self, extra_args, tmp_path):
        output_csv = tmp_path / "report.csv"
        summary_json = tmp_path / "summary.json"
        plot_dir = tmp_path / "plots"
        subprocess.run(
            [
                sys.executable,
                "log_hunter.py",
                *extra_args,
                "--output",
                str(output_csv),
                "--summary",
                str(summary_json),
                "--plot-dir",
                str(plot_dir),
            ],
            cwd=PROJECT_DIR,
            check=True,
        )
        return output_csv, summary_json, plot_dir

    def test_csv_sample_run_produces_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_csv, summary_json, plot_dir = self._run(
                ["--input", "data/sample_auth_logs.csv"], tmp_path
            )
            self.assertTrue(output_csv.exists())
            self.assertTrue(summary_json.exists())
            self.assertTrue((plot_dir / "failed_logins_by_ip.png").exists())

    def test_linux_auth_format_run_produces_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_csv, _, _ = self._run(
                ["--input", "data/sample_linux_auth.log", "--format", "linux-auth"],
                tmp_path,
            )
            self.assertTrue(output_csv.exists())

    def test_windows_events_format_run_produces_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_csv, _, _ = self._run(
                [
                    "--input",
                    "data/sample_windows_security_events.csv",
                    "--format",
                    "windows-events",
                ],
                tmp_path,
            )
            self.assertTrue(output_csv.exists())


if __name__ == "__main__":
    unittest.main()

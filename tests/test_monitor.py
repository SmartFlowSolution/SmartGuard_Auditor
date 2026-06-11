import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.llm import OllamaAuditResult
from app.monitor import BlockchainMonitor, attach_source_code
from app.storage import ScanStore


class MonitorPersistenceTests(unittest.TestCase):
    def test_llm_result_is_stored_without_runtime_name_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ScanStore(Path(tmpdir) / "smartguard.sqlite3")
            monitor = BlockchainMonitor(store)
            report = {"risk": "INFO", "findings": []}

            with patch(
                "app.monitor.summarize_with_ollama_result",
                return_value=OllamaAuditResult(summary="Looks clean.", status="done"),
            ):
                monitor._run_llm_analysis(1, "0xabc", "contract A {}", report, "model", None)

            self.assertEqual(report["llm_status"], "done")
            self.assertEqual(report["llm_summary"], "Looks clean.")
            self.assertNotIn("llm_error", report)
            monitor.shutdown()

    def test_source_code_storage_metadata_marks_truncated_source(self) -> None:
        report = {}
        source = "x" * 200000

        attach_source_code(report, source)

        self.assertLess(len(report["source_code"]), len(source))
        self.assertTrue(report["source_truncated"])
        self.assertEqual(report["source_chars"], len(source))


if __name__ == "__main__":
    unittest.main()

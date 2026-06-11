import tempfile
import unittest
from pathlib import Path

from app.storage import ScanStore


class ScanStoreTests(unittest.TestCase):
    def make_store(self, tmpdir: str) -> ScanStore:
        return ScanStore(Path(tmpdir) / "smartguard.sqlite3")

    def test_contract_report_round_trips_and_can_be_updated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self.make_store(tmpdir)
            store.upsert_contract(
                {
                    "chain_id": 1,
                    "address": "0xABC",
                    "block_number": 123,
                    "tx_hash": "0xtx",
                    "creator": "0xcreator",
                    "status": "analyzed",
                    "reason": "Verified Solidity source found and audited.",
                    "risk": "INFO",
                    "source_name": "Sourcify",
                    "bytecode_preview": None,
                    "balance_wei": 0,
                    "balance_eth": "0",
                    "tries": 0,
                    "updated_at": "2026-06-10T12:00:00+00:00",
                    "report": {"risk": "INFO", "llm_status": "queued"},
                }
            )

            store.update_contract_report(1, "0xABC", {"risk": "INFO", "llm_status": "done", "llm_summary": "Clean."})
            contracts = store.recent_contracts()

            self.assertEqual(len(contracts), 1)
            self.assertEqual(contracts[0]["address"], "0xabc")
            self.assertEqual(contracts[0]["report"]["llm_status"], "done")
            self.assertEqual(contracts[0]["report"]["llm_summary"], "Clean.")

    def test_alert_report_round_trips_and_can_be_updated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self.make_store(tmpdir)
            stored = store.add_alert(
                {
                    "alert_key": "1:0xabc:CRITICAL:Possible Reentrancy",
                    "created_at": "2026-06-10T12:00:00+00:00",
                    "chain_id": 1,
                    "address": "0xABC",
                    "block_number": 123,
                    "tx_hash": "0xtx",
                    "creator": "0xcreator",
                    "source_name": "Sourcify",
                    "risk": "CRITICAL",
                },
                {"risk": "CRITICAL", "llm_status": "queued"},
            )

            self.assertTrue(stored)
            store.update_alert_report(
                "1:0xabc:CRITICAL:Possible Reentrancy",
                {"risk": "CRITICAL", "llm_status": "empty", "llm_summary": None},
            )
            alerts = store.recent_alerts()

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["address"], "0xabc")
            self.assertEqual(alerts[0]["report"]["llm_status"], "empty")

    def test_queued_llm_jobs_are_marked_interrupted_on_startup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self.make_store(tmpdir)
            store.upsert_contract(
                {
                    "chain_id": 1,
                    "address": "0xABC",
                    "block_number": 123,
                    "tx_hash": "0xtx",
                    "creator": None,
                    "status": "analyzed",
                    "reason": "Verified Solidity source found and audited.",
                    "risk": "INFO",
                    "source_name": "Sourcify",
                    "bytecode_preview": None,
                    "balance_wei": 0,
                    "balance_eth": "0",
                    "tries": 0,
                    "updated_at": "2026-06-10T12:00:00+00:00",
                    "report": {"risk": "INFO", "llm_status": "queued"},
                }
            )
            store.add_alert(
                {
                    "alert_key": "1:0xabc:CRITICAL:Possible Reentrancy",
                    "created_at": "2026-06-10T12:00:00+00:00",
                    "chain_id": 1,
                    "address": "0xABC",
                    "block_number": 123,
                    "tx_hash": "0xtx",
                    "creator": None,
                    "source_name": "Sourcify",
                    "risk": "CRITICAL",
                },
                {"risk": "CRITICAL", "llm_status": "queued"},
            )

            changed = store.mark_interrupted_llm_jobs()
            contract_report = store.recent_contracts()[0]["report"]
            alert_report = store.recent_alerts()[0]["report"]

            self.assertEqual(changed, 2)
            self.assertEqual(contract_report["llm_status"], "interrupted")
            self.assertIn("backend stopped", contract_report["llm_error"])
            self.assertEqual(alert_report["llm_status"], "interrupted")


if __name__ == "__main__":
    unittest.main()

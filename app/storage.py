from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import json
import sqlite3
import threading
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "smartguard.sqlite3"


class ScanStore:
    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = path
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                create table if not exists scanned_blocks (
                    chain_id integer not null,
                    block_number integer not null,
                    scanned_at text not null default current_timestamp,
                    contracts_found integer not null default 0,
                    primary key (chain_id, block_number)
                );

                create table if not exists seen_contracts (
                    chain_id integer not null,
                    address text not null,
                    block_number integer not null,
                    tx_hash text not null,
                    creator text,
                    status text not null,
                    reason text not null,
                    risk text,
                    source_name text,
                    bytecode_preview text,
                    tries integer not null default 0,
                    updated_at text not null default current_timestamp,
                    primary key (chain_id, address)
                );

                create table if not exists alerts (
                    alert_key text primary key,
                    created_at text not null,
                    chain_id integer not null,
                    address text not null,
                    block_number integer not null,
                    tx_hash text not null,
                    creator text,
                    source_name text not null,
                    risk text not null,
                    report_json text not null,
                    dismissed integer not null default 0
                );
                """
            )
            self._ensure_column(conn, "seen_contracts", "balance_wei", "integer")
            self._ensure_column(conn, "seen_contracts", "balance_eth", "text")
            self._ensure_column(conn, "seen_contracts", "report_json", "text")

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
        columns = {row["name"] for row in conn.execute(f"pragma table_info({table})").fetchall()}
        if column not in columns:
            conn.execute(f"alter table {table} add column {column} {column_type}")

    def has_block(self, chain_id: int, block_number: int) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "select 1 from scanned_blocks where chain_id = ? and block_number = ?",
                (chain_id, block_number),
            ).fetchone()
            return row is not None

    def mark_block(self, chain_id: int, block_number: int, contracts_found: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                insert into scanned_blocks (chain_id, block_number, contracts_found)
                values (?, ?, ?)
                on conflict(chain_id, block_number) do update set
                    scanned_at = current_timestamp,
                    contracts_found = excluded.contracts_found
                """,
                (chain_id, block_number, contracts_found),
            )

    def upsert_contract(self, contract: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                insert into seen_contracts (
                    chain_id, address, block_number, tx_hash, creator, status, reason,
                    risk, source_name, bytecode_preview, balance_wei, balance_eth, tries, updated_at,
                    report_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(chain_id, address) do update set
                    block_number = excluded.block_number,
                    tx_hash = excluded.tx_hash,
                    creator = excluded.creator,
                    status = excluded.status,
                    reason = excluded.reason,
                    risk = excluded.risk,
                    source_name = excluded.source_name,
                    bytecode_preview = excluded.bytecode_preview,
                    balance_wei = excluded.balance_wei,
                    balance_eth = excluded.balance_eth,
                    tries = excluded.tries,
                    updated_at = excluded.updated_at,
                    report_json = excluded.report_json
                """,
                (
                    contract["chain_id"],
                    contract["address"].lower(),
                    contract["block_number"],
                    contract["tx_hash"],
                    contract.get("creator"),
                    contract["status"],
                    contract["reason"],
                    contract.get("risk"),
                    contract.get("source_name"),
                    contract.get("bytecode_preview"),
                    contract.get("balance_wei"),
                    contract.get("balance_eth"),
                    contract.get("tries", 0),
                    contract["updated_at"],
                    json.dumps(contract.get("report"), ensure_ascii=False, sort_keys=True)
                    if contract.get("report")
                    else None,
                ),
            )

    def recent_contracts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                select chain_id, address, block_number, tx_hash, creator, status, reason,
                       risk, source_name, bytecode_preview, balance_wei, balance_eth, tries, updated_at,
                       report_json
                from seen_contracts
                order by updated_at desc
                limit ?
                """,
                (limit,),
            ).fetchall()
            contracts: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                report_json = item.pop("report_json", None)
                item["report"] = json.loads(report_json) if report_json else None
                contracts.append(item)
            return contracts

    def update_contract_report(self, chain_id: int, address: str, report: dict[str, Any]) -> None:
        report_json = json.dumps(report, ensure_ascii=False, sort_keys=True)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                update seen_contracts
                set report_json = ?, updated_at = current_timestamp
                where chain_id = ? and address = ?
                """,
                (report_json, chain_id, address.lower()),
            )

    def pending_contracts(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                select chain_id, address, block_number, tx_hash, creator, bytecode_preview,
                       balance_wei, balance_eth, tries
                from seen_contracts
                where status = 'pending_source'
                order by updated_at desc
                limit ?
                """,
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def add_alert(self, alert: dict[str, Any], report: dict[str, Any]) -> bool:
        report_json = json.dumps(report, ensure_ascii=False, sort_keys=True)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                insert or ignore into alerts (
                    alert_key, created_at, chain_id, address, block_number, tx_hash,
                    creator, source_name, risk, report_json
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["alert_key"],
                    alert["created_at"],
                    alert["chain_id"],
                    alert["address"].lower(),
                    alert["block_number"],
                    alert["tx_hash"],
                    alert.get("creator"),
                    alert["source_name"],
                    alert["risk"],
                    report_json,
                ),
            )
            return cursor.rowcount > 0

    def update_alert_report(self, alert_key: str, report: dict[str, Any]) -> None:
        report_json = json.dumps(report, ensure_ascii=False, sort_keys=True)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                update alerts
                set report_json = ?
                where alert_key = ?
                """,
                (report_json, alert_key),
            )

    def mark_interrupted_llm_jobs(self) -> int:
        changed = 0
        with self._lock, self._connect() as conn:
            contract_rows = conn.execute(
                """
                select chain_id, address, report_json
                from seen_contracts
                where report_json is not null
                """
            ).fetchall()
            for row in contract_rows:
                report = json.loads(row["report_json"])
                if report.get("llm_status") != "queued":
                    continue
                report["llm_status"] = "interrupted"
                report["llm_error"] = "The backend stopped before the queued Ollama job finished."
                conn.execute(
                    """
                    update seen_contracts
                    set report_json = ?
                    where chain_id = ? and address = ?
                    """,
                    (
                        json.dumps(report, ensure_ascii=False, sort_keys=True),
                        row["chain_id"],
                        row["address"],
                    ),
                )
                changed += 1

            alert_rows = conn.execute(
                """
                select alert_key, report_json
                from alerts
                where report_json is not null
                """
            ).fetchall()
            for row in alert_rows:
                report = json.loads(row["report_json"])
                if report.get("llm_status") != "queued":
                    continue
                report["llm_status"] = "interrupted"
                report["llm_error"] = "The backend stopped before the queued Ollama job finished."
                conn.execute(
                    """
                    update alerts
                    set report_json = ?
                    where alert_key = ?
                    """,
                    (json.dumps(report, ensure_ascii=False, sort_keys=True), row["alert_key"]),
                )
                changed += 1
        return changed

    def recent_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                select rowid as id, created_at, chain_id, address, block_number, tx_hash,
                       creator, source_name, risk, report_json
                from alerts
                where dismissed = 0
                order by created_at desc
                limit ?
                """,
                (limit,),
            ).fetchall()
            alerts: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["report"] = json.loads(item.pop("report_json"))
                alerts.append(item)
            return alerts

    def dismiss_alerts(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("update alerts set dismissed = 1 where dismissed = 0")

    def counts(self) -> dict[str, int]:
        with self._lock, self._connect() as conn:
            blocks = conn.execute("select count(*) from scanned_blocks").fetchone()[0]
            contracts = conn.execute("select count(*) from seen_contracts").fetchone()[0]
            alerts = conn.execute("select count(*) from alerts").fetchone()[0]
            return {"stored_blocks": blocks, "stored_contracts": contracts, "stored_alerts": alerts}

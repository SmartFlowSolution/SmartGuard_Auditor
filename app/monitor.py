from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import os
import threading
import time
from typing import Any

from pydantic import BaseModel, Field

from app.analyzer import analyze_source
from app.blockchain import (
    BlockchainError,
    contract_creations_from_block,
    default_rpc_url,
    fetch_contract_source,
    format_eth,
    get_balance_wei,
    get_bytecode,
    latest_block_number,
    rpc_candidates,
)
from app.llm import summarize_with_ollama_result
from app.storage import ScanStore


ALERT_LEVELS = {"CRITICAL", "HIGH"}
MAX_STORED_SOURCE_CHARS = int(os.getenv("MAX_STORED_SOURCE_CHARS", "120000"))
logger = logging.getLogger(__name__)


class MonitorConfig(BaseModel):
    rpc_url: str | None
    chain_id: int = 1
    etherscan_api_key: str | None = None
    poll_interval: int = 20
    start_block: int | None = None
    lookback_blocks: int = 100
    max_blocks_per_tick: int = 12
    analyze_llm: bool = False
    llm_model: str | None = None


class LiveAlert(BaseModel):
    id: int
    created_at: str
    address: str
    chain_id: int
    block_number: int
    tx_hash: str
    creator: str | None
    source_name: str
    risk: str
    report: dict[str, Any]


class LiveSeenContract(BaseModel):
    address: str
    chain_id: int
    block_number: int
    tx_hash: str
    creator: str | None
    status: str
    reason: str
    risk: str | None = None
    source_name: str | None = None
    bytecode_preview: str | None = None
    balance_wei: int | None = None
    balance_eth: str | None = None
    report: dict[str, Any] | None = None
    tries: int = 0
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MonitorState(BaseModel):
    running: bool = False
    last_block: int | None = None
    latest_seen_block: int | None = None
    scanned_contracts: int = 0
    analyzed_contracts: int = 0
    pending_unverified: int = 0
    skipped_blocks: int = 0
    last_error: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)


class BlockchainMonitor:
    def __init__(self, store: ScanStore | None = None) -> None:
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._state = MonitorState()
        self._store = store or ScanStore()
        self._alerts: list[LiveAlert] = []
        self._pending: dict[str, dict[str, Any]] = {}
        self._seen: dict[str, LiveSeenContract] = {}
        self._next_alert_id = 1
        self._llm_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="smartguard-llm")
        interrupted = self._store.mark_interrupted_llm_jobs()
        if interrupted:
            logger.info("marked interrupted llm jobs count=%s", interrupted)
        self._load_persisted_state()

    def start(self, config: MonitorConfig) -> dict:
        if not config.rpc_url:
            config.rpc_url = default_rpc_url(config.chain_id)
        if not config.rpc_url:
            raise RuntimeError("No RPC URL provided and no default public RPC exists for this chain")
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("Live monitor is already running")
            logger.info(
                "monitor start chain_id=%s rpc=%s poll_interval=%s lookback_blocks=%s start_block=%s max_blocks_per_tick=%s analyze_llm=%s llm_model=%s pending_loaded=%s",
                config.chain_id,
                mask_url(config.rpc_url),
                config.poll_interval,
                config.lookback_blocks,
                config.start_block,
                config.max_blocks_per_tick,
                config.analyze_llm,
                config.llm_model,
                len(self._pending),
            )
            self._stop_event.clear()
            self._load_persisted_state()
            self._state = MonitorState(running=True, config=self._public_config(config))
            self._state.pending_unverified = len(self._pending)
            self._thread = threading.Thread(target=self._run, args=(config,), daemon=True)
            self._thread.start()
            return self.status()

    def restart(self, config: MonitorConfig) -> dict:
        logger.info("monitor restart requested")
        self._stop_event.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=35)
        if thread and thread.is_alive():
            logger.warning("monitor restart blocked previous thread still alive")
            self._set_state(
                running=True,
                last_error="Previous live monitor is still stopping. Wait a moment and start again.",
            )
            return self.status()
        return self.start(config)

    def stop(self) -> dict:
        logger.info("monitor stop requested")
        self._stop_event.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=35)
        with self._lock:
            self._state.running = bool(thread and thread.is_alive())
            logger.info("monitor stop done running=%s", self._state.running)
            return self.status()

    def shutdown(self) -> None:
        self.stop()
        self._llm_executor.shutdown(wait=False, cancel_futures=True)

    def clear_alerts(self) -> dict:
        with self._lock:
            logger.info("monitor clear alerts")
            self._alerts.clear()
            self._store.dismiss_alerts()
            self._next_alert_id = 1
            return {"ok": True}

    def status(self) -> dict:
        with self._lock:
            payload = self._state.model_dump()
            payload["alerts"] = len(self._store.recent_alerts())
            payload.update(self._store.counts())
            return payload

    def alerts(self) -> list[dict]:
        return self._store.recent_alerts()

    def contracts(self) -> list[dict]:
        return self._store.recent_contracts()

    def _run(self, config: MonitorConfig) -> None:
        """Drive the live polling loop, including RPC failover and pending-source retries."""
        try:
            candidates = rpc_candidates(config.chain_id, config.rpc_url)
            config.rpc_url = self._first_working_rpc(candidates)
            self._set_state(config=self._public_config(config), last_error=None)
            latest = latest_block_number(config.rpc_url)
            start_block = config.start_block
            if start_block is None:
                start_block = max(0, latest - max(0, config.lookback_blocks))
            self._set_state(last_block=start_block - 1, latest_seen_block=latest)
            logger.info(
                "monitor run started rpc=%s latest_block=%s start_block=%s pending=%s",
                mask_url(config.rpc_url),
                latest,
                start_block,
                len(self._pending),
            )

            next_block = start_block
            while not self._stop_event.is_set():
                try:
                    latest = latest_block_number(config.rpc_url)
                except BlockchainError as exc:
                    logger.warning("latest block failed rpc=%s error=%s", mask_url(config.rpc_url), exc)
                    config.rpc_url = self._next_working_rpc(candidates, config.rpc_url, exc)
                    self._set_state(config=self._public_config(config))
                    latest = latest_block_number(config.rpc_url)
                self._set_state(latest_seen_block=latest, last_error=None)
                self._retry_pending(config)

                processed = 0
                while next_block <= latest and processed < config.max_blocks_per_tick:
                    self._scan_block(config, next_block)
                    self._set_state(last_block=next_block)
                    next_block += 1
                    processed += 1

                logger.debug(
                    "monitor tick latest=%s next_block=%s processed=%s pending=%s",
                    latest,
                    next_block,
                    processed,
                    len(self._pending),
                )
                self._stop_event.wait(max(3, config.poll_interval))
        except Exception as exc:
            logger.exception("monitor run failed")
            self._set_state(running=False, last_error=str(exc))
        finally:
            logger.info("monitor run stopped")
            self._set_state(running=False)

    def _first_working_rpc(self, candidates: list[str]) -> str:
        last_error: Exception | None = None
        for rpc_url in candidates:
            try:
                latest_block_number(rpc_url)
                logger.info("rpc selected rpc=%s", mask_url(rpc_url))
                return rpc_url
            except BlockchainError as exc:
                last_error = exc
                logger.warning("rpc candidate failed rpc=%s error=%s", mask_url(rpc_url), exc)
                self._set_state(last_error=f"RPC failed, trying next: {mask_url(rpc_url)} ({exc})")
        raise RuntimeError(f"No public RPC candidate works. Last error: {last_error}")

    def _next_working_rpc(self, candidates: list[str], current_rpc: str, reason: Exception) -> str:
        if current_rpc in candidates:
            start = candidates.index(current_rpc) + 1
            rotated = candidates[start:] + candidates[:start]
        else:
            rotated = candidates

        self._set_state(last_error=f"RPC failed: {mask_url(current_rpc)} ({reason}). Trying fallback.")
        logger.warning("rpc fallback current=%s reason=%s", mask_url(current_rpc), reason)
        return self._first_working_rpc(rotated)

    def _scan_block(self, config: MonitorConfig, block_number: int) -> None:
        """Scan one block for contract creations and persist the block cursor."""
        if self._store.has_block(config.chain_id, block_number):
            self._increment("skipped_blocks")
            logger.debug("block skipped already scanned chain_id=%s block=%s", config.chain_id, block_number)
            return

        try:
            creations = contract_creations_from_block(config.rpc_url, block_number)
        except BlockchainError as exc:
            logger.warning("block scan failed chain_id=%s block=%s error=%s", config.chain_id, block_number, exc)
            candidates = rpc_candidates(config.chain_id, config.rpc_url)
            try:
                config.rpc_url = self._next_working_rpc(candidates, config.rpc_url, exc)
                self._set_state(config=self._public_config(config))
                creations = contract_creations_from_block(config.rpc_url, block_number)
            except Exception as retry_exc:
                logger.exception("block scan retry failed chain_id=%s block=%s", config.chain_id, block_number)
                self._set_state(last_error=str(retry_exc))
                return

        logger.debug(
            "block scanned chain_id=%s block=%s contract_creations=%s",
            config.chain_id,
            block_number,
            len(creations),
        )
        for contract in creations:
            logger.info(
                "contract creation detected chain_id=%s block=%s address=%s tx=%s creator=%s",
                config.chain_id,
                block_number,
                contract["address"],
                contract.get("tx_hash"),
                contract.get("creator"),
            )
            self._increment("scanned_contracts")
            self._attach_balance(config, contract)
            self._remember_contract(
                config,
                contract,
                status="detected",
                reason="Contract creation transaction found. Waiting for source lookup.",
            )
            self._audit_contract(config, contract)
        self._store.mark_block(config.chain_id, block_number, len(creations))

    def _audit_contract(self, config: MonitorConfig, contract: dict[str, Any]) -> None:
        """Fetch verified source for a new contract and create reports, alerts, or retry state."""
        address = contract["address"]
        logger.info("contract audit start chain_id=%s address=%s", config.chain_id, address)
        source = fetch_contract_source(address, config.chain_id, config.etherscan_api_key)
        if not source:
            try:
                bytecode = get_bytecode(config.rpc_url, address)
            except BlockchainError:
                bytecode = ""
                logger.warning("bytecode fetch failed chain_id=%s address=%s", config.chain_id, address)
            self._pending[address.lower()] = {**contract, "bytecode": bytecode, "tries": 0}
            logger.info("contract pending source chain_id=%s address=%s bytecode_present=%s", config.chain_id, address, bool(bytecode))
            self._remember_contract(
                config,
                contract,
                status="pending_source",
                reason="No verified Solidity source found in Sourcify/Etherscan yet.",
                bytecode_preview=preview_bytecode(bytecode),
            )
            self._set_state(pending_unverified=len(self._pending))
            return

        report = analyze_source(source.source).to_dict()
        report["address"] = address
        report["chain_id"] = config.chain_id
        report["source_name"] = source.source_name
        attach_source_code(report, source.source)
        self._attach_balance(config, contract)
        report["balance_wei"] = contract.get("balance_wei")
        report["balance_eth"] = contract.get("balance_eth")
        report["funds_at_risk"] = bool(contract.get("balance_wei"))
        if config.analyze_llm:
            report["llm_summary"] = None
            report["llm_status"] = "queued"
        self._increment("analyzed_contracts")
        logger.info(
            "contract audit done chain_id=%s address=%s source=%s risk=%s findings=%s balance_eth=%s",
            config.chain_id,
            address,
            source.source_name,
            report.get("risk"),
            len(report.get("findings", [])),
            report.get("balance_eth"),
        )
        self._remember_contract(
            config,
            contract,
            status="analyzed",
            reason="Verified Solidity source found and audited.",
            risk=report.get("risk"),
            source_name=source.source_name,
            report=report,
        )
        if report.get("risk") in ALERT_LEVELS:
            self._add_alert(config, contract, source.source_name, report)
        if config.analyze_llm:
            self._schedule_llm_analysis(config, contract, source.source, report)

    def _retry_pending(self, config: MonitorConfig) -> None:
        """Re-check contracts whose verified source was unavailable on first detection."""
        for address, contract in list(self._pending.items())[:10]:
            contract["tries"] = int(contract.get("tries", 0)) + 1
            logger.debug(
                "pending retry chain_id=%s address=%s tries=%s",
                config.chain_id,
                contract["address"],
                contract["tries"],
            )
            source = fetch_contract_source(contract["address"], config.chain_id, config.etherscan_api_key)
            if not source:
                self._remember_contract(
                    config,
                    contract,
                    status="pending_source",
                    reason="Still waiting for verified Solidity source.",
                    bytecode_preview=preview_bytecode(contract.get("bytecode", "")),
                    tries=contract["tries"],
                )
                if contract["tries"] > 60:
                    logger.info("pending dropped chain_id=%s address=%s tries=%s", config.chain_id, contract["address"], contract["tries"])
                    self._pending.pop(address, None)
                continue

            report = analyze_source(source.source).to_dict()
            report["address"] = contract["address"]
            report["chain_id"] = config.chain_id
            report["source_name"] = source.source_name
            attach_source_code(report, source.source)
            self._attach_balance(config, contract)
            report["balance_wei"] = contract.get("balance_wei")
            report["balance_eth"] = contract.get("balance_eth")
            report["funds_at_risk"] = bool(contract.get("balance_wei"))
            if config.analyze_llm:
                report["llm_summary"] = None
                report["llm_status"] = "queued"
            self._pending.pop(address, None)
            self._increment("analyzed_contracts")
            logger.info(
                "pending source resolved chain_id=%s address=%s source=%s risk=%s findings=%s tries=%s",
                config.chain_id,
                contract["address"],
                source.source_name,
                report.get("risk"),
                len(report.get("findings", [])),
                contract["tries"],
            )
            self._remember_contract(
                config,
                contract,
                status="analyzed",
                reason="Verified Solidity source became available and was audited.",
                risk=report.get("risk"),
                source_name=source.source_name,
                report=report,
                tries=contract["tries"],
            )
            if report.get("risk") in ALERT_LEVELS:
                self._add_alert(config, contract, source.source_name, report)
            if config.analyze_llm:
                self._schedule_llm_analysis(config, contract, source.source, report)
        self._set_state(pending_unverified=len(self._pending))

    def _add_alert(self, config: MonitorConfig, contract: dict[str, Any], source_name: str, report: dict[str, Any]) -> None:
        with self._lock:
            alert_key = make_alert_key(config.chain_id, contract["address"], report)
            alert = LiveAlert(
                id=self._next_alert_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                address=contract["address"],
                chain_id=config.chain_id,
                block_number=int(contract["block_number"]),
                tx_hash=contract["tx_hash"],
                creator=contract.get("creator"),
                source_name=source_name,
                risk=report.get("risk", "INFO"),
                report=report,
            )
            stored = self._store.add_alert(
                {
                    "alert_key": alert_key,
                    "created_at": alert.created_at,
                    "chain_id": alert.chain_id,
                    "address": alert.address,
                    "block_number": alert.block_number,
                    "tx_hash": alert.tx_hash,
                    "creator": alert.creator,
                    "source_name": alert.source_name,
                    "risk": alert.risk,
                },
                report,
            )
            if not stored:
                logger.debug("alert duplicate ignored chain_id=%s address=%s risk=%s", config.chain_id, contract["address"], report.get("risk"))
                return
            self._next_alert_id += 1
            self._alerts.append(alert)
            self._alerts = self._alerts[-500:]
            logger.warning(
                "alert stored chain_id=%s address=%s risk=%s findings=%s source=%s",
                config.chain_id,
                contract["address"],
                report.get("risk"),
                len(report.get("findings", [])),
                source_name,
            )

    def _schedule_llm_analysis(self, config: MonitorConfig, contract: dict[str, Any], source: str, report: dict[str, Any]) -> None:
        report_copy = dict(report)
        contract_copy = dict(contract)
        alert_key = make_alert_key(config.chain_id, contract["address"], report)
        logger.info(
            "llm analysis queued chain_id=%s address=%s model=%s",
            config.chain_id,
            contract["address"],
            config.llm_model,
        )
        self._llm_executor.submit(
            self._run_llm_analysis,
            config.chain_id,
            contract_copy["address"],
            source,
            report_copy,
            config.llm_model,
            alert_key if report.get("risk") in ALERT_LEVELS else None,
        )

    def _run_llm_analysis(
        self,
        chain_id: int,
        address: str,
        source: str,
        report: dict[str, Any],
        model: str | None,
        alert_key: str | None,
    ) -> None:
        """Store an asynchronous Ollama result back into contract and alert reports."""
        logger.info("llm analysis start chain_id=%s address=%s model=%s", chain_id, address, model)
        try:
            result = summarize_with_ollama_result(source, report, model)
            report["llm_summary"] = result.summary
            report["llm_status"] = result.status
            if result.error:
                report["llm_error"] = result.error
            else:
                report.pop("llm_error", None)
            self._store.update_contract_report(chain_id, address, report)
            if alert_key:
                self._store.update_alert_report(alert_key, report)
            with self._lock:
                seen = self._seen.get(address.lower())
                if seen:
                    seen.report = report
            logger.info(
                "llm analysis stored chain_id=%s address=%s has_summary=%s alert=%s",
                chain_id,
                address,
                bool(result.summary),
                bool(alert_key),
            )
        except Exception as exc:
            report["llm_status"] = "error"
            report["llm_error"] = str(exc)
            self._store.update_contract_report(chain_id, address, report)
            if alert_key:
                self._store.update_alert_report(alert_key, report)
            logger.exception("llm analysis failed chain_id=%s address=%s", chain_id, address)

    def _remember_contract(
        self,
        config: MonitorConfig,
        contract: dict[str, Any],
        status: str,
        reason: str,
        risk: str | None = None,
        source_name: str | None = None,
        bytecode_preview: str | None = None,
        report: dict[str, Any] | None = None,
        tries: int = 0,
    ) -> None:
        with self._lock:
            address = contract["address"].lower()
            self._seen[address] = LiveSeenContract(
                address=contract["address"],
                chain_id=config.chain_id,
                block_number=int(contract["block_number"]),
                tx_hash=contract["tx_hash"],
                creator=contract.get("creator"),
                status=status,
                reason=reason,
                risk=risk,
                source_name=source_name,
                bytecode_preview=bytecode_preview,
                balance_wei=contract.get("balance_wei"),
                balance_eth=contract.get("balance_eth"),
                report=report,
                tries=tries,
            )
            self._store.upsert_contract(self._seen[address].model_dump())
            if len(self._seen) > 500:
                oldest = sorted(self._seen.items(), key=lambda item: item[1].updated_at)[:100]
                for key, _ in oldest:
                    self._seen.pop(key, None)

    def _load_persisted_state(self) -> None:
        with self._lock:
            self._seen.clear()
            for contract in self._store.recent_contracts(500):
                self._seen[contract["address"].lower()] = LiveSeenContract(**contract)

            self._pending.clear()
            for contract in self._store.pending_contracts(500):
                self._pending[contract["address"].lower()] = {
                    "address": contract["address"],
                    "chain_id": contract["chain_id"],
                    "block_number": contract["block_number"],
                    "tx_hash": contract["tx_hash"],
                    "creator": contract.get("creator"),
                    "bytecode": contract.get("bytecode_preview") or "",
                    "balance_wei": contract.get("balance_wei"),
                    "balance_eth": contract.get("balance_eth"),
                    "tries": contract.get("tries", 0),
                }

    def _set_state(self, **updates: Any) -> None:
        with self._lock:
            for key, value in updates.items():
                setattr(self._state, key, value)

    def _increment(self, field_name: str) -> None:
        with self._lock:
            setattr(self._state, field_name, getattr(self._state, field_name) + 1)

    def _attach_balance(self, config: MonitorConfig, contract: dict[str, Any]) -> None:
        if contract.get("balance_wei") is not None:
            return
        try:
            balance_wei = get_balance_wei(config.rpc_url, contract["address"])
        except BlockchainError:
            logger.debug("balance fetch failed chain_id=%s address=%s", config.chain_id, contract["address"])
            return
        contract["balance_wei"] = balance_wei
        contract["balance_eth"] = format_eth(balance_wei)
        logger.debug("balance fetched chain_id=%s address=%s balance_eth=%s", config.chain_id, contract["address"], contract["balance_eth"])

    def _public_config(self, config: MonitorConfig) -> dict[str, Any]:
        payload = config.model_dump()
        payload["rpc_url"] = mask_url(config.rpc_url)
        payload["etherscan_api_key"] = "***" if config.etherscan_api_key else None
        return payload


def mask_url(url: str) -> str:
    if "://" not in url:
        return "***"
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/..."


def preview_bytecode(bytecode: str) -> str | None:
    if not bytecode or bytecode == "0x":
        return None
    return bytecode[:82] + "..." if len(bytecode) > 82 else bytecode


def attach_source_code(report: dict[str, Any], source: str) -> None:
    report["source_code"] = source[:MAX_STORED_SOURCE_CHARS]
    report["source_truncated"] = len(source) > MAX_STORED_SOURCE_CHARS
    report["source_chars"] = len(source)


def make_alert_key(chain_id: int, address: str, report: dict[str, Any]) -> str:
    titles = ",".join(sorted(finding.get("title", "") for finding in report.get("findings", [])))
    return f"{chain_id}:{address.lower()}:{report.get('risk', 'INFO')}:{titles}"


monitor = BlockchainMonitor()

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.analyzer import analyze_source
from app.blockchain import BlockchainError, default_rpc_url, fetch_contract_source, get_bytecode, latest_block_number, rpc_candidates
from app.llm import DEFAULT_MODEL, summarize_with_ollama_result
from app.monitor import MonitorConfig, monitor


ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"

LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "DEBUG").upper(), logging.DEBUG)
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logging.getLogger().setLevel(LOG_LEVEL)
logging.getLogger("app").setLevel(LOG_LEVEL)
logger = logging.getLogger(__name__)

MAX_SOURCE_CHARS = int(os.getenv("MAX_SOURCE_CHARS", "500000"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "1000000"))
MAX_LOOKBACK_BLOCKS = int(os.getenv("MAX_LOOKBACK_BLOCKS", "1000"))
MAX_BLOCKS_PER_TICK = int(os.getenv("MAX_BLOCKS_PER_TICK", "25"))
MAX_POLL_INTERVAL = int(os.getenv("MAX_POLL_INTERVAL", "3600"))
API_TOKEN = os.getenv("SMARTGUARD_API_TOKEN")


def configured_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS")
    if raw:
        return [origin.strip() for origin in raw.split(",") if origin.strip()]
    return [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]


def require_api_token(
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    if not API_TOKEN:
        return
    bearer = f"Bearer {API_TOKEN}"
    if x_api_token == API_TOKEN or authorization == bearer:
        return
    raise HTTPException(status_code=401, detail="Invalid or missing API token")


def clamp_int(value: int, low: int, high: int) -> int:
    return min(max(value, low), high)


app = FastAPI(title="SmartGuard Auditor", version="0.2.0")
CORS_ORIGINS = configured_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    source: str = Field(min_length=1, max_length=MAX_SOURCE_CHARS)
    use_llm: bool = True
    model: str | None = Field(default=None, max_length=120)


class ContractFetchRequest(BaseModel):
    address: str = Field(min_length=1, max_length=80)
    chain_id: int = 1
    etherscan_api_key: str | None = Field(default=None, max_length=160)
    rpc_url: str | None = Field(default=None, max_length=500)
    use_llm: bool = False
    model: str | None = Field(default=None, max_length=120)


class LiveStartRequest(BaseModel):
    rpc_url: str | None = Field(default=None, max_length=500)
    chain_id: int = 1
    etherscan_api_key: str | None = Field(default=None, max_length=160)
    poll_interval: int = Field(default=20, ge=3, le=MAX_POLL_INTERVAL)
    start_block: int | None = None
    lookback_blocks: int = Field(default=100, ge=0, le=MAX_LOOKBACK_BLOCKS)
    max_blocks_per_tick: int = Field(default=12, ge=1, le=MAX_BLOCKS_PER_TICK)
    analyze_llm: bool = False
    llm_model: str | None = Field(default=None, max_length=120)


class RpcTestRequest(BaseModel):
    chain_id: int = 1
    rpc_url: str | None = Field(default=None, max_length=500)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning("invalid integer env %s=%s, using default=%s", name, value, default)
        return default


@app.on_event("startup")
def startup_live_monitor() -> None:
    if not env_bool("LIVE_AUTOSTART", True):
        logger.info("live monitor autostart disabled")
        return

    chain_id = env_int("LIVE_CHAIN_ID", 1)
    config = MonitorConfig(
        rpc_url=os.getenv("LIVE_RPC_URL") or default_rpc_url(chain_id),
        chain_id=chain_id,
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY"),
        poll_interval=clamp_int(env_int("LIVE_POLL_INTERVAL", 20), 3, MAX_POLL_INTERVAL),
        start_block=env_int("LIVE_START_BLOCK", 0) or None,
        lookback_blocks=clamp_int(env_int("LIVE_LOOKBACK_BLOCKS", 100), 0, MAX_LOOKBACK_BLOCKS),
        max_blocks_per_tick=clamp_int(env_int("LIVE_MAX_BLOCKS_PER_TICK", 12), 1, MAX_BLOCKS_PER_TICK),
        analyze_llm=env_bool("LIVE_ANALYZE_LLM", True),
        llm_model=os.getenv("LIVE_LLM_MODEL") or DEFAULT_MODEL,
    )
    logger.info(
        "live monitor autostart chain_id=%s lookback_blocks=%s poll_interval=%s max_blocks_per_tick=%s analyze_llm=%s llm_model=%s",
        config.chain_id,
        config.lookback_blocks,
        config.poll_interval,
        config.max_blocks_per_tick,
        config.analyze_llm,
        config.llm_model,
    )
    try:
        monitor.restart(config)
    except Exception:
        logger.exception("live monitor autostart failed")


@app.on_event("shutdown")
def shutdown_live_monitor() -> None:
    logger.info("application shutdown stopping live monitor")
    monitor.shutdown()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(PUBLIC / "index.html")


@app.get("/health")
def health() -> dict:
    logger.debug("health check")
    return {"ok": True}


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest, _: None = Depends(require_api_token)) -> dict:
    logger.info(
        "analyze source request use_llm=%s model=%s source_chars=%s",
        request.use_llm,
        request.model,
        len(request.source),
    )
    report = analyze_source(request.source)
    payload = report.to_dict()
    if request.use_llm:
        result = summarize_with_ollama_result(request.source, payload, request.model)
        payload["llm_summary"] = result.summary
        payload["llm_status"] = result.status
        if result.error:
            payload["llm_error"] = result.error
    logger.info(
        "analyze source done contract=%s risk=%s findings=%s llm=%s",
        payload.get("contract_name"),
        payload.get("risk"),
        len(payload.get("findings", [])),
        bool(payload.get("llm_summary")),
    )
    return payload


@app.post("/api/analyze-address")
def analyze_address(request: ContractFetchRequest, _: None = Depends(require_api_token)) -> dict:
    logger.info(
        "analyze address request address=%s chain_id=%s use_llm=%s model=%s",
        request.address,
        request.chain_id,
        request.use_llm,
        request.model,
    )
    source = fetch_contract_source(request.address, request.chain_id, request.etherscan_api_key)
    rpc_url = request.rpc_url or default_rpc_url(request.chain_id)
    bytecode = get_bytecode(rpc_url, request.address) if rpc_url else None
    if not source:
        logger.info("analyze address no verified source address=%s chain_id=%s", request.address, request.chain_id)
        return {
            "address": request.address,
            "chain_id": request.chain_id,
            "risk": "INFO",
            "source_found": False,
            "bytecode": bytecode[:120] + "..." if bytecode and len(bytecode) > 120 else bytecode,
            "message": "No verified code found in Sourcify/Etherscan. Full audit requires Solidity source.",
        }

    report = analyze_source(source.source)
    payload = report.to_dict()
    payload["address"] = request.address
    payload["chain_id"] = request.chain_id
    payload["source_found"] = True
    payload["source_name"] = source.source_name
    payload["bytecode"] = bytecode[:120] + "..." if bytecode and len(bytecode) > 120 else bytecode
    if request.use_llm:
        result = summarize_with_ollama_result(source.source, payload, request.model)
        payload["llm_summary"] = result.summary
        payload["llm_status"] = result.status
        if result.error:
            payload["llm_error"] = result.error
    logger.info(
        "analyze address done address=%s risk=%s findings=%s source=%s llm=%s",
        request.address,
        payload.get("risk"),
        len(payload.get("findings", [])),
        payload.get("source_name"),
        bool(payload.get("llm_summary")),
    )
    return payload


@app.post("/api/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    use_llm: bool = Form(True),
    model: str | None = Form(None),
    _: None = Depends(require_api_token),
) -> dict:
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Uploaded file exceeds {MAX_UPLOAD_BYTES} bytes")
    source = content.decode("utf-8", errors="replace")
    logger.info(
        "analyze file request filename=%s use_llm=%s model=%s source_chars=%s",
        file.filename,
        use_llm,
        model,
        len(source),
    )
    report = analyze_source(source)
    payload = report.to_dict()
    payload["filename"] = file.filename
    if use_llm:
        result = summarize_with_ollama_result(source, payload, model)
        payload["llm_summary"] = result.summary
        payload["llm_status"] = result.status
        if result.error:
            payload["llm_error"] = result.error
    logger.info(
        "analyze file done filename=%s contract=%s risk=%s findings=%s llm=%s",
        file.filename,
        payload.get("contract_name"),
        payload.get("risk"),
        len(payload.get("findings", [])),
        bool(payload.get("llm_summary")),
    )
    return payload


@app.post("/api/live/start")
def live_start(request: LiveStartRequest, _: None = Depends(require_api_token)) -> dict:
    logger.info(
        "live start request chain_id=%s poll_interval=%s lookback_blocks=%s max_blocks_per_tick=%s analyze_llm=%s llm_model=%s rpc_url_set=%s etherscan_key_set=%s",
        request.chain_id,
        request.poll_interval,
        request.lookback_blocks,
        request.max_blocks_per_tick,
        request.analyze_llm,
        request.llm_model,
        bool(request.rpc_url),
        bool(request.etherscan_api_key),
    )
    config = MonitorConfig(
        rpc_url=request.rpc_url,
        chain_id=request.chain_id,
        etherscan_api_key=request.etherscan_api_key,
        poll_interval=request.poll_interval,
        start_block=request.start_block,
        lookback_blocks=request.lookback_blocks,
        max_blocks_per_tick=request.max_blocks_per_tick,
        analyze_llm=request.analyze_llm,
        llm_model=request.llm_model,
    )
    return monitor.restart(config)


@app.post("/api/rpc/test")
def rpc_test(request: RpcTestRequest, _: None = Depends(require_api_token)) -> dict:
    logger.info("rpc test request chain_id=%s rpc_url_set=%s", request.chain_id, bool(request.rpc_url))
    results = []
    for rpc_url in rpc_candidates(request.chain_id, request.rpc_url):
        try:
            block = latest_block_number(rpc_url)
            results.append({"rpc_url": rpc_url, "ok": True, "latest_block": block})
        except BlockchainError as exc:
            logger.warning("rpc test failed rpc_url=%s error=%s", rpc_url, exc)
            results.append({"rpc_url": rpc_url, "ok": False, "error": str(exc)})
    working = next((item for item in results if item["ok"]), None)
    logger.info("rpc test done ok=%s working=%s", working is not None, working["rpc_url"] if working else None)
    return {"ok": working is not None, "working": working, "results": results}


@app.post("/api/live/stop")
def live_stop(_: None = Depends(require_api_token)) -> dict:
    logger.info("live stop request")
    return monitor.stop()


@app.post("/api/live/clear")
def live_clear(_: None = Depends(require_api_token)) -> dict:
    logger.info("live clear alerts request")
    return monitor.clear_alerts()


@app.get("/api/live/status")
def live_status() -> dict:
    return monitor.status()


@app.get("/api/live/alerts")
def live_alerts() -> list[dict]:
    return monitor.alerts()


@app.get("/api/live/contracts")
def live_contracts() -> list[dict]:
    return monitor.contracts()

app.mount("/", StaticFiles(directory=PUBLIC), name="public")

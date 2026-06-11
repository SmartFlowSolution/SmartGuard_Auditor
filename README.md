# SmartGuard Auditor

SmartGuard Auditor is a local FastAPI app for live smart contract security triage. It watches new Ethereum contract deployments, tries to resolve verified Solidity source, runs heuristic vulnerability checks, optionally adds an Ollama audit note, and shows the results in a browser UI.

The project is intentionally practical: it does not claim to replace a manual audit, but it helps surface contracts that deserve review first.

## How It Works

```text
Ethereum RPC
    |
    v
New contract creation transactions
    |
    v
Transaction receipts -> deployed contract addresses
    |
    v
Source lookup: Sourcify, then optional Etherscan
    |
    +--> no verified source -> pending_source, retry later
    |
    v
Heuristic Solidity analysis
    |
    +--> INFO/MEDIUM report -> stored as analyzed
    |
    +--> HIGH/CRITICAL report -> stored as alert
    |
    v
Optional async Ollama comment
    |
    v
SQLite + browser dashboard
```

Important: JSON-RPC gives bytecode and transaction data, not full Solidity. Source-level findings require verified source from Sourcify or Etherscan.

## What It Detects

- possible reentrancy: external value call before state update,
- Ether transfers without a visible `nonReentrant` guard,
- public withdrawal paths without obvious access control,
- unchecked low-level `call` / `send` results,
- full-balance sweep functions,
- `tx.origin`, `delegatecall`, and `selfdestruct` risk signals,
- transfers inside loops and time-dependent payout logic,
- token rug or honeypot indicators such as extreme owner-set taxes or hidden origin checks.

The analyzer reduces some common false positives: standard ERC20 `transfer` / `transferFrom` flows are not treated as open withdrawals by themselves, and account-bound pull-payment patterns are downgraded when state is updated before the external call.

## Live Monitor States

- `detected`: deployment was found and source lookup has started.
- `pending_source`: verified Solidity was not available yet; the monitor retries it.
- `analyzed`: verified source was found and the heuristic audit ran.

Alerts are created only for `HIGH` and `CRITICAL` heuristic risk. Ollama does not decide alert severity; it adds an asynchronous review comment to an existing report.

## UI Snapshot

SmartGuard has been run against Ethereum mainnet and produced live results like this:

![SmartGuard live run snapshot](docs/live-run-snapshot.svg)

The dashboard opens in **Live blockchain** mode and shows live alerts, recently detected contracts, report details, LLM status, findings, functions, and source excerpts when available.

## Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000
```

By default the backend autostarts live monitoring on Ethereum mainnet with Flashbots RPC, a 100-block lookback, and async Ollama enabled.

## Ollama

Ollama is optional. Without it, heuristic analysis and alerting still work; only the LLM comment is missing or marked with an LLM status.

```bash
ollama serve
ollama pull llama3.2:latest
```

Verify:

```bash
curl http://127.0.0.1:11434/api/tags
```

## API

- `GET /health`
- `POST /api/analyze`
- `POST /api/analyze-address`
- `POST /api/analyze-file`
- `POST /api/rpc/test`
- `POST /api/live/start`
- `POST /api/live/stop`
- `POST /api/live/clear`
- `GET /api/live/status`
- `GET /api/live/alerts`
- `GET /api/live/contracts`

## Persistence

Runtime data is stored in:

```text
data/smartguard.sqlite3
```

The database keeps scanned blocks, seen contracts, pending source contracts, reports, alerts, and LLM status/comments. Stored source excerpts are capped by `MAX_STORED_SOURCE_CHARS`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `LIVE_AUTOSTART` | `true` | Start live monitoring when FastAPI starts. |
| `LIVE_RPC_URL` | default RPC for chain | RPC URL used by autostart. |
| `LIVE_CHAIN_ID` | `1` | Chain ID, e.g. `1` for Ethereum mainnet. |
| `LIVE_POLL_INTERVAL` | `20` | Seconds between polling ticks. |
| `LIVE_LOOKBACK_BLOCKS` | `100` | Blocks scanned backwards from latest block when no start block is set. |
| `LIVE_START_BLOCK` | unset | Explicit first block for autostart. Overrides lookback when set. |
| `LIVE_MAX_BLOCKS_PER_TICK` | `12` | Max blocks scanned per monitor tick. |
| `LIVE_ANALYZE_LLM` | `true` | Queue Ollama comments for analyzed verified contracts. |
| `LIVE_LLM_MODEL` | `llama3.2:latest` | Ollama model used by live monitor. |
| `OLLAMA_MODEL` | `llama3.2:latest` | Default model for file/address analysis. |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama generation endpoint. |
| `ETHERSCAN_API_KEY` | unset | Optional fallback for verified source lookup. |
| `LOG_LEVEL` | `DEBUG` | Backend logging level. |
| `SMARTGUARD_API_TOKEN` | unset | Optional token for mutating/costly POST endpoints. |
| `CORS_ORIGINS` | local origins | Comma-separated allowed browser origins. |
| `MAX_SOURCE_CHARS` | `500000` | Maximum Solidity source length accepted by `/api/analyze`. |
| `MAX_UPLOAD_BYTES` | `1000000` | Maximum uploaded file size for `/api/analyze-file`. |
| `MAX_LOOKBACK_BLOCKS` | `1000` | Maximum accepted live lookback. |
| `MAX_BLOCKS_PER_TICK` | `25` | Maximum accepted live scan batch size. |
| `MAX_POLL_INTERVAL` | `3600` | Maximum accepted live polling interval in seconds. |
| `MAX_STORED_SOURCE_CHARS` | `120000` | Maximum Solidity source characters stored in report JSON. |

Examples:

```bash
LIVE_LOOKBACK_BLOCKS=500 LIVE_POLL_INTERVAL=10 ETHERSCAN_API_KEY=your_key \
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

```bash
LIVE_AUTOSTART=false uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

```bash
SMARTGUARD_API_TOKEN=change-me uvicorn app.main:app --host 127.0.0.1 --port 8000
curl -X POST -H "X-API-Token: change-me" http://127.0.0.1:8000/api/live/clear
```

## Docker

```bash
docker compose up --build
```

If Ollama runs on the host, set `OLLAMA_URL` so the container can reach it:

```bash
OLLAMA_URL=http://host.docker.internal:11434/api/generate docker compose up --build
```

## Tests

```bash
python3 -m unittest discover -s tests
python3 -m py_compile app/analyzer.py app/monitor.py app/main.py app/storage.py app/llm.py
```

## Troubleshooting

If everything is `pending_source`, the contracts were found but verified Solidity was not available yet. Add `ETHERSCAN_API_KEY`, wait for verification, scan older blocks, or increase `LIVE_LOOKBACK_BLOCKS`.

If LLM comments are missing, check that `ollama serve` is running, the model is pulled, and `OLLAMA_URL` points to the right endpoint.

If RPC tests fail, try another preset or provide your own RPC URL. Public endpoints may rate-limit requests.

## License

MIT License. See [LICENSE](LICENSE).

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import quote, urlencode
import urllib.error
import urllib.request

from pydantic import BaseModel


SOURCIFY_REPOSITORY = "https://repo.sourcify.dev/contracts"
ETHERSCAN_API = "https://api.etherscan.io/v2/api"
DEFAULT_PUBLIC_RPCS = {
    1: "https://rpc.flashbots.net",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
}
PUBLIC_RPC_CANDIDATES = {
    1: [
        "https://rpc.flashbots.net",
        "https://rpc.mevblocker.io",
        "https://eth.drpc.org",
        "https://eth-mainnet.public.blastapi.io",
        "https://1rpc.io/eth",
        "https://ethereum.blockpi.network/v1/rpc/public",
        "https://eth.llamarpc.com",
        "https://ethereum-rpc.publicnode.com",
        "https://rpc.ankr.com/eth",
    ],
    11155111: [
        "https://ethereum-sepolia-rpc.publicnode.com",
        "https://rpc.sepolia.org",
    ],
}


class BlockchainError(RuntimeError):
    pass


def default_rpc_url(chain_id: int) -> str | None:
    return DEFAULT_PUBLIC_RPCS.get(chain_id)


def rpc_candidates(chain_id: int, preferred: str | None = None) -> list[str]:
    candidates = []
    if preferred:
        candidates.append(preferred)
    candidates.extend(PUBLIC_RPC_CANDIDATES.get(chain_id, []))

    deduped: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


class ContractSource(BaseModel):
    address: str
    chain_id: int
    source: str
    source_name: str


def rpc_call(rpc_url: str, method: str, params: list[Any], timeout: int = 25) -> Any:
    payload = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": method, "params": params}
    request = urllib.request.Request(
        rpc_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": "SmartGuardAuditor/0.3",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise BlockchainError(f"RPC error for {method}: {exc}") from exc

    if data.get("error"):
        raise BlockchainError(data["error"].get("message", f"RPC returned error for {method}"))
    return data.get("result")


def latest_block_number(rpc_url: str) -> int:
    result = rpc_call(rpc_url, "eth_blockNumber", [])
    return int(result, 16)


def get_block(rpc_url: str, block_number: int) -> dict:
    result = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(block_number), True])
    if not result:
        raise BlockchainError(f"Block {block_number} not found")
    return result


def get_receipt(rpc_url: str, tx_hash: str) -> dict:
    result = rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash])
    if not result:
        raise BlockchainError(f"Receipt not ready for {tx_hash}")
    return result


def get_bytecode(rpc_url: str, address: str) -> str:
    return rpc_call(rpc_url, "eth_getCode", [address, "latest"]) or "0x"


def get_balance_wei(rpc_url: str, address: str, block: str = "latest") -> int:
    result = rpc_call(rpc_url, "eth_getBalance", [address, block])
    return int(result or "0x0", 16)


def format_eth(wei: int) -> str:
    eth = wei / 10**18
    if eth == 0:
        return "0 ETH"
    if eth < 0.000001:
        return f"{eth:.18f}".rstrip("0").rstrip(".") + " ETH"
    return f"{eth:.6f}".rstrip("0").rstrip(".") + " ETH"


def contract_creations_from_block(rpc_url: str, block_number: int) -> list[dict]:
    block = get_block(rpc_url, block_number)
    creations: list[dict] = []
    for tx in block.get("transactions", []):
        if tx.get("to") is not None:
            continue
        receipt = get_receipt(rpc_url, tx["hash"])
        address = receipt.get("contractAddress")
        if not address:
            continue
        creations.append(
            {
                "address": address,
                "tx_hash": tx["hash"],
                "block_number": block_number,
                "creator": tx.get("from"),
            }
        )
    return creations


def fetch_contract_source(address: str, chain_id: int, etherscan_api_key: str | None = None) -> ContractSource | None:
    source = fetch_sourcify_source(address, chain_id)
    if source:
        return ContractSource(address=address, chain_id=chain_id, source=source, source_name="Sourcify")

    if etherscan_api_key:
        source = fetch_etherscan_source(address, chain_id, etherscan_api_key)
        if source:
            return ContractSource(address=address, chain_id=chain_id, source=source, source_name="Etherscan")

    return None


def fetch_sourcify_source(address: str, chain_id: int) -> str | None:
    normalized = address.lower()
    for match_type in ("full_match", "partial_match"):
        metadata_url = f"{SOURCIFY_REPOSITORY}/{match_type}/{chain_id}/{normalized}/metadata.json"
        metadata = get_json(metadata_url)
        if not metadata:
            continue

        files: list[str] = []
        for path in (metadata.get("sources") or {}).keys():
            encoded_path = quote(path, safe="/")
            file_url = f"{SOURCIFY_REPOSITORY}/{match_type}/{chain_id}/{normalized}/sources/{encoded_path}"
            content = get_text(file_url)
            if content:
                files.append(f"// {path}\n{content}")

        if files:
            return "\n\n".join(files)
    return None


def fetch_etherscan_source(address: str, chain_id: int, api_key: str) -> str | None:
    query = urlencode(
        {
            "chainid": str(chain_id),
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }
    )
    payload = get_json(f"{ETHERSCAN_API}?{query}")
    if not payload:
        return None
    result = payload.get("result") or []
    if not result:
        return None
    raw_source = result[0].get("SourceCode") or ""
    if not raw_source.strip():
        return None
    return normalize_etherscan_source(raw_source)


def normalize_etherscan_source(source_code: str) -> str:
    trimmed = source_code.strip()
    wrapped_json = trimmed[1:-1] if trimmed.startswith("{{") and trimmed.endswith("}}") else trimmed

    try:
        parsed = json.loads(wrapped_json)
    except json.JSONDecodeError:
        return source_code

    sources = parsed.get("sources")
    if not isinstance(sources, dict):
        return source_code
    return "\n\n".join(f"// {path}\n{data.get('content', '')}" for path, data in sources.items())


def get_json(url: str) -> dict | None:
    text = get_text(url)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def get_text(url: str) -> str | None:
    request = urllib.request.Request(
        url,
        headers={
            "accept": "application/json,text/plain,*/*",
            "user-agent": "SmartGuardAuditor/0.3",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            if response.status >= 400:
                return None
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError):
        return None

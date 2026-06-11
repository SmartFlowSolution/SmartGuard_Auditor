from __future__ import annotations

from enum import IntEnum
import re
from typing import Iterable

from pydantic import BaseModel, Field


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


SEVERITY_LABELS = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}


class SolidityFunction(BaseModel):
    name: str
    signature: str
    body: str
    start_line: int
    end_line: int
    visibility: str = "unknown"


class Finding(BaseModel):
    severity: Severity
    title: str
    function: str
    reason: str
    recommendation: str
    evidence: str
    references: list[str] = Field(default_factory=list)
    source: str = "heuristic"

    def to_dict(self) -> dict:
        payload = self.model_dump()
        payload["severity"] = SEVERITY_LABELS[self.severity]
        payload["severity_score"] = int(self.severity)
        return payload


class AnalysisReport(BaseModel):
    contract_name: str
    functions: list[SolidityFunction]
    findings: list[Finding]
    llm_summary: str | None = None

    def to_dict(self) -> dict:
        counts = {label: 0 for label in SEVERITY_LABELS.values()}
        for finding in self.findings:
            counts[SEVERITY_LABELS[finding.severity]] += 1

        max_severity = max((finding.severity for finding in self.findings), default=Severity.INFO)
        return {
            "contract_name": self.contract_name,
            "risk": SEVERITY_LABELS[max_severity],
            "counts": counts,
            "functions": [fn.model_dump() for fn in self.functions],
            "findings": [
                item.to_dict()
                for item in sorted(self.findings, key=lambda finding: finding.severity, reverse=True)
            ],
            "llm_summary": self.llm_summary,
        }


class AccessControlInfo(BaseModel, frozen=True):
    kind: str
    description: str


def analyze_source(source: str, llm_summary: str | None = None) -> AnalysisReport:
    """Run the complete static-analysis pass for one Solidity source bundle."""
    normalized = strip_comments(source)
    contract_name = detect_contract_name(normalized)
    functions = parse_functions(normalized)
    findings = list(run_rules(normalized, functions))

    if not findings:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="No obvious withdrawal vulnerability detected",
                function="contract",
                reason="The rules did not find a known high-risk withdrawal pattern.",
                recommendation="Treat this as a first pass only. Run tests, fuzzing, and manual review.",
                evidence="No heuristic matched.",
                references=["OWASP SCSTG", "SWC Registry"],
            )
        )

    return AnalysisReport(
        contract_name=contract_name,
        functions=functions,
        findings=dedupe_findings(findings),
        llm_summary=llm_summary,
    )


def strip_comments(source: str) -> str:
    without_block = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//.*", "", without_block)


def detect_contract_name(source: str) -> str:
    match = re.search(r"\b(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)", source)
    return match.group(1) if match else "UnknownContract"


def parse_functions(source: str) -> list[SolidityFunction]:
    """Extract Solidity function-like blocks with line ranges for UI expansion."""
    pattern = re.compile(
        r"\b(function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*|"
        r"constructor\s*\([^)]*\)[^{;]*|"
        r"receive\s*\([^)]*\)\s*[^{;]*|"
        r"fallback\s*\([^)]*\)\s*[^{;]*)\{",
        re.MULTILINE,
    )
    functions: list[SolidityFunction] = []

    for match in pattern.finditer(source):
        open_brace = match.end() - 1
        close_brace = find_matching_brace(source, open_brace)
        if close_brace is None:
            continue

        signature = " ".join(match.group(1).split())
        name = match.group(2) or signature.split("(", 1)[0].strip()
        body = source[match.start() : close_brace + 1]
        start_line = source.count("\n", 0, match.start()) + 1
        end_line = source.count("\n", 0, close_brace) + 1
        visibility = detect_visibility(signature)
        functions.append(
            SolidityFunction(
                name=name,
                signature=signature,
                body=body,
                start_line=start_line,
                end_line=end_line,
                visibility=visibility,
            )
        )

    return functions


def find_matching_brace(source: str, open_brace: int) -> int | None:
    depth = 0
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def detect_visibility(signature: str) -> str:
    for visibility in ("public", "external", "internal", "private"):
        if re.search(rf"\b{visibility}\b", signature):
            return visibility
    return "default"


def run_rules(source: str, functions: Iterable[SolidityFunction]) -> Iterable[Finding]:
    """Apply source-wide and function-level heuristics while preserving finding order."""
    source_lower = source.lower()

    if re.search(r"\btx\.origin\b", source):
        yield Finding(
            severity=Severity.HIGH,
            title="Authorization uses tx.origin",
            function="contract",
            reason="tx.origin can be abused by a phishing contract that calls into this contract.",
            recommendation="Use msg.sender and explicit role checks instead of tx.origin.",
            evidence=snippet(source, r"\btx\.origin\b"),
            references=["SWC-115", "OWASP SCWE-018"],
        )

    if re.search(r"\bdelegatecall\s*\(", source):
        yield Finding(
            severity=Severity.HIGH,
            title="delegatecall detected",
            function="contract",
            reason="delegatecall executes external code in this contract's storage context.",
            recommendation="Avoid delegatecall in withdrawal paths or strictly pin and validate the implementation.",
            evidence=snippet(source, r"\bdelegatecall\s*\("),
            references=["SWC-112"],
        )

    if re.search(r"\bselfdestruct\s*\(|\bsuicide\s*\(", source):
        yield Finding(
            severity=Severity.MEDIUM,
            title="Selfdestruct capability detected",
            function="contract",
            reason="Forced balance movement or contract destruction changes withdrawal assumptions.",
            recommendation="Remove selfdestruct or gate it behind a reviewed emergency process.",
            evidence=snippet(source, r"\bselfdestruct\s*\(|\bsuicide\s*\("),
            references=["SWC-106"],
        )

    yield from analyze_source_level_token_rules(source, list(functions))

    for fn in functions:
        yield from analyze_function(fn, source_lower)


def analyze_function(fn: SolidityFunction, source_lower: str) -> Iterable[Finding]:
    """Inspect one Solidity function for withdrawal, reentrancy, and token-risk patterns."""
    body = fn.body
    visible_to_user = fn.visibility in {"public", "external"}
    external_call = has_external_value_call(body)
    token_transfer = has_token_transfer_call(fn)
    state_writes = state_write_positions(body)
    external_positions = external_call_positions(body)
    guard = access_control_info(body, fn.signature)
    has_guard = guard is not None
    has_reentrancy_guard = re.search(r"\bnonReentrant\b", fn.signature + body) or "reentrancyguard" in source_lower
    external_before_state = bool(external_call and state_writes and min(external_positions) < max(state_writes))
    account_bound_payout = has_account_bound_payout(body)

    if external_before_state:
        yield Finding(
            severity=Severity.CRITICAL,
            title="Possible Reentrancy",
            function=f"{fn.name}()",
            reason="External call happens before state update.",
            recommendation="Update balances or claim state before the external call and add nonReentrant.",
            evidence=compact(body),
            references=["SWC-107", "OWASP SCWE-046"],
        )

    if external_call and not has_reentrancy_guard:
        severity = Severity.MEDIUM if account_bound_payout and not external_before_state else Severity.HIGH
        yield Finding(
            severity=severity,
            title="Missing reentrancy guard around Ether transfer",
            function=f"{fn.name}()",
            reason=(
                "The function sends Ether without a visible nonReentrant guard. The payout appears tied to msg.sender accounting, "
                "so this is advisory unless another rule finds an unsafe call order."
                if severity == Severity.MEDIUM
                else "The function sends Ether without a visible nonReentrant guard."
            ),
            recommendation="Use checks-effects-interactions and OpenZeppelin ReentrancyGuard.",
            evidence=snippet(body, r"\.transfer\s*\(|\.send\s*\(|\.call\s*\{[^}]*value"),
            references=["SWC-107"],
        )

    if visible_to_user and (external_call or token_transfer) and not has_guard and not account_bound_payout:
        yield Finding(
            severity=Severity.CRITICAL,
            title="Public withdrawal path without obvious access control",
            function=f"{fn.name}()",
            reason="A public/external function transfers funds, but no role, owner, or sender balance check was detected.",
            recommendation="Add explicit authorization or prove that user-specific accounting limits the payout.",
            evidence=fn.signature,
            references=["OWASP SCWE-049"],
        )

    if re.search(r"\.call\s*\{[^}]*value", body) and not re.search(r"require\s*\([^;]*(success|ok|sent)|if\s*\([^)]*(success|ok|sent)", body):
        yield Finding(
            severity=Severity.HIGH,
            title="Unchecked low-level call result",
            function=f"{fn.name}()",
            reason="A low-level value call can fail without reverting unless its result is checked.",
            recommendation="Capture the boolean result and revert when the transfer fails.",
            evidence=snippet(body, r"\.call\s*\{[^}]*value"),
            references=["SWC-104"],
        )

    if re.search(r"\.send\s*\(", body) and not re.search(r"require\s*\([^;]*\.send|if\s*\([^)]*\.send", body):
        yield Finding(
            severity=Severity.HIGH,
            title="Unchecked send result",
            function=f"{fn.name}()",
            reason="send returns false on failure and does not automatically revert.",
            recommendation="Check the return value or use call with explicit success handling.",
            evidence=snippet(body, r"\.send\s*\("),
            references=["SWC-104"],
        )

    if external_call and re.search(r"address\s*\(\s*this\s*\)\.balance|\bthis\.balance\b", body):
        if guard and guard.kind in {"owner", "role", "specific_wallet"}:
            severity = Severity.MEDIUM
            title = "Privileged function can sweep contract ETH"
            reason = f"The function can transfer the whole ETH balance, but it is gated by {guard.description}."
        else:
            severity = Severity.CRITICAL
            title = "Function may drain entire contract balance"
            reason = "The payout appears to use the whole contract balance and no strong access control was detected."
        yield Finding(
            severity=severity,
            title=title,
            function=f"{fn.name}()",
            reason=reason,
            recommendation="For user withdrawals, pay only accounted balances. For emergency sweep, keep strict authorization and document the trust assumption.",
            evidence=snippet(body, r"address\s*\(\s*this\s*\)\.balance|\bthis\.balance\b"),
            references=["OWASP SCWE-049"],
        )

    if (external_call or token_transfer) and re.search(r"\b(for|while)\s*\(", body):
        yield Finding(
            severity=Severity.MEDIUM,
            title="Transfer inside loop",
            function=f"{fn.name}()",
            reason="Looped payouts can run out of gas or be blocked by one receiver.",
            recommendation="Use pull payments or bounded batches with retryable state.",
            evidence=snippet(body, r"\b(for|while)\s*\("),
            references=["OWASP SCWE-058"],
        )

    if (external_call or token_transfer) and re.search(r"\bblock\.(timestamp|number)\b|\bnow\b", body):
        yield Finding(
            severity=Severity.MEDIUM,
            title="Time-dependent payout logic",
            function=f"{fn.name}()",
            reason="Miners/validators can slightly influence timestamps and block timing.",
            recommendation="Use conservative windows and test boundary conditions.",
            evidence=snippet(body, r"\bblock\.(timestamp|number)\b|\bnow\b"),
            references=["SWC-116"],
        )

    if fn.name == "balanceOf" and re.search(r"\bpm\s*\(", fn.signature):
        yield Finding(
            severity=Severity.HIGH,
            title="balanceOf is gated by custom modifier",
            function="balanceOf()",
            reason="A standard ERC20 view function can return no value/revert depending on hidden modifier logic. This is often used to break wallets, routers, or honeypot simulations.",
            recommendation="Manually inspect the modifier and simulate balanceOf for pair/router/user/tax wallet addresses.",
            evidence=compact(fn.signature),
            references=["ERC-20 behavioral risk"],
        )

    if fn.name == "_transfer" and re.search(r"\b(tx\.origin|origin\s*\(\)|_taxCaller\s*\()", body):
        yield Finding(
            severity=Severity.HIGH,
            title="Transfer logic depends on transaction origin",
            function="_transfer()",
            reason="Token transfer behavior changes based on tx.origin-style logic, which can make DEX sells and contract-mediated transfers behave differently from direct user transfers.",
            recommendation="Simulate buy/sell through the router and compare with direct transfers. Treat this as a honeypot/backdoor indicator.",
            evidence=snippet(body, r"\b(tx\.origin|origin\s*\(\)|_taxCaller\s*\()"),
            references=["SWC-115", "Honeypot heuristic"],
        )


def has_external_value_call(body: str) -> bool:
    return bool(re.search(r"\.transfer\s*\(|\.send\s*\(|\.call\s*\{[^}]*value", body))


def has_token_transfer_call(fn: SolidityFunction) -> bool:
    body_without_signature = fn.body[len(fn.signature) :]
    if is_standard_erc20_entrypoint(fn):
        return bool(re.search(r"\bIERC20\s*\([^)]*\)\s*\.\s*(?:transfer|transferFrom)\s*\(", body_without_signature))
    return bool(
        re.search(
            r"(?:\b(?:safeTransfer|safeTransferFrom)\s*\(|\.\s*(?:transfer|transferFrom)\s*\()",
            body_without_signature,
        )
    )


def is_standard_erc20_entrypoint(fn: SolidityFunction) -> bool:
    return fn.name in {"transfer", "transferFrom", "approve", "increaseAllowance", "decreaseAllowance"}


def external_call_positions(body: str) -> list[int]:
    return [match.start() for match in re.finditer(r"\.transfer\s*\(|\.send\s*\(|\.call\s*\{[^}]*value", body)]


def state_write_positions(body: str) -> list[int]:
    positions: list[int] = []
    assignment = re.compile(r"(?<![=!<>])=(?!=)|\+=|-=|\*=|/=|\+\+|--|\bdelete\b")
    for match in assignment.finditer(body):
        statement = statement_around(body, match.start())
        if re.search(r"\b(require|if|return|emit|revert)\b", statement):
            continue
        if re.match(r"\s*(?:uint|uint256|int|int256|bool|address|string|bytes(?:\d+)?|var)\b", statement):
            continue
        if match.group(0) != "delete":
            lhs = statement[: statement.find(match.group(0))]
            if "[" not in lhs and "." not in lhs:
                continue
        positions.append(match.start())
    return positions


def statement_around(source: str, index: int) -> str:
    start = max(source.rfind(";", 0, index), source.rfind("{", 0, index), source.rfind("\n", 0, index)) + 1
    semicolon = source.find(";", index)
    newline = source.find("\n", index)
    candidates = [pos for pos in (semicolon, newline) if pos != -1]
    end = min(candidates) if candidates else len(source)
    return source[start:end]


def has_account_bound_payout(body: str) -> bool:
    """Detect common pull-payment accounting patterns keyed by msg.sender."""
    sender = r"(?:msg\.sender|_msgSender\(\))"
    account_slot = rf"\b(?:balances?|shares?|credits?|deposits?|claims?|allowance)\s*\[[^\]]*{sender}[^\]]*\]"
    value_vars = assigned_from_pattern(body, account_slot)
    value_terms = [account_slot, *[re.escape(var) for var in value_vars]]
    value_expr = rf"(?:{'|'.join(value_terms)})"

    if re.search(rf"require\s*\([^;]*{account_slot}", body, re.IGNORECASE):
        return True
    if re.search(rf"{account_slot}\s*(?:=|-=|\+=)", body, re.IGNORECASE) and value_vars:
        return True
    if re.search(rf"\.call\s*\{{[^}}]*value\s*:\s*{value_expr}\b", body, re.IGNORECASE):
        return True
    if re.search(rf"\.\s*(?:transfer|send)\s*\(\s*{value_expr}\b", body, re.IGNORECASE):
        return True
    return False


def assigned_from_pattern(body: str, pattern: str) -> set[str]:
    names: set[str] = set()
    for match in re.finditer(
        rf"\b(?:uint(?:256)?|int(?:256)?|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{pattern}",
        body,
        re.IGNORECASE,
    ):
        names.add(match.group(1))
    return names


def access_control_info(body: str, signature: str) -> AccessControlInfo | None:
    """Return the strongest obvious authorization signal visible in a function."""
    text = signature + "\n" + body

    if re.search(r"\bonlyOwner\b", signature, re.IGNORECASE):
        return AccessControlInfo("owner", "onlyOwner")
    if re.search(r"\bonlyRole\b|\bhasRole\s*\(", text, re.IGNORECASE):
        return AccessControlInfo("role", "role-based access control")

    sender = r"(?:msg\.sender|_msgSender\(\))"
    owner = r"(?:owner\s*\(\)|_owner|owner)"
    if re.search(rf"require\s*\([^;]*(?:{sender}\s*==\s*{owner}|{owner}\s*==\s*{sender})", text, re.IGNORECASE):
        return AccessControlInfo("owner", "explicit owner require")

    if re.search(rf"require\s*\([^;]*{sender}[^;]*==[^;]*_(?:taxWallet|feeWallet|marketingWallet|treasury|devWallet)", text, re.IGNORECASE):
        return AccessControlInfo("specific_wallet", "specific privileged wallet require")
    if re.search(rf"require\s*\([^;]*_(?:taxWallet|feeWallet|marketingWallet|treasury|devWallet)[^;]*==[^;]*{sender}", text, re.IGNORECASE):
        return AccessControlInfo("specific_wallet", "specific privileged wallet require")

    if re.search(rf"require\s*\([^;]*(?:balances?|shares?|credits?|claims?|allowance)\s*\[[^\]]*{sender}", text, re.IGNORECASE):
        return AccessControlInfo("accounting", "msg.sender accounting require")

    return None


def has_access_control(body: str, signature: str) -> bool:
    return access_control_info(body, signature) is not None


def analyze_source_level_token_rules(source: str, functions: list[SolidityFunction]) -> Iterable[Finding]:
    """Token-specific heuristics for rug/honeypot indicators, separate from exploitable withdrawal bugs."""
    modifier_map = parse_modifiers(source)

    for name, body in modifier_map.items():
        if re.search(r"\breturn\s*;", body) and re.search(r"\bif\s*\(", body):
            yield Finding(
                severity=Severity.HIGH,
                title="Modifier can silently skip function body",
                function=f"modifier {name}",
                reason="The modifier contains a conditional return before '_;'. This can make protected functions return default values or fail unexpectedly.",
                recommendation="Inspect every function using this modifier, especially ERC20 view/transfer functions used by DEX routers.",
                evidence=compact(body),
                references=["Honeypot heuristic"],
            )

    if re.search(r"require\s*\([^;]*(fee|tax)[A-Za-z0-9_]*\s*<=\s*99", source, re.IGNORECASE):
        yield Finding(
            severity=Severity.HIGH,
            title="Owner can set extreme token tax",
            function="contract",
            reason="The code allows a tax/fee parameter up to 99%, which can make selling economically impossible even if transfers do not revert.",
            recommendation="Report this as rug-risk, not as a public exploit. Check whether ownership is renounced and whether tax changes are timelocked.",
            evidence=snippet(source, r"require\s*\([^;]*(fee|tax)[A-Za-z0-9_]*\s*<=\s*99"),
            references=["Token rug-pull heuristic"],
        )

    if re.search(r"function\s+change(?:MarketingWallet|FeeWallet|TaxWallet)|_(?:taxWallet|feeWallet|marketingWallet)\s*=", source, re.IGNORECASE):
        yield Finding(
            severity=Severity.MEDIUM,
            title="Privileged fee wallet can be changed",
            function="contract",
            reason="A privileged wallet receiving ETH/taxes can be reassigned. This is normal for some tokens but increases trust assumptions.",
            recommendation="Check who controls owner/tax wallet and whether ownership was renounced.",
            evidence=snippet(source, r"function\s+change(?:MarketingWallet|FeeWallet|TaxWallet)|_(?:taxWallet|feeWallet|marketingWallet)\s*="),
            references=["Token owner-control heuristic"],
        )

    if re.search(r"assembly\s*\{[^}]*\borigin\s*\(\s*\)", source, re.IGNORECASE | re.DOTALL):
        yield Finding(
            severity=Severity.HIGH,
            title="Inline assembly reads tx.origin",
            function="contract",
            reason="The code reads tx.origin through assembly, which can hide origin-based logic from simple scanners.",
            recommendation="Track every caller of this helper and simulate router-mediated buys/sells.",
            evidence=snippet(source, r"assembly\s*\{[^}]*\borigin\s*\(\s*\)"),
            references=["SWC-115", "Honeypot heuristic"],
        )


def parse_modifiers(source: str) -> dict[str, str]:
    pattern = re.compile(r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{", re.MULTILINE)
    modifiers: dict[str, str] = {}
    for match in pattern.finditer(source):
        close = find_matching_brace(source, match.end() - 1)
        if close is None:
            continue
        modifiers[match.group(1)] = source[match.start(): close + 1]
    return modifiers


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.title, finding.function, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def snippet(source: str, pattern: str, radius: int = 260) -> str:
    match = re.search(pattern, source, re.IGNORECASE | re.DOTALL)
    if not match:
        return compact(source, 700)
    start = max(0, match.start() - radius)
    end = min(len(source), match.end() + radius)
    return compact(source[start:end], 700)


def compact(text: str, max_len: int = 1200) -> str:
    cleaned = "\n".join(line.rstrip() for line in text.strip().splitlines() if line.strip())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[:max_len] + "..."

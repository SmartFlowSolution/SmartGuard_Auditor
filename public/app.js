const fileModeButton = document.querySelector("#fileModeButton");
const liveModeButton = document.querySelector("#liveModeButton");
const fileControls = document.querySelector("#fileControls");
const liveControls = document.querySelector("#liveControls");
const fileView = document.querySelector("#fileView");
const liveView = document.querySelector("#liveView");
const monitorStatusCard = document.querySelector("#monitorStatusCard");
const monitorStatusLabel = document.querySelector("#monitorStatusLabel");
const monitorStatusMeta = document.querySelector("#monitorStatusMeta");

const editor = document.querySelector("#editor");
const fileInput = document.querySelector("#fileInput");
const dropZone = document.querySelector("#dropZone");
const analyzeButton = document.querySelector("#analyzeButton");
const sampleButton = document.querySelector("#sampleButton");
const llmToggle = document.querySelector("#llmToggle");
const modelInput = document.querySelector("#modelInput");
const statusText = document.querySelector("#statusText");
const reportTitle = document.querySelector("#reportTitle");
const riskBadge = document.querySelector("#riskBadge");
const findingsList = document.querySelector("#findingsList");
const functionList = document.querySelector("#functionList");
const llmSummary = document.querySelector("#llmSummary");

const rpcUrlInput = document.querySelector("#rpcUrlInput");
const rpcPresetInput = document.querySelector("#rpcPresetInput");
const chainIdInput = document.querySelector("#chainIdInput");
const etherscanKeyInput = document.querySelector("#etherscanKeyInput");
const pollIntervalInput = document.querySelector("#pollIntervalInput");
const lookbackBlocksInput = document.querySelector("#lookbackBlocksInput");
const startBlockInput = document.querySelector("#startBlockInput");
const liveLlmToggle = document.querySelector("#liveLlmToggle");
const liveModelInput = document.querySelector("#liveModelInput");
const startLiveButton = document.querySelector("#startLiveButton");
const stopLiveButton = document.querySelector("#stopLiveButton");
const testRpcButton = document.querySelector("#testRpcButton");
const clearAlertsButton = document.querySelector("#clearAlertsButton");
const liveStatus = document.querySelector("#liveStatus");
const liveStats = document.querySelector("#liveStats");
const alertsList = document.querySelector("#alertsList");
const contractsStatus = document.querySelector("#contractsStatus");
const contractsList = document.querySelector("#contractsList");
const detailKind = document.querySelector("#detailKind");
const detailBox = document.querySelector("#detailBox");

const counters = {
  CRITICAL: document.querySelector("#criticalCount"),
  HIGH: document.querySelector("#highCount"),
  MEDIUM: document.querySelector("#mediumCount"),
  LOW: document.querySelector("#lowCount"),
  INFO: document.querySelector("#infoCount"),
};

const liveState = {
  alerts: [],
  contracts: [],
};

let liveTimer = null;

fileModeButton.addEventListener("click", () => setMode("file"));
liveModeButton.addEventListener("click", () => setMode("live"));

sampleButton.addEventListener("click", async () => {
  const response = await fetch("/samples/VulnerableBank.sol");
  editor.value = await response.text();
  setStatus("Loaded vulnerable Bank sample.");
});

analyzeButton.addEventListener("click", () => analyzeSource(editor.value));
startLiveButton.addEventListener("click", startLiveMonitor);
stopLiveButton.addEventListener("click", stopLiveMonitor);
testRpcButton.addEventListener("click", testRpcEndpoints);
clearAlertsButton.addEventListener("click", clearLiveAlerts);

rpcPresetInput.addEventListener("change", () => {
  rpcUrlInput.value = rpcPresetInput.value;
  chainIdInput.value = rpcPresetInput.value.includes("sepolia") ? "11155111" : "1";
});

fileInput.addEventListener("change", async () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  editor.value = await file.text();
  setStatus(`Loaded file ${file.name}.`);
});

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("active");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("active");
  });
}

dropZone.addEventListener("drop", async (event) => {
  const file = event.dataTransfer.files?.[0];
  if (!file) return;
  editor.value = await file.text();
  setStatus(`Loaded file ${file.name}.`);
});

setMode("live");
scheduleLivePolling();

function setMode(mode) {
  const live = mode === "live";
  fileModeButton.classList.toggle("active", !live);
  liveModeButton.classList.toggle("active", live);
  fileControls.classList.toggle("active", !live);
  liveControls.classList.toggle("active", live);
  fileView.classList.toggle("active", !live);
  liveView.classList.toggle("active", live);
  setStatus(live ? "Live mode: blockchain monitor, alerts, and recent contracts." : "File audit mode: paste Solidity or drop a .sol file.");
}

async function analyzeSource(source) {
  if (!source.trim()) {
    setStatus("Paste Solidity code or drop a .sol file.", true);
    return;
  }

  analyzeButton.disabled = true;
  analyzeButton.textContent = "Analyzing...";
  setStatus("The parser finds functions, rules check known patterns, and Ollama receives only the result plus a code excerpt.");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source,
        use_llm: llmToggle.checked,
        model: modelInput.value.trim() || null,
      }),
    });

    if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
    renderReport(await response.json());
  } catch (error) {
    setStatus(error.message || "Analysis failed.", true);
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = "Analyze contract";
  }
}

async function startLiveMonitor() {
  startLiveButton.disabled = true;
  const llmMode = liveLlmToggle.checked ? `Ollama: ${liveModelInput.value.trim() || "default model"}` : "Ollama disabled";
  setStatus(`Starting live monitor on public RPC. ${llmMode}. Public endpoints may be slower because of rate limits.`);
  try {
    const response = await fetch("/api/live/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        rpc_url: rpcUrlInput.value.trim() || null,
        chain_id: Number(chainIdInput.value || 1),
        etherscan_api_key: etherscanKeyInput.value.trim() || null,
        poll_interval: Number(pollIntervalInput.value || 20),
        start_block: startBlockInput.value.trim() ? Number(startBlockInput.value.trim()) : null,
        lookback_blocks: Number(lookbackBlocksInput.value || 100),
        max_blocks_per_tick: 12,
        analyze_llm: liveLlmToggle.checked,
        llm_model: liveModelInput.value.trim() || null,
      }),
    });
    if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
    renderLiveStatus(await response.json());
    scheduleLivePolling();
    setMode("live");
  } catch (error) {
    setStatus(error.message || "Could not start live monitor.", true);
  } finally {
    startLiveButton.disabled = false;
  }
}

async function testRpcEndpoints() {
  testRpcButton.disabled = true;
  setStatus("Testing public RPC endpoints. This may take a few seconds.");
  try {
    const response = await fetch("/api/rpc/test", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        rpc_url: rpcUrlInput.value.trim() || null,
        chain_id: Number(chainIdInput.value || 1),
      }),
    });
    if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
    const result = await response.json();
    if (result.working) {
      rpcUrlInput.value = result.working.rpc_url;
      setStatus(`Working: ${result.working.rpc_url}, latest block ${result.working.latest_block}.`);
      return;
    }
    const firstError = result.results?.[0]?.error || "no working public RPC";
    setStatus(`No working RPC found. First error: ${firstError}`, true);
  } catch (error) {
    setStatus(error.message || "RPC test failed.", true);
  } finally {
    testRpcButton.disabled = false;
  }
}

async function stopLiveMonitor() {
  await fetch("/api/live/stop", { method: "POST" });
  renderLiveStatus(await fetchJson("/api/live/status"));
  if (liveTimer) clearInterval(liveTimer);
  liveTimer = null;
  setStatus("Live monitor stopped.");
}

async function clearLiveAlerts() {
  await fetch("/api/live/clear", { method: "POST" });
  await refreshLiveData();
}

function scheduleLivePolling() {
  if (liveTimer) clearInterval(liveTimer);
  refreshLiveData();
  liveTimer = setInterval(refreshLiveData, 5000);
}

async function refreshLiveData() {
  try {
    const [status, alerts, contracts] = await Promise.all([
      fetchJson("/api/live/status"),
      fetchJson("/api/live/alerts"),
      fetchJson("/api/live/contracts"),
    ]);
    liveState.alerts = alerts;
    liveState.contracts = contracts;
    renderLiveStatus(status);
    renderAlerts(alerts);
    renderContracts(contracts);
  } catch (error) {
    liveStatus.textContent = "Could not refresh monitor";
    monitorStatusCard.className = "monitor-status checking";
    monitorStatusLabel.textContent = "Monitoring status unknown";
    monitorStatusMeta.textContent = "Live API is not responding";
  }
}

function renderLiveStatus(status) {
  const state = status.running ? "running" : "stopped";
  const totalContracts = status.stored_contracts ?? status.scanned_contracts ?? 0;
  liveStatus.textContent = `Monitor ${state} · block ${status.last_block ?? "-"} / ${status.latest_seen_block ?? "-"} · contracts ${totalContracts} total / ${
    status.scanned_contracts ?? 0
  } this run · skipped blocks ${status.skipped_blocks ?? 0} · stored blocks ${status.stored_blocks ?? 0} · alerts ${status.alerts ?? 0}`;
  const lastBlock = status.last_block ?? "-";
  liveStats.innerHTML = `
    <div title="${escapeHtml(lastBlock)}"><strong>${escapeHtml(lastBlock)}</strong><span>Last block</span></div>
    <div title="${escapeHtml(`${totalContracts} total, ${status.scanned_contracts ?? 0} this run`)}"><strong>${escapeHtml(totalContracts)}</strong><span>Contracts checked</span></div>
    <div><strong>${escapeHtml(status.pending_unverified ?? 0)}</strong><span>Pending contracts</span></div>
    <div><strong>${escapeHtml(status.alerts ?? 0)}</strong><span>Alert contracts</span></div>
  `;
  monitorStatusCard.className = `monitor-status ${status.running ? "running" : "stopped"}`;
  monitorStatusLabel.textContent = status.running ? "Monitoring enabled" : "Monitoring disabled";
  monitorStatusMeta.textContent = `Block ${status.last_block ?? "-"} / ${status.latest_seen_block ?? "-"} · alerts ${status.alerts ?? 0}`;
  if (status.last_error) {
    setStatus(`Live monitor error: ${status.last_error}`, true);
  }
}

function renderAlerts(alerts) {
  if (!alerts.length) {
    alertsList.className = "alerts empty";
    alertsList.innerHTML = "<p>No alerts. The monitor will show HIGH/CRITICAL contracts here.</p>";
    return;
  }

  const groups = groupAlerts(alerts);
  alertsList.className = "alerts grouped";
  alertsList.innerHTML = groups
    .map(
      (group) => `
        <details class="alert-group ${group.severity.toLowerCase()}" open>
          <summary>
            <span class="risk ${group.severity.toLowerCase()}">${escapeHtml(group.severity)}</span>
            <strong>${escapeHtml(group.title)}</strong>
            <span class="alert-count">${group.items.length} ${pluralizeAlert(group.items.length)}</span>
          </summary>
          <div class="alert-group-items">
            ${group.items
              .map(({ alert, index }) => {
                const findings = (alert.report?.findings || []).slice(0, 3);
                return `
                  <button class="alert ${String(alert.risk || group.severity).toLowerCase()}" type="button" data-alert-index="${index}">
                    <header>
                      <div>
                        <span class="severity">${escapeHtml(alert.risk || group.severity)}</span>
                        <h3>${escapeHtml(alert.address)}</h3>
                      </div>
            <strong>block ${escapeHtml(alert.block_number)}</strong>
                    </header>
                    <p>${escapeHtml(alert.source_name)} · tx ${escapeHtml(shortHash(alert.tx_hash))} · balance ${escapeHtml(alert.report?.balance_eth || "unknown")}</p>
                    <ul>
                      ${findings.map((finding) => `<li>${escapeHtml(finding.severity)}: ${escapeHtml(finding.title)}</li>`).join("")}
                    </ul>
                  </button>
                `;
              })
              .join("")}
          </div>
        </details>
      `,
    )
    .join("");

  for (const item of alertsList.querySelectorAll("[data-alert-index]")) {
    item.addEventListener("click", () => {
      markSelected(alertsList, item);
      showAlertDetail(liveState.alerts[Number(item.dataset.alertIndex)]);
    });
  }
}

function groupAlerts(alerts) {
  const groups = new Map();
  alerts.forEach((alert, index) => {
    const primary = alert.report?.findings?.[0] || {};
    const severity = normalizeSeverity(alert.risk || primary.severity || "INFO");
    const title = primary.title || "Other warnings";
    const key = `${severity}:${title}`;
    if (!groups.has(key)) {
      groups.set(key, { severity, title, items: [] });
    }
    groups.get(key).items.push({ alert, index });
  });

  return Array.from(groups.values()).sort((left, right) => {
    const severityDiff = severityWeight(right.severity) - severityWeight(left.severity);
    if (severityDiff !== 0) return severityDiff;
    const countDiff = right.items.length - left.items.length;
    if (countDiff !== 0) return countDiff;
    return left.title.localeCompare(right.title);
  });
}

function normalizeSeverity(value) {
  const severity = String(value || "INFO").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(severity) ? severity : "INFO";
}

function severityWeight(severity) {
  return { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 }[normalizeSeverity(severity)] || 0;
}

function pluralizeAlert(count) {
  if (count === 1) return "alert";
  return "alerts";
}

function renderContracts(contracts) {
  contractsStatus.textContent = `${contracts.length} visible`;
  if (!contracts.length) {
    contractsList.className = "contracts empty";
    contractsList.innerHTML = "<p>No new contracts detected yet.</p>";
    return;
  }

  contractsList.className = "contracts";
  contractsList.innerHTML = contracts
    .map(
      (contract, index) => `
        <button class="contract-row ${contract.status}" type="button" data-contract-index="${index}">
          <header>
            <div>
              <span class="severity">${escapeHtml(translateStatus(contract.status))}</span>
              <h3>${escapeHtml(contract.address)}</h3>
            </div>
            <strong>block ${escapeHtml(contract.block_number)}</strong>
          </header>
          <p>${escapeHtml(contract.reason)}</p>
          <div class="row-badges">
            <span>${escapeHtml(contract.source_name || "unverified")}</span>
            <span>${escapeHtml(contract.risk || "not assessed")}</span>
            <span>${escapeHtml(contract.report?.llm_status ? `LLM ${contract.report.llm_status}` : "LLM waiting")}</span>
          </div>
          <dl>
            <dt>Tx</dt>
            <dd>${escapeHtml(shortHash(contract.tx_hash))}</dd>
            <dt>Creator</dt>
            <dd>${escapeHtml(shortHash(contract.creator))}</dd>
            <dt>Source</dt>
            <dd>${escapeHtml(contract.source_name || "no verified Solidity")}</dd>
            <dt>Risk</dt>
            <dd>${escapeHtml(contract.risk || "not assessed")}</dd>
            <dt>Balance</dt>
            <dd>${escapeHtml(contract.balance_eth || "unknown")}</dd>
          </dl>
        </button>
      `,
    )
    .join("");

  for (const item of contractsList.querySelectorAll("[data-contract-index]")) {
    item.addEventListener("click", () => {
      markSelected(contractsList, item);
      showContractDetail(liveState.contracts[Number(item.dataset.contractIndex)]);
    });
  }
}

function showAlertDetail(alert) {
  if (!alert) return;
  detailKind.textContent = "alert";
  const report = alert.report || {};
  const findings = report.findings || [];
  detailBox.className = "detail-box";
  detailBox.innerHTML = `
    <div class="detail-head">
      <span class="risk ${String(alert.risk || "info").toLowerCase()}">${escapeHtml(alert.risk || "INFO")}</span>
      <h3>${escapeHtml(alert.address)}</h3>
    </div>
    ${renderKeyValue({
      Chain: alert.chain_id,
      Block: alert.block_number,
      Tx: alert.tx_hash,
      Creator: alert.creator || "-",
      Source: alert.source_name,
      Risk: report.risk || alert.risk,
      Balance: report.balance_eth || "unknown",
      "Funds at risk": report.funds_at_risk ? "yes" : "no",
    })}
    <div class="section-title inline"><h2>Findings</h2><span>${findings.length}</span></div>
    <div class="findings detail-list">
      ${findings.map(renderFinding).join("") || "<p>No findings in the report.</p>"}
    </div>
    <div class="section-title inline"><h2>LLM comment</h2></div>
    <pre>${escapeHtml(report.llm_summary || llmReportStatusMessage(report))}</pre>
    <div class="section-title inline"><h2>Functions</h2><span>${(report.functions || []).length}</span></div>
    <div class="functions detail-list">
      ${renderFunctionList(report.functions || [])}
    </div>
    ${renderSourceCode(report)}
  `;
}

function showContractDetail(contract) {
  if (!contract) return;
  const report = contract.report || {};
  const llmSummary = report.llm_summary;
  detailKind.textContent = "contract";
  detailBox.className = "detail-box";
  detailBox.innerHTML = `
    <div class="detail-head">
      <span class="pill">${escapeHtml(translateStatus(contract.status))}</span>
      <h3>${escapeHtml(contract.address)}</h3>
    </div>
    <p>${escapeHtml(contract.reason)}</p>
    ${renderKeyValue({
      Chain: contract.chain_id,
      Block: contract.block_number,
      Tx: contract.tx_hash,
      Creator: contract.creator || "-",
      Source: contract.source_name || "no verified Solidity",
      Risk: report.risk || contract.risk || "not assessed",
      Balance: contract.balance_eth || "unknown",
      Retries: contract.tries || 0,
      Updated: contract.updated_at || "-",
    })}
    <div class="section-title inline"><h2>Bytecode preview</h2></div>
    <pre>${escapeHtml(contract.bytecode_preview || "No bytecode preview. The contract may have only been detected before code retrieval.")}</pre>
    <div class="section-title inline"><h2>LLM comment</h2></div>
    <pre>${escapeHtml(llmSummary || llmStatusMessage(contract, report))}</pre>
    ${renderSourceCode(report)}
  `;
}

function llmStatusMessage(contract, report) {
  if (contract.status !== "analyzed") return "LLM will run after verified Solidity source is retrieved.";
  if (!report || !Object.keys(report).length) return "This contract was analyzed before full report persistence was enabled. Wait for a re-audit or restart monitoring.";
  return llmReportStatusMessage(report);
}

function llmReportStatusMessage(report) {
  if (report?.llm_status === "queued") return "LLM comment is queued. The monitor does not wait for Ollama and keeps fetching data.";
  if (report?.llm_status === "done") return "Ollama finished analysis and stored a comment.";
  if (report?.llm_status === "empty") return "Ollama returned an empty comment. Check backend logs and the model.";
  if (report?.llm_status === "error") return `LLM analysis failed${report.llm_error ? `: ${report.llm_error}` : ". Check backend logs."}`;
  if (report?.llm_status === "interrupted") return "The queued Ollama job was interrupted by a backend restart. Re-scan or restart live monitoring to queue it again.";
  return "No LLM comment for this record.";
}

function renderReport(report) {
  reportTitle.textContent = report.contract_name || "Report";
  riskBadge.textContent = report.risk;
  riskBadge.className = `risk ${report.risk.toLowerCase()}`;

  for (const [key, element] of Object.entries(counters)) {
    element.textContent = report.counts?.[key] || 0;
  }

  findingsList.innerHTML = report.findings.map(renderFinding).join("");

  functionList.innerHTML = renderFunctionList(report.functions || []);

  llmSummary.textContent =
    report.llm_summary ||
    (llmToggle.checked
      ? "No response from Ollama. Check that `ollama serve` is running and the model is downloaded."
      : "LLM analysis was disabled.");

  setStatus(`Analysis complete. Functions: ${report.functions.length}, findings: ${report.findings.length}.`);
}

function renderSourceCode(report) {
  if (!report?.source_code) {
    return `
      <div class="section-title inline"><h2>Solidity code</h2></div>
      <pre>No source code stored for this record. New audits after backend restart will persist full Solidity code.</pre>
    `;
  }
  const sourceMeta = report.source_truncated
    ? `${escapeHtml(report.source_code.length)} of ${escapeHtml(report.source_chars || report.source_code.length)} chars stored`
    : `${escapeHtml(report.source_code.length)} chars`;
  return `
    <div class="section-title inline"><h2>Solidity code</h2><span>${sourceMeta}</span></div>
    <pre class="source-code">${escapeHtml(report.source_code)}</pre>
  `;
}

function renderFunctionList(functions) {
  if (!functions.length) return "<p>No functions.</p>";
  return functions.map(renderFunctionDetails).join("");
}

function renderFunctionDetails(fn) {
  return `
    <details class="function-row">
      <summary>
        <strong>${escapeHtml(fn.name)}()</strong>
        <span>${escapeHtml(fn.visibility)} · lines ${escapeHtml(fn.start_line)}-${escapeHtml(fn.end_line)}</span>
      </summary>
      <pre>${escapeHtml(fn.body || fn.signature || "No function body available.")}</pre>
    </details>
  `;
}

function renderFinding(finding) {
  return `
    <article class="finding ${String(finding.severity || "info").toLowerCase()}">
      <header>
        <div>
          <span class="severity">${escapeHtml(finding.severity)}</span>
          <h3>${escapeHtml(finding.title)}</h3>
        </div>
        <strong>${escapeHtml(finding.function)}</strong>
      </header>
      <dl>
        <dt>Reason</dt>
        <dd>${escapeHtml(finding.reason)}</dd>
        <dt>Recommendation</dt>
        <dd>${escapeHtml(finding.recommendation)}</dd>
      </dl>
      <pre>${escapeHtml(finding.evidence)}</pre>
      <p class="refs">${escapeHtml((finding.references || []).join(" · "))}</p>
    </article>
  `;
}

function translateStatus(value) {
  return {
    detected: "detected",
    pending_source: "pending source",
    analyzed: "analyzed",
  }[String(value || "").toLowerCase()] || value || "unknown";
}

function markSelected(container, item) {
  for (const selected of container.querySelectorAll(".selected")) {
    selected.classList.remove("selected");
  }
  item.classList.add("selected");
}

function renderKeyValue(values) {
  return `
    <dl class="kv">
      ${Object.entries(values)
        .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value ?? "-")}</dd>`)
        .join("")}
    </dl>
  `;
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
  return response.json();
}

function shortHash(value) {
  if (!value || value.length < 14) return value || "-";
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

function setStatus(message, error = false) {
  statusText.textContent = message;
  statusText.className = error ? "status error" : "status";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

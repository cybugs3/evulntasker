let rows = [];

const STAGE_LABELS = {
  INGESTED: "Ingest",
  EXTRACTED: "Extract",
  ENRICHED: "Enrichment (NVD/EPSS)",
  MATCHED: "Asset match (local inventory)",
  ACTIONED: "Actioned",
  AI_FALLBACK: "Targeted AI fallback",
  FAILED: "Failed",
};

function runStatus(row) {
  const status = pipelineStatus(row.status || row.pipeline_status);
  if (status === "FAILED") return { cls: "st-error", label: "Failed (retry)" };
  if (status === "AI_FALLBACK") return { cls: "st-paused", label: "Processing (AI)" };
  if (status === "ACTIONED") return { cls: "st-ok", label: "Completed (success)" };
  if (status === "MATCHED") return { cls: "st-ok", label: "Matched" };
  return { cls: "st-syncing", label: "Processing" };
}

function priorityEl(row) {
  const sev = String(row.severity || "").toUpperCase();
  if (sev === "CRITICAL") return makePill("sev", "CRITICAL");
  if (sev === "HIGH") return makePill("sev", "HIGH");
  if (sev === "MEDIUM") return makePill("sev", "MEDIUM");
  if (sev === "LOW") return makePill("sev", "LOW");
  return makePill("pri", row.priority || "P3");
}

function targetTeam(row) {
  const ticket = (row.tickets || []).find((t) => t.assignee) || (row.tickets || [])[0];
  return (ticket && ticket.assignee) || "Unassigned";
}

function jiraEl(row) {
  const tickets = row.tickets || [];
  if (!tickets.length) return labeledPill("st-paused", "PENDING");
  const first = tickets[0];
  if (first.dry_run) return labeledPill("st-paused", first.ticket_key || "DRY-RUN");
  if (first.url) {
    const a = document.createElement("a");
    a.className = "link";
    a.href = first.url;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = first.ticket_key || "ticket";
    return a;
  }
  return labeledPill("st-error", "ERROR");
}

function renderTable() {
  const q = (document.getElementById("table-search").value || "").toLowerCase();
  const status = document.getElementById("status-filter").value;
  const tbody = document.getElementById("vuln-tbody");
  const filtered = rows.filter((row) => {
    const hay = `${row.cve_id} ${row.source_name || ""} ${targetTeam(row)}`.toLowerCase();
    const okQ = !q || hay.includes(q);
    const rowStatus = pipelineStatus(row.status || row.pipeline_status);
    const okS = !status || rowStatus === status;
    return okQ && okS;
  });
  if (!filtered.length) {
    setEmptyRow(tbody, 7, "No vulnerabilities match the current filters.");
    return;
  }
  tbody.replaceChildren();
  filtered.forEach((row) => {
    const stage = pipelineStatus(row.status || row.pipeline_status);
    const run = runStatus(row);
    const href = `/vulnerabilities/${encodeURIComponent(row.cve_id)}`;
    const tr = useTemplate("tpl-status-row");
    tr.dataset.href = href;
    const link = slot(tr, "cve-link");
    link.href = href;
    link.textContent = row.cve_id;
    slot(tr, "source").textContent = dash(row.source_name);
    slot(tr, "stage").textContent = STAGE_LABELS[stage] || stage;
    const runEl = labeledPill(run.cls, run.label);
    slot(tr, "run").replaceChildren(runEl);
    slot(tr, "priority").replaceChildren(priorityEl(row));
    slot(tr, "team").textContent = targetTeam(row);
    slot(tr, "jira").replaceChildren(jiraEl(row));
    tbody.appendChild(tr);
  });
}

function renderIntegrations(data) {
  const root = document.getElementById("integ-list");
  const items = (data && data.integrations) || [];
  root.replaceChildren();
  if (!items.length) {
    root.appendChild(useTemplate("tpl-integ-empty"));
    return;
  }
  items.forEach((item) => {
    const li = fillTemplate("tpl-integ-item", {
      name: item.name,
      state: item.ok ? "Connected" : "Not configured",
    });
    slot(li, "dot").classList.add(item.ok ? "is-on" : "is-off");
    root.appendChild(li);
  });
}

async function loadStatus() {
  const [vulns, integrations] = await Promise.all([
    api("/api/vulnerabilities"),
    api("/api/integrations"),
  ]);
  rows = vulns;
  renderTable();
  renderIntegrations(integrations);
}

document.getElementById("table-search").addEventListener("input", renderTable);
document.getElementById("status-filter").addEventListener("change", renderTable);
document.getElementById("refresh-btn").addEventListener("click", loadStatus);
loadStatus().catch((err) => {
  setEmptyRow(document.getElementById("vuln-tbody"), 7, `Failed to load status: ${err.message}`);
});
setInterval(loadStatus, 30000);

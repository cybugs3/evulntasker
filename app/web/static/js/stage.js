const stage = document.querySelector("script[data-stage]")?.dataset.stage || "extraction";

function setCveLink(tr, href, cveId) {
  tr.dataset.href = href;
  const link = slot(tr, "cve-link");
  link.href = href;
  link.textContent = cveId;
}

function fillCveList(cell, cves) {
  const items = Array.isArray(cves) ? cves : [];
  cell.replaceChildren();
  if (!items.length) {
    cell.appendChild(mutedText("none"));
    return;
  }
  items.forEach((cve, i) => {
    if (i) cell.appendChild(document.createTextNode(", "));
    const a = useTemplate("tpl-cve-link");
    const link = slot(a, "link");
    link.href = `/vulnerabilities/${encodeURIComponent(cve)}`;
    link.textContent = cve;
    cell.appendChild(a);
  });
}

function ticketEl(key, url, dryRun) {
  if (!key) return mutedText("—");
  if (url && !dryRun) {
    const a = document.createElement("a");
    a.className = "link";
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = key;
    return a;
  }
  return labeledPill("st-paused", dryRun ? `${key} dry-run` : key);
}

function actionStatusEl(row, ticketing) {
  const ticketingInfo = ticketing || {};
  let state = row.action_state;
  let label = row.action_label;
  if (!label) {
    const name = ticketingInfo.provider_label || "ticketing";
    if (row.owner_ticket && !row.dry_run) {
      state = "created";
      label = `New ${name} task created`;
    } else if (ticketingInfo.connected) {
      state = "waiting";
      label = `Waiting to open ${name} task`;
    } else {
      state = "not_connected";
      label = "No ticketing system connected";
    }
  }
  const cls = state === "created" ? "st-ok" : "st-paused";
  const pill = labeledPill(cls, label);
  pill.classList.add("action-pill");
  return pill;
}

function renderKpis(kpis) {
  document.querySelectorAll("#stage-kpis [data-k]").forEach((el) => {
    const value = kpis[el.dataset.k];
    el.textContent = value == null ? "—" : fmtNum(value);
  });
}

function renderExtraction(data) {
  const events = data.events || [];
  const eventBody = document.getElementById("event-tbody");
  if (eventBody) {
    if (!events.length) {
      setEmptyRow(eventBody, 5, "No ingest events with a CVE ID yet.");
    } else {
      eventBody.replaceChildren();
      events.forEach((row) => {
        const tr = useTemplate("tpl-extract-event");
        slot(tr, "source").textContent = dash(row.source);
        slot(tr, "filename").textContent = dash(row.filename);
        fillCveList(slot(tr, "cves"), row.cves);
        slot(tr, "status").replaceChildren(makePipelinePill(row.status));
        slot(tr, "received").textContent = fmtTime(row.received_at);
        eventBody.appendChild(tr);
      });
    }
  }
  const tbody = document.getElementById("stage-tbody");
  const rows = data.rows || [];
  if (!rows.length) {
    setEmptyRow(tbody, 5, "No extracted CVE records yet.");
    return;
  }
  tbody.replaceChildren();
  rows.forEach((row) => {
    const tr = useTemplate("tpl-extract-row");
    setCveLink(tr, row.href, row.cve_id);
    slot(tr, "source").textContent = dash(row.source);
    slot(tr, "status").replaceChildren(
      labeledPill(
        row.waiting ? "st-paused" : row.unmatched ? "st-paused" : row.completed ? "st-ok" : "st-syncing",
        row.run_label || row.station_label || pipelineStatus(row.status)
      )
    );
    slot(tr, "ai").replaceChildren(row.ai_extract ? labeledPill("st-ok", "AI") : mutedText("regex"));
    slot(tr, "updated").textContent = fmtTime(row.updated_at);
    tbody.appendChild(tr);
  });
}

function renderEnrichment(data) {
  const tbody = document.getElementById("stage-tbody");
  const rows = data.rows || [];
  if (!rows.length) {
    setEmptyRow(tbody, 6, "No CVE records to enrich yet.");
    return;
  }
  tbody.replaceChildren();
  rows.forEach((row) => {
    const tr = useTemplate("tpl-enrich-row");
    setCveLink(tr, row.href, row.cve_id);
    slot(tr, "product").textContent = `${dash(row.vendor)} / ${dash(row.product)}`;
    slot(tr, "scores").textContent = `${row.cvss == null ? "—" : row.cvss} / ${row.epss == null ? "—" : row.epss}`;
    slot(tr, "vector").textContent = dash(row.attack_vector);
    slot(tr, "missing").textContent = (row.missing || []).join(", ") || "—";
    let method;
    if (row.waiting) {
      const when = row.retry_at ? ` Retry ${fmtTime(row.retry_at)}` : "";
      const timed = row.wait_kind === "timeout" || row.wait_kind === "unreachable";
      method = labeledPill("st-paused", `${timed ? "NVD/EPSS timed out" : "Waiting for intel"}${when}`);
      method.title = row.wait_reason || "Matching and tickets are paused until enrichment is complete.";
    } else if (row.ai_enrich) method = labeledPill("st-ok", "AI");
    else if (row.intel) method = labeledPill("st-ok", "NVD/EPSS");
    else if (row.skipped) method = labeledPill("st-paused", "Skipped");
    else method = mutedText("No intel yet");
    slot(tr, "method").replaceChildren(method);
    tbody.appendChild(tr);
  });
}

function renderMatching(data) {
  const tbody = document.getElementById("stage-tbody");
  const rows = data.rows || [];
  if (!rows.length) {
    setEmptyRow(tbody, 6, "No assets to match yet. Enrichment must finish first.");
    return;
  }
  tbody.replaceChildren();
  rows.forEach((row) => {
    const tr = useTemplate("tpl-match-row");
    setCveLink(tr, row.href, row.cve_id);
    slot(tr, "product").textContent = `${dash(row.vendor)} / ${dash(row.product)}`;
    slot(tr, "asset").textContent = row.asset || "Unmatched";
    slot(tr, "owner").textContent = dash(row.owner);
    slot(tr, "team").textContent = row.team || "";
    slot(tr, "method").textContent = dash(row.method);
    const unmatched = Boolean(row.unmatched);
    slot(tr, "status").replaceChildren(
      unmatched
        ? labeledPill("st-paused", row.run_label || "Unmatched")
        : labeledPill(
            row.completed ? "st-ok" : "st-syncing",
            row.run_label || row.station_label || (row.ai_match ? "AI" : "Matched")
          )
    );
    tbody.appendChild(tr);
  });
}

function renderActions(data) {
  const ticketing = data.ticketing || {};
  const hint = document.getElementById("ticketing-hint");
  if (hint) {
    if (ticketing.connected) {
      hint.textContent = `Ticketing is connected to ${ticketing.provider_label}. Only matched CVEs get tickets.`;
    } else {
      hint.textContent =
        "No ticketing system is connected. Configure Jira, Monday.com, email (mail relay), or an internal CRM in Settings. Tasks stay waiting until a provider is enabled.";
    }
  }
  const tbody = document.getElementById("stage-tbody");
  const rows = data.rows || [];
  if (!rows.length) {
    setEmptyRow(tbody, 5, "No tickets yet. Matched CVEs appear here before ticketing and SIEM actions.");
    return;
  }
  tbody.replaceChildren();
  rows.forEach((row) => {
    const tr = useTemplate("tpl-action-row");
    setCveLink(tr, row.href, row.cve_id);
    slot(tr, "owner-ticket").replaceChildren(ticketEl(row.owner_ticket, row.owner_url, row.dry_run));
    slot(tr, "hunt-ticket").replaceChildren(ticketEl(row.hunt_ticket, row.hunt_url, row.dry_run));
    slot(tr, "detections").textContent = fmtNum(row.detections);
    slot(tr, "action-status").replaceChildren(actionStatusEl(row, ticketing));
    tbody.appendChild(tr);
  });
}

const renderers = {
  extraction: renderExtraction,
  enrichment: renderEnrichment,
  matching: renderMatching,
  actions: renderActions,
};

async function loadStage() {
  const data = await api(`/api/pipeline/${stage}`);
  renderKpis(data.kpis || {});
  (renderers[stage] || renderExtraction)(data);
  stampUpdated(true);
}

loadStage().catch((err) => {
  stampUpdated(false);
  const tbody = document.getElementById("stage-tbody");
  if (tbody) setEmptyRow(tbody, 7, `Failed to load queue: ${err.message}`);
});
setInterval(() => {
  loadStage().catch((err) => {
    stampUpdated(false);
    console.error(err);
  });
}, 30000);

let cveRows = [];
let openCve = null;

const cveSelect = bindSelectDelete({
  panelId: "cve-panel",
  startBtnId: "cve-select-start",
  cancelBtnId: "cve-select-cancel",
  okBtnId: "cve-select-ok",
  selectAllId: "cve-select-all",
  tbodyId: "cve-tbody",
  modalId: "cve-select-modal",
  modalTitleId: "cve-select-modal-title",
  modalConfirmId: "cve-select-modal-confirm",
  modalCancelId: "cve-select-modal-cancel",
  statusId: "cve-select-status",
  countId: "cve-select-count",
  normalCols: 10,
  selectCols: 10,
  endpoint: "/api/cves/delete",
  payload: (ids) => ({ cve_ids: ids }),
  pending: "Deleting selected CVEs…",
  titleFor: (n) => (n === 1 ? "This will delete 1 selected CVE" : `This will delete ${n} selected CVEs`),
  done: (result) => `Deleted ${result.deleted || 0} CVE(s).`,
  onEnter() {
    closeJourney();
    renderCves();
  },
  onExit() {
    renderCves();
  },
  async onDeleted() {
    openCve = null;
    await loadCves();
  },
});

function setClippedCell(el, value) {
  const full = String(value || "").trim();
  el.textContent = dash(full);
  el.title = full || "";
}

function closeJourney() {
  document.querySelectorAll("tr.journey-row").forEach((row) => row.remove());
  document.querySelectorAll("#cve-tbody tr.clickable.is-open").forEach((row) => row.classList.remove("is-open"));
  openCve = null;
}

async function openJourney(row, cve) {
  closeJourney();
  openCve = cve;
  row.classList.add("is-open");
  const expand = useTemplate("tpl-cve-journey");
  const cell = expand.querySelector("[data-slot='journey-cell']") || expand.querySelector("td");
  if (cell) cell.colSpan = cveSelect.colCount();
  row.after(expand);
  const box = expand.querySelector(".journey-inline");
  const list = expand.querySelector(".stations-h");
  try {
    const data = await api(`/api/tracker/${encodeURIComponent(cve)}`);
    const bits = [data.vendor, data.product, data.version].filter(Boolean);
    const note = bits.length
      ? bits.join(" · ")
      : (data.run_label || data.station_label || "");
    box.querySelector(".journey-loading").textContent = note || "Live Workflow stations";
    (data.stations || []).forEach((s, i) => {
      const li = fillTemplate("tpl-cve-station", {
        index: String(i + 1),
        title: s.title,
        detail: s.detail || s.status,
      });
      li.classList.add(`is-${s.status || "pending"}`);
      list.appendChild(li);
    });
  } catch (err) {
    box.querySelector(".journey-loading").textContent = String(err.message || err);
  }
}

function renderCves() {
  const tbody = document.getElementById("cve-tbody");
  const q = (document.getElementById("cve-filter").value || "").toLowerCase();
  const filtered = cveRows.filter((row) => {
    const hay = [
      row.cve_id,
      row.name,
      row.description,
      row.vendor,
      row.product,
      row.product_type,
      row.version,
      row.severity,
      row.source_name,
      row.match_label,
      row.matched ? "matched true" : "",
      row.unmatched ? "unmatched" : "",
    ]
      .join(" ")
      .toLowerCase();
    return !q || hay.includes(q);
  });
  if (!filtered.length) {
    setEmptyRow(tbody, cveSelect.colCount(), cveRows.length ? "No CVEs match this filter." : "No CVEs received yet.");
    openCve = null;
    cveSelect.syncUi();
    return;
  }
  tbody.replaceChildren();
  filtered.forEach((row) => {
    const href = row.href || "";
    const tr = useTemplate("tpl-cve-row");
    tr.dataset.cve = row.cve_id || "";
    const link = slot(tr, "cve-link");
    link.href = href || "#";
    link.textContent = row.cve_id || "—";
    link.title = row.cve_id ? `${row.cve_id} — open record` : "";
    setClippedCell(slot(tr, "description"), (row.description || "").replace(/\s+/g, " "));
    setClippedCell(slot(tr, "vendor"), row.vendor);
    setClippedCell(slot(tr, "product"), row.product);
    setClippedCell(slot(tr, "product-type"), row.product_type);
    setClippedCell(slot(tr, "version"), row.version);
    const sev = String(row.severity || "UNKNOWN").toUpperCase();
    slot(tr, "severity").replaceChildren(makePill("sev", sev));
    setClippedCell(slot(tr, "source"), row.source_name);
    const matched = Boolean(row.matched);
    const unmatched = Boolean(row.unmatched);
    const label = row.match_label || (matched ? "TRUE" : unmatched ? "UNMATCHED" : "—");
    const cls = matched ? "match-true" : unmatched ? "match-false" : "st-paused";
    slot(tr, "match").replaceChildren(labeledPill(cls, label));
    cveSelect.restoreRow(tr, row.cve_id || "");
    tbody.appendChild(tr);
  });
  cveSelect.syncUi();
  if (openCve && !cveSelect.isSelecting()) {
    const row = tbody.querySelector(`tr.clickable[data-cve="${CSS.escape(openCve)}"]`);
    if (row) openJourney(row, openCve);
    else openCve = null;
  }
}

async function loadCves() {
  const tbody = document.getElementById("cve-tbody");
  try {
    const data = await api("/api/cves");
    cveRows = data.rows || [];
    renderCves();
  } catch (err) {
    setEmptyRow(tbody, cveSelect.colCount(), err.message || String(err));
  }
}

document.getElementById("cve-tbody").addEventListener("click", (ev) => {
  if (cveSelect.isSelecting()) return;
  if (ev.target.closest("a, button, input, select, textarea, label")) return;
  const tr = ev.target.closest("tr.clickable");
  if (!tr || tr.classList.contains("journey-row")) return;
  const cve = tr.dataset.cve;
  if (!cve) return;
  if (openCve === cve) {
    closeJourney();
    return;
  }
  openJourney(tr, cve);
});

document.getElementById("cve-filter").addEventListener("input", () => {
  openCve = null;
  renderCves();
});
loadCves();

let trackerRows = [];
let openCve = null;

function vulnType(row) {
  if (row.vuln_type) return row.vuln_type;
  const cwes = row.cwe_ids || row.cwes || [];
  if (Array.isArray(cwes) && cwes.length) return cwes.join(", ");
  return row.product_type || row.severity || "—";
}

async function loadTracker() {
  const tbody = document.getElementById("tracker-tbody");
  try {
    const data = await api("/api/tracker");
    trackerRows = data || [];
    renderTracker();
  } catch (err) {
    setEmptyRow(tbody, 5, err.message || String(err));
  }
}

function closeJourney() {
  document.querySelectorAll("tr.journey-row").forEach((row) => row.remove());
  document.querySelectorAll("tr.clickable.is-open").forEach((row) => row.classList.remove("is-open"));
  openCve = null;
}

function renderTracker() {
  const q = (document.getElementById("tracker-filter").value || "").toLowerCase();
  const tbody = document.getElementById("tracker-tbody");
  const filtered = trackerRows.filter((row) => {
    const hay = [row.cve_id, vulnType(row), row.vendor, row.product, row.version].join(" ").toLowerCase();
    return !q || hay.includes(q);
  });
  if (!filtered.length) {
    setEmptyRow(tbody, 5, "No CVEs ingested yet.");
    openCve = null;
    return;
  }
  tbody.replaceChildren();
  filtered.forEach((row) => {
    const tr = fillTemplate("tpl-tracker-row", {
      cve: row.cve_id,
      type: vulnType(row),
      vendor: dash(row.vendor),
      product: dash(row.product),
      version: dash(row.version),
    });
    tr.dataset.cve = row.cve_id;
    tbody.appendChild(tr);
  });
  if (openCve) {
    const row = tbody.querySelector(`tr.clickable[data-cve="${CSS.escape(openCve)}"]`);
    if (row) openJourney(row, openCve);
    else openCve = null;
  }
}

async function openJourney(row, cve) {
  closeJourney();
  openCve = cve;
  row.classList.add("is-open");
  const expand = useTemplate("tpl-tracker-journey");
  row.after(expand);
  const box = expand.querySelector(".journey-inline");
  const list = expand.querySelector(".stations-h");
  try {
    const data = await api(`/api/tracker/${encodeURIComponent(cve)}`);
    const bits = [data.vendor, data.product, data.version].filter(Boolean);
    const note = bits.length
      ? bits.join(" · ")
      : (data.skipped_as_duplicate ? "Already in the internal database — later stations were skipped." : (data.pipeline_status || ""));
    box.querySelector(".journey-loading").textContent = note;
    (data.stations || []).forEach((s, i) => {
      const li = fillTemplate("tpl-tracker-station", {
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

document.getElementById("tracker-tbody").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr.clickable");
  if (!tr || tr.classList.contains("journey-row")) return;
  const cve = tr.dataset.cve;
  if (openCve === cve) {
    closeJourney();
    return;
  }
  openJourney(tr, cve);
});

document.getElementById("tracker-filter").addEventListener("input", () => {
  openCve = null;
  renderTracker();
});
loadTracker();

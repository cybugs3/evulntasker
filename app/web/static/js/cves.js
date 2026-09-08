let cveRows = [];

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
    ]
      .join(" ")
      .toLowerCase();
    return !q || hay.includes(q);
  });
  if (!filtered.length) {
    setEmptyRow(tbody, 8, cveRows.length ? "No CVEs match this filter." : "No CVEs received yet.");
    return;
  }
  tbody.replaceChildren();
  filtered.forEach((row) => {
    const href = row.href || "";
    const tr = useTemplate("tpl-cve-row");
    tr.dataset.href = href;
    const link = slot(tr, "cve-link");
    link.href = href || "#";
    link.textContent = row.cve_id || "—";
    const desc = slot(tr, "description");
    const full = (row.description || "").trim();
    const preview = full.replace(/\s+/g, " ");
    desc.title = full;
    desc.textContent = dash(preview);
    slot(tr, "vendor").textContent = dash(row.vendor);
    slot(tr, "product").textContent = dash(row.product);
    slot(tr, "product-type").textContent = dash(row.product_type);
    slot(tr, "version").textContent = dash(row.version);
    const sev = String(row.severity || "UNKNOWN").toUpperCase();
    slot(tr, "severity").replaceChildren(makePill("sev", sev));
    slot(tr, "source").textContent = dash(row.source_name);
    tbody.appendChild(tr);
  });
}

async function loadCves() {
  const tbody = document.getElementById("cve-tbody");
  try {
    const data = await api("/api/cves");
    cveRows = data.rows || [];
    renderCves();
  } catch (err) {
    setEmptyRow(tbody, 8, err.message || String(err));
  }
}

document.getElementById("cve-filter").addEventListener("input", renderCves);
loadCves();

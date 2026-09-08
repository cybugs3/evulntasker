function setInvStatus(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

let catalogRows = [];

function formPayload() {
  return {
    vendor: document.getElementById("inv-vendor").value.trim(),
    product: document.getElementById("inv-product").value.trim(),
    product_type: document.getElementById("inv-product-type").value.trim(),
    version: document.getElementById("inv-version").value.trim(),
    owner_name: document.getElementById("inv-owner").value.trim(),
    owner_email: document.getElementById("inv-email").value.trim(),
    team: document.getElementById("inv-team").value.trim(),
  };
}

function resetForm() {
  document.getElementById("inv-id").value = "";
  document.getElementById("inv-asset-form").reset();
  document.getElementById("inv-form-title").textContent = "Add system";
  document.getElementById("inv-save-btn").textContent = "Add system";
  document.getElementById("inv-cancel-btn").hidden = true;
  setInvStatus("inv-form-status", "");
}

function fillForm(row) {
  document.getElementById("inv-id").value = String(row.id || "");
  document.getElementById("inv-vendor").value = row.vendor || "";
  document.getElementById("inv-product").value = row.product || "";
  document.getElementById("inv-product-type").value = row.product_type || "";
  document.getElementById("inv-version").value = row.version || "";
  document.getElementById("inv-owner").value = row.owner_name || "";
  document.getElementById("inv-email").value = row.owner_email || "";
  document.getElementById("inv-team").value = row.team || "";
  document.getElementById("inv-form-title").textContent = "Edit system";
  document.getElementById("inv-save-btn").textContent = "Save changes";
  document.getElementById("inv-cancel-btn").hidden = false;
  document.getElementById("inv-form-panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderCatalog(rows) {
  catalogRows = rows;
  const tbody = document.getElementById("inv-catalog");
  if (!tbody) return;
  if (!rows.length) {
    setEmptyRow(tbody, 9, "No systems yet. Add a row above or import a CSV.");
    return;
  }
  tbody.replaceChildren();
  rows.forEach((r) => {
    const tr = fillTemplate("tpl-inv-row", {
      vendor: dash(r.vendor),
      product: dash(r.product),
      "product-type": dash(r.product_type),
      version: dash(r.version),
      owner: dash(r.owner_name),
      email: dash(r.owner_email),
      team: dash(r.team),
      updated: fmtTime(r.last_update || r.last_synced_at || r.created_at),
    });
    tr.dataset.id = String(r.id);
    tbody.appendChild(tr);
  });
}

function fillInvKpis(kpis) {
  const root = document.getElementById("inv-kpis");
  if (!root) return;
  root.querySelectorAll("[data-k]").forEach((el) => {
    const value = (kpis || {})[el.dataset.k];
    el.textContent = typeof value === "number" ? fmtNum(value) : value == null ? "0" : String(value);
  });
}

async function loadInventory() {
  const data = await api("/api/inventory");
  fillInvKpis(data.kpis || {});
  renderCatalog(data.catalog || []);
}

async function deleteAsset(id) {
  if (!id || !window.confirm("Delete this system from the database?")) return;
  setInvStatus("inv-form-status", "Deleting…");
  try {
    await api(`/api/inventory/assets/${encodeURIComponent(id)}`, { method: "DELETE" });
    resetForm();
    await loadInventory();
    setInvStatus("inv-form-status", "Deleted.");
  } catch (err) {
    setInvStatus("inv-form-status", String(err.message || err));
  }
}

document.getElementById("inv-asset-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const payload = formPayload();
  if (!payload.vendor || !payload.product) {
    setInvStatus("inv-form-status", "Vendor and product are required.");
    return;
  }
  const id = document.getElementById("inv-id").value.trim();
  setInvStatus("inv-form-status", "Saving…");
  try {
    await api(id ? `/api/inventory/assets/${encodeURIComponent(id)}` : "/api/inventory/assets", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    resetForm();
    await loadInventory();
    setInvStatus("inv-form-status", id ? "Saved." : "Added.");
  } catch (err) {
    setInvStatus("inv-form-status", String(err.message || err));
  }
});

document.getElementById("inv-cancel-btn").addEventListener("click", resetForm);

document.getElementById("inv-catalog").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr[data-id]");
  if (!tr) return;
  if (ev.target.closest("[data-edit]")) {
    const row = catalogRows.find((item) => String(item.id) === String(tr.dataset.id));
    if (row) fillForm(row);
    return;
  }
  if (ev.target.closest("[data-del]")) {
    deleteAsset(tr.dataset.id);
  }
});

document.getElementById("inv-csv-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("inv-csv-file");
  const file = input.files && input.files[0];
  if (!file) {
    setInvStatus("inv-csv-status", "Choose a CSV file first.");
    return;
  }
  setInvStatus("inv-csv-status", "Importing…");
  try {
    const body = new FormData();
    body.append("file", file);
    const response = await fetch("/api/inventory/csv", { method: "POST", body });
    const text = await response.text();
    if (!response.ok) throw new Error(text || response.statusText);
    const result = JSON.parse(text);
    setInvStatus("inv-csv-status", `Imported ${result.count || 0} row(s) (${result.created || 0} new, ${result.updated || 0} updated).`);
    input.value = "";
    await loadInventory();
  } catch (err) {
    setInvStatus("inv-csv-status", String(err.message || err));
  }
});

loadInventory().catch((err) => {
  const tbody = document.getElementById("inv-catalog");
  if (tbody) setEmptyRow(tbody, 9, `Failed to load: ${err.message}`);
});

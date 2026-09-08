let sources = [];

const TYPE_LABELS = {
  smb: "SMB share",
  local: "Local folder",
  outlook: "Outlook / Exchange",
  web_api: "ATOM feed",
};

const DATA_TYPES = {
  smb: "CVEs",
  local: "CVEs",
  outlook: "Alerts",
  web_api: "CVEs",
};

function typeLabel(source) {
  return TYPE_LABELS[source.source_type] || source.source_type || "Unknown";
}

function dataType(source) {
  return DATA_TYPES[source.source_type] || "CVEs";
}

const FEED_SUBTABS = {
  smb: "smb",
  local: "local",
  outlook: "exchange",
  email: "exchange",
  web_api: "web",
  api_feed: "web",
  webhook: "web",
};

function settingsEditHref(source) {
  const subtab = FEED_SUBTABS[source.source_type];
  return subtab ? `/settings#feeds/${subtab}` : "/settings#feeds";
}

function fmtRelative(value) {
  if (!value) return "—";
  const then = new Date(value);
  if (Number.isNaN(then.getTime())) return String(value);
  const sec = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (sec < 60) return `${sec} seconds ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} minute${min === 1 ? "" : "s"} ago`;
  const hour = Math.round(min / 60);
  if (hour < 24) return `${hour} hour${hour === 1 ? "" : "s"} ago`;
  const day = Math.round(hour / 24);
  return `${day} day${day === 1 ? "" : "s"} ago`;
}

function statusEl(source) {
  if (!source.enabled) return labeledPill("st-paused", "Off");
  if (source.last_error) return labeledPill("st-error", "Error");
  return labeledPill("st-ok", "Active");
}

function filteredSources() {
  const q = (document.getElementById("source-search").value || "").toLowerCase();
  const type = document.getElementById("source-type-filter").value;
  return sources.filter((s) => {
    const hay = `${s.name} ${s.source_type} ${s.description || ""}`.toLowerCase();
    return (!q || hay.includes(q)) && (!type || s.source_type === type);
  });
}

function fillTypeFilter() {
  const select = document.getElementById("source-type-filter");
  const current = select.value;
  const types = [...new Set(sources.map((s) => s.source_type).filter(Boolean))];
  select.replaceChildren();
  const all = document.createElement("option");
  all.value = "";
  all.textContent = "All types";
  select.appendChild(all);
  types.forEach((t) => {
    const opt = document.createElement("option");
    opt.value = t;
    opt.textContent = TYPE_LABELS[t] || t;
    select.appendChild(opt);
  });
  if (types.includes(current)) select.value = current;
}

function renderTable() {
  const tbody = document.getElementById("source-tbody");
  const rows = filteredSources();
  if (!rows.length) {
    setEmptyRow(tbody, 7, "No input sources match the current filters. Configure feeds in Settings.");
    return;
  }
  tbody.replaceChildren();
  rows.forEach((s) => {
    const tr = useTemplate("tpl-source-row");
    slot(tr, "name").textContent = s.name;
    slot(tr, "desc").textContent = s.description || "";
    slot(tr, "type").textContent = typeLabel(s);
    slot(tr, "status").replaceChildren(statusEl(s));
    slot(tr, "data-type").textContent = dataType(s);
    slot(tr, "updated").textContent = fmtRelative(s.last_event_at);
    slot(tr, "cves").textContent = fmtNum(s.cve_count != null ? s.cve_count : s.event_count);
    const toggle = slot(tr, "toggle");
    toggle.dataset.id = String(s.id);
    toggle.title = s.enabled ? "Pause" : "Activate";
    toggle.textContent = s.enabled ? "❚❚" : "▶";
    slot(tr, "edit").href = settingsEditHref(s);
    tbody.appendChild(tr);
  });
}

async function loadSources() {
  sources = await api("/api/sources");
  fillTypeFilter();
  renderTable();
}

document.getElementById("source-tbody").addEventListener("click", async (ev) => {
  const toggle = ev.target.closest("[data-act=toggle]");
  if (!toggle) return;
  ev.stopPropagation();
  await api(`/api/sources/${toggle.dataset.id}/toggle`, { method: "POST" });
  await loadSources();
});

document.getElementById("source-search").addEventListener("input", renderTable);
document.getElementById("source-type-filter").addEventListener("change", renderTable);

loadSources().catch((err) => {
  setEmptyRow(document.getElementById("source-tbody"), 7, `Failed to load sources: ${err.message}`);
});

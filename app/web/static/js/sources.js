let sources = [];

const TYPE_LABELS = {
  nvd: "NVD lookup",
  epss: "EPSS lookup",
  atom: "ATOM feed",
  exploitdb: "Exploit-DB",
  inline: "Inline CVE",
  smb: "SMB share",
  local: "Local folder",
  outlook: "Outlook / Exchange",
  web_api: "ATOM feed",
};

const FEED_SUBTABS = {
  smb: "smb",
  local: "local",
  outlook: "exchange",
  email: "exchange",
  atom: "web",
  web_api: "web",
  api_feed: "web",
  webhook: "web",
  nvd: "web",
  epss: "web",
};

const NO_SYNC_TYPES = new Set(["inline", "nvd", "epss"]);

function typeLabel(source) {
  return TYPE_LABELS[source.feed_type] || source.feed_type || "Unknown";
}

function settingsEditHref(source) {
  const subtab = FEED_SUBTABS[source.feed_type];
  return subtab ? `/settings#feeds/${subtab}` : "/settings#feeds";
}

function cveCount(source) {
  return source.cve_count != null ? source.cve_count : 0;
}

function statusEl(source) {
  if (!source.enabled) return labeledPill("st-paused", "Off");
  if (source.last_error || source.sync_status === "error") return labeledPill("st-error", "Error");
  if (source.sync_status === "ok") return labeledPill("st-ok", "Active");
  if (source.sync_status === "syncing") return labeledPill("st-syncing", "Syncing");
  return labeledPill("st-idle", "Idle");
}

function filteredSources() {
  const q = (document.getElementById("source-search").value || "").toLowerCase();
  const type = document.getElementById("source-type-filter").value;
  return sources.filter((s) => {
    const hay = `${s.name} ${s.feed_type} ${s.endpoint || ""} ${s.notes || ""}`.toLowerCase();
    return (!q || hay.includes(q)) && (!type || s.feed_type === type);
  });
}

function fillTypeFilter() {
  const select = document.getElementById("source-type-filter");
  const current = select.value;
  const types = [...new Set(sources.map((s) => s.feed_type).filter(Boolean))];
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
    slot(tr, "desc").textContent = s.notes || "";
    slot(tr, "type").textContent = typeLabel(s);
    slot(tr, "endpoint").textContent = s.endpoint || "—";
    slot(tr, "status").replaceChildren(statusEl(s));
    slot(tr, "updated").textContent = fmtTime(s.last_sync_at);
    slot(tr, "cves").textContent = fmtNum(cveCount(s));
    const toggle = slot(tr, "toggle");
    toggle.dataset.id = String(s.id);
    toggle.textContent = s.enabled ? "Pause" : "Enable";
    const sync = tr.querySelector("[data-act=sync]");
    sync.dataset.id = String(s.id);
    if (NO_SYNC_TYPES.has(s.feed_type)) sync.hidden = true;
    const edit = slot(tr, "edit");
    if (s.feed_type === "inline") {
      edit.hidden = true;
    } else {
      edit.href = settingsEditHref(s);
    }
    tbody.appendChild(tr);
  });
}

async function loadSources() {
  sources = await api("/api/repositories");
  fillTypeFilter();
  renderTable();
  stampUpdated(true);
}

document.getElementById("source-tbody").addEventListener("click", async (ev) => {
  const toggle = ev.target.closest("[data-act=toggle]");
  const sync = ev.target.closest("[data-act=sync]");
  try {
    if (toggle?.dataset.id) {
      ev.stopPropagation();
      await api(`/api/repositories/${toggle.dataset.id}/toggle`, { method: "POST" });
      await loadSources();
      return;
    }
    if (sync?.dataset.id) {
      ev.stopPropagation();
      await api(`/api/repositories/${sync.dataset.id}/sync`, { method: "POST" });
      await loadSources();
    }
  } catch (err) {
    stampUpdated(false);
    window.alert(err.message || String(err));
  }
});

document.getElementById("source-search").addEventListener("input", renderTable);
document.getElementById("source-type-filter").addEventListener("change", renderTable);

document.addEventListener("inline-cve-queued", () => {
  loadSources().catch((err) => {
    stampUpdated(false);
    console.error(err);
  });
});

loadSources().catch((err) => {
  stampUpdated(false);
  setEmptyRow(document.getElementById("source-tbody"), 7, `Failed to load sources: ${err.message}`);
});
setInterval(() => {
  loadSources().catch((err) => {
    stampUpdated(false);
    console.error(err);
  });
}, 30000);

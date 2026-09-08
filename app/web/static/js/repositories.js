const TYPE_LABELS = {
  nvd: "NVD lookup",
  epss: "EPSS lookup",
  atom: "ATOM feed",
  exploitdb: "Exploit-DB",
};

async function loadRepos() {
  const repos = await api("/api/repositories");
  const tbody = document.getElementById("repo-tbody");
  tbody.replaceChildren();
  if (!repos.length) {
    setEmptyRow(tbody, 8, "No repositories yet. Add ATOM feeds in Settings → Feeds, or restore NVD/EPSS in Internet intel.");
    return;
  }
  repos.forEach((r) => {
    const tr = fillTemplate("tpl-repo-row", {
      name: r.name,
      notes: r.notes || "",
      type: TYPE_LABELS[r.feed_type] || r.feed_type,
      endpoint: r.endpoint,
      synced: fmtTime(r.last_sync_at),
      count: fmtNum(r.raw_count),
      toggle: r.enabled ? "Pause" : "Enable",
    });
    slot(tr, "status").replaceChildren(makePill("st", r.sync_status));
    slot(tr, "enabled").replaceChildren(r.enabled ? makePill("st", "ok") : makePill("st", "idle"));
    tr.querySelector("[data-sync]").dataset.sync = String(r.id);
    tr.querySelector("[data-toggle]").dataset.toggle = String(r.id);
    tbody.appendChild(tr);
  });
}

document.getElementById("repo-tbody").addEventListener("click", async (ev) => {
  try {
    const sync = ev.target.closest("[data-sync]");
    if (sync?.dataset.sync) {
      await api(`/api/repositories/${sync.dataset.sync}/sync`, { method: "POST" });
      await loadRepos();
      return;
    }
    const toggle = ev.target.closest("[data-toggle]");
    if (toggle?.dataset.toggle) {
      await api(`/api/repositories/${toggle.dataset.toggle}/toggle`, { method: "POST" });
      await loadRepos();
    }
  } catch (err) {
    window.alert(err.message || String(err));
  }
});

loadRepos().catch((err) => {
  setEmptyRow(document.getElementById("repo-tbody"), 8, err.message);
});

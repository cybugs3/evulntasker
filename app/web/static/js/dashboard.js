function fillKpis(rootId, data) {
  const root = document.getElementById(rootId);
  if (!root || !data) return;
  root.querySelectorAll("[data-k]").forEach((el) => {
    const key = el.dataset.k;
    const value = data[key];
    if (key === "relevance_rate") {
      el.textContent = value == null ? "—" : `${value}%`;
      return;
    }
    if (value == null) {
      el.textContent = "—";
      return;
    }
    el.textContent = typeof value === "number" ? fmtNum(value) : String(value);
  });
  const sub = root.querySelector('[data-k-sub="sources"]');
  if (sub) {
    sub.textContent = `${fmtNum(data.sources_online || 0)} online / ${fmtNum(data.sources || 0)} registered`;
  }
}

async function loadDashboard() {
  const [overview, integrations] = await Promise.all([
    api("/api/overview"),
    api("/api/integrations"),
  ]);
  fillKpis("kpi-main", overview.main || {});
  fillKpis("kpi-sources", overview.sources || {});
  fillKpis("kpi-extraction", overview.extraction || {});
  fillKpis("kpi-enrichment", overview.enrichment || {});
  fillKpis("kpi-inventory", overview.inventory || {});
  fillKpis("kpi-matching", overview.matching || {});
  fillKpis("kpi-actions", overview.actions || {});
  const banner = document.getElementById("dash-inv-banner");
  if (banner) banner.hidden = Boolean(integrations.inventory_ready);
}

document.getElementById("refresh-btn").addEventListener("click", loadDashboard);
loadDashboard().catch((err) => {
  const first = document.querySelector("#kpi-main .kpi-value");
  if (first) first.textContent = "Error";
  console.error(err);
});
setInterval(loadDashboard, 30000);

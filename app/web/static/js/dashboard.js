function kpiText(el) {
  const live = el.querySelector(".kpi-num.is-live");
  if (live) return live.textContent;
  return (el.textContent || "").trim();
}

function paintKpi(el, next) {
  const span = document.createElement("span");
  span.className = "kpi-num is-live";
  span.textContent = next;
  el.replaceChildren(span);
}

function setKpiValue(el, next) {
  const prev = kpiText(el);
  if (prev === next) return;
  const live = el.querySelector(".kpi-num.is-live");
  const first = !live || prev === "" || prev === "—" || prev === "Error";
  if (first) {
    paintKpi(el, next);
    return;
  }
  live.classList.remove("is-live");
  live.classList.add("is-exit");
  const incoming = document.createElement("span");
  incoming.className = "kpi-num is-enter";
  incoming.textContent = next;
  el.appendChild(incoming);
  const card = el.closest(".main-tile, .main-metric");
  if (card) {
    card.classList.add("is-ticking");
    window.setTimeout(() => card.classList.remove("is-ticking"), 1200);
  }
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      incoming.classList.remove("is-enter");
      incoming.classList.add("is-live");
    });
  });
  window.setTimeout(() => live.remove(), 2200);
}

function fillKpis(rootId, data) {
  const root = document.getElementById(rootId);
  if (!root || !data) return;
  root.querySelectorAll("[data-k]").forEach((el) => {
    const key = el.dataset.k;
    const value = data[key];
    let next = "—";
    if (key === "relevance_rate") next = value == null ? "—" : `${value}%`;
    else if (value == null) next = "—";
    else next = typeof value === "number" ? fmtNum(value) : String(value);
    setKpiValue(el, next);
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
  stampUpdated(true);
}

loadDashboard().catch((err) => {
  stampUpdated(false);
  const first = document.querySelector("#kpi-main .kpi-value");
  if (first) paintKpi(first, "Error");
  console.error(err);
});
setInterval(() => {
  loadDashboard().catch((err) => {
    stampUpdated(false);
    console.error(err);
  });
}, 30000);

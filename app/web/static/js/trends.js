let currentRange = "7d";

function svgEl(name, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", name);
  Object.entries(attrs || {}).forEach(([key, value]) => {
    if (value != null) el.setAttribute(key, String(value));
  });
  return el;
}

function niceMax(values) {
  const m = Math.max(0, ...values);
  if (m <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(m));
  return Math.ceil(m / pow) * pow;
}

function chartLayout(svg, n) {
  const width = Math.max(640, svg.clientWidth || 800);
  const height = 320;
  const pad = { l: 44, r: 16, t: 16, b: n > 16 ? 56 : 44 };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
  return {
    width,
    height,
    pad,
    plotW: width - pad.l - pad.r,
    plotH: height - pad.t - pad.b,
  };
}

function drawAxes(svg, layout, yMax, labels, title, desc) {
  svg.replaceChildren();
  const titleEl = svgEl("title", { id: `${svg.id}-title` });
  titleEl.textContent = title;
  const descEl = svgEl("desc", { id: `${svg.id}-desc` });
  descEl.textContent = desc;
  svg.append(titleEl, descEl);

  const axis = svgEl("g", { class: "chart-axis" });
  const ticks = 4;
  for (let i = 0; i <= ticks; i += 1) {
    const value = Math.round((yMax * i) / ticks);
    const y = layout.pad.t + layout.plotH - (layout.plotH * i) / ticks;
    axis.appendChild(
      svgEl("line", {
        x1: layout.pad.l,
        x2: layout.pad.l + layout.plotW,
        y1: y,
        y2: y,
        class: "chart-grid",
      })
    );
    const label = svgEl("text", { x: layout.pad.l - 8, y: y + 4, class: "chart-tick", "text-anchor": "end" });
    label.textContent = String(value);
    axis.appendChild(label);
  }
  const yName = svgEl("text", {
    x: 14,
    y: layout.pad.t + layout.plotH / 2,
    class: "chart-axis-name",
    transform: `rotate(-90 14 ${layout.pad.t + layout.plotH / 2})`,
    "text-anchor": "middle",
  });
  yName.textContent = "CVE count";
  axis.appendChild(yName);

  const step = labels.length > 16 ? Math.ceil(labels.length / 12) : 1;
  labels.forEach((text, i) => {
    if (i % step !== 0 && i !== labels.length - 1) return;
    const x = layout.pad.l + ((i + 0.5) * layout.plotW) / labels.length;
    const label = svgEl("text", {
      x,
      y: layout.height - 12,
      class: "chart-tick",
      "text-anchor": "middle",
    });
    label.textContent = text;
    axis.appendChild(label);
  });
  svg.appendChild(axis);
}

function drawBars(svg, data) {
  const buckets = data.buckets || [];
  const layout = chartLayout(svg, buckets.length);
  const yMax = niceMax(buckets.flatMap((row) => [row.ingested, row.matched, row.unmatched || 0]));
  drawAxes(
    svg,
    layout,
    yMax,
    buckets.map((row) => row.label),
    "CVEs ingested vs matched vs unmatched",
    `Source: EVulnTasker · ${data.range} · Live Workflow classification by ingest day`
  );
  if (!buckets.length) return;
  const groupW = layout.plotW / buckets.length;
  const barW = Math.max(3, Math.min(18, groupW * 0.22));
  const gap = Math.max(2, barW * 0.18);
  buckets.forEach((row, i) => {
    const gx = layout.pad.l + i * groupW + (groupW - (barW * 3 + gap * 2)) / 2;
    const bars = [
      ["ingested", row.ingested, "ingested"],
      ["matched", row.matched, "matched"],
      ["unmatched", row.unmatched || 0, "unmatched"],
    ];
    bars.forEach(([key, value, cls], bi) => {
      const h = yMax ? (value / yMax) * layout.plotH : 0;
      const y = layout.pad.t + layout.plotH - h;
      const rect = svgEl("rect", {
        x: gx + bi * (barW + gap),
        y,
        width: barW,
        height: Math.max(0, h),
        class: `chart-bar ${cls}`,
      });
      rect.appendChild(svgEl("title")).textContent = `${row.label}: ${value} ${key}`;
      svg.appendChild(rect);
    });
  });
}

function drawLines(svg, data) {
  const buckets = data.buckets || [];
  const layout = chartLayout(svg, buckets.length);
  let ingested = 0;
  let matched = 0;
  let unmatched = 0;
  const points = buckets.map((row) => {
    ingested += row.ingested;
    matched += row.matched;
    unmatched += row.unmatched || 0;
    return { label: row.label, ingested, matched, unmatched };
  });
  const yMax = niceMax(points.flatMap((row) => [row.ingested, row.matched, row.unmatched]));
  drawAxes(
    svg,
    layout,
    yMax,
    points.map((row) => row.label),
    "Cumulative CVEs ingested vs matched vs unmatched",
    `Source: EVulnTasker · ${data.range} · running Live Workflow totals`
  );
  if (points.length < 1) return;

  function polyline(key, className) {
    const pts = points
      .map((row, i) => {
        const x = layout.pad.l + ((i + 0.5) * layout.plotW) / points.length;
        const y = layout.pad.t + layout.plotH - (yMax ? (row[key] / yMax) * layout.plotH : 0);
        return `${x},${y}`;
      })
      .join(" ");
    svg.appendChild(svgEl("polyline", { points: pts, class: className, fill: "none" }));
    points.forEach((row, i) => {
      const x = layout.pad.l + ((i + 0.5) * layout.plotW) / points.length;
      const y = layout.pad.t + layout.plotH - (yMax ? (row[key] / yMax) * layout.plotH : 0);
      const dot = svgEl("circle", { cx: x, cy: y, r: 3, class: className });
      dot.appendChild(svgEl("title")).textContent = `${row.label}: ${row[key]} ${key}`;
      svg.appendChild(dot);
    });
  }
  polyline("ingested", "chart-line ingested");
  polyline("matched", "chart-line matched");
  polyline("unmatched", "chart-line unmatched");
}

function fillTrendKpis(totals) {
  const root = document.getElementById("trend-kpis");
  if (!root || !totals) return;
  root.querySelector('[data-k="ingested"]').textContent = fmtNum(totals.ingested);
  root.querySelector('[data-k="matched"]').textContent = fmtNum(totals.matched);
  root.querySelector('[data-k="unmatched"]').textContent = fmtNum(totals.unmatched);
  const rate = root.querySelector('[data-k="match_rate"]');
  const reached = (totals.matched || 0) + (totals.unmatched || 0);
  rate.textContent = reached ? `${totals.match_rate}%` : "—";
}

async function loadTrends() {
  const data = await api(`/api/trends?range=${encodeURIComponent(currentRange)}`);
  fillTrendKpis(data.totals || {});
  const caption = document.getElementById("trend-caption");
  if (caption) {
    const grain = data.granularity === "hour" ? "hour" : data.granularity === "week" ? "week" : "day";
    caption.textContent =
      `CVEs received each ${grain}, classified with Live Workflow as matched or unmatched.`;
  }
  drawBars(document.getElementById("trend-bars"), data);
  drawLines(document.getElementById("trend-lines"), data);
  stampUpdated(true);
}

function setRange(range) {
  currentRange = range;
  document.querySelectorAll(".range-btn").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.range === range);
  });
  loadTrends().catch((err) => {
    stampUpdated(false);
    document.getElementById("trend-caption").textContent = err.message || String(err);
  });
}

document.getElementById("trend-range").addEventListener("click", (ev) => {
  const btn = ev.target.closest(".range-btn");
  if (!btn) return;
  setRange(btn.dataset.range);
});
window.addEventListener("resize", () => {
  if (currentRange) loadTrends().catch(() => {});
});
setInterval(() => {
  if (currentRange) {
    loadTrends().catch((err) => {
      stampUpdated(false);
      console.error(err);
    });
  }
}, 30000);
setRange("7d");

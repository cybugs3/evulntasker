function statusClass(status) {
  return {
    ok: "dbg-ok",
    fail: "dbg-fail",
    warn: "dbg-warn",
    skip: "dbg-skip",
    info: "dbg-info",
  }[status] || "dbg-info";
}

function statusLabel(status) {
  return String(status || "info").toUpperCase();
}

function pretty(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function addSumCard(body, label, value, extraClass) {
  const card = fillTemplate("tpl-debug-sum", { label, value });
  const valueEl = slot(card, "value");
  if (extraClass) valueEl.classList.add(extraClass);
  body.appendChild(card);
  return card;
}

function renderSummary(data) {
  const box = document.getElementById("debug-summary");
  const body = document.getElementById("debug-summary-body");
  box.hidden = false;
  body.replaceChildren();
  const cve = data.cve_id || "—";
  const cveCard = addSumCard(body, "CVE", cve);
  if (data.cve_id) {
    const a = document.createElement("a");
    a.className = "link";
    a.href = `/vulnerabilities/${encodeURIComponent(data.cve_id)}`;
    a.textContent = cve;
    slot(cveCard, "value").replaceChildren(a);
    slot(cveCard, "value").classList.add("mono");
  } else {
    slot(cveCard, "value").classList.add("mono");
  }
  addSumCard(body, "Outcome", data.ok ? "Completed" : `Stopped at step ${data.stopped_at || "?"}`);
  addSumCard(body, "Relevant to org", data.relevant ? "Yes" : "No", data.relevant ? "ok-text" : "");
  addSumCard(body, "Persisted", data.persisted ? "Yes" : "No");
  addSumCard(
    body,
    "Vendor / product",
    `${dash((data.enrichment || {}).vendor)} / ${dash((data.enrichment || {}).product)}`
  );
  addSumCard(body, "Matches", fmtNum((data.matches || []).length));
}

function renderTimeline(steps) {
  const root = document.getElementById("debug-timeline");
  root.replaceChildren();
  if (!steps.length) {
    root.appendChild(useTemplate("tpl-debug-empty"));
    return;
  }
  steps.forEach((s) => {
    const article = fillTemplate("tpl-debug-step", {
      num: s.step,
      title: s.title,
      path: `${s.module} → ${s.function}`,
      duration: `${s.duration_ms || 0} ms`,
      summary: s.summary,
      detail: pretty(s.detail || {}),
    });
    article.classList.add(statusClass(s.status));
    const st = slot(article, "status");
    st.className = `pill ${statusClass(s.status)}`;
    st.textContent = statusLabel(s.status);
    root.appendChild(article);
  });
}

document.getElementById("debug-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = document.getElementById("debug-run");
  const status = document.getElementById("debug-status");
  btn.disabled = true;
  status.textContent = "Running pipeline stages…";
  try {
    const data = await api("/api/debug/run", {
      method: "POST",
      body: JSON.stringify({
        cve_id: document.getElementById("debug-cve").value.trim(),
        sample_text: document.getElementById("debug-text").value,
        persist: document.getElementById("debug-persist").checked,
      }),
    });
    status.textContent = data.ok
      ? `Done — ${data.cve_id}${data.relevant ? " (relevant)" : " (no org relevance)"}.`
      : `Stopped — see timeline.`;
    renderSummary(data);
    renderTimeline(data.steps || []);
  } catch (err) {
    status.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("debug-clear").addEventListener("click", () => {
  const root = document.getElementById("debug-timeline");
  root.replaceChildren();
  root.appendChild(useTemplate("tpl-debug-idle"));
  document.getElementById("debug-summary").hidden = true;
  document.getElementById("debug-status").textContent = "";
});

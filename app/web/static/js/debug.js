function statusClass(status) {
  return {
    ok: "dbg-ok",
    fail: "dbg-fail",
    warn: "dbg-warn",
    skip: "dbg-skip",
    info: "dbg-info",
    run: "dbg-run",
  }[status] || "dbg-info";
}

function statusLabel(status) {
  if (status === "run") return "WORKING";
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
  slot(cveCard, "value").classList.add("mono");
  addSumCard(body, "Outcome", data.ok ? "Completed" : `Stopped at step ${data.stopped_at || "?"}`);
  addSumCard(body, "Relevant to org", data.relevant ? "Yes" : "No", data.relevant ? "ok-text" : "");
  addSumCard(body, "Saved", "No — Debugger never writes records");
  addSumCard(
    body,
    "Vendor / product",
    `${dash((data.enrichment || {}).vendor)} / ${dash((data.enrichment || {}).product)}`
  );
  addSumCard(body, "Matches", fmtNum((data.matches || []).length));
  addSumCard(body, "Match", data.match_lesson || (data.relevant ? "See stage 6" : "No Internal systems overlap"));
  const plan = data.ticketing_plan || {};
  const would = plan.would_notify || [];
  addSumCard(
    body,
    "Would notify",
    would.length
      ? would.map((item) => item.to || item.kind).join(", ")
      : "Nobody — nothing sent"
  );
  addSumCard(body, "Sent", "No — Debugger never sends mail or tickets");
}

function fillBreakdown(article, items, running) {
  const list = article.querySelector("[data-slot='breakdown']");
  if (!list) return;
  list.replaceChildren();
  const lines = running ? [] : (items || []).filter((line) => String(line || "").trim());
  if (!lines.length) {
    list.hidden = true;
    return;
  }
  list.hidden = false;
  lines.forEach((text) => {
    const li = document.createElement("li");
    li.textContent = String(text);
    list.appendChild(li);
  });
}

function upsertStep(data, running) {
  const root = document.getElementById("debug-timeline");
  const empty = root.querySelector(".debug-empty");
  if (empty) empty.remove();
  const id = `debug-step-${data.step}`;
  let article = document.getElementById(id);
  const status = running ? "run" : data.status;
  const next = fillTemplate("tpl-debug-step", {
    num: data.step,
    title: data.title || `Stage ${data.step}`,
    path: data.module && data.function ? `${data.module} → ${data.function}` : "",
    duration: running ? "" : `${data.duration_ms || 0} ms`,
    summary: running ? "Working…" : data.summary || "",
    detail: running ? "" : pretty(data.detail || {}),
  });
  next.id = id;
  next.classList.add(statusClass(status));
  const st = slot(next, "status");
  st.className = `pill ${statusClass(status)}`;
  st.textContent = statusLabel(status);
  fillBreakdown(next, data.breakdown || (data.detail && data.detail.breakdown) || [], running);
  const details = next.querySelector(".debug-detail");
  if (running && details) details.hidden = true;
  if (article) article.replaceWith(next);
  else root.appendChild(next);
  next.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function httpErrorMessage(text, fallback) {
  try {
    const data = JSON.parse(text);
    if (data && data.detail) {
      return typeof data.detail === "string" ? data.detail : pretty(data.detail);
    }
  } catch {
    /* use raw text */
  }
  const trimmed = (text || "").trim();
  return trimmed || fallback || "Request failed";
}

function finishRun(data, status) {
  (data.steps || []).forEach((step) => upsertStep(step, false));
  status.textContent = data.ok
    ? `Done — ${data.cve_id}${data.relevant ? " (relevant)" : " (no org relevance)"}. Nothing sent.`
    : `Stopped — see timeline.`;
  renderSummary(data);
}

async function postDebug(path, payload) {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function readNdjson(response, onEvent) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl = buf.indexOf("\n");
    while (nl >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) onEvent(JSON.parse(line));
      nl = buf.indexOf("\n");
    }
  }
  const tail = buf.trim();
  if (tail) onEvent(JSON.parse(tail));
}

document.getElementById("debug-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = document.getElementById("debug-run");
  const status = document.getElementById("debug-status");
  const root = document.getElementById("debug-timeline");
  const summary = document.getElementById("debug-summary");
  btn.disabled = true;
  summary.hidden = true;
  root.replaceChildren();
  status.textContent = "Starting…";
  const payload = {
    cve_id: document.getElementById("debug-cve").value.trim(),
    sample_text: document.getElementById("debug-text").value,
    persist: false,
  };
  try {
    let response = await postDebug("/api/debug/run/stream", payload);
    if (response.status === 404 || response.status === 405) {
      response = await postDebug("/api/debug/run", payload);
    }
    if (!response.ok) {
      throw new Error(httpErrorMessage(await response.text(), response.statusText));
    }
    const ctype = (response.headers.get("content-type") || "").toLowerCase();
    if (ctype.includes("ndjson")) {
      let final = null;
      await readNdjson(response, (event) => {
        if (event.type === "begin") {
          status.textContent = `Working — ${dataTitle(event)}`;
          upsertStep(event, true);
          return;
        }
        if (event.type === "step") {
          status.textContent = `Done — ${event.title}`;
          upsertStep(event, false);
          return;
        }
        if (event.type === "error") {
          status.textContent = event.message || "Debug run failed";
          return;
        }
        if (event.type === "done") {
          final = event;
        }
      });
      if (final) {
        finishRun(final, status);
      } else if (!status.textContent || status.textContent.startsWith("Working") || status.textContent === "Starting…") {
        status.textContent = "Run finished with no result.";
      }
      return;
    }
    finishRun(await response.json(), status);
  } catch (err) {
    status.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

function dataTitle(event) {
  return event.title || `stage ${event.step}`;
}

document.getElementById("debug-clear").addEventListener("click", () => {
  const root = document.getElementById("debug-timeline");
  root.replaceChildren();
  root.appendChild(useTemplate("tpl-debug-idle"));
  document.getElementById("debug-summary").hidden = true;
  document.getElementById("debug-status").textContent = "";
});

(() => {
  const raw = (new URLSearchParams(location.search).get("cve") || "").trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/.test(raw)) return;
  history.replaceState({}, "", location.pathname);
  const field = document.getElementById("debug-cve");
  if (field) field.value = raw;
  document.getElementById("debug-form").requestSubmit();
})();

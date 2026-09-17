const SIDEBAR_KEY = "evulntasker-sidebar";

function initSidebar() {
  const toggles = document.querySelectorAll(".js-sidebar-toggle");
  if (!toggles.length) return;
  const saved = localStorage.getItem(SIDEBAR_KEY);
  const collapsed = saved ? saved === "collapsed" : window.innerWidth <= 800;
  setSidebarCollapsed(collapsed);
  toggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
      setSidebarCollapsed(!document.body.classList.contains("sidebar-collapsed"));
    });
  });
}

function setSidebarCollapsed(collapsed) {
  document.body.classList.toggle("sidebar-collapsed", collapsed);
  document.body.classList.toggle("sidebar-open", !collapsed);
  document.querySelectorAll(".js-sidebar-toggle").forEach((toggle) => {
    toggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
  });
  localStorage.setItem(SIDEBAR_KEY, collapsed ? "collapsed" : "open");
}

function initHeader() {
  const bell = document.getElementById("notify-btn");
  const panel = document.getElementById("notify-panel");
  const list = document.getElementById("notify-list");
  const badge = document.getElementById("notify-badge");
  if (!bell || !panel || !list) return;

  bell.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const open = panel.hidden;
    panel.hidden = !open;
    bell.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) loadNotifications();
  });
  document.addEventListener("click", () => {
    panel.hidden = true;
    bell.setAttribute("aria-expanded", "false");
  });
  panel.addEventListener("click", (ev) => ev.stopPropagation());
  loadNotifications();

  async function loadNotifications() {
    try {
      const data = await api("/api/notifications");
      const items = data.items || [];
      const count = data.count || items.length;
      badge.hidden = !count;
      badge.textContent = count > 9 ? "9+" : String(count);
      list.replaceChildren();
      if (!items.length) {
        list.appendChild(fillTemplate("tpl-notify-empty", { text: "No notifications." }));
        return;
      }
      items.forEach((item) => {
        const li = fillTemplate("tpl-notify-item", { link: item.title || "" });
        const link = slot(li, "link");
        if (link) link.href = item.href || "#";
        list.appendChild(li);
      });
    } catch (err) {
      list.replaceChildren();
      list.appendChild(fillTemplate("tpl-notify-empty", { text: err.message }));
    }
  }
}

function initActiveNav() {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  document.querySelectorAll("a.nav-item").forEach((el) => {
    const href = el.getAttribute("href") || "";
    let on = false;
    if (href === "/") on = path === "/";
    else if (href === "/sources") on = path === "/sources" || path === "/feeds";
    else on = path === href || path.startsWith(`${href}/`);
    el.classList.toggle("is-active", on);
  });
}

function initRowNav() {
  document.addEventListener("click", (ev) => {
    if (ev.target.closest("a, button, input, select, textarea, label")) return;
    const tr = ev.target.closest("tr.clickable[data-href]");
    if (tr?.dataset.href) location.href = tr.dataset.href;
  });
}

function bindInlineCveForm() {
  const form = document.getElementById("inline-cve-form");
  if (!form) return;
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = document.getElementById("inline-submit");
    const status = document.getElementById("inline-status");
    const field = document.getElementById("inline-cve");
    const cveId = (field?.value || "").trim();
    if (!cveId) {
      status.textContent = "Enter a CVE ID such as CVE-2024-1234";
      return;
    }
    btn.disabled = true;
    status.textContent = "Queueing…";
    try {
      const result = await api("/api/sources/inline", {
        method: "POST",
        body: JSON.stringify({ cve_id: cveId }),
      });
      const ids = (result.extracted_cves || []).join(", ");
      status.textContent = result.message || `Queued ${ids}.`;
      field.value = "";
      document.dispatchEvent(new CustomEvent("inline-cve-queued", { detail: result }));
    } catch (err) {
      status.textContent = String(err.message || err);
    } finally {
      btn.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initSidebar();
  initHeader();
  initActiveNav();
  initRowNav();
  bindInlineCveForm();
});

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    let message = text || response.statusText;
    try {
      const body = JSON.parse(text);
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail)) {
        message = body.detail.map((item) => item.msg || item.detail || JSON.stringify(item)).join("; ");
      }
    } catch (_err) {
      /* keep raw text */
    }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}

function useTemplate(id) {
  const tpl = document.getElementById(id);
  if (!tpl) throw new Error(`Missing template #${id}`);
  const node = tpl.content.firstElementChild.cloneNode(true);
  if (!node) throw new Error(`Template #${id} has no root element`);
  return node;
}

function slot(root, name) {
  if (!root) return null;
  if (root.dataset?.slot === name) return root;
  return root.querySelector(`[data-slot="${name}"]`);
}

function fillTemplate(id, values = {}) {
  const node = useTemplate(id);
  Object.entries(values).forEach(([name, value]) => {
    const el = slot(node, name);
    if (!el) return;
    if (value == null) el.textContent = "";
    else el.textContent = String(value);
  });
  return node;
}

function dash(value) {
  if (value == null || value === "") return "—";
  return String(value);
}

function makePill(kind, value) {
  const span = document.createElement("span");
  const raw = String(value || "n/a");
  span.className = `pill ${kind}-${raw.replace(/\s+/g, "")}`;
  span.textContent = raw;
  return span;
}

function labeledPill(cls, label) {
  const span = document.createElement("span");
  span.className = `pill ${cls}`;
  span.textContent = label;
  return span;
}

function pipelineStatus(value) {
  const raw = String(value || "").trim();
  const map = {
    ingested: "INGESTED",
    extracting: "EXTRACTED",
    extracted: "EXTRACTED",
    enriching: "ENRICHED",
    enriched: "ENRICHED",
    waiting_enrichment: "WAITING_ENRICHMENT",
    matching: "MATCHED",
    matched: "MATCHED",
    acting: "ACTIONED",
    completed: "ACTIONED",
    actioned: "ACTIONED",
    failed: "FAILED",
    ai_fallback: "AI_FALLBACK",
  };
  if (!raw) return "INGESTED";
  return map[raw.toLowerCase()] || raw.toUpperCase();
}

function makePipelinePill(status) {
  const value = pipelineStatus(status);
  const span = document.createElement("span");
  span.className = `pill st-${value}`;
  if (value === "WAITING_ENRICHMENT") span.textContent = "Waiting for intel";
  else if (value === "AI_FALLBACK") span.textContent = "AI";
  else span.textContent = value.replaceAll("_", " ");
  return span;
}

function setEmptyRow(tbody, cols, message) {
  tbody.replaceChildren();
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = cols;
  td.className = "empty";
  td.textContent = message;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

function bindSelectDelete(opts) {
  const panel = document.getElementById(opts.panelId);
  const startBtn = document.getElementById(opts.startBtnId);
  const cancelBtn = document.getElementById(opts.cancelBtnId);
  const okBtn = document.getElementById(opts.okBtnId);
  const selectAll = document.getElementById(opts.selectAllId);
  const tbody = document.getElementById(opts.tbodyId);
  const modal = document.getElementById(opts.modalId);
  const modalTitle = document.getElementById(opts.modalTitleId);
  const modalConfirm = document.getElementById(opts.modalConfirmId);
  const modalCancel = document.getElementById(opts.modalCancelId);
  const statusEl = document.getElementById(opts.statusId);
  const countEl = document.getElementById(opts.countId);
  const selected = new Set();

  function isSelecting() {
    return Boolean(panel && panel.classList.contains("is-selecting"));
  }

  function colCount() {
    return isSelecting() ? opts.selectCols : opts.normalCols;
  }

  function setStatus(text) {
    if (statusEl) statusEl.textContent = text || "";
  }

  function selectedList() {
    return Array.from(selected);
  }

  function syncRowState(tr) {
    const box = tr.querySelector("input[data-select]");
    if (!box) return;
    const on = selected.has(box.value);
    box.checked = on;
    tr.classList.toggle("is-checked", on);
  }

  function syncUi() {
    const boxes = Array.from(tbody.querySelectorAll("input[data-select]"));
    const visibleChecked = boxes.filter((el) => selected.has(el.value)).length;
    boxes.forEach((box) => {
      const tr = box.closest("tr");
      if (tr) syncRowState(tr);
    });
    if (selectAll) {
      selectAll.checked = boxes.length > 0 && visibleChecked === boxes.length;
      selectAll.indeterminate = visibleChecked > 0 && visibleChecked < boxes.length;
    }
    if (okBtn) okBtn.disabled = selected.size === 0;
    if (countEl) countEl.textContent = selected.size ? `${selected.size} selected` : "";
  }

  function enterSelect() {
    if (!panel) return;
    panel.classList.add("is-selecting");
    setStatus("");
    if (typeof opts.onEnter === "function") opts.onEnter();
    syncUi();
  }

  function exitSelect() {
    if (!panel) return;
    panel.classList.remove("is-selecting");
    selected.clear();
    if (selectAll) {
      selectAll.checked = false;
      selectAll.indeterminate = false;
    }
    if (okBtn) okBtn.disabled = true;
    if (countEl) countEl.textContent = "";
    tbody.querySelectorAll("tr.is-checked").forEach((tr) => tr.classList.remove("is-checked"));
    tbody.querySelectorAll("input[data-select]").forEach((box) => {
      box.checked = false;
    });
    if (typeof opts.onExit === "function") opts.onExit();
  }

  function openModal() {
    const ids = selectedList();
    if (!ids.length) return;
    if (modalTitle && typeof opts.titleFor === "function") {
      modalTitle.textContent = opts.titleFor(ids.length);
    }
    modal.hidden = false;
    modal.removeAttribute("hidden");
  }

  function closeModal() {
    modal.hidden = true;
    modal.setAttribute("hidden", "");
  }

  startBtn.addEventListener("click", enterSelect);
  cancelBtn.addEventListener("click", exitSelect);
  okBtn.addEventListener("click", openModal);
  modalCancel.addEventListener("click", closeModal);
  modal.addEventListener("click", (ev) => {
    if (ev.target === modal) closeModal();
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && modal && !modal.hidden) closeModal();
  });
  modalConfirm.addEventListener("click", async () => {
    const ids = selectedList();
    closeModal();
    if (!ids.length) return;
    setStatus(opts.pending || "Deleting…");
    okBtn.disabled = true;
    startBtn.disabled = true;
    try {
      const result = await api(opts.endpoint, {
        method: "POST",
        body: JSON.stringify(opts.payload(ids)),
      });
      exitSelect();
      if (typeof opts.onDeleted === "function") await opts.onDeleted(result);
      setStatus(typeof opts.done === "function" ? opts.done(result, ids.length) : "Deleted.");
    } catch (err) {
      setStatus(String(err.message || err));
      syncUi();
    } finally {
      startBtn.disabled = false;
    }
  });
  if (selectAll) {
    selectAll.addEventListener("change", () => {
      tbody.querySelectorAll("input[data-select]").forEach((box) => {
        if (selectAll.checked) selected.add(box.value);
        else selected.delete(box.value);
      });
      syncUi();
    });
  }
  tbody.addEventListener("change", (ev) => {
    const box = ev.target.closest("input[data-select]");
    if (!box) return;
    if (box.checked) selected.add(box.value);
    else selected.delete(box.value);
    syncUi();
  });

  return {
    isSelecting,
    colCount,
    selected,
    restoreRow(tr, id) {
      const box = tr.querySelector("input[data-select]");
      if (!box) return;
      box.value = String(id || "");
      syncRowState(tr);
    },
    syncUi,
  };
}

function mutedText(text) {
  const span = document.createElement("span");
  span.className = "muted";
  span.textContent = text;
  return span;
}

function fmtTime(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" });
}

function fmtNum(value) {
  if (value === null || value === undefined) return "—";
  return Number(value).toLocaleString("en-US");
}

function stampUpdated(ok = true) {
  const el = document.getElementById("page-updated");
  if (!el) return;
  if (!ok) {
    el.textContent = "Update failed";
    el.classList.remove("is-fresh");
    return;
  }
  const time = new Date().toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  el.textContent = `Updated ${time}`;
  if (el.dataset.flash === "off") return;
  el.classList.remove("is-fresh");
  void el.offsetWidth;
  el.classList.add("is-fresh");
}

window.pipelineStatus = pipelineStatus;
window.makePipelinePill = makePipelinePill;
window.makePill = makePill;
window.labeledPill = labeledPill;
window.useTemplate = useTemplate;
window.fillTemplate = fillTemplate;
window.slot = slot;
window.dash = dash;
window.setEmptyRow = setEmptyRow;
window.bindSelectDelete = bindSelectDelete;
window.mutedText = mutedText;
window.stampUpdated = stampUpdated;
window.fmtTime = fmtTime;
window.fmtNum = fmtNum;

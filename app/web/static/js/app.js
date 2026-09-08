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

document.addEventListener("DOMContentLoaded", () => {
  initSidebar();
  initHeader();
  initActiveNav();
  initRowNav();
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
  span.textContent = value.replaceAll("_", " ");
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

window.pipelineStatus = pipelineStatus;
window.makePipelinePill = makePipelinePill;
window.makePill = makePill;
window.labeledPill = labeledPill;
window.useTemplate = useTemplate;
window.fillTemplate = fillTemplate;
window.slot = slot;
window.dash = dash;
window.setEmptyRow = setEmptyRow;
window.mutedText = mutedText;

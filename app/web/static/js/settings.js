const AI_PROVIDERS = {
  gemini: {
    api_base: "https://generativelanguage.googleapis.com/v1beta/openai",
    model: "gemini-1.5-flash",
    keyHint: "Google AI Studio API key",
    match: ["generativelanguage.googleapis.com"],
  },
  chatgpt: {
    api_base: "https://api.openai.com/v1",
    model: "gpt-4o-mini",
    keyHint: "OpenAI API key from platform.openai.com",
    match: ["api.openai.com"],
  },
  azure_openai: {
    api_base: "https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT",
    model: "gpt-4o",
    keyHint: "Azure OpenAI API key",
    match: ["openai.azure.com", "cognitiveservices.azure.com"],
  },
  github_copilot: {
    api_base: "https://api.githubcopilot.com",
    model: "gpt-4o",
    keyHint: "GitHub Copilot or enterprise token",
    match: ["githubcopilot.com"],
  },
};

function urlMatchesProvider(url, provider) {
  const preset = AI_PROVIDERS[provider];
  if (!url || !preset) return false;
  const lower = String(url).toLowerCase();
  return (preset.match || []).some((part) => lower.includes(part));
}

function urlBelongsToOtherProvider(url, provider) {
  return Object.keys(AI_PROVIDERS).some(
    (name) => name !== provider && urlMatchesProvider(url, name)
  );
}

let aiSaved = {
  enabled: false,
  provider: "gemini",
  api_base: "",
  model: "",
  api_key_set: false,
};
let atomFeedsReady = false;

const ENRICH_HINTS = {
  on: "Look up NVD / EPSS. If AI modules are also enabled, the model may rewrite the owner-facing description. Then match against Internal systems.",
  off: "Skip NVD and EPSS. After extract, go straight to matching ingested fields against Internal systems. The AI modules switch still controls extract and matching.",
};

const AI_HINTS = {
  on: "Requires an API key. The selected provider is used only when regex/NVD/Internal systems cannot finish the step.",
  off: "No LLM calls anywhere. Tickets still open from Ticketing using ingested/NVD fields and the Message templates.",
};

function selectedChoice(group) {
  const root = document.querySelector(`[data-choice-group="${group}"]`);
  const btn = root && root.querySelector(".choice-seg-btn.is-active");
  return btn ? btn.dataset.choice : "";
}

function setChoice(group, value) {
  const root = document.querySelector(`[data-choice-group="${group}"]`);
  if (!root) return;
  let active = null;
  root.querySelectorAll(".choice-seg-btn").forEach((btn) => {
    const on = btn.dataset.choice === value;
    btn.classList.toggle("is-active", on);
    btn.setAttribute("aria-pressed", on ? "true" : "false");
    if (on) active = btn;
  });
  const hintId = root.dataset.hintTarget;
  if (hintId && active) {
    const hint = document.getElementById(hintId);
    if (hint) hint.textContent = active.dataset.hint || "";
  }
}

function enrichmentEnabled() {
  return selectedChoice("enrich-stage") !== "disable";
}

function setEnrichmentEnabled(on) {
  setChoice("enrich-stage", on ? "enable" : "disable");
  syncEnrichmentUi();
}

function syncEnrichmentUi() {
  const on = enrichmentEnabled();
  const note = document.getElementById("intel-enrich-off-note");
  if (note) note.hidden = on;
  const hint = document.getElementById("enrich-stage-hint");
  if (hint) hint.textContent = on ? ENRICH_HINTS.on : ENRICH_HINTS.off;
}

function aiEnabled() {
  return selectedChoice("ai-stage") !== "disable";
}

function setAiEnabled(on) {
  setChoice("ai-stage", on ? "enable" : "disable");
  if (on) {
    const current = enabledAiProvider() || document.getElementById("ai-provider")?.value || aiSaved.provider || "gemini";
    setAiProviderEnables(current, true);
    const hidden = document.getElementById("ai-provider");
    if (hidden) hidden.value = current;
  }
  syncAiUi();
}

function syncAiUi() {
  const on = aiEnabled();
  const body = document.getElementById("ai-enabled-body");
  if (body) body.hidden = !on;
  const note = document.getElementById("ai-disabled-note");
  if (note) note.hidden = on;
  const hint = document.getElementById("ai-stage-hint");
  if (hint) hint.textContent = on ? AI_HINTS.on : AI_HINTS.off;
}

function showTab(name) {
  document.querySelectorAll(".settings-tab").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.tab === name);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.panel === name);
  });
}

function applySettingsHash() {
  const raw = (location.hash || "").replace(/^#/, "").trim();
  if (!raw) return;
  const aliases = { nvd: "feeds", epss: "feeds", intel: "feeds", wipe: "reset", reset: "reset", system: "reset", mail: "message", template: "message", message: "message" };
  const [rawTab, subtab] = raw.split("/").map((part) => part.trim()).filter(Boolean);
  const tab = aliases[rawTab] || rawTab;
  if (!tab || !document.querySelector(`.settings-tab[data-tab="${tab}"]`)) return;
  showTab(tab);
  const resolvedSub = subtab || (["intel", "nvd", "epss"].includes(rawTab) ? "web" : "");
  if (!resolvedSub) return;
  const group = tab;
  if (document.querySelector(`.settings-subtab[data-group="${group}"][data-subtab="${resolvedSub}"]`)) {
    showSubtab(resolvedSub, group);
  }
}

function showSubtab(name, group) {
  document.querySelectorAll(`.settings-subtab[data-group="${group}"]`).forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.subtab === name);
  });
  document.querySelectorAll(`.subtab-panel[data-group="${group}"]`).forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.subpanel === name);
  });
  if (group === "ai") {
    document.getElementById("ai-provider").value = name;
    const enabled = enabledAiProvider();
    if (!enabled || enabled === name) {
      fillAiConnectionFor(name);
    } else {
      const fields = document.getElementById("ai-connection-fields");
      if (fields) fields.hidden = true;
    }
  }
  if (group === "ticketing") {
    document.getElementById("ticketing-provider").value = name;
    document.querySelectorAll("[data-ticketing-enable]").forEach((bar) => {
      bar.hidden = bar.dataset.ticketingEnable !== name;
    });
    const httpFields = document.getElementById("ticketing-http-fields");
    if (httpFields) httpFields.hidden = name === "email";
    syncTicketingTestButton();
  }
}

function setAiProviderEnables(activeProvider, enabled) {
  Object.keys(AI_PROVIDERS).forEach((name) => {
    const el = document.getElementById(`ai-enabled-${name}`);
    if (el) el.checked = Boolean(enabled && name === activeProvider);
  });
}

function enabledAiProvider() {
  return Object.keys(AI_PROVIDERS).find((name) => document.getElementById(`ai-enabled-${name}`)?.checked) || "";
}

function fillAiConnectionFor(provider) {
  const preset = AI_PROVIDERS[provider] || AI_PROVIDERS.gemini;
  const baseEl = document.getElementById("ai-base");
  const modelEl = document.getElementById("ai-model");
  const enabled = Boolean(document.getElementById(`ai-enabled-${provider}`)?.checked);
  baseEl.placeholder = preset.api_base;
  modelEl.placeholder = preset.model;
  if (enabled) {
    const savedFits = aiSaved.provider === provider
      && Boolean(aiSaved.api_base)
      && !urlBelongsToOtherProvider(aiSaved.api_base, provider);
    baseEl.value = savedFits ? aiSaved.api_base : preset.api_base;
    modelEl.value = savedFits && aiSaved.model ? aiSaved.model : preset.model;
    hint("ai-key-hint", savedFits && aiSaved.api_key_set, "key");
  }
  const fields = document.getElementById("ai-connection-fields");
  if (fields) fields.hidden = !enabled;
}

function onAiEnableToggle(provider, checked) {
  if (checked) {
    setChoice("ai-stage", "enable");
    setAiProviderEnables(provider, true);
    document.getElementById("ai-provider").value = provider;
  } else {
    setAiProviderEnables(provider, false);
    setChoice("ai-stage", "disable");
  }
  fillAiConnectionFor(provider);
  syncAiUi();
}

function addAtomFeedRow(feed) {
  const list = document.getElementById("atom-feed-list");
  if (!list) return;
  const row = useTemplate("tpl-atom-feed-row");
  row.querySelector(".atom-feed-name").value = feed?.name || "";
  row.querySelector(".atom-feed-url").value = feed?.url || "";
  const typeEl = row.querySelector(".atom-feed-type");
  if (typeEl) typeEl.value = feed?.feed_type || "atom";
  list.appendChild(row);
}

function renderAtomFeeds(feeds) {
  const list = document.getElementById("atom-feed-list");
  if (!list) return;
  list.replaceChildren();
  const rows = feeds && feeds.length ? feeds : [{ url: "", name: "" }];
  rows.forEach((feed) => addAtomFeedRow(feed));
  atomFeedsReady = true;
}

function collectAtomFeeds() {
  return [...document.querySelectorAll("#atom-feed-list .atom-feed-row")].map((row) => ({
    name: (row.querySelector(".atom-feed-name")?.value || "").trim(),
    url: (row.querySelector(".atom-feed-url")?.value || "").trim(),
    token: "",
    feed_type: (row.querySelector(".atom-feed-type")?.value || "atom").trim() || "atom",
  })).filter((feed) => feed.url);
}

document.getElementById("atom-feed-list")?.addEventListener("click", (ev) => {
  const btn = ev.target.closest(".atom-feed-remove");
  if (!btn) return;
  const list = document.getElementById("atom-feed-list");
  const row = btn.closest(".atom-feed-row");
  if (!list || !row) return;
  if (list.querySelectorAll(".atom-feed-row").length <= 1) {
    row.querySelector(".atom-feed-url").value = "";
    row.querySelector(".atom-feed-name").value = "";
    return;
  }
  row.remove();
});

document.getElementById("atom-feed-add")?.addEventListener("click", () => addAtomFeedRow({ url: "", name: "" }));

document.getElementById("atom-feed-restore")?.addEventListener("click", async () => {
  setStatus("web-status", "Restoring built-in ATOM feeds…");
  try {
    const result = await api("/api/settings/web-api/restore", { method: "POST" });
    const web = result.web_api || {};
    renderAtomFeeds(Array.isArray(web.feeds) && web.feeds.length ? web.feeds : []);
    setStatus("web-status", "Built-in ATOM feeds are back. Polling stays off until you enable it.");
  } catch (err) {
    setStatus("web-status", String(err.message || err));
  }
});

function syncIntelKeyWrap(card) {
  const type = card.querySelector(".intel-type")?.value || "nvd";
  const wrap = card.querySelector(".intel-key-wrap");
  if (wrap) wrap.hidden = type !== "nvd";
}

function addIntelSourceRow(source) {
  const list = document.getElementById("intel-source-list");
  if (!list) return;
  const row = useTemplate("tpl-intel-source");
  row.querySelector(".intel-id").value = source?.id || "";
  row.querySelector(".intel-name").value = source?.name || "";
  row.querySelector(".intel-type").value = source?.feed_type === "epss" ? "epss" : "nvd";
  row.querySelector(".intel-url").value = source?.endpoint || "";
  row.querySelector(".intel-enabled").checked = Boolean(source?.enabled);
  const hintEl = row.querySelector(".intel-key-hint");
  if (hintEl) hintEl.textContent = source?.api_key_set ? "A key is saved." : "";
  syncIntelKeyWrap(row);
  list.appendChild(row);
}

function renderIntelSources(sources) {
  const list = document.getElementById("intel-source-list");
  if (!list) return;
  list.replaceChildren();
  (sources || []).forEach((source) => addIntelSourceRow(source));
}

function collectIntelSources() {
  return [...document.querySelectorAll("#intel-source-list [data-intel-card]")].map((row) => ({
    id: Number(row.querySelector(".intel-id")?.value || 0) || null,
    name: (row.querySelector(".intel-name")?.value || "").trim(),
    feed_type: row.querySelector(".intel-type")?.value || "nvd",
    endpoint: (row.querySelector(".intel-url")?.value || "").trim(),
    enabled: Boolean(row.querySelector(".intel-enabled")?.checked),
    api_key: row.querySelector(".intel-key")?.value || "",
  })).filter((source) => source.id || source.endpoint);
}

document.getElementById("intel-source-list")?.addEventListener("click", (ev) => {
  const btn = ev.target.closest(".intel-remove");
  if (!btn) return;
  const list = document.getElementById("intel-source-list");
  const row = btn.closest("[data-intel-card]");
  if (!list || !row) return;
  row.remove();
});

document.getElementById("intel-source-list")?.addEventListener("change", (ev) => {
  const select = ev.target.closest(".intel-type");
  if (!select) return;
  const card = select.closest("[data-intel-card]");
  if (card) syncIntelKeyWrap(card);
});

document.getElementById("intel-source-add")?.addEventListener("click", () => {
  addIntelSourceRow({ name: "", feed_type: "nvd", endpoint: "", enabled: false });
});

document.getElementById("intel-source-restore")?.addEventListener("click", async () => {
  setStatus("enrich-status", "Restoring built-in sources…");
  try {
    const result = await api("/api/settings/intel/restore", { method: "POST" });
    renderIntelSources(result.sources || []);
    setStatus("enrich-status", "Built-in NVD and EPSS are back. Save if you also changed other fields.");
  } catch (err) {
    setStatus("enrich-status", String(err.message || err));
  }
});

function addSmbLocationRow(loc) {
  const list = document.getElementById("smb-location-list");
  if (!list) return;
  const row = useTemplate("tpl-smb-location");
  row.querySelector(".smb-loc-name").value = loc?.name || "";
  row.querySelector(".smb-loc-server").value = loc?.server || "";
  row.querySelector(".smb-loc-share").value = loc?.share || "";
  row.querySelector(".smb-loc-path").value = loc?.path || "";
  list.appendChild(row);
}

function renderSmbLocations(locations) {
  const list = document.getElementById("smb-location-list");
  if (!list) return;
  list.replaceChildren();
  const rows = locations && locations.length ? locations : [{ name: "", server: "", share: "", path: "" }];
  rows.forEach((loc) => addSmbLocationRow(loc));
}

function collectSmbLocations() {
  return [...document.querySelectorAll("#smb-location-list .smb-location-card")].map((row) => ({
    name: (row.querySelector(".smb-loc-name")?.value || "").trim(),
    server: (row.querySelector(".smb-loc-server")?.value || "").trim(),
    share: (row.querySelector(".smb-loc-share")?.value || "").trim(),
    path: (row.querySelector(".smb-loc-path")?.value || "").trim(),
  })).filter((loc) => loc.server && loc.share);
}

document.getElementById("smb-location-list")?.addEventListener("click", (ev) => {
  const btn = ev.target.closest(".smb-location-remove");
  if (!btn) return;
  const list = document.getElementById("smb-location-list");
  const row = btn.closest(".smb-location-card");
  if (!list || !row) return;
  if (list.querySelectorAll(".smb-location-card").length <= 1) {
    row.querySelectorAll("input").forEach((input) => { input.value = ""; });
    return;
  }
  row.remove();
});

document.getElementById("smb-location-add")?.addEventListener("click", () => addSmbLocationRow({}));

document.querySelectorAll(".settings-tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    showTab(btn.dataset.tab);
    history.replaceState(null, "", `#${btn.dataset.tab}`);
  });
});

document.querySelectorAll(".settings-subtab").forEach((btn) => {
  btn.addEventListener("click", () => {
    showSubtab(btn.dataset.subtab, btn.dataset.group);
    history.replaceState(null, "", `#${btn.dataset.group}/${btn.dataset.subtab}`);
  });
});

window.addEventListener("hashchange", applySettingsHash);
applySettingsHash();

function formatProbeResult(result) {
  if (!result || typeof result !== "object") return "OK.";
  if (result.provider === "smtp" || result.host) {
    const host = result.host || "SMTP";
    const port = result.port ? `:${result.port}` : "";
    const mode = result.mode ? ` (${result.mode})` : "";
    if (result.sent && result.to) {
      return `Sent a test email to ${result.to} via ${host}${port}${mode}. Check that inbox (and spam).`;
    }
    const user = result.username ? ` as ${result.username}` : "";
    return `Connected to ${host}${port}${mode}${user}.`;
  }
  if (result.provider) return `OK — ${result.provider} connected.`;
  return "OK — connection succeeded.";
}

function setStatus(id, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  const lower = String(text || "").toLowerCase();
  el.classList.toggle("is-error", /fail|error|reject|not found/.test(lower));
  el.classList.toggle("is-ok", /^(ok|saved|connected|sent|reset complete|delete complete)/.test(lower));
}

function showStoredSmtpAccount(username, passwordSet) {
  const chip = document.getElementById("smtp-stored-account");
  if (!chip) return;
  const address = (username || "").trim();
  if (!address) {
    chip.hidden = true;
    chip.textContent = "";
    return;
  }
  chip.hidden = false;
  chip.textContent = passwordSet
    ? `Stored SMTP login: ${address} (password is saved)`
    : `Stored SMTP login: ${address} (no password saved yet)`;
}

function feedStatusLine(source) {
  if (!source) return "";
  return source.last_error ? `Last error: ${source.last_error}` : "";
}

function hint(id, stored, kind) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = stored ? `A ${kind} is stored. Leave blank to keep it.` : `No ${kind} stored yet.`;
}

async function loadSettings() {
  atomFeedsReady = false;
  const data = await api("/api/settings");
  const pg = data.postgres || {};
  const smb = data.smb || {};
  const local = data.local || {};
  const outlook = data.outlook || {};
  const web = data.web_api || {};

  const mode = pg.mode || (pg.enabled ? "remote" : "sqlite");
  setChoice("pg-mode", mode);
  document.getElementById("pg-host").value = pg.host || "";
  document.getElementById("pg-port").value = pg.port || 5432;
  document.getElementById("pg-database").value = pg.database || "evulntasker";
  document.getElementById("pg-username").value = pg.username || "";
  document.getElementById("pg-password").value = "";
  document.getElementById("pg-ssl").value = pg.sslmode || "prefer";
  document.getElementById("pg-use-socket").checked = Boolean(pg.socket);
  document.getElementById("pg-socket").value = pg.socket || "/var/run/postgresql";
  hint("pg-password-hint", pg.password_set, "password");
  const labels = { sqlite: "SQLite file", local: "local PostgreSQL on this Linux host", remote: "external PostgreSQL" };
  document.getElementById("pg-current").textContent = pg.current_url
    ? `Active: ${labels[mode] || mode} — ${pg.current_url}`
    : "Active: SQLite file on this server";
  syncPgUi();

  document.getElementById("smb-name").value = smb.name || "";
  const smbLocations = Array.isArray(smb.locations) && smb.locations.length
    ? smb.locations
    : (smb.server && smb.share ? [{ name: "", server: smb.server, share: smb.share, path: smb.path || "" }] : [{ name: "", server: "", share: "", path: "" }]);
  renderSmbLocations(smbLocations);
  document.getElementById("smb-domain").value = smb.domain || "";
  document.getElementById("smb-username").value = smb.username || "";
  document.getElementById("smb-poll").value = smb.poll_seconds || 300;
  document.getElementById("smb-password").value = "";
  hint("smb-password-hint", smb.password_set, "password");
  setStatus("smb-status", feedStatusLine(smb));

  document.getElementById("local-name").value = local.name || "";
  document.getElementById("local-path").value = local.path || "";
  document.getElementById("local-poll").value = local.poll_seconds || 60;
  setStatus("local-status", feedStatusLine(local));

  document.getElementById("outlook-name").value = outlook.name || "";
  document.getElementById("outlook-server").value = outlook.server || "";
  document.getElementById("outlook-domain").value = outlook.domain || "";
  document.getElementById("outlook-username").value = outlook.username || "";
  document.getElementById("outlook-email").value = outlook.email || "";
  document.getElementById("outlook-folder").value = outlook.folder || "Inbox";
  document.getElementById("outlook-poll").value = outlook.poll_seconds || 120;
  document.getElementById("outlook-password").value = "";
  hint("outlook-password-hint", outlook.password_set, "password");
  setStatus("outlook-status", feedStatusLine(outlook));

  document.getElementById("web-name").value = web.name || "";
  const pollEl = document.getElementById("web-poll");
  const pollValue = String(web.poll_seconds || 3600);
  if (pollEl && ![...pollEl.options].some((opt) => opt.value === pollValue)) {
    pollEl.add(new Option(`Every ${Math.round(Number(pollValue) / 60)} minutes`, pollValue), 0);
  }
  if (pollEl) pollEl.value = pollValue;
  const feeds = Array.isArray(web.feeds) && web.feeds.length
    ? web.feeds
    : (web.url ? [{ url: web.url, name: "" }] : [{ url: "", name: "" }]);
  renderAtomFeeds(feeds);
  setStatus("web-status", feedStatusLine(web));

  const enrich = data.enrichment || {};
  setEnrichmentEnabled(enrich.enrichment_enabled !== false);
  const startEl = document.getElementById("intel-start");
  if (startEl) startEl.value = (enrich.intel_start_date || "2024-01-01").slice(0, 10);
  renderIntelSources(enrich.sources || []);
  syncEnrichmentUi();

  const ai = data.ai || {};
  const provider = ai.provider || "gemini";
  const enrichMode = ai.enrichment_mode || "direct";
  aiSaved = {
    enabled: Boolean(ai.enabled),
    provider,
    api_base: ai.api_base || "",
    model: ai.model || "",
    api_key_set: Boolean(ai.api_key_set),
  };
  document.getElementById("ai-provider").value = provider;
  setAiEnabled(aiSaved.enabled);
  setAiProviderEnables(provider, aiSaved.enabled);
  setChoice("ai-enrichment-mode", enrichMode);
  document.getElementById("ai-key").value = "";
  showSubtab(provider, "ai");

  const assets = data.assets || {};
  const cmdb = assets.cmdb || {};
  const sonatype = assets.sonatype || {};
  document.getElementById("cmdb-enabled").checked = Boolean(cmdb.enabled);
  document.getElementById("cmdb-host").value = cmdb.host || "";
  document.getElementById("cmdb-port").value = cmdb.port || 443;
  document.getElementById("cmdb-use-tls").checked = cmdb.use_tls !== false;
  document.getElementById("cmdb-ignore-cert").checked = Boolean(cmdb.ignore_cert);
  document.getElementById("cmdb-api-path").value = cmdb.api_path || "/api";
  document.getElementById("cmdb-username").value = cmdb.username || "";
  document.getElementById("cmdb-password").value = "";
  hint("cmdb-password-hint", cmdb.password_set, "password");

  document.getElementById("sonatype-enabled").checked = Boolean(sonatype.enabled);
  document.getElementById("sonatype-host").value = sonatype.host || "";
  document.getElementById("sonatype-port").value = sonatype.port || 8070;
  document.getElementById("sonatype-use-tls").checked = sonatype.use_tls !== false;
  document.getElementById("sonatype-ignore-cert").checked = Boolean(sonatype.ignore_cert);
  document.getElementById("sonatype-api-path").value = sonatype.api_path || "";
  document.getElementById("sonatype-username").value = sonatype.username || "";
  document.getElementById("sonatype-password").value = "";
  hint("sonatype-password-hint", sonatype.password_set, "password");

  const itnm = assets.itnm || {};
  document.getElementById("itnm-enabled").checked = Boolean(itnm.enabled);
  document.getElementById("itnm-host").value = itnm.host || "";
  document.getElementById("itnm-port").value = itnm.port || 443;
  document.getElementById("itnm-use-tls").checked = itnm.use_tls !== false;
  document.getElementById("itnm-ignore-cert").checked = Boolean(itnm.ignore_cert);
  document.getElementById("itnm-api-path").value = itnm.api_path || "/api";
  document.getElementById("itnm-list-path").value = itnm.list_path || "/devices";
  document.getElementById("itnm-username").value = itnm.username || "";
  document.getElementById("itnm-password").value = "";
  hint("itnm-password-hint", itnm.password_set, "password");

  const ticket = data.ticketing || {};
  const enables = ticket.enables || {};
  document.getElementById("ticketing-enabled-jira").checked = Boolean(enables.jira);
  document.getElementById("ticketing-enabled-monday").checked = Boolean(enables.monday);
  document.getElementById("ticketing-enabled-email").checked = Boolean(enables.email);
  document.getElementById("ticketing-enabled-custom").checked = Boolean(enables.custom);
  document.getElementById("ticketing-host").value = ticket.host || "";
  document.getElementById("ticketing-port").value = ticket.port || 443;
  document.getElementById("ticketing-use-tls").checked = ticket.use_tls !== false;
  document.getElementById("ticketing-ignore-cert").checked = Boolean(ticket.ignore_cert);
  document.getElementById("ticketing-username").value = ticket.username || "";
  document.getElementById("ticketing-password").value = "";
  hint("ticketing-password-hint", ticket.password_set, "token");
  const keepTab = document.getElementById("ticket-form")?.dataset.loaded === "1";
  const currentTab = document.getElementById("ticketing-provider").value;
  const hashSub = (location.hash || "").replace(/^#/, "").split("/")[1] || "";
  const firstEnabled = ["jira", "monday", "email", "custom"].find((name) => enables[name]);
  const ticketProvider = (keepTab && currentTab)
    || (["jira", "monday", "email", "custom"].includes(hashSub) ? hashSub : "")
    || firstEnabled
    || ticket.provider
    || "jira";
  document.getElementById("ticketing-provider").value = ticketProvider;
  showSubtab(ticketProvider, "ticketing");
  document.getElementById("ticket-form").dataset.loaded = "1";
  document.getElementById("jira-email").value = ticket.jira_user_email || "";
  document.getElementById("jira-project").value = ticket.jira_project_key || "VULN";
  document.getElementById("jira-hunt").value = ticket.jira_hunt_project_key || "HUNT";
  document.getElementById("jira-type").value = ticket.jira_issue_type || "Task";
  document.getElementById("monday-board").value = ticket.monday_board_id || "";
  document.getElementById("monday-group").value = ticket.monday_group_id || "";
  document.getElementById("custom-api-path").value = ticket.custom_api_path || "/api/tickets";
  document.getElementById("custom-owner-project").value = ticket.custom_owner_project || "VULN";
  document.getElementById("custom-hunt-project").value = ticket.custom_hunt_project || "HUNT";
  document.getElementById("ticket-hunt-email").value = ticket.hunt_email || "";
  document.getElementById("ticket-owner-email").value = ticket.fallback_owner_email || "";
  document.getElementById("ticket-email-domains").value = (ticket.email_domains || "").trim();
  document.getElementById("smtp-host").value = ticket.smtp_host || "";
  document.getElementById("smtp-port").value = ticket.smtp_port || 25;
  setChoice("smtp-tls", ticket.smtp_tls_mode || "plain");
  document.getElementById("smtp-username").value = ticket.smtp_username || "";
  document.getElementById("smtp-from").value = ticket.smtp_from || "";
  document.getElementById("smtp-ignore-cert").checked = Boolean(ticket.smtp_ignore_cert);
  document.getElementById("smtp-password").value = "";
  hint("smtp-password-hint", ticket.smtp_password_set, "password");
  showStoredSmtpAccount(ticket.smtp_username, ticket.smtp_password_set);
  fillMessageForm(data.message || {});
}

function smbBody() {
  return {
    name: document.getElementById("smb-name").value.trim(),
    locations: collectSmbLocations(),
    domain: document.getElementById("smb-domain").value.trim(),
    username: document.getElementById("smb-username").value.trim(),
    password: document.getElementById("smb-password").value,
    poll_seconds: Number(document.getElementById("smb-poll").value || 300),
  };
}

function selectedPgMode() {
  return selectedChoice("pg-mode") || "sqlite";
}

function selectedAiEnrichmentMode() {
  return selectedChoice("ai-enrichment-mode") || "direct";
}

function syncPgUi() {
  const mode = selectedPgMode();
  const useSocket = document.getElementById("pg-use-socket").checked;
  document.getElementById("pg-fields").hidden = mode === "sqlite";
  document.getElementById("pg-remote-fields").hidden = mode !== "remote";
  document.getElementById("pg-local-fields").hidden = mode !== "local";
  document.getElementById("pg-socket-path-wrap").hidden = mode !== "local" || !useSocket;
  document.getElementById("pg-port-wrap").hidden = mode === "local" && useSocket;
}

function localBody() {
  return {
    name: document.getElementById("local-name").value.trim(),
    path: document.getElementById("local-path").value.trim(),
    poll_seconds: Number(document.getElementById("local-poll").value || 60),
  };
}

function outlookBody() {
  return {
    name: document.getElementById("outlook-name").value.trim(),
    server: document.getElementById("outlook-server").value.trim(),
    domain: document.getElementById("outlook-domain").value.trim(),
    username: document.getElementById("outlook-username").value.trim(),
    password: document.getElementById("outlook-password").value,
    email: document.getElementById("outlook-email").value.trim(),
    folder: document.getElementById("outlook-folder").value.trim() || "Inbox",
    poll_seconds: Number(document.getElementById("outlook-poll").value || 120),
  };
}

function webApiBody() {
  return {
    name: document.getElementById("web-name").value.trim(),
    feeds: collectAtomFeeds(),
    poll_seconds: Number(document.getElementById("web-poll").value || 3600),
    intel_start_date: document.getElementById("intel-start")?.value || "",
  };
}

async function saveIntelStart() {
  const start = document.getElementById("intel-start")?.value;
  if (!start) return;
  await api("/api/settings/enrichment", {
    method: "PUT",
    body: JSON.stringify({ intel_start_date: start }),
  });
}

async function saveFeed(kind) {
  if (kind === "local") {
    await api("/api/settings/local", { method: "PUT", body: JSON.stringify(localBody()) });
    await saveIntelStart();
    return;
  }
  if (kind === "smb") {
    await api("/api/settings/smb", { method: "PUT", body: JSON.stringify(smbBody()) });
    await saveIntelStart();
    return;
  }
  if (kind === "outlook") {
    await api("/api/settings/outlook", { method: "PUT", body: JSON.stringify(outlookBody()) });
    await saveIntelStart();
    return;
  }
  if (kind === "web-api") {
    await saveWebApi();
  }
}

async function saveWebApi() {
  if (!atomFeedsReady) {
    throw new Error("ATOM feeds have not loaded yet. Wait a moment and try Save again.");
  }
  await api("/api/settings/web-api", { method: "PUT", body: JSON.stringify(webApiBody()) });
  await saveIntelStart();
}

function postgresBody() {
  const mode = selectedPgMode();
  const useSocket = document.getElementById("pg-use-socket").checked;
  return {
    mode,
    enabled: mode !== "sqlite",
    host: mode === "local" ? "127.0.0.1" : document.getElementById("pg-host").value.trim(),
    port: Number(document.getElementById("pg-port").value || 5432),
    database: document.getElementById("pg-database").value.trim(),
    username: document.getElementById("pg-username").value.trim(),
    password: document.getElementById("pg-password").value,
    sslmode: mode === "local" ? "disable" : document.getElementById("pg-ssl").value,
    socket: mode === "local" && useSocket ? document.getElementById("pg-socket").value.trim() : "",
  };
}

document.querySelectorAll("[data-choice-group]").forEach((root) => {
  root.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".choice-seg-btn");
    if (!btn || !root.contains(btn)) return;
    setChoice(root.dataset.choiceGroup, btn.dataset.choice);
    if (root.dataset.choiceGroup === "pg-mode") syncPgUi();
    if (root.dataset.choiceGroup === "enrich-stage") syncEnrichmentUi();
    if (root.dataset.choiceGroup === "ai-stage") setAiEnabled(btn.dataset.choice !== "disable");
    if (root.dataset.choiceGroup === "smtp-tls") syncSmtpPortHint();
  });
});
document.getElementById("pg-use-socket").addEventListener("change", syncPgUi);
syncPgUi();

document.getElementById("postgres-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setStatus("pg-status", "Saving…");
  try {
    const result = await api("/api/settings/postgres", { method: "PUT", body: JSON.stringify(postgresBody()) });
    const messages = {
      sqlite: "Switched back to local SQLite.",
      local: "Local PostgreSQL on this Linux host is now the system database.",
      remote: "External PostgreSQL is now the system database.",
    };
    setStatus("pg-status", messages[result.mode] || (result.backend === "postgresql" ? "PostgreSQL is now the system database." : "Saved."));
    await loadSettings();
  } catch (err) {
    setStatus("pg-status", String(err.message || err));
  }
});

document.getElementById("pg-test").addEventListener("click", async () => {
  setStatus("pg-status", "Testing…");
  try {
    const result = await api("/api/settings/postgres/test", { method: "POST", body: JSON.stringify(postgresBody()) });
    setStatus("pg-status", result.message || "Connection OK.");
  } catch (err) {
    setStatus("pg-status", String(err.message || err));
  }
});

document.getElementById("smb-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await saveFeed("smb");
  setStatus("smb-status", "Saved.");
  await loadSettings();
});

document.getElementById("local-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await saveFeed("local");
  setStatus("local-status", "Saved.");
  await loadSettings();
});

document.getElementById("outlook-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await saveFeed("outlook");
  setStatus("outlook-status", "Saved.");
  await loadSettings();
});

document.getElementById("intel-start-form")?.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await saveIntelStart();
  setStatus("intel-start-status", "Saved. Incoming CVEs older than this date are ignored.");
});

document.getElementById("web-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await saveWebApi();
  setStatus("web-status", "Saved.");
  await loadSettings();
});

document.querySelectorAll("[data-test]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const kind = btn.dataset.test;
    const statusId = kind === "web-api" ? "web-status" : `${kind}-status`;
    setStatus(statusId, "Testing…");
    try {
      await saveFeed(kind);
      const opts = { method: "POST" };
      if (kind === "local") {
        opts.body = JSON.stringify({ path: localBody().path });
      }
      const result = await api(`/api/settings/${kind}/test`, opts);
      if (kind === "web-api" && Array.isArray(result.feeds)) {
        const parts = result.feeds.map((feed) => (
          feed.error
            ? `${feed.url}: ${feed.error}`
            : `${feed.format || "atom"} · ${feed.entries || 0} entries · ${feed.cves || 0} CVE(s)`
        ));
        setStatus(statusId, parts.join(" | ") || "OK.");
      } else if (kind === "smb" && Array.isArray(result.locations)) {
        const parts = result.locations.map((loc) => (
          loc.error
            ? `${loc.path || loc.name}: ${loc.error}`
            : `${loc.path || loc.name} · ${loc.entries || 0} entries`
        ));
        setStatus(statusId, parts.join(" | ") || "OK.");
      } else if (kind === "local") {
        setStatus(statusId, `OK. ${result.path} · ${result.files || 0} file(s)`);
      } else {
        setStatus(statusId, `OK. ${JSON.stringify(result).slice(0, 180)}`);
      }
    } catch (err) {
      setStatus(statusId, String(err.message || err));
    }
  });
});

document.querySelectorAll("[data-sync]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const kind = btn.dataset.sync;
    const statusId = kind === "web-api" ? "web-status" : `${kind}-status`;
    setStatus(statusId, "Syncing…");
    try {
      await saveFeed(kind);
      const result = await api(`/api/settings/${kind}/sync`, { method: "POST" });
      setStatus(statusId, `Ingested ${result.ingested} item(s).`);
      await loadSettings();
    } catch (err) {
      setStatus(statusId, String(err.message || err));
    }
  });
});

document.getElementById("enrich-stage-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await api("/api/settings/enrichment", {
    method: "PUT",
    body: JSON.stringify({ enrichment_enabled: enrichmentEnabled() }),
  });
  setStatus("enrich-stage-status", enrichmentEnabled()
    ? "Saved. Enrichment will run (NVD/EPSS and/or AI), then matching."
    : "Saved. Enrichment skipped — pipeline goes straight to Internal systems matching.");
  await loadSettings();
});

document.getElementById("ai-form").addEventListener("change", (ev) => {
  const box = ev.target.closest("[data-ai-provider]");
  if (!box || ev.target.type !== "checkbox") return;
  onAiEnableToggle(box.dataset.aiProvider, ev.target.checked);
});

document.getElementById("ai-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const provider = enabledAiProvider() || document.getElementById("ai-provider").value || "gemini";
  const result = await api("/api/settings/ai", {
    method: "PUT",
    body: JSON.stringify({
      enabled: aiEnabled(),
      provider,
      enrichment_mode: selectedAiEnrichmentMode(),
      api_base: document.getElementById("ai-base").value.trim(),
      model: document.getElementById("ai-model").value.trim(),
      api_key: document.getElementById("ai-key").value,
    }),
  });
  if (result && result.needs_key) {
    setStatus("ai-status", "AI stays off until you save an API key.");
  } else if (result && result.enabled) {
    setStatus("ai-status", "Saved. AI is on for this provider.");
  } else {
    setStatus("ai-status", "Saved. AI is off.");
  }
  await loadSettings();
});

document.getElementById("cmdb-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await api("/api/settings/assets/cmdb", {
    method: "PUT",
    body: JSON.stringify({
      enabled: document.getElementById("cmdb-enabled").checked,
      host: document.getElementById("cmdb-host").value.trim(),
      port: Number(document.getElementById("cmdb-port").value || 443),
      use_tls: document.getElementById("cmdb-use-tls").checked,
      ignore_cert: document.getElementById("cmdb-ignore-cert").checked,
      api_path: document.getElementById("cmdb-api-path").value.trim() || "/api",
      username: document.getElementById("cmdb-username").value.trim(),
      password: document.getElementById("cmdb-password").value,
    }),
  });
  setStatus("cmdb-status", "Saved.");
  await loadSettings();
});

document.getElementById("sonatype-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const saved = await api("/api/settings/assets/sonatype", {
    method: "PUT",
    body: JSON.stringify({
      enabled: document.getElementById("sonatype-enabled").checked,
      host: document.getElementById("sonatype-host").value.trim(),
      port: Number(document.getElementById("sonatype-port").value || 8070),
      use_tls: document.getElementById("sonatype-use-tls").checked,
      ignore_cert: document.getElementById("sonatype-ignore-cert").checked,
      api_path: document.getElementById("sonatype-api-path").value.trim(),
      username: document.getElementById("sonatype-username").value.trim(),
      password: document.getElementById("sonatype-password").value,
    }),
  });
  setStatus(
    "sonatype-status",
    saved && saved.sync_started
      ? "Saved. Catalog sync started — applications and libraries will appear in Internal systems."
      : "Saved."
  );
  await loadSettings();
});

document.getElementById("itnm-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await api("/api/settings/assets/itnm", {
    method: "PUT",
    body: JSON.stringify({
      enabled: document.getElementById("itnm-enabled").checked,
      host: document.getElementById("itnm-host").value.trim(),
      port: Number(document.getElementById("itnm-port").value || 443),
      use_tls: document.getElementById("itnm-use-tls").checked,
      ignore_cert: document.getElementById("itnm-ignore-cert").checked,
      api_path: document.getElementById("itnm-api-path").value.trim() || "/api",
      list_path: document.getElementById("itnm-list-path").value.trim() || "/devices",
      username: document.getElementById("itnm-username").value.trim(),
      password: document.getElementById("itnm-password").value,
    }),
  });
  setStatus("itnm-status", "Saved.");
  await loadSettings();
});

document.getElementById("cmdb-test").addEventListener("click", async () => {
  document.getElementById("cmdb-form").requestSubmit();
  setStatus("cmdb-status", "Testing…");
  try {
    await new Promise((r) => setTimeout(r, 200));
    const result = await api("/api/settings/assets/cmdb/test", { method: "POST" });
    setStatus("cmdb-status", `OK. ${JSON.stringify(result).slice(0, 180)}`);
  } catch (err) {
    setStatus("cmdb-status", String(err.message || err));
  }
});

document.getElementById("sonatype-test").addEventListener("click", async () => {
  document.getElementById("sonatype-form").requestSubmit();
  setStatus("sonatype-status", "Testing…");
  try {
    await new Promise((r) => setTimeout(r, 200));
    const result = await api("/api/settings/assets/sonatype/test", { method: "POST" });
    setStatus("sonatype-status", `OK. ${JSON.stringify(result).slice(0, 180)}`);
  } catch (err) {
    setStatus("sonatype-status", String(err.message || err));
  }
});

document.getElementById("itnm-test").addEventListener("click", async () => {
  document.getElementById("itnm-form").requestSubmit();
  setStatus("itnm-status", "Testing…");
  try {
    await new Promise((r) => setTimeout(r, 200));
    const result = await api("/api/settings/assets/itnm/test", { method: "POST" });
    setStatus("itnm-status", `OK. ${JSON.stringify(result).slice(0, 180)}`);
  } catch (err) {
    setStatus("itnm-status", String(err.message || err));
  }
});

function ticketingBody() {
  return {
    enabled_jira: document.getElementById("ticketing-enabled-jira").checked,
    enabled_monday: document.getElementById("ticketing-enabled-monday").checked,
    enabled_email: document.getElementById("ticketing-enabled-email").checked,
    enabled_custom: document.getElementById("ticketing-enabled-custom").checked,
    provider: document.getElementById("ticketing-provider").value,
    host: document.getElementById("ticketing-host").value.trim(),
    port: Number(document.getElementById("ticketing-port").value || 443),
    use_tls: document.getElementById("ticketing-use-tls").checked,
    ignore_cert: document.getElementById("ticketing-ignore-cert").checked,
    username: document.getElementById("ticketing-username").value.trim(),
    password: document.getElementById("ticketing-password").value,
    jira_user_email: document.getElementById("jira-email").value.trim(),
    jira_project_key: document.getElementById("jira-project").value.trim(),
    jira_hunt_project_key: document.getElementById("jira-hunt").value.trim(),
    jira_issue_type: document.getElementById("jira-type").value.trim(),
    monday_board_id: document.getElementById("monday-board").value.trim(),
    monday_group_id: document.getElementById("monday-group").value.trim(),
    custom_api_path: document.getElementById("custom-api-path").value.trim(),
    custom_owner_project: document.getElementById("custom-owner-project").value.trim(),
    custom_hunt_project: document.getElementById("custom-hunt-project").value.trim(),
    hunt_email: document.getElementById("ticket-hunt-email").value.trim(),
    fallback_owner_email: document.getElementById("ticket-owner-email").value.trim(),
    email_domains: document.getElementById("ticket-email-domains").value.trim(),
    smtp_host: document.getElementById("smtp-host").value.trim(),
    smtp_port: Number(document.getElementById("smtp-port").value || 25),
    smtp_tls_mode: selectedChoice("smtp-tls") || "plain",
    smtp_username: document.getElementById("smtp-username").value.trim(),
    smtp_password: document.getElementById("smtp-password").value,
    smtp_from: document.getElementById("smtp-from").value.trim(),
    smtp_ignore_cert: document.getElementById("smtp-ignore-cert").checked,
  };
}

async function saveTicketing() {
  await api("/api/settings/ticketing", {
    method: "PUT",
    body: JSON.stringify(ticketingBody()),
  });
}

document.getElementById("ticket-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  setStatus("ticket-status", "Saving…");
  try {
    await saveTicketing();
    setStatus("ticket-status", "Saved.");
    await loadSettings();
  } catch (err) {
    setStatus("ticket-status", String(err.message || err));
  }
});

document.getElementById("ticketing-test").addEventListener("click", async () => {
  const provider = document.getElementById("ticketing-provider").value;
  setStatus("ticket-status", "Saving…");
  try {
    await saveTicketing();
    setStatus("ticket-status", "Testing…");
    const result = await api(`/api/settings/ticketing/test?provider=${encodeURIComponent(provider)}`, { method: "POST" });
    setStatus("ticket-status", formatProbeResult(result));
    await loadSettings();
  } catch (err) {
    setStatus("ticket-status", String(err.message || err));
  }
});

const TICKETING_TEST_HINTS = {
  jira: "Jira: GET /rest/api/3/myself with the saved token.",
  monday: "Monday.com: GraphQL me query with the API token in the password field.",
  email: "Email: logs in, then sends a short message to the Username (or From / Hunt address).",
  custom: "Internal CRM: GET the API path on the saved host.",
};

function syncTicketingTestButton() {
  const provider = document.getElementById("ticketing-provider")?.value || "jira";
  const btn = document.getElementById("ticketing-test");
  if (btn) btn.textContent = provider === "email" ? "Send test email" : "Test connection";
  const hint = document.getElementById("ticketing-test-hint");
  if (hint) hint.textContent = TICKETING_TEST_HINTS[provider] || TICKETING_TEST_HINTS.jira;
}

const SMTP_PORT_HINTS = {
  plain: "Plain SMTP on port 25. Use STARTTLS (587) or SMTPS (465) when the relay requires encryption.",
  starttls: "STARTTLS after connect. Usual for port 587.",
  ssl: "SMTPS from the start. Usual for port 465.",
};

function syncSmtpPortHint() {
  const mode = selectedChoice("smtp-tls") || "plain";
  const hintEl = document.getElementById("smtp-tls-hint");
  if (hintEl) hintEl.textContent = SMTP_PORT_HINTS[mode] || SMTP_PORT_HINTS.plain;
}

function messageBody() {
  return {
    owner_subject: document.getElementById("msg-owner-subject").value,
    owner_body: document.getElementById("msg-owner-body").value,
    hunt_subject: document.getElementById("msg-hunt-subject").value,
    hunt_body: document.getElementById("msg-hunt-body").value,
  };
}

function fillMessageForm(message) {
  const templates = message.templates || {};
  document.getElementById("msg-owner-subject").value = templates.owner_subject || "";
  document.getElementById("msg-owner-body").value = templates.owner_body || "";
  document.getElementById("msg-hunt-subject").value = templates.hunt_subject || "";
  document.getElementById("msg-hunt-body").value = templates.hunt_body || "";
  const chips = document.getElementById("message-tokens");
  if (!chips) return;
  chips.replaceChildren();
  (message.tokens || []).forEach((item) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "token-chip";
    btn.dataset.token = item.token;
    btn.textContent = item.token;
    btn.title = `Insert ${item.token}`;
    chips.appendChild(btn);
  });
}

let lastTplField = document.getElementById("msg-owner-body");
document.querySelectorAll("[data-tpl]").forEach((el) => {
  el.addEventListener("focus", () => {
    lastTplField = el;
  });
});

document.getElementById("message-tokens").addEventListener("click", (ev) => {
  const btn = ev.target.closest(".token-chip");
  if (!btn) return;
  const field = lastTplField || document.getElementById("msg-owner-body");
  const token = btn.dataset.token || "";
  const start = field.selectionStart ?? field.value.length;
  const end = field.selectionEnd ?? field.value.length;
  field.value = field.value.slice(0, start) + token + field.value.slice(end);
  const pos = start + token.length;
  field.focus();
  field.selectionStart = field.selectionEnd = pos;
});

document.getElementById("message-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  await api("/api/settings/message", { method: "PUT", body: JSON.stringify(messageBody()) });
  setStatus("message-status", "Saved.");
});

document.getElementById("message-preview").addEventListener("click", async () => {
  setStatus("message-status", "Rendering sample…");
  try {
    const result = await api("/api/settings/message/preview", {
      method: "POST",
      body: JSON.stringify(messageBody()),
    });
    const box = document.getElementById("message-preview-box");
    box.hidden = false;
    box.textContent =
      `Owner subject\n${result.owner_subject}\n\nOwner body\n${result.owner_body}\n\n` +
      `Hunt subject\n${result.hunt_subject}\n\nHunt body\n${result.hunt_body}`;
    setStatus("message-status", "Preview uses sample JSON from the AI schema.");
  } catch (err) {
    setStatus("message-status", String(err.message || err));
  }
});

function bindWipeConfirm({ openBtnId, modalId, confirmId, cancelId, statusId, endpoint, pending, done }) {
  const openBtn = document.getElementById(openBtnId);
  const modal = document.getElementById(modalId);
  const confirmBtn = document.getElementById(confirmId);
  const cancelBtn = document.getElementById(cancelId);
  if (!openBtn || !modal || !confirmBtn || !cancelBtn) return;

  function openModal() {
    modal.hidden = false;
    modal.removeAttribute("hidden");
    confirmBtn.disabled = false;
    cancelBtn.disabled = false;
    cancelBtn.focus();
  }

  function closeModal() {
    modal.hidden = true;
    modal.setAttribute("hidden", "");
    confirmBtn.disabled = false;
    cancelBtn.disabled = false;
  }

  async function confirmWipe(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    closeModal();
    setStatus(statusId, pending);
    openBtn.disabled = true;
    try {
      const result = await api(endpoint, { method: "POST" });
      setStatus(statusId, done((result && result.deleted) || {}));
    } catch (err) {
      setStatus(statusId, String(err.message || err));
    } finally {
      openBtn.disabled = false;
    }
  }

  openBtn.addEventListener("click", openModal);
  cancelBtn.addEventListener("click", closeModal);
  confirmBtn.addEventListener("click", confirmWipe);
  modal.addEventListener("click", (ev) => {
    if (ev.target === modal) closeModal();
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && !modal.hidden) closeModal();
  });
}

bindWipeConfirm({
  openBtnId: "reset-systems-btn",
  modalId: "reset-systems-modal",
  confirmId: "reset-systems-modal-confirm",
  cancelId: "reset-systems-modal-cancel",
  statusId: "wipe-systems-status",
  endpoint: "/api/settings/reset-system",
  pending: "Resetting Internal systems…",
  done: (deleted) => `Reset complete. Deleted ${deleted.assets || 0} system row(s).`,
});

bindWipeConfirm({
  openBtnId: "reset-cves-btn",
  modalId: "reset-cves-modal",
  confirmId: "reset-cves-modal-confirm",
  cancelId: "reset-cves-modal-cancel",
  statusId: "wipe-cves-status",
  endpoint: "/api/settings/wipe-cve-data",
  pending: "Deleting Incoming CVEs…",
  done: (deleted) => `Delete complete. Removed ${deleted.vulnerabilities || 0} CVE(s).`,
});

loadSettings()
  .then(() => applySettingsHash())
  .catch((err) => setStatus("smb-status", String(err.message || err)));

const POLL_MS = 2500;
const STATION_HOLD_MS = 5000;
const MOVE_MS = 2800;
const ENTER_LEFT = "-14%";
const EXIT_DWELL_MS = 0;
const EXIT_FADE_MS = 2800;
const CHIP_TOP = 8;
const STATION_IDS = ["ingest", "extract", "enrich", "match", "act"];

let requestedFocus = (() => {
  const raw = (new URLSearchParams(location.search).get("cve") || "").trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/.test(raw)) return "";
  history.replaceState({}, "", location.pathname);
  return raw;
})();
let rerunQueued = false;

const catalog = new Map();
const historical = new Set();
const played = new Set();
const queue = [];
const exitTimers = new Map();
let play = null;
let seeded = false;
let stopsReady = false;

function ensureBoard(stations) {
  const stops = document.getElementById("wf-stops");
  if (stopsReady && stops.children.length === STATION_IDS.length) return;
  stops.replaceChildren();
  (stations || []).forEach((station, index) => {
    const stop = fillTemplate("tpl-wf-stop", {
      title: station.title,
      count: "",
      index: String(index + 1).padStart(2, "0"),
    });
    stop.dataset.station = station.id;
    stops.appendChild(stop);
  });
  stopsReady = true;
  watchRail();
  syncRail();
}

function stationIndex(id) {
  const index = STATION_IDS.indexOf(id);
  return index >= 0 ? index : 0;
}

function stationLeft(id) {
  return `${((stationIndex(id) + 0.5) / STATION_IDS.length) * 100}%`;
}

function stationState(cve, stationId) {
  if ((cve.done || []).includes(stationId)) return "done";
  if (cve.current === stationId) return "live";
  return "pending";
}

function renderDots(cve) {
  const wrap = document.createElement("div");
  wrap.className = "wf-dots";
  STATION_IDS.forEach((id) => {
    const dot = document.createElement("i");
    const state = stationState(cve, id);
    dot.className = `wf-dot is-${state}`;
    if (id === "extract" && cve.duplicate && state === "live") dot.classList.add("is-dup");
    if (id === "match" && cve.unmatched && state === "live") dot.classList.add("is-miss");
    if (id === "act" && !cve.unmatched && !cve.duplicate && state === "live") dot.classList.add("is-hit");
    wrap.appendChild(dot);
  });
  return wrap;
}

const SOURCE_SHORT = {
  inline: "Inline CVE",
  local: "Local",
  smb: "SMB",
  outlook: "Exchange",
  email: "Exchange",
  web_api: "ATOM",
  api_feed: "ATOM",
};

function sourceBits(cve) {
  const src = cve.source || {};
  const type = String(src.type || "").trim().toLowerCase();
  const kindShort = String(src.kind_short || SOURCE_SHORT[type] || "").trim();
  const headline = String(src.headline || "").trim();
  const detail = String(src.detail || src.filename || src.feed_name || src.location || src.subject || "").trim();
  const label = headline || kindShort || String(src.kind || src.name || "").trim();
  return { src, type, kindShort, headline, detail, label };
}

function sourceLabel(cve) {
  return sourceBits(cve).label;
}

function rowKey(row) {
  return (row && (row.play_key || row.cve_id)) || "";
}

function cveKnown(cve) {
  return pastStation(cve, "ingest") || (cve.column && cve.column !== "ingest");
}

function outcomeState(cve) {
  if (cve.duplicate) return "dup";
  if (cve.unmatched) return "miss";
  if (cve.column === "act") return "hit";
  return "";
}

function applyChip(chip, cve) {
  const known = cveKnown(cve);
  const bits = sourceBits(cve);
  const outcome = outcomeState(cve);
  chip.dataset.cve = rowKey(cve);
  chip.dataset.station = cve.column;
  if (known) {
    chip.href = `/vulnerabilities/${encodeURIComponent(cve.cve_id)}`;
    chip.querySelector('[data-slot="cve"]').textContent = cve.cve_id;
  } else {
    chip.href = "/sources";
    chip.querySelector('[data-slot="cve"]').textContent = bits.kindShort || bits.label || "New ingest";
  }
  const identityOn = ["enrich", "match", "act"].includes(cve.column);
  const product = identityOn ? [cve.vendor, cve.product].filter(Boolean).join(" · ") : "";
  let meta = "";
  if (cve.duplicate) meta = "Already in the system";
  else if (cve.refresh_label === "Re-run") meta = "Re-run";
  else if (cve.waiting) meta = waitIntelShort(cve);
  else if (cve.unmatched) meta = "Unmatched — last station";
  else if (cve.refreshed && !known) meta = cve.refresh_label || bits.detail || bits.label;
  else if (product) meta = product;
  else if (known) meta = bits.label;
  else if (bits.detail && bits.detail !== (bits.kindShort || bits.label)) meta = bits.detail;
  chip.querySelector('[data-slot="meta"]').textContent = meta;
  chip.classList.add("is-live");
  chip.classList.toggle("is-fresh", !outcome);
  chip.classList.toggle("is-waiting", Boolean(cve.waiting));
  chip.classList.toggle("is-duplicate", outcome === "dup");
  chip.classList.toggle("is-unmatched", outcome === "miss");
  chip.classList.toggle("is-matched", outcome === "hit");
  const oldDots = chip.querySelector(".wf-dots, [data-slot='dots']");
  if (oldDots) oldDots.replaceWith(renderDots(cve));
}

function setChipPose(chip, left, top, instant) {
  if (instant) chip.classList.add("is-instant");
  chip.style.left = left;
  chip.style.top = `${top}px`;
  if (instant) {
    void chip.offsetWidth;
    chip.classList.remove("is-instant");
  }
}

function enterFromLeft(chip, left, top) {
  chip.classList.add("is-ghost");
  setChipPose(chip, ENTER_LEFT, top, true);
  chip.style.opacity = "0";
  chip.style.filter = "blur(14px)";
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      chip.classList.remove("is-ghost");
      chip.style.left = left;
      chip.style.opacity = "1";
      chip.style.filter = "blur(0px)";
      window.setTimeout(() => {
        chip.style.opacity = "";
        chip.style.filter = "";
      }, 2500);
    });
  });
}

const STORY_ORDER = ["source", "notice", "title", "description", "product", "intel", "match", "owner", "action"];
const STORY_STAGE = {
  source: 0,
  notice: 1,
  title: 1,
  description: 1,
  product: 1,
  intel: 1,
  match: 2,
  owner: 2,
  action: 3,
};

function storyInsertBefore(newKey, existingKey) {
  const newer = STORY_STAGE[newKey] ?? 0;
  const older = STORY_STAGE[existingKey] ?? 0;
  if (newer !== older) return newer > older;
  return STORY_ORDER.indexOf(newKey) < STORY_ORDER.indexOf(existingKey);
}

function scheduleExit(chip, cveId) {
  if (!chip || exitTimers.has(cveId) || chip.classList.contains("is-exit")) return;
  const dwell = window.setTimeout(() => {
    chip.style.opacity = "";
    chip.style.filter = "";
    chip.classList.add("is-exit");
    const story = document.querySelector(`#wf-dossier .wf-story[data-cve="${CSS.escape(cveId)}"]`);
    if (story) story.classList.add("is-exit");
    const fade = window.setTimeout(() => {
      chip.remove();
      story?.remove();
      const dossier = document.getElementById("wf-dossier");
      if (dossier && !dossier.querySelector(".wf-story")) dossier.hidden = true;
      exitTimers.delete(cveId);
      finishPlay(cveId);
    }, EXIT_FADE_MS);
    exitTimers.set(cveId, fade);
  }, EXIT_DWELL_MS);
  exitTimers.set(cveId, dwell);
}

function pastStation(cve, stationId) {
  const done = cve.done || [];
  if (done.includes(stationId)) return true;
  return stationIndex(cve.column) > stationIndex(stationId);
}

function storyStage(cve) {
  if (cve.duplicate) return "Already in the system";
  if (cve.refreshed && cve.column === "ingest") return cve.refresh_label || "Updated";
  if (cve.unmatched) return "Unmatched";
  if (cve.waiting) return waitIntelShort(cve);
  if (cve.failed) return "Failed";
  return {
    ingest: "Ingest",
    extract: "Extraction",
    enrich: "Enrichment",
    match: "Matching",
    act: "Actions",
  }[cve.column] || "Ingest";
}

function hasIntel(cve) {
  const intel = cve.intel || {};
  if (intel.skipped) return true;
  if (intel.cvss_score != null || intel.epss_score != null) return true;
  if (intel.severity && intel.severity !== "UNKNOWN") return true;
  if ((intel.cwe_ids || []).length) return true;
  return Boolean(intel.attack_vector || intel.attack_complexity);
}

function fmtScore(value, digits) {
  if (value == null || value === "") return "";
  const num = Number(value);
  if (Number.isNaN(num)) return String(value);
  return num.toFixed(digits);
}

function factsList(pairs) {
  const dl = document.createElement("dl");
  dl.className = "wf-facts";
  let count = 0;
  pairs.forEach(([label, value]) => {
    if (value == null || value === "") return;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = String(value);
    dl.append(dt, dd);
    count += 1;
  });
  return count ? dl : null;
}

function textList(items) {
  const ul = document.createElement("ul");
  ul.className = "wf-story-list";
  items.forEach((item) => {
    const li = document.createElement("li");
    if (typeof item === "string") li.textContent = item;
    else li.append(item);
    ul.appendChild(li);
  });
  return ul;
}

function ownerLines(cve) {
  const seenOwners = new Set();
  const lines = [];
  (cve.matches || []).forEach((row) => {
    const name = (row.owner_name || "").trim();
    const email = (row.owner_email || "").trim();
    const team = (row.team || "").trim();
    if (!name && !email) return;
    const key = `${name}|${email}`.toLowerCase();
    if (seenOwners.has(key)) return;
    seenOwners.add(key);
    lines.push([name, email, team].filter(Boolean).join(" · "));
  });
  return lines;
}

function waitIntelShort(cve) {
  const intel = cve.intel || {};
  const kind = intel.wait_kind || cve.wait_kind || "";
  if (kind === "timeout" || kind === "unreachable") return "NVD/EPSS timed out";
  return "Waiting for intel";
}

function waitIntelDetail(cve) {
  const intel = cve.intel || {};
  const reason = intel.wait_reason || cve.wait_reason || "";
  const retry = intel.retry_at || cve.retry_at || "";
  const when = retry ? ` Next retry ${fmtTime(retry)}.` : "";
  if (reason) return `${reason.replace(/\s+$/, "")}${reason.endsWith(".") ? "" : "."}${when}`;
  return `Waiting for intel.${when}`;
}

function intelNode(cve) {
  const intel = cve.intel || {};
  if (intel.waiting) return mutedText(waitIntelDetail(cve));
  if (intel.skipped) return mutedText("Enrichment skipped — using ingested fields.");
  const epss = intel.epss_score == null ? "" : fmtScore(intel.epss_score, 4);
  const pct = intel.epss_percentile == null ? "" : `${Math.round(Number(intel.epss_percentile) * (Number(intel.epss_percentile) <= 1 ? 100 : 1))}%`;
  return factsList([
    ["Severity", intel.severity && intel.severity !== "UNKNOWN" ? intel.severity : ""],
    ["Priority", intel.priority],
    ["CVSS", fmtScore(intel.cvss_score, 1)],
    ["CVSS vector", intel.cvss_vector],
    ["EPSS", epss],
    ["EPSS percentile", pct],
    ["Attack vector", intel.attack_vector],
    ["Attack complexity", intel.attack_complexity],
    ["Privileges", intel.privileges_required],
    ["User interaction", intel.user_interaction],
    ["CWE", (intel.cwe_ids || []).join(", ")],
    ["AI rewrite", intel.ai_used ? "Yes" : ""],
  ]);
}

function matchNode(cve) {
  const rows = cve.matches || [];
  if (rows.length) {
    return textList(
      rows.map((row) => {
        const name = row.name || [row.vendor, row.product].filter(Boolean).join(" ");
        return [name, row.system_type, row.version].filter(Boolean).join(" · ");
      })
    );
  }
  if (cve.unmatched) return mutedText("No matching system in Internal systems.");
  return mutedText("Looking for a match in Internal systems…");
}

function actionNode(cve) {
  const tickets = cve.tickets || [];
  if (tickets.length) {
    const items = tickets.map((ticket) => {
      const label = [ticket.key, ticket.summary || ticket.type].filter(Boolean).join(" — ");
      if (!ticket.url) {
        const span = document.createElement("span");
        span.textContent = `${label}${ticket.dry_run ? " (dry run)" : ""}`;
        return span;
      }
      const a = document.createElement("a");
      a.className = "link";
      a.href = ticket.url;
      a.textContent = `${label}${ticket.dry_run ? " (dry run)" : ""}`;
      return a;
    });
    return textList(items);
  }
  if (cve.unmatched) return mutedText("Actions skipped until a match exists.");
  return mutedText("Waiting to open the owner / hunt task.");
}

function sourceNode(cve) {
  const bits = sourceBits(cve);
  const src = bits.src;
  const node = factsList([
    ["Learned from", bits.label],
    ["File", src.filename],
    ["Location", src.location],
    ["Feed", src.feed_name],
    ["Folder", src.folder],
    ["Subject", src.subject],
    ["Update", cve.refresh_label],
  ]);
  if (node) return node;
  return null;
}

function storyBlocks(cve) {
  if (cve.duplicate) {
    return {
      source: sourceNode(cve),
      notice: mutedText("This CVE is already in the system. Later stations are skipped."),
      title: "",
      description: "",
      product: null,
      intel: null,
      match: null,
      owner: null,
      action: null,
    };
  }
  const enrichOn = pastStation(cve, "extract") || ["enrich", "match", "act"].includes(cve.column);
  const matchOn = pastStation(cve, "enrich") || ["match", "act"].includes(cve.column);
  const actOn = pastStation(cve, "match") || cve.column === "act";
  const productOn = enrichOn && (cve.vendor || cve.product || cve.product_type || cve.version);
  return {
    source: sourceNode(cve),
    notice: null,
    title: enrichOn && cve.title ? cve.title : "",
    description: enrichOn && cve.description ? cve.description : "",
    product: productOn
      ? factsList([
          ["Vendor", cve.vendor],
          ["Product", cve.product],
          ["Type", cve.product_type],
          ["Version", cve.version],
        ])
      : null,
    intel: enrichOn && (hasIntel(cve) || cve.waiting) ? intelNode(cve) : null,
    match: matchOn ? matchNode(cve) : null,
    owner: matchOn && ownerLines(cve).length ? textList(ownerLines(cve)) : null,
    action: actOn && !cve.unmatched ? actionNode(cve) : cve.unmatched && matchOn ? actionNode(cve) : null,
  };
}

function ensureStoryBlock(body, key, label, content) {
  let block = body.querySelector(`[data-reveal="${key}"]`);
  if (!content) {
    if (block) block.remove();
    return;
  }
  if (!block) {
    block = fillTemplate("tpl-wf-story-block", { label, value: "" });
    block.dataset.reveal = key;
    let placed = false;
    [...body.children].forEach((child) => {
      if (placed) return;
      if (storyInsertBefore(key, child.dataset.reveal)) {
        body.insertBefore(block, child);
        placed = true;
      }
    });
    if (!placed) body.appendChild(block);
  } else {
    slot(block, "label").textContent = label;
  }
  const valueEl = slot(block, "value");
  if (typeof content === "string") valueEl.textContent = content;
  else valueEl.replaceChildren(content);
}

function paintStory(featured) {
  const dossier = document.getElementById("wf-dossier");
  if (!dossier) return;
  if (!featured) {
    if (!dossier.querySelector(".wf-story.is-exit")) {
      dossier.replaceChildren();
      dossier.hidden = true;
    }
    return;
  }
  dossier.hidden = false;
  const featuredKey = rowKey(featured);
  dossier.querySelectorAll(".wf-story:not(.is-exit)").forEach((el) => {
    if (el.dataset.cve !== featuredKey) el.remove();
  });
  let article = dossier.querySelector(`.wf-story[data-cve="${CSS.escape(featuredKey)}"]`);
  if (!article) {
    article = useTemplate("tpl-wf-story");
    article.dataset.cve = featuredKey;
    dossier.appendChild(article);
  }
  const link = slot(article, "cve");
  const known = cveKnown(featured);
  const from = sourceLabel(featured);
  if (known) {
    link.textContent = featured.cve_id;
    link.href = `/vulnerabilities/${encodeURIComponent(featured.cve_id)}`;
  } else {
    link.textContent = from || "New ingest";
    link.href = "/sources";
  }
  const pill = slot(article, "stage");
  const outcome = outcomeState(featured);
  pill.textContent = storyStage(featured);
  pill.classList.toggle("is-dup", outcome === "dup");
  pill.classList.toggle("is-miss", outcome === "miss");
  pill.classList.toggle("is-hit", outcome === "hit");
  article.classList.toggle("is-duplicate", outcome === "dup");
  article.classList.toggle("is-unmatched", outcome === "miss");
  article.classList.toggle("is-matched", outcome === "hit");
  const blocks = storyBlocks(featured);
  const body = slot(article, "body");
  ensureStoryBlock(body, "source", "Ingest source", blocks.source);
  ensureStoryBlock(body, "notice", "Status", blocks.notice);
  ensureStoryBlock(body, "title", "Name", blocks.title);
  ensureStoryBlock(body, "description", "Description", blocks.description);
  ensureStoryBlock(body, "product", "Product", blocks.product);
  ensureStoryBlock(body, "intel", "Enrichment", blocks.intel);
  ensureStoryBlock(body, "match", "Organization match", blocks.match);
  ensureStoryBlock(body, "owner", "Owner", blocks.owner);
  ensureStoryBlock(body, "action", "Action", blocks.action);
}

function paintStops(view, queued) {
  const liveId = play?.station || null;
  const cur = liveId ? stationIndex(liveId) : -1;
  document.querySelectorAll("#wf-stops .wf-stop").forEach((stop) => {
    const id = stop.dataset.station;
    const idx = stationIndex(id);
    const here = Boolean(liveId) && id === liveId;
    stop.classList.toggle("is-live", here);
    stop.classList.toggle("is-done", cur >= 0 && idx < cur);
    stop.classList.toggle("is-duplicate", here && id === "extract" && Boolean(view?.duplicate));
    stop.classList.toggle("is-miss", here && id === "match" && Boolean(view?.unmatched));
    stop.classList.toggle("is-hit", here && id === "act" && !view?.unmatched && !view?.duplicate);
    const count = stop.querySelector("[data-slot='count']");
    if (here) count.textContent = "now";
    else if (queued > 0 && id === "ingest") count.textContent = `${queued} waiting`;
    else count.textContent = "";
  });
}

let railWatch = null;

function stationNode(id) {
  if (!id) return null;
  return document.querySelector(`#wf-stops .wf-stop[data-station="${CSS.escape(id)}"] .wf-node`);
}

function watchRail() {
  const axis = document.querySelector(".wf-axis");
  if (!axis || railWatch) return;
  railWatch = new ResizeObserver(() => syncRail());
  railWatch.observe(axis);
}

function layoutRailTrack() {
  const rail = document.querySelector(".wf-rail");
  const axis = document.querySelector(".wf-axis");
  const nodes = [...document.querySelectorAll("#wf-stops .wf-stop .wf-node")];
  if (!rail || !axis || nodes.length < 2) return;
  const axisBox = axis.getBoundingClientRect();
  if (axisBox.width <= 0) return;
  const first = nodes[0].getBoundingClientRect();
  const last = nodes[nodes.length - 1].getBoundingClientRect();
  const start = first.left + first.width / 2 - axisBox.left;
  const end = last.left + last.width / 2 - axisBox.left;
  rail.style.left = `${Math.round(Math.max(0, start))}px`;
  rail.style.right = `${Math.round(Math.max(0, axisBox.width - end))}px`;
}

function paintRail() {
  const fill = document.getElementById("wf-rail-fill");
  const rail = document.querySelector(".wf-rail");
  if (!fill || !rail) return;
  const liveId = play?.station || null;
  if (!liveId) {
    fill.style.width = "0px";
    return;
  }
  const node = stationNode(liveId);
  const railBox = rail.getBoundingClientRect();
  if (!node || railBox.width <= 0) {
    fill.style.width = "0px";
    return;
  }
  const nodeBox = node.getBoundingClientRect();
  const center = nodeBox.left + nodeBox.width / 2;
  const width = Math.min(railBox.width, Math.max(0, center - railBox.left));
  fill.style.width = `${Math.round(width)}px`;
}

function syncRail() {
  layoutRailTrack();
  paintRail();
}

function createdStamp(cve) {
  return Date.parse(cve.created_at || "") || Date.parse(cve.updated_at || "") || 0;
}

function pickLatest(rows) {
  return (rows || []).reduce((best, row) => {
    if (!rowKey(row)) return best;
    if (!best) return row;
    const a = createdStamp(row);
    const b = createdStamp(best);
    if (a === b) return (row.updated_at || "") > (best.updated_at || "") ? row : best;
    return a > b ? row : best;
  }, null);
}

function matchingCve(row, cveId) {
  return String((row && row.cve_id) || "").toUpperCase() === cveId;
}

function pickFocus(rows) {
  if (!requestedFocus) return pickLatest(rows);
  const matches = (rows || []).filter((row) => matchingCve(row, requestedFocus));
  const rerun = pickLatest(
    matches.filter((row) => row.refreshed || String(row.play_key || "").startsWith("ref-"))
  );
  if (rerun) return rerun;
  if (rerunQueued) return null;
  return pickLatest(matches);
}

function consumeFocusIf(row) {
  if (requestedFocus && matchingCve(row, requestedFocus)) requestedFocus = "";
}

function enqueue(id) {
  if (!id || played.has(id) || queue.includes(id) || play?.id === id) return;
  queue.push(id);
}

function finishPlay(cveId) {
  played.add(cveId);
  if (play?.id === cveId) play = null;
  startNext();
}

function lastVisualStation(cve) {
  if (cve?.duplicate) return "extract";
  return cve?.unmatched ? "match" : "act";
}

function realReachableIndex(cve) {
  if (!cve) return 0;
  if (cve.duplicate) return stationIndex("extract");
  if (cve.unmatched) return stationIndex("match");
  if (cve.terminal || !cve.current) return STATION_IDS.length - 1;
  return stationIndex(cve.current);
}

function playingView() {
  if (!play) return null;
  const row = catalog.get(play.id);
  if (!row) return null;
  const atMatch = ["match", "act"].includes(play.station);
  const atAct = play.station === "act";
  return {
    ...row,
    column: play.station,
    current: play.station,
    done: play.done,
    waiting: play.station === "enrich" && Boolean(row.waiting),
    unmatched: Boolean(row.unmatched) && play.station === "match",
    duplicate: Boolean(row.duplicate) && play.station === "extract",
    refreshed: Boolean(row.refreshed),
    terminal: false,
    matches: atMatch ? row.matches : [],
    tickets: atAct ? row.tickets : [],
  };
}

function stageChip(id) {
  return document.querySelector(`#wf-stage .wf-chip[data-cve="${CSS.escape(id)}"]`);
}

function paintPlaying() {
  const view = playingView();
  const stage = document.getElementById("wf-stage");
  if (view && stage) {
    let chip = stageChip(play.id);
    const left = stationLeft(view.column);
    if (!chip) {
      chip = useTemplate("tpl-wf-chip");
      applyChip(chip, view);
      stage.appendChild(chip);
      enterFromLeft(chip, left, CHIP_TOP);
    } else if (!chip.classList.contains("is-exit")) {
      applyChip(chip, view);
      setChipPose(chip, left, CHIP_TOP, false);
    }
  }
  if (stage) stage.style.minHeight = "140px";
  paintStops(view, queue.length);
  paintRail();
  paintStory(view);
  const empty = document.getElementById("wf-empty");
  if (empty) {
    empty.hidden = Boolean(view) || queue.length > 0;
    if (!view && queue.length === 0) empty.textContent = "Listening for the next CVE…";
  }
}

function startNext() {
  if (play || !queue.length) {
    paintPlaying();
    return;
  }
  const id = queue.shift();
  const row = catalog.get(id);
  if (!row || played.has(id)) {
    startNext();
    return;
  }
  play = {
    id,
    station: "ingest",
    done: [],
    phase: "enter",
    since: Date.now(),
  };
  paintPlaying();
}

function advancePlay() {
  if (!play || play.phase === "exit") return;
  const cve = catalog.get(play.id);
  if (!cve) return;
  const last = lastVisualStation(cve);
  const reachable = realReachableIndex(cve);
  if (stationIndex(play.station) >= stationIndex(last) && stationIndex(play.station) <= reachable) {
    play.phase = "exit";
    const chip = stageChip(play.id);
    if (chip) scheduleExit(chip, play.id);
    else finishPlay(play.id);
    return;
  }
  const nextIdx = stationIndex(play.station) + 1;
  if (nextIdx <= stationIndex(last) && nextIdx <= reachable) {
    play.done = STATION_IDS.slice(0, nextIdx);
    play.station = STATION_IDS[nextIdx];
    play.phase = "move";
    play.since = Date.now();
    paintPlaying();
  }
}

function tickPlayback() {
  const now = Date.now();
  if (!play) {
    startNext();
    return;
  }
  if (play.phase === "enter" && now - play.since >= MOVE_MS) {
    play.phase = "hold";
    play.since = now;
  } else if (play.phase === "move" && now - play.since >= MOVE_MS) {
    play.phase = "hold";
    play.since = now;
    paintPlaying();
  } else if (play.phase === "hold" && now - play.since >= STATION_HOLD_MS) {
    advancePlay();
  } else {
    paintPlaying();
  }
}

function ingestRows(rows, seed) {
  (rows || []).forEach((row) => {
    const key = rowKey(row);
    if (key) catalog.set(key, row);
  });
  if (seed) {
    (rows || []).forEach((row) => {
      const key = rowKey(row);
      if (key) historical.add(key);
    });
    const latest = pickFocus(rows);
    if (latest) {
      enqueue(rowKey(latest));
      consumeFocusIf(latest);
    }
    return;
  }
  const fresh = (rows || []).filter((row) => {
    const key = rowKey(row);
    if (!key || historical.has(key)) return false;
    if (requestedFocus && !matchingCve(row, requestedFocus)) return false;
    return true;
  });
  fresh.sort((a, b) => createdStamp(a) - createdStamp(b));
  fresh.forEach((row) => {
    const key = rowKey(row);
    historical.add(key);
    enqueue(key);
    consumeFocusIf(row);
  });
}

function resetPlayback() {
  exitTimers.forEach((timer) => window.clearTimeout(timer));
  exitTimers.clear();
  play = null;
  queue.length = 0;
  historical.clear();
  played.clear();
  catalog.clear();
  seeded = false;
  document.getElementById("wf-stage")?.replaceChildren();
  const dossier = document.getElementById("wf-dossier");
  if (dossier) {
    dossier.replaceChildren();
    dossier.hidden = true;
  }
}

function renderWorkflow(data, { seed } = {}) {
  const stations = data.stations || [];
  ensureBoard(stations);

  const summary = data.summary || {};
  const kpis = document.getElementById("wf-kpis");
  kpis.querySelector('[data-k="inflight"]').textContent = fmtNum(summary.inflight);
  kpis.querySelector('[data-k="waiting"]').textContent = fmtNum(summary.waiting);
  kpis.querySelector('[data-k="unmatched"]').textContent = fmtNum(summary.unmatched);
  kpis.querySelector('[data-k="completed"]').textContent = fmtNum(summary.completed);

  ingestRows(data.cves || [], seed);
  if (!play) startNext();
  else paintPlaying();
}

async function loadWorkflow({ seed } = {}) {
  const data = await api("/api/workflow");
  const shouldSeed = seed || !seeded;
  if (shouldSeed) seeded = true;
  renderWorkflow(data, { seed: shouldSeed });
  stampUpdated(true);
}

async function kickoffRequestedRerun() {
  if (!requestedFocus) return;
  const field = document.getElementById("inline-cve");
  const status = document.getElementById("inline-status");
  if (field) field.value = requestedFocus;
  if (status) status.textContent = `Re-running ${requestedFocus}…`;
  try {
    await api(`/api/vulnerabilities/${encodeURIComponent(requestedFocus)}/reprocess`, {
      method: "POST",
    });
    rerunQueued = true;
    if (status) status.textContent = `Queued ${requestedFocus}.`;
  } catch (err) {
    if (status) status.textContent = String(err.message || err);
  }
}

(async () => {
  await kickoffRequestedRerun();
  await loadWorkflow({ seed: true });
})().catch((err) => {
  stampUpdated(false);
  document.getElementById("wf-empty").hidden = false;
  document.getElementById("wf-empty").textContent = err.message || String(err);
});
document.addEventListener("inline-cve-queued", () => {
  loadWorkflow().catch(() => {});
});
setInterval(() => {
  loadWorkflow().catch((err) => {
    stampUpdated(false);
    console.error(err);
  });
}, POLL_MS);
setInterval(tickPlayback, 250);

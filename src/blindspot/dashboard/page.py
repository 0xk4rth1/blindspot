"""HTML case file used by `blindspot serve` and by exported reports."""

from __future__ import annotations

from pathlib import Path

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blindspot</title>
<style>
:root {
  --bg: #14120f;
  --panel: #1e1b16;
  --line: #3a342c;
  --text: #f3efe4;
  --muted: #b3a894;
  --accent: #e08a3c;
  --ok: #8fbf8a;
  --warn: #e0b15a;
  --bad: #d46a5c;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.45 "Segoe UI", "Helvetica Neue", sans-serif; }
header, nav, .toolbar, main { padding: 16px 22px; }
header { display: flex; justify-content: space-between; gap: 16px; border-bottom: 1px solid var(--line); }
.brand { font-weight: 700; letter-spacing: 0.04em; }
.brand span { color: var(--accent); }
.muted { color: var(--muted); }
nav { display: flex; gap: 8px; flex-wrap: wrap; }
button, input { font: inherit; color: var(--text); background: var(--panel); border: 1px solid var(--line); border-radius: 6px; }
nav button, .queue button { padding: 8px 12px; cursor: pointer; }
nav button[aria-pressed="true"] { border-color: var(--accent); color: var(--accent); }
.toolbar input { width: min(420px, 100%); padding: 8px 10px; }
main { display: grid; gap: 12px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
.card, .row, .detail { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
.card strong { display: block; font-size: 22px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--line); vertical-align: top; font-family: "Cascadia Mono", "Segoe UI Mono", ui-monospace, monospace; font-size: 12.5px; }
th { color: var(--muted); font-family: "Segoe UI", sans-serif; }
.tag { color: var(--accent); }
.group { margin-top: 8px; }
.queue { display: grid; gap: 10px; }
.actions { display: flex; gap: 8px; margin-top: 8px; }
.note { color: var(--muted); max-width: 78ch; }
.queue .card strong { font-size: 16px; }
.queue ul { margin: 8px 0 0; padding-left: 18px; color: var(--muted); }
.queue li { margin: 4px 0; }
</style>
</head>
<body>
<header>
  <div>
    <div class="brand">Blind<span>spot</span></div>
    <div id="case" class="muted"></div>
  </div>
  <div id="program" class="muted"></div>
</header>
<nav id="tabs">
  <button type="button" data-tab="overview" aria-pressed="true">Overview</button>
  <button type="button" data-tab="assets">Assets</button>
  <button type="button" data-tab="functionality">Functionality</button>
  <button type="button" data-tab="history">History</button>
  <button type="button" data-tab="queue">Queue</button>
</nav>
<div class="toolbar"><input id="search" type="search" placeholder="Filter this view" aria-label="Filter this view"></div>
<main id="view"></main>
<script id="bootstrap" type="application/json">__BOOTSTRAP__</script>
<script>
const embedded = document.getElementById("bootstrap").textContent.trim();
const live = !embedded;
let data = null;
let tab = "overview";

function text(value) {
  return String(value ?? "");
}

function matches(parts) {
  const query = document.getElementById("search").value.trim().toLowerCase();
  if (!query) return true;
  return parts.join(" ").toLowerCase().includes(query);
}

async function load() {
  data = embedded ? JSON.parse(embedded) : await fetch("/api/bootstrap").then((res) => res.json());
  document.getElementById("case").textContent = data.engagement.name;
  document.getElementById("program").textContent = data.engagement.program || "";
  render();
}

function render() {
  const view = document.getElementById("view");
  view.innerHTML = "";
  if (tab === "overview") view.append(overview());
  if (tab === "assets") view.append(tableView());
  if (tab === "functionality") view.append(functionality());
  if (tab === "history") view.append(history());
  if (tab === "queue") view.append(queue());
}

function overview() {
  const wrap = document.createElement("section");
  const cards = document.createElement("div");
  cards.className = "cards";
  for (const [key, value] of Object.entries(data.summary)) {
    if (!matches([key, value])) continue;
    const card = document.createElement("div");
    card.className = "card";
    const label = document.createElement("div");
    label.className = "muted";
    label.textContent = key;
    const strong = document.createElement("strong");
    strong.textContent = text(value);
    card.append(label, strong);
    cards.append(card);
  }
  const note = document.createElement("p");
  note.className = "note";
  note.textContent = "Every host and URL in this case was checked against the engagement scope. Review prompts in the queue are leads for manual testing, not confirmed findings. " + data.engagement.authorization;
  wrap.append(cards, note);
  return wrap;
}

function tableView() {
  const rows = data.assets.filter((row) => matches([row.asset_type, row.normalized, row.sources, row.in_scope]));
  return grid(["Type", "Value", "In scope", "Sources", "First seen", "Last seen"], rows.map((row) => [
    row.asset_type, row.normalized, row.in_scope ? "yes" : "no", row.sources || "", row.first_seen, row.last_seen
  ]));
}

function functionality() {
  const wrap = document.createElement("section");
  const groups = new Map();
  for (const row of data.endpoints) {
    const label = row.method + " " + row.host + row.templated_path + " " + row.classification;
    if (!matches([row.functionality, label, row.sources])) continue;
    if (!groups.has(row.functionality)) groups.set(row.functionality, []);
    groups.get(row.functionality).push(label);
  }
  if (!groups.size) {
    wrap.textContent = "No classified endpoints yet.";
    return wrap;
  }
  for (const [name, items] of groups) {
    const block = document.createElement("div");
    block.className = "group card";
    const title = document.createElement("strong");
    title.textContent = name;
    const list = document.createElement("ul");
    for (const item of items) {
      const li = document.createElement("li");
      li.textContent = item;
      list.append(li);
    }
    block.append(title, list);
    wrap.append(block);
  }
  return wrap;
}

function history() {
  const rows = data.changes.filter((row) => matches([row.change_type, row.subject, row.before_value, row.after_value]));
  return grid(["When", "Type", "Subject", "Before", "After"], rows.map((row) => [
    row.detected_at, row.change_type, row.subject, row.before_value, row.after_value
  ]));
}

function queue() {
  const wrap = document.createElement("section");
  wrap.className = "queue";
  const intro = document.createElement("p");
  intro.className = "note";
  intro.textContent = "These prompts cite evidence already in the case. Manual verification stays the authority.";
  wrap.append(intro);
  const rows = data.hypotheses.filter((row) => row.status !== "superseded" && matches([
    row.title, row.category, row.summary, row.status, row.subject, row.confidence_band, row.rationale
  ]));
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.textContent = "No matching review prompts.";
    wrap.append(empty);
    return wrap;
  }
  for (const row of rows) {
    const card = document.createElement("article");
    card.className = "card";
    const title = document.createElement("strong");
    title.textContent = row.priority + " · " + row.title;
    const meta = document.createElement("div");
    meta.className = "muted";
    meta.textContent = [row.confidence_band, row.category, row.status, "confidence " + row.confidence].filter(Boolean).join(" · ");
    const body = document.createElement("p");
    body.textContent = row.summary;
    card.append(title, meta, body);
    addLine(card, "Why", row.rationale);
    addLine(card, "Limitations", row.limitations);
    addLine(card, "Manual review", row.validation_steps);
    const related = (row.endpoints || []).slice(0, 8);
    if (related.length) addLine(card, "Related", related.join(", "));
    const observations = row.observations || [];
    if (observations.length) {
      const list = document.createElement("ul");
      for (const item of observations.slice(0, 8)) {
        const li = document.createElement("li");
        const bits = [];
        if (item.event_id) bits.push("#" + item.event_id);
        bits.push(item.kind, item.source, item.value);
        li.textContent = bits.filter(Boolean).join(" · ");
        list.append(li);
      }
      card.append(list);
    }
    if (live) {
      const actions = document.createElement("div");
      actions.className = "actions";
      for (const status of ["accepted", "done", "dismissed", "queued"]) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = status;
        button.addEventListener("click", () => setStatus(row.id, status));
        actions.append(button);
      }
      card.append(actions);
    }
    wrap.append(card);
  }
  return wrap;
}

function addLine(card, label, value) {
  if (!value) return;
  const line = document.createElement("p");
  const name = document.createElement("strong");
  name.textContent = label + " ";
  line.append(name, document.createTextNode(value));
  card.append(line);
}

function grid(headers, rows) {
  const wrap = document.createElement("div");
  wrap.className = "card";
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const header of headers) {
    const cell = document.createElement("th");
    cell.textContent = header;
    head.append(cell);
  }
  table.append(head);
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const value of row) {
      const cell = document.createElement("td");
      cell.textContent = text(value);
      tr.append(cell);
    }
    table.append(tr);
  }
  wrap.append(table);
  return wrap;
}

async function setStatus(id, status) {
  const response = await fetch("/api/hypotheses/" + id, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({status})
  });
  if (!response.ok) return;
  const updated = await response.json();
  const item = data.hypotheses.find((row) => row.id === id);
  if (item) item.status = updated.status;
  render();
}

document.getElementById("tabs").addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  tab = button.dataset.tab;
  for (const item of document.querySelectorAll("#tabs button")) {
    item.setAttribute("aria-pressed", item === button ? "true" : "false");
  }
  render();
});
document.getElementById("search").addEventListener("input", render);
load();
</script>
</body>
</html>
"""


def render_page(bootstrap: str = "") -> str:
    if "</" in bootstrap.lower():
        raise ValueError("bootstrap payload is not safe to embed")
    return PAGE.replace("__BOOTSTRAP__", bootstrap)


def page_path() -> Path:
    return Path(__file__)

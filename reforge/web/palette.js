/* ================================================================
   ReTrace — global search + command palette (Ctrl/⌘ K).

   Searches the real contents of the active assessment: findings, imports, strings, evidence,
   artifacts, tool calls and Evidence Graph nodes — plus the commands that move around the
   app. The index is built from data the backend already returned; nothing is synthesised, and a
   category with no matches is simply not shown.

   Depends on globals from app.js: $, esc, switchTab, sessionId, openFinding, findingsData,
   tmShowNode, runPlaybook, generateReport, exportRaw.
   ================================================================ */

const PALETTE_MAX_PER_GROUP = 6;

let paletteIndex = null;        // {commands, findings, imports, strings, evidence, artifacts, tools, nodes}
let paletteIndexedFor = null;   // session id the index was built for
let paletteRows = [];           // flattened, selectable rows currently rendered
let paletteCursor = 0;

/* ---------- commands ---------- */

function paletteCommands() {
  const go = (view, label, hint) => ({ label, hint, run: () => switchTab(view) });
  const cmds = [
    go("assessment", "Open assessment overview", "Target profile, risk, next actions"),
    go("findings", "Open findings", "Vulnerability management"),
    go("posture", "Open security posture", "Mitigations and attack surface"),
    go("graph", "Open Evidence Graph", "Investigate relationships"),
    go("evidence", "Open evidence", "Stored technical proof"),
    go("toollog", "Open tool log", "Every tool execution"),
    go("strings", "Open strings", "High-signal string analysis"),
    go("imports", "Open imports", "Imported API surface"),
    go("artifacts", "Open artifacts", "Traces, PCAPs, dumps"),
    go("playbooks", "Open playbooks", "Repeatable assessment procedures"),
    go("jobs", "Open jobs", "Long-running background work"),
    go("reports", "Open reports and exports", "Report centre"),
    go("servers", "Open servers and tools", "MCP connectivity"),
    go("projects", "Open projects", "Create, switch, set target"),
    go("chat", "Open investigation assistant", "Ask the agent"),
    { label: "Generate report", hint: "Build the deterministic assessment report",
      run: () => { switchTab("reports"); generateReport(); } },
    { label: "Export SARIF 2.1.0", hint: "Findings for code-scanning pipelines",
      run: () => window.open(`/api/projects/${sessionId}/export/sarif`, "_blank") },
    { label: "Export CycloneDX SBOM", hint: "Third-party components",
      run: () => window.open(`/api/projects/${sessionId}/export/cyclonedx`, "_blank") },
    { label: "Export raw investigation", hint: "Everything, as one Markdown document",
      run: () => exportRaw() },
    { label: "Toggle theme", hint: "Switch between dark and light", run: () => toggleTheme() },
    { label: "Open settings", hint: "LLM provider, safety mode",
      run: () => { const b = $("#settingsBtn"); if (b) b.click(); } },
  ];
  return cmds.map(c => ({ ...c, type: "command" }));
}

/* ---------- index ---------- */

async function buildPaletteIndex() {
  if (!sessionId) return { commands: paletteCommands() };
  const idx = { commands: paletteCommands() };

  /* One project payload carries findings, evidence, strings, imports and artifacts. The
     tool log and the graph are separate endpoints; a failure in any of them narrows the search
     rather than breaking it. */
  try {
    const p = await (await fetch(`/api/projects/${sessionId}`)).json();

    idx.findings = (p.findings || []).map((f, i) => ({
      type: "finding",
      label: f.title || "(untitled finding)",
      hint: [f.severity, f.cwe, f.location].filter(Boolean).join(" · "),
      text: `${f.title || ""} ${f.cwe || ""} ${f.location || ""} ${f.description || ""}`,
      badge: (f.severity || "INFO").toUpperCase(),
      run: () => { switchTab("findings"); openFinding(i); },
    }));

    idx.imports = (p.static_imports || []).map(name => ({
      type: "import", label: name, hint: "imported symbol", text: name,
      run: () => { switchTab("imports"); prefillFilter("#impSearch", name, () => renderImports(name)); },
    }));

    idx.strings = (p.static_strings || []).map(v => ({
      type: "string", label: v, hint: "static string", text: v,
      run: () => { switchTab("strings"); prefillFilter("#strSearch", v, () => renderStrings(v)); },
    }));

    idx.evidence = (p.evidence || []).map(e => ({
      type: "evidence",
      label: e.summary || e.id,
      // location is an object ({function, address}); interpolating it gave
      // every evidence hit the hint "[object Object]".
      hint: [e.id, e.source, evidenceLocation(e.location)].filter(Boolean).join(" · "),
      text: `${e.id || ""} ${e.summary || ""} ${e.source || ""} ${evidenceLocation(e.location)}`,
      run: () => { switchTab("evidence"); prefillFilter("#evSearch", e.id || "", () => renderEvidence(e.id || "")); },
    }));

    idx.artifacts = (p.artifacts || []).map(a => ({
      type: "artifact",
      label: a.name || a.id,
      hint: [a.id, a.type].filter(Boolean).join(" · "),
      text: `${a.id || ""} ${a.name || ""} ${a.type || ""}`,
      run: () => switchTab("artifacts"),
    }));

  } catch (err) { /* keep whatever was indexed; the palette still works on commands */ }

  try {
    const log = (await (await fetch(`/api/projects/${sessionId}/toollog`)).json()).log || [];
    idx.tools = log.map(e => ({
      type: "tool call",
      label: e.tool || "(tool)",
      hint: e.is_error ? "failed" : "ok",
      text: `${e.tool || ""} ${JSON.stringify(e.args || {})} ${e.result_preview || ""}`,
      run: () => { switchTab("toollog"); prefillFilter("#tlSearch", e.tool || "", () => renderToollog(e.tool || "")); },
    }));
  } catch (err) { /* tool log unavailable: skip the category */ }

  /* Graph nodes are already in memory when the graph has been opened; do not force a sync. */
  try {
    const nodes = (typeof _gvFullGraph === "object" && _gvFullGraph && _gvFullGraph.nodes) || [];
    idx.nodes = nodes.map(n => ({
      type: "graph node",
      label: n.label || (n.id || "").split(":").pop() || n.id,
      hint: n.type || "node",
      text: `${n.id || ""} ${n.label || ""} ${n.type || ""}`,
      run: () => { switchTab("graph"); tmShowNode(n.id, { center: true }); },
    }));
  } catch (err) { /* graph not loaded yet */ }

  return idx;
}

function prefillFilter(selector, value, rerender) {
  const el = $(selector);
  if (el) el.value = value;
  try { rerender(); } catch (err) { /* view not rendered yet; switchTab will load it */ }
}

/* ---------- matching ---------- */

function paletteScore(row, q) {
  const label = (row.label || "").toLowerCase();
  const text = (row.text || row.label || "").toLowerCase();
  if (label === q) return 0;
  if (label.startsWith(q)) return 1;
  if (label.includes(q)) return 2;
  if (text.includes(q)) return 3;
  return -1;
}

function paletteSearch(idx, query) {
  const q = query.trim().toLowerCase();
  const groups = [];
  const order = [
    ["commands", "Commands"], ["findings", "Findings"], ["nodes", "Graph nodes"],
    ["imports", "Imports"], ["strings", "Strings"], ["evidence", "Evidence"],
    ["artifacts", "Artifacts"], ["tools", "Tool calls"],
  ];
  for (const [key, title] of order) {
    const rows = idx[key] || [];
    if (!rows.length) continue;
    let hits;
    if (!q) {
      /* No query: show the commands only — a dump of every string in the binary is not a useful
         default state. */
      if (key !== "commands") continue;
      hits = rows.slice(0, 10);
    } else {
      hits = rows
        .map(r => ({ r, s: paletteScore(r, q) }))
        .filter(x => x.s >= 0)
        .sort((a, b) => a.s - b.s)
        .map(x => x.r);
    }
    if (hits.length) groups.push({ key, title, total: hits.length, rows: hits.slice(0, PALETTE_MAX_PER_GROUP) });
  }
  return groups;
}

/* ---------- rendering ---------- */

function renderPalette(query) {
  const box = $("#paletteResults");
  if (!box) return;
  if (!paletteIndex) {
    box.innerHTML = `<div class="palette-loading">Indexing the assessment…</div>`;
    paletteRows = [];
    return;
  }
  const groups = paletteSearch(paletteIndex, query);
  if (!groups.length) {
    box.innerHTML = `<div class="palette-none">
      <strong>No match for “${esc(query)}”</strong>
      <span>Searched findings, graph nodes, imports, strings, evidence, artifacts and tool
      calls in this project.</span></div>`;
    paletteRows = [];
    return;
  }

  paletteRows = [];
  const html = groups.map(g => {
    const rows = g.rows.map(r => {
      const i = paletteRows.push(r) - 1;
      return `<button class="pal-row" role="option" type="button" data-pal="${i}" id="pal-row-${i}">
        <span class="pal-type">${esc(r.type)}</span>
        <span class="pal-label">${esc(String(r.label).slice(0, 140))}</span>
        ${r.badge ? `<span class="pal-badge sev-${esc(r.badge)}">${esc(r.badge)}</span>` : ""}
        ${r.hint ? `<span class="pal-hint">${esc(String(r.hint).slice(0, 80))}</span>` : ""}
      </button>`;
    }).join("");
    const more = g.total > g.rows.length
      ? `<span class="pal-more">+${g.total - g.rows.length} more</span>` : "";
    return `<div class="pal-group">
      <div class="pal-group-h"><span>${esc(g.title)}</span><span class="pal-count">${g.total} result${g.total === 1 ? "" : "s"}</span>${more}</div>
      ${rows}</div>`;
  }).join("");

  box.innerHTML = html;
  paletteCursor = 0;
  highlightPaletteRow();
}

function highlightPaletteRow() {
  const box = $("#paletteResults");
  if (!box) return;
  box.querySelectorAll(".pal-row").forEach((el, i) => {
    const on = i === paletteCursor;
    el.classList.toggle("sel", on);
    el.setAttribute("aria-selected", on ? "true" : "false");
    if (on) {
      el.scrollIntoView({ block: "nearest" });
      const input = $("#paletteInput");
      if (input) input.setAttribute("aria-activedescendant", el.id);
    }
  });
}

/* ---------- open / close / run ---------- */

async function openPalette(initialQuery) {
  const modal = $("#palette");
  const input = $("#paletteInput");
  if (!modal || !input) return;
  modal.hidden = false;
  input.value = initialQuery || "";
  renderPalette(input.value);
  input.focus();
  input.select();

  if (paletteIndexedFor !== sessionId || !paletteIndex) {
    paletteIndex = await buildPaletteIndex();
    paletteIndexedFor = sessionId;
    if (!modal.hidden) renderPalette($("#paletteInput").value);
  }
}

function closePalette() {
  const modal = $("#palette");
  if (modal) modal.hidden = true;
  paletteRows = [];
}

/* The index is a snapshot: drop it when the project changes or new data arrives, so a search
   never returns findings from a project the operator already left. */
function invalidatePaletteIndex() { paletteIndex = null; paletteIndexedFor = null; }

function runPaletteRow(i) {
  const row = paletteRows[i];
  if (!row) return;
  closePalette();
  try { row.run(); } catch (err) { /* a stale row must not break the app */ }
}

/* ---------- wiring ---------- */

document.addEventListener("keydown", (e) => {
  const mod = e.metaKey || e.ctrlKey;
  if (mod && e.key.toLowerCase() === "k") {
    e.preventDefault();
    const modal = $("#palette");
    if (modal && !modal.hidden) closePalette(); else openPalette("");
    return;
  }
  const modal = $("#palette");
  if (!modal || modal.hidden) return;
  if (e.key === "Escape") { e.preventDefault(); closePalette(); return; }
  if (e.key === "ArrowDown") {
    e.preventDefault();
    paletteCursor = Math.min(paletteCursor + 1, Math.max(0, paletteRows.length - 1));
    highlightPaletteRow();
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    paletteCursor = Math.max(paletteCursor - 1, 0);
    highlightPaletteRow();
  } else if (e.key === "Enter") {
    e.preventDefault();
    runPaletteRow(paletteCursor);
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const input = $("#paletteInput");
  if (input) input.addEventListener("input", () => renderPalette(input.value));
  const btn = $("#paletteBtn");
  if (btn) btn.addEventListener("click", () => openPalette(""));
  const x = $("#paletteClose");
  if (x) x.addEventListener("click", closePalette);
  const modal = $("#palette");
  if (modal) modal.addEventListener("click", (e) => { if (e.target === modal) closePalette(); });
  const results = $("#paletteResults");
  if (results) results.addEventListener("click", (e) => {
    const row = e.target.closest("[data-pal]");
    if (row) runPaletteRow(Number(row.dataset.pal));
  });
});

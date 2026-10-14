/* ================================================================
   ReTrace — Assessment, Security posture and Reports views.

   Everything rendered here comes from GET /api/projects/{id}/assessment, a deterministic
   snapshot of real session state. Where a value is unknown the UI says so ("—", "not analyzed")
   rather than showing a plausible-looking number: a vulnerability dashboard that guesses is worse
   than no dashboard at all.

   Depends on globals defined by app.js: $, esc, switchTab, sessionId, sendPromptSafe,
   fmtBytes, downloadText, generateReport, runPlaybook.
   ================================================================ */

/* ---------- shared formatting ---------- */

const RISK_COPY = {
  CRITICAL: { label: "Critical", tone: "crit" },
  HIGH:     { label: "High",     tone: "high" },
  MEDIUM:   { label: "Medium",   tone: "med" },
  LOW:      { label: "Low",      tone: "low" },
  INFO:     { label: "Info",     tone: "info" },
  NONE:     { label: "None found", tone: "ok" },
  UNKNOWN:  { label: "Not assessed", tone: "unknown" },
};

/* Severity is never communicated by colour alone: every band is spelled out.
   The four-block meter that used to sit beside the word said the same thing
   twice, so the word carries it on its own. */
function titleCase(s){ s = String(s || ""); return s.charAt(0) + s.slice(1).toLowerCase(); }

const PRIORITY_COPY = { p0: "Do first", p1: "High value", p2: "When convenient", p3: "Optional" };

function pct(v) { return v === null || v === undefined ? "—" : `${v}%`; }
function num(v) { return v === null || v === undefined ? "—" : String(v); }

function shortHash(h) {
  if (!h) return "";
  return h.length > 24 ? `${h.slice(0, 12)}…${h.slice(-8)}` : h;
}

function copyChip(value, label) {
  if (!value) return "";
  return `<button class="copy-chip" type="button" data-copy="${esc(value)}" title="Copy ${esc(label)}">`
    + `<span class="copy-chip-k">${esc(label)}</span>`
    + `<code>${esc(shortHash(value))}</code>`
    + `<span class="copy-chip-ic" aria-hidden="true">⧉</span></button>`;
}

/* Delegated copy handling — one listener for every copy chip the app ever renders. */
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    btn.classList.add("copied");
    setTimeout(() => btn.classList.remove("copied"), 1100);
  } catch (err) {
    /* Clipboard blocked (insecure context or denied permission): select the text instead so the
       operator can still copy it by hand, rather than failing silently. */
    const r = document.createRange();
    r.selectNodeContents(btn.querySelector("code") || btn);
    const sel = window.getSelection();
    sel.removeAllRanges(); sel.addRange(r);
  }
});

/* ---------- empty / error states ---------- */

function loadingSkeleton(blocks){
  const rows = Array.from({length: blocks || 3}, () => `<div class="skel skel-block"></div>`).join("");
  return `<div class="skeleton-stack" aria-busy="true" aria-live="polite">${rows}</div>`;
}

function emptyState(iconName, title, body, actions) {
  const btns = (actions || []).map(a =>
    `<button class="${a.primary ? "solid-btn" : "btn-sm"}" type="button" data-empty-action="${esc(a.view || "")}"
       ${a.prompt ? `data-empty-prompt="${esc(a.prompt)}"` : ""}>${esc(a.label)}</button>`).join("");
  return `<div class="empty-state">
    <div class="empty-state-ic">${icon(iconName, "ic ic-lg")}</div>
    <h3>${esc(title)}</h3>
    <p>${esc(body)}</p>
    ${btns ? `<div class="empty-state-actions">${btns}</div>` : ""}
  </div>`;
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-empty-action]");
  if (!btn) return;
  const prompt = btn.dataset.emptyPrompt;
  const view = btn.dataset.emptyAction;
  if (prompt) { sendPromptSafe(prompt); return; }
  if (view) switchTab(view);
});

/* ================================================================
   ASSESSMENT (landing view)
   ================================================================ */

let assessmentSnapshot = null;

async function loadAssessment() {
  const box = $("#assessmentBody");
  if (!box || !sessionId) return;
  if (assessmentSnapshot && assessmentSnapshot.__for !== sessionId) box.innerHTML = loadingSkeleton(3);
  try {
    const r = await fetch(`/api/projects/${sessionId}/assessment`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    assessmentSnapshot = await r.json();
    assessmentSnapshot.__for = sessionId;
    renderAssessment(assessmentSnapshot);
    renderChatContext(assessmentSnapshot);
  } catch (err) {
    box.innerHTML = emptyState("alert", "Could not load the assessment",
      `The assessment snapshot could not be fetched (${err.message}). The analysis itself is `
      + `unaffected — this is a display problem. Retry, or open another section.`,
      [{ label: "Retry", primary: true, view: "assessment" }]);
  }
}

function renderAssessment(snap) {
  const box = $("#assessmentBody");
  if (!box) return;

  if (!snap.target.loaded) {
    box.innerHTML = emptyState("target", "No target loaded",
      "An assessment starts from an executable. Upload a binary or point ReTrace at a local path — "
      + "offline static triage runs immediately and needs no LLM and no MCP server.",
      [{ label: "Load a target", primary: true, view: "projects" },
       { label: "How ReTrace works", view: "howto" }]);
    return;
  }

  box.innerHTML = [
    heroHtml(snap),
    nextActionsHtml(snap),
    phaseHtml(snap),
    `<div class="assess-split">${findingsBreakdownHtml(snap)}${attackSurfaceHtml(snap)}</div>`,
    targetDetailHtml(snap),
    activityHtml(snap),
  ].join("");
}

/* ---------- hero ---------- */

function heroHtml(snap) {
  const t = snap.target || {};
  const r = snap.risk || {};
  const c = snap.counts || {};
  const cov = snap.coverage || {};
  const risk = RISK_COPY[r.band] || RISK_COPY.UNKNOWN;

  const facts = [
    t.format && t.format !== "non-PE" ? `${esc(t.format)}` : (t.format ? "Non-PE" : null),
    t.arch && t.arch !== "?" ? esc(t.arch) : null,
    t.size ? esc(fmtBytes(t.size)) : null,
    t.entropy != null ? `entropy ${esc(t.entropy)}` : null,
    t.import_count ? `${t.import_count} imports` : null,
  ].filter(Boolean).join(" · ");

  const confirmed = (c.status || {}).confirmed || 0;
  const vulnTotal = c.vulnerabilities || 0;

  return `<section class="assess-hero tone-${risk.tone}">
    <div class="hero-main">
      <span class="hero-eyebrow">Assessment</span>
      <h1 class="hero-target">${esc(t.file || "target")}</h1>
      <div class="hero-facts">${facts || "Profile not available"}</div>
      <div class="hero-hashes">${copyChip(t.sha256, "SHA-256")}${copyChip(t.md5, "MD5")}</div>
    </div>
    <div class="hero-tiles">
      ${tileHtml("Risk", `<span class="risk-band tone-${risk.tone}">${esc(risk.label)}</span>`,
                 r.basis || "", r.confirmed ? "Evidence-backed" : "Not yet confirmed")}
      ${tileHtml("Vulnerabilities", `${confirmed} <span class="tile-of">of ${vulnTotal}</span>`,
                 "Confirmed out of all recorded vulnerabilities. Hardening gaps and informational "
                 + "signals are counted separately.",
                 vulnTotal ? "confirmed" : "none recorded")}
      ${tileHtml("Attack surface", num(snap.attack_surface.signal_count),
                 "Dangerous sinks plus untrusted input sources, mapped from the import table. Attack "
                 + "surface is where to look, not a count of defects.",
                 `${snap.attack_surface.sinks.length} sink classes · ${(snap.attack_surface.sources || []).length} input sources`)}
      ${tileHtml("Coverage", pct(cov.phase_pct),
                 "Share of the eight deterministic assessment phases whose completion criteria are "
                 + "met by the current project state.",
                 `${num(cov.phases_done)}/${num(cov.phases_total)} phases`)}
    </div>
  </section>`;
}

function tileHtml(label, value, tooltip, foot) {
  return `<div class="hero-tile"${tooltip ? ` title="${esc(tooltip)}"` : ""}>
    <span class="tile-k">${esc(label)}</span>
    <span class="tile-v">${value}</span>
    <span class="tile-foot">${esc(foot || "")}</span>
  </div>`;
}

/* ---------- recommended next actions ---------- */

function nextActionsHtml(snap) {
  const actions = snap.next_actions || [];
  if (!actions.length) {
    return `<section class="assess-card">
      <h2 class="assess-h">Recommended next actions</h2>
      <p class="assess-sub">Nothing outstanding: every candidate has evidence, and the report has
      been generated. Continue manually, or start a new assessment of another version.</p>
    </section>`;
  }
  const rows = actions.map(a => `
    <button class="next-action prio-${esc(a.priority)}" type="button"
            data-action-view="${esc(a.view || "")}"
            ${a.prompt ? `data-action-prompt="${esc(a.prompt)}"` : ""}>
      <span class="na-prio">${esc(PRIORITY_COPY[a.priority] || a.priority)}</span>
      <span class="na-body">
        <strong>${esc(a.title)}</strong>
        <span>${esc(a.detail)}</span>
      </span>
      <span class="na-go">${icon("arrow-right")}</span>
    </button>`).join("");
  return `<section class="assess-card">
    <h2 class="assess-h">Recommended next actions</h2>
    <p class="assess-sub">Derived from this project's actual state — each one is shown because a
    real count triggered it, never as a generic suggestion.</p>
    <div class="next-actions">${rows}</div>
  </section>`;
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-action-view]");
  if (!btn) return;
  const prompt = btn.dataset.actionPrompt;
  if (prompt) { switchTab("chat"); sendPromptSafe(prompt); return; }
  if (btn.dataset.actionView) switchTab(btn.dataset.actionView);
});

/* ---------- assessment phases ---------- */

function phaseHtml(snap) {
  const wf = snap.workflow || {};
  const phases = wf.phases || [];
  if (!phases.length) return "";
  const steps = phases.map((p, i) => {
    const active = p.key === wf.phase;
    const cls = p.done ? "done" : (active ? "active" : "todo");
    const mark = p.done ? icon("check", "ic") : i + 1;
    return `<li class="phase-step ${cls}">
      <span class="ps-mark" aria-hidden="true">${mark}</span>
      <span class="ps-title">${esc(p.title)}</span>
      <span class="ps-state">${p.done ? "complete" : (active ? "in progress" : "pending")}</span>
    </li>`;
  }).join("");
  return `<section class="assess-card">
    <div class="assess-head">
      <div>
        <h2 class="assess-h">Assessment phase</h2>
        <p class="assess-sub">Completion is judged deterministically from project state, not by the
        model. The workflow guides — it never blocks manual investigation.</p>
      </div>
      ${wf.pinned ? `<span class="pin-badge" title="A phase is pinned manually">pinned</span>` : ""}
    </div>
    <ol class="phase-rail">${steps}</ol>
    <div class="phase-now">
      <strong>${esc(wf.title || "")}</strong>
      <span>${esc(wf.objective || "")}</span>
      ${(wf.next_steps || []).length
        ? `<ul class="phase-next">${wf.next_steps.map(n => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
    </div>
  </section>`;
}

/* ---------- findings breakdown ---------- */

function findingsBreakdownHtml(snap) {
  const c = snap.counts || {};
  const sevs = c.severity || {};
  const total = Object.values(sevs).reduce((a, b) => a + b, 0);

  const bars = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(band => {
    const n = sevs[band] || 0;
    const w = total ? Math.round((n / total) * 100) : 0;
    return `<div class="sev-row ${n ? "" : "zero"}">
      <span class="sev-k sev-${band}">${titleCase(band)}</span>
      <span class="sev-bar"><span class="sev-fill sev-${band}" style="width:${w}%"></span></span>
      <span class="sev-n">${n}</span>
    </div>`;
  }).join("");

  const kinds = [
    ["Vulnerabilities", c.vulnerabilities || 0, "Actual or strongly supported weaknesses.", "findings"],
    ["Hardening weaknesses", c.hardening || 0, "Missing exploit mitigations. Not defects on their own — they make a defect worse.", "posture"],
    ["Informational", c.informational || 0, "Attack-surface signals and observations. Context, not findings.", "posture"],
    ["Rejected", c.rejected || 0, "Investigated and ruled out.", "findings"],
  ].map(([label, n, why, view]) => `
    <button class="kind-row" type="button" data-action-view="${view}" title="${esc(why)}">
      <span class="kind-n">${n}</span>
      <span class="kind-l">${esc(label)}</span>
    </button>`).join("");

  if (!total && !(c.hardening || c.informational)) {
    return `<section class="assess-card">
      <h2 class="assess-h">Findings</h2>
      ${emptyState("flag", "No findings yet",
        "Static triage recorded nothing to report for this target. Run a vulnerability audit or "
        + "trace the attack surface to start hunting.",
        [{ label: "Open playbooks", primary: true, view: "playbooks" },
         { label: "Review attack surface", view: "posture" }])}
    </section>`;
  }

  return `<section class="assess-card">
    <h2 class="assess-h">Findings</h2>
    <p class="assess-sub">Severity distribution covers vulnerabilities only. The three classes below
    are kept apart on purpose.</p>
    <div class="sev-chart">${bars}</div>
    <div class="kind-grid">${kinds}</div>
  </section>`;
}

/* ---------- attack surface ---------- */

function attackSurfaceHtml(snap) {
  const s = snap.attack_surface || {};
  if (!s.available) {
    return `<section class="assess-card">
      <h2 class="assess-h">Attack surface</h2>
      ${emptyState("⊞", "Attack surface not mapped",
        "The import table has not been classified into dangerous sinks and untrusted input sources "
        + "yet. It is produced by the offline static pass and needs no LLM.", [])}
    </section>`;
  }

  const sinks = (s.sinks || []).slice(0, 7).map(r => `
    <li class="surf-row prio-${esc(r.priority)}" title="${esc(r.why || "")}">
      <span class="surf-prio" aria-label="${esc(r.priority)} review priority">${esc(r.priority)}</span>
      <span class="surf-label">${esc(r.label)}</span>
      <span class="sink-cwe">${esc(r.cwe || "")}</span>
      <span class="sink-pot sev-${esc(r.potential_severity)}" title="Worst case if this sink turns out to be reachable from untrusted input">${esc(r.potential_severity)} if reachable</span>
      <span class="surf-n">${r.count}</span>
    </li>`).join("");

  const groups = (s.source_groups || []).map(g => `
    <li class="src-group">
      <span class="src-origin">${esc(g.origin)}</span>
      <span class="src-syms mono">${esc(g.symbols.join(", "))}</span>
    </li>`).join("");

  return `<section class="assess-card">
    <div class="assess-head">
      <div>
        <h2 class="assess-h">Attack surface</h2>
        <p class="assess-sub">Dangerous sinks and the untrusted input that could reach them. Presence
        of a sink is not a vulnerability — a demonstrated source→sink path is.</p>
      </div>
      <button class="btn-sm" type="button" data-action-view="posture">Full posture${icon("arrow-right")}</button>
    </div>
    ${sinks ? `<h3 class="assess-h3">Dangerous sinks</h3><ul class="surf-list">${sinks}</ul>` : ""}
    ${groups
      ? `<h3 class="assess-h3">Untrusted input sources</h3><ul class="src-groups">${groups}</ul>`
      : `<p class="assess-note">No untrusted input source identified in the import table. Without a
         source, a dangerous sink is far less likely to be reachable by an attacker.</p>`}
  </section>`;
}

/* ---------- target detail ---------- */

function targetDetailHtml(snap) {
  const t = snap.target || {};
  const cov = snap.coverage || {};
  const sections = (t.sections || []);
  const rows = [
    ["File", t.file],
    ["Path", t.path, true],
    ["Format", t.format],
    ["Architecture", t.arch && t.arch !== "?" ? t.arch : null],
    ["Size", t.size ? fmtBytes(t.size) : null],
    ["Overall entropy", t.entropy != null ? String(t.entropy) : null],
    ["Imported symbols", t.import_count ? String(t.import_count) : null],
    ["SHA-256", t.sha256, true],
    ["MD5", t.md5, true],
  ].filter(r => r[1]);

  const sectionRows = sections.length ? `
    <h3 class="assess-h3">Sections</h3>
    <div class="tbl-wrap"><table class="data-tbl">
      <thead><tr><th scope="col">Name</th>
        <th scope="col" title="Shannon entropy of the section bytes; ≥ 7.2 suggests compression or packing">Entropy</th>
        <th scope="col">Virtual size</th><th scope="col">Raw size</th></tr></thead>
      <tbody>${sections.map(x => `<tr>
        <td class="mono">${esc(x.name || "")}</td>
        <td class="mono${x.entropy >= 7.2 ? " warn-cell" : ""}">${esc(String(x.entropy ?? "—"))}</td>
        <td class="mono">${x.vsize != null ? esc(fmtBytes(x.vsize)) : "—"}</td>
        <td class="mono">${x.rawsize != null ? esc(fmtBytes(x.rawsize)) : "—"}</td>
      </tr>`).join("")}</tbody>
    </table></div>` : "";

  return `<section class="assess-card">
    <h2 class="assess-h">Target profile</h2>
    <dl class="kv-grid">${rows.map(r =>
      `<dt>${esc(r[0])}</dt><dd class="${r[2] ? "mono wrap" : ""}">${esc(r[1])}</dd>`).join("")}</dl>
    ${sectionRows}
    <div class="coverage-strip">
      ${covChip("Evidence-backed", pct(cov.evidence_backed_pct), `${num(cov.evidence_backed)} of ${num(cov.findings_total)} findings carry evidence`)}
      ${covChip("Confirmed", pct(cov.confirmed_pct), `${num(cov.confirmed)} findings reached CONFIRMED`)}
      ${covChip("Dynamically confirmed", pct(cov.dynamically_confirmed_pct), `${num(cov.dynamically_confirmed)} findings observed at runtime`)}
      ${covChip("Evidence items", num(cov.evidence_items), "Stored evidence records")}
      ${covChip("Tool calls", num(cov.tool_calls), "Recorded MCP/meta tool executions")}
    </div>
  </section>`;
}

function covChip(label, value, tooltip) {
  return `<div class="cov-chip" title="${esc(tooltip)}">
    <span class="cov-v">${esc(value)}</span><span class="cov-k">${esc(label)}</span></div>`;
}

/* ---------- activity ---------- */

function activityHtml(snap) {
  const rows = snap.activity || [];
  if (!rows.length) {
    return `<section class="assess-card">
      <h2 class="assess-h">Recent activity</h2>
      <p class="assess-note">No tool has run yet in this project. The offline static pass does not
      appear here — it is not an MCP tool call.</p>
    </section>`;
  }
  return `<section class="assess-card">
    <div class="assess-head">
      <div><h2 class="assess-h">Recent activity</h2></div>
      <button class="btn-sm" type="button" data-action-view="toollog">Full tool log${icon("arrow-right")}</button>
    </div>
    <ul class="activity-list">${rows.map(r => `
      <li class="act-row ${r.ok ? "" : "err"}">
        <span class="act-dot" aria-hidden="true"></span>
        <span class="act-tool mono">${esc(r.tool || "")}</span>
        ${r.approved === false ? `<span class="act-tag deny">denied</span>`
          : r.approved === true ? `<span class="act-tag ok">approved</span>` : ""}
        <span class="act-prev">${esc(r.preview || "")}</span>
      </li>`).join("")}</ul>
  </section>`;
}

/* ================================================================
   SECURITY POSTURE
   ================================================================ */

async function loadPosture() {
  const box = $("#postureBody");
  if (!box || !sessionId) return;
  box.innerHTML = loadingSkeleton(3);
  try {
    const [snapRes, projRes] = await Promise.all([
      fetch(`/api/projects/${sessionId}/assessment`),
      fetch(`/api/projects/${sessionId}`),
    ]);
    const snap = await snapRes.json();
    const proj = await projRes.json();
    renderPosture(snap, proj.findings || []);
  } catch (err) {
    box.innerHTML = emptyState("alert", "Could not load the security posture", String(err.message), []);
  }
}

function renderPosture(snap, findings) {
  const box = $("#postureBody");
  if (!box) return;
  if (!snap.target.loaded) {
    box.innerHTML = emptyState("posture", "No target loaded",
      "Mitigation analysis runs on the binary itself. Load a target to see its hardening profile.",
      [{ label: "Load a target", primary: true, view: "projects" }]);
    return;
  }

  const hardening = findings.filter(f => (f.vuln_type || "").toLowerCase() === "hardening");
  const informational = findings.filter(f => {
    if ((f.vuln_type || "").toLowerCase() === "hardening") return false;
    const st = (f.status || "").toLowerCase();
    if (st === "indicator" || st === "observation") return true;
    const b = f.evidence_bundle;
    return !!(b && b.isolated_only);
  });

  box.innerHTML = [
    postureLegendHtml(),
    hardeningHtml(hardening, snap),
    surfaceDetailHtml(snap),
    informationalHtml(informational),
  ].join("");
}

function postureLegendHtml() {
  return `<section class="assess-card legend-card">
    <div class="legend-grid">
      <div class="legend-item tone-crit">
        <strong>Vulnerabilities</strong>
        <span>Actual or strongly supported weaknesses. These drive the risk band and the report's
        headline numbers.</span>
        <button class="btn-sm" type="button" data-action-view="findings">Open findings${icon("arrow-right")}</button>
      </div>
      <div class="legend-item tone-high">
        <strong>Security weaknesses</strong>
        <span>Missing exploit mitigations. Not exploitable on their own; they decide how bad an
        actual defect turns out to be.</span>
      </div>
      <div class="legend-item tone-info">
        <strong>Informational signals</strong>
        <span>Interesting characteristics and attack-surface observations. Context for the analyst,
        never counted as defects.</span>
      </div>
    </div>
  </section>`;
}

function hardeningHtml(hardening, snap) {
  const mitig = (snap.target || {}).mitigations || [];
  if (!hardening.length && !mitig.length) {
    return `<section class="assess-card">
      <h2 class="assess-h">Exploit mitigations</h2>
      ${emptyState("posture", "No mitigation audit available",
        "The hardening audit runs as part of static triage. It supports PE and ELF binaries; for "
        + "other formats no mitigation data can be produced.", [])}
    </section>`;
  }

  const enabled = mitig.filter(m => m.present);
  const missing = mitig.filter(m => !m.present);
  const card = (m, on) => `<li class="mitig ${on ? "on" : "off"}">
    <span class="mitig-state">${icon(on ? "check" : "x", "ic")}</span>
    <span class="mitig-body">
      <strong>${esc(m.label || m.name || "")}</strong>
      <span>${esc(m.detail || "")}</span>
    </span>
    <span class="mitig-tag">${on ? "enabled" : "not enabled"}</span>
  </li>`;

  const fromFindings = hardening.map(f => `<li class="mitig off">
    <span class="mitig-state">${icon("x", "ic")}</span>
    <span class="mitig-body">
      <strong>${esc(f.title || "")}</strong>
      <span>${esc(f.description || "")}</span>
      ${f.recommendation ? `<span class="mitig-fix"><em>Fix:</em> ${esc(f.recommendation)}</span>` : ""}
    </span>
    <span class="mitig-tag sev-${esc((f.severity || "INFO").toUpperCase())}">${esc(f.cwe || f.severity || "")}</span>
  </li>`).join("");

  return `<section class="assess-card">
    <h2 class="assess-h">Exploit mitigations</h2>
    <p class="assess-sub">What the compiler and linker turned on. A gap here is an amplifier: it
    does not create a vulnerability, it removes a barrier in front of one.</p>
    ${mitig.length ? `<div class="mitig-split">
      <div><h3 class="assess-h3">Enabled (${enabled.length})</h3>
        <ul class="mitig-list">${enabled.map(m => card(m, true)).join("") || `<li class="mitig-none">None detected.</li>`}</ul></div>
      <div><h3 class="assess-h3">Not enabled (${missing.length})</h3>
        <ul class="mitig-list">${missing.map(m => card(m, false)).join("") || `<li class="mitig-none">None missing.</li>`}</ul></div>
    </div>` : ""}
    ${fromFindings ? `<h3 class="assess-h3">Recorded hardening weaknesses</h3>
      <ul class="mitig-list">${fromFindings}</ul>` : ""}
  </section>`;
}

function surfaceDetailHtml(snap) {
  const s = snap.attack_surface || {};
  if (!s.available) return "";

  const cards = (s.sinks || []).map(r => `
    <article class="surf-card prio-${esc(r.priority)}">
      <header>
        <h3>${esc(r.label)}</h3>
        <span class="sink-pot sev-${esc(r.potential_severity)}" title="Worst case if this sink is reachable from untrusted input">${esc(r.potential_severity)} if reachable</span>
      </header>
      <p>${esc(r.why || "")}</p>
      <div class="surf-card-meta">
        <span class="sink-cwe">${esc(r.cwe || "")}</span>
        <span class="surf-n">${r.count} imported</span>
      </div>
      <div class="api-chips">${r.apis.map(a =>
        `<button class="api-chip" type="button" data-api="${esc(a)}" title="Search the assessment for ${esc(a)}">${esc(a)}</button>`).join("")}</div>
    </article>`).join("");

  return `<section class="assess-card">
    <h2 class="assess-h">Attack surface detail</h2>
    <p class="assess-sub">Each sink class is the operation an attacker-controlled value could break,
    with the CWE it maps to. Click an API to search the whole assessment for it.</p>
    <div class="surf-cards">${cards}</div>
    ${(s.sources || []).length ? `<h3 class="assess-h3">Untrusted input sources</h3>
      <p class="assess-sub">Where data an attacker may control enters the program. A sink is only
      exploitable if one of these can reach it.</p>
      <div class="tbl-wrap"><table class="data-tbl">
        <thead><tr><th scope="col">Symbol</th><th scope="col">Origin of the data</th></tr></thead>
        <tbody>${s.sources.map(x =>
          `<tr><td class="mono">${esc(x.symbol)}</td><td>${esc(x.origin)}</td></tr>`).join("")}</tbody>
      </table></div>` : ""}
  </section>`;
}

function informationalHtml(rows) {
  if (!rows.length) return "";
  return `<section class="assess-card">
    <h2 class="assess-h">Informational signals</h2>
    <p class="assess-sub">Recorded for completeness. These are deliberately excluded from the risk
    band and the vulnerability counts.</p>
    <ul class="info-list">${rows.map(f => `<li class="info-row">
      <span class="info-tag">${esc(f.status || "INFO")}</span>
      <span class="info-body"><strong>${esc(f.title || "")}</strong>
        <span>${esc(f.description || "")}</span></span>
    </li>`).join("")}</ul>
  </section>`;
}

/* API chip → global search */
document.addEventListener("click", (e) => {
  const chip = e.target.closest("[data-api]");
  if (chip && typeof openPalette === "function") openPalette(chip.dataset.api);
});

/* ================================================================
   REPORTS & EXPORTS
   ================================================================ */

async function loadReports() {
  const box = $("#reportsBody");
  if (!box || !sessionId) return;
  box.innerHTML = loadingSkeleton(3);
  try {
    const [snapRes, warnRes, valRes] = await Promise.all([
      fetch(`/api/projects/${sessionId}/assessment`),
      fetch(`/api/report/${sessionId}/validate`).catch(() => null),
      fetch(`/api/projects/${sessionId}/validate-findings`).catch(() => null),
    ]);
    const snap = await snapRes.json();
    const warnings = warnRes && warnRes.ok ? (await warnRes.json()).warnings || [] : [];
    const validator = valRes && valRes.ok ? await valRes.json() : null;
    renderReports(snap, warnings, validator);
  } catch (err) {
    box.innerHTML = emptyState("alert", "Could not load the report centre", String(err.message), []);
  }
}

function renderReports(snap, warnings, validator) {
  const box = $("#reportsBody");
  if (!box) return;
  if (!snap.target.loaded) {
    box.innerHTML = emptyState("reports", "Nothing to report yet",
      "A report is built from the findings of an assessment. Load a target and run an analysis "
      + "first.", [{ label: "Load a target", primary: true, view: "projects" }]);
    return;
  }

  const c = snap.counts || {};
  const cov = snap.coverage || {};
  const sevs = c.severity || {};

  const warnRows = (warnings || []).length
    ? `<ul class="val-list">${warnings.map(w =>
        `<li class="val-row ${esc(w.level || "info")}"><span class="val-tag">${esc(w.level || "info")}</span>${esc(w.msg || "")}</li>`).join("")}</ul>`
    : `<p class="assess-note">No pre-export warning. Every recorded finding carries evidence and a
       location consistent with its status.</p>`;

  const vs = validator && validator.summary ? validator.summary : null;
  const validatorRow = vs ? `<div class="report-scope">
      ${covChip("Validated", String(vs.confirmed || 0), "Findings the deterministic validator rates CONFIRMED")}
      ${covChip("Suspicious", String(vs.suspicious || 0), "Supported by evidence but not confirmed")}
      ${covChip("Hypothesis", String(vs.hypothesis || 0), "Proposed, not yet supported")}
      ${covChip("Needs dynamic proof", String(vs.needs_dynamic || 0), "High severity awaiting runtime confirmation")}
      ${covChip("False positive", String(vs.false_positive || 0), "Ruled out by the validator")}
    </div>` : "";

  box.innerHTML = `
    <section class="assess-card">
      <h2 class="assess-h">Report scope</h2>
      <div class="report-scope">
        ${covChip("Target", snap.target.file || "—", "The binary this report covers")}
        ${covChip("Vulnerabilities", String(c.vulnerabilities || 0), "Findings classified as defects")}
        ${covChip("Hardening", String(c.hardening || 0), "Missing mitigations")}
        ${covChip("Confirmed", pct(cov.confirmed_pct), "Share of findings that reached CONFIRMED")}
        ${covChip("Evidence items", num(cov.evidence_items), "Stored evidence records referenced by the report")}
      </div>
      <div class="sev-inline">${["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(b =>
        `<span class="sev-pill sev-${b}" title="${b} severity vulnerabilities">${b} ${sevs[b] || 0}</span>`).join("")}</div>
    </section>

    <section class="assess-card">
      <h2 class="assess-h">Pre-export validation</h2>
      <p class="assess-sub">Deterministic checks run before the report is delivered, so weak
      findings are never promoted silently.</p>
      ${validatorRow}
      ${warnRows}
    </section>

    <section class="assess-card">
      <h2 class="assess-h">Generate</h2>
      <p class="assess-sub">One complete technical report: executive summary, methodology, scope,
      per-finding analysis with CWE/CVSS, conclusions and appendices. Fully deterministic — it does
      not need an LLM.</p>
      <div class="report-actions">
        <button class="solid-btn" id="rcPreview" type="button">Preview report</button>
        <button class="btn-sm" data-report-fmt="html" type="button">Export HTML</button>
        <button class="btn-sm" data-report-fmt="pdf" type="button">Export PDF</button>
        <button class="btn-sm" data-report-fmt="docx" type="button">Export DOCX</button>
        <button class="btn-sm" data-report-fmt="md" type="button">Export Markdown</button>
      </div>
    </section>

    <section class="assess-card">
      <h2 class="assess-h">Machine-readable exports</h2>
      <p class="assess-sub">For pipelines and other tools, generated from the same findings.</p>
      <div class="report-actions">
        <button class="btn-sm" id="rcSarif" type="button" title="SARIF 2.1.0 — consumable by GitHub code scanning and VS Code">SARIF 2.1.0</button>
        <button class="btn-sm" id="rcCdx" type="button" title="CycloneDX 1.5 SBOM of detected third-party components">CycloneDX SBOM</button>
        <button class="btn-sm" id="rcRaw" type="button" title="Everything ReTrace knows, as one self-contained Markdown document">Raw investigation (.md)</button>
        <button class="btn-sm" id="rcTemplate" type="button" title="Blank report with the same structure, for manual compilation">Blank template (.docx)</button>
      </div>
    </section>`;

  const prev = $("#rcPreview");
  if (prev) prev.onclick = () => generateReport();
  box.querySelectorAll("[data-report-fmt]").forEach(b => {
    b.onclick = () => exportReport(b.dataset.reportFmt, b);
  });
  const sarif = $("#rcSarif");
  if (sarif) sarif.onclick = () => window.open(`/api/projects/${sessionId}/export/sarif`, "_blank");
  const cdx = $("#rcCdx");
  if (cdx) cdx.onclick = () => window.open(`/api/projects/${sessionId}/export/cyclonedx`, "_blank");
  const raw = $("#rcRaw");
  if (raw) raw.onclick = () => exportRaw();
  const tpl = $("#rcTemplate");
  if (tpl) tpl.onclick = () => window.open("/api/report/template", "_blank");
}

/* Export a report in the requested format. Generates the Markdown first when needed, so the
   export always reflects the current findings rather than a stale preview. */
async function exportReport(fmt, btn) {
  const label = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "Generating…"; }
  try {
    const r = await fetch(`/api/report/${sessionId}`, { method: "POST" });
    if (!r.ok) throw new Error(`report generation failed (HTTP ${r.status})`);
    const j = await r.json();
    const mdText = j.markdown || j.report || "";
    if (!mdText) throw new Error("the report came back empty");

    if (fmt === "md") {
      downloadText(mdText, `retrace-report-${sessionId}.md`, "text/markdown");
      return;
    }
    const ex = await fetch("/api/report/export", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ markdown: mdText, fmt, name: `retrace-report-${sessionId}` }),
    });
    if (!ex.ok) {
      const detail = await ex.json().catch(() => ({}));
      throw new Error(detail.detail || `export failed (HTTP ${ex.status})`);
    }
    const blob = await ex.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `retrace-report-${sessionId}.${fmt}`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  } catch (err) {
    if (btn) {
      btn.classList.add("btn-err");
      btn.textContent = String(err.message).slice(0, 60);
      setTimeout(() => { btn.classList.remove("btn-err"); btn.textContent = label; }, 4000);
      return;
    }
  } finally {
    if (btn && !btn.classList.contains("btn-err")) { btn.disabled = false; btn.textContent = label; }
    else if (btn) btn.disabled = false;
  }
}


/* ================================================================
   INVESTIGATION ASSISTANT — conversation context

   The assistant is not a general-purpose chatbot: the conversation belongs to one assessment.
   This strip says which one, so the operator never has to guess what "the target" refers to.
   ================================================================ */

function renderChatContext(snap) {
  const bar = $("#chatContext");
  if (!bar) return;
  if (!snap || !snap.target || !snap.target.loaded) {
    bar.hidden = false;
    bar.innerHTML = `<span class="cc-item cc-warn">
      <span class="cc-k">No target</span>
      <span class="cc-v">The assistant has no binary to reason about — load one first.</span></span>`;
    return;
  }
  const c = snap.counts || {};
  const cov = snap.coverage || {};
  const wf = snap.workflow || {};
  const item = (k, v, title) => `<span class="cc-item"${title ? ` title="${esc(title)}"` : ""}>
    <span class="cc-k">${esc(k)}</span><span class="cc-v">${esc(v)}</span></span>`;
  bar.hidden = false;
  bar.innerHTML =
    item("Target", snap.target.file || "—", snap.target.path || "")
    + item("Phase", wf.title || "—", wf.objective || "")
    + item("Findings", `${c.vulnerabilities || 0} vuln · ${c.hardening || 0} hardening`,
           "Vulnerabilities and hardening weaknesses recorded on this project")
    + item("Evidence", String(cov.evidence_items ?? 0), "Stored evidence records")
    // The badge is now icon + label + value, so scraping its textContent
    // produced "Safety Autonomous" under a cell already headed "Safety".
    + item("Safety", document.querySelector("#safetyBadge b")?.textContent?.trim() || "—",
           "Which actions pause for your approval");
}

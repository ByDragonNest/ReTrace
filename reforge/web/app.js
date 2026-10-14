const $ = (s) => document.querySelector(s);

/* ---------- authentication failures must be visible ----------
 * There is no central fetch helper in this file: ~90 call sites each do their own `fetch()` and
 * most do `(await fetch(...)).json()`, so an HTTP error became a JSON parse failure swallowed by
 * a `try{}catch{}`. When the API started refusing unauthenticated calls, every request returned
 * 401 and the UI showed nothing at all - it just looped creating a project called "undefined".
 *
 * Rather than touch 90 call sites, `window.fetch` is wrapped once here. It changes no behaviour
 * for successful calls; it only makes an authentication failure impossible to miss, and says what
 * to do about it. Any new call site is covered automatically.
 */
(function () {
  const realFetch = window.fetch.bind(window);
  let banner = null;

  function showAuthBanner() {
    if (banner) return;
    banner = document.createElement("div");
    banner.setAttribute("role", "alert");
    banner.style.cssText =
      "position:fixed;top:0;left:0;right:0;z-index:99999;padding:12px 18px;" +
      "background:#7f1d1d;color:#fff;font:14px/1.5 system-ui,sans-serif;" +
      "box-shadow:0 2px 12px rgba(0,0,0,.4)";
    banner.innerHTML =
      "<strong>Not authenticated.</strong> The API is refusing this browser (HTTP 401). " +
      "Open the one-time link printed in the server log " +
      "(<code style=\"background:rgba(255,255,255,.15);padding:1px 5px;border-radius:3px\">" +
      "http://host:port/?token=&hellip;</code>) to authenticate this browser, then reload." +
      "<br><span style=\"opacity:.85\">On a shared machine, set " +
      "<code>auth_trust_localhost=false</code> and use that link every time.</span>";
    const close = document.createElement("button");
    close.textContent = "\u00d7";
    close.setAttribute("aria-label", "Dismiss");
    close.style.cssText =
      "position:absolute;top:6px;right:12px;background:none;border:0;color:#fff;" +
      "font-size:22px;line-height:1;cursor:pointer";
    close.onclick = () => { banner.remove(); banner = null; };
    banner.appendChild(close);
    (document.body || document.documentElement).appendChild(banner);
  }

  window.fetch = async function (input, init) {
    const response = await realFetch(input, init);
    try {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      if (response.status === 401 && url.indexOf("/api/") !== -1) showAuthBanner();
    } catch (e) { /* never let the wrapper break a request */ }
    return response;
  };
})();

/* ---------- UI strings (English) ---------- */
const I18N = {
  en: {
    "graph.artifactsGraph":"Uploaded artifacts in the graph","graph.chains":"Source → sink chains","graph.diff":"Version diff (Evidence Graph)","graph.highSignal":"High-signal nodes","graph.map":"Interactive map","graph.runtime":"Runtime / Procmon summary","graph.sinks":"Unvalidated sinks","graph.weak":"HIGH/CRITICAL findings with insufficient evidence (&lt; 2 items)",
    "nav.chat":"Assistant","nav.findings":"Findings","nav.evidence":"Evidence","nav.toollog":"Tool log",
    "nav.strings":"Strings","nav.artifacts":"Artifacts","nav.imports":"Imports","nav.servers":"Servers & tools",
    "nav.help":"How it works","nav.projects":"Projects",
    "nav.graph":"Evidence Graph","nav.playbooks":"Playbooks","nav.jobs":"Jobs",
    "nav.assessment":"Overview","nav.posture":"Security posture","nav.reports":"Reports & exports",
    "view.graph":"Evidence Graph","view.playbooks":"Playbooks","view.jobs":"Jobs",
    "top.eyebrow":"Reverse engineering · vuln audit","a11y.skip":"Skip to main content","top.report":"Report",
    "rail.activeproj":"Active project","empty.title":"Ready to investigate.","chat.send":"Send",
    "report.template":"Template",
    "chat.placeholder":"E.g. \"Confirm in x64dbg the untrusted search path on CreateProcessA\"",
    "mode.static":"Static analysis","mode.dynamic":"Dynamic analysis",
    "empty.sub":"Open or create a project, set the target binary (static analysis starts automatically) and describe what to audit.",
    "view.findings":"Findings","view.evidence":"Evidence","view.toollog":"Tool log","view.strings":"Strings",
    "view.imports":"Imports","view.artifacts":"Artifacts","view.projects":"Projects","view.settings":"Settings",
  }
};
Object.assign(I18N.en, {
  "graph.refresh":"Refresh","graph.interactive":"Interactive map","graph.resetFilters":"Reset default filters",
  "graph.resetFilters.title":"Restore view, search and filters to the investigative default",
  "graph.resetLayout":"Layout","graph.fit":"Fit","graph.fullscreen":"Fullscreen",
  "graph.search.placeholder":"Search the graph: function, path, finding, artifact...",
  "graph.ask.kicker":"Graph AI","graph.ask.placeholder":"Ask the AI about the selected node, the subgraph, or the whole map...",
  "graph.ask.button":"Ask AI","graph.help":"Drag nodes - mouse wheel to zoom - drag background to pan - click a node to open its dossier",
  "graph.typeFilters":"Node type filters","graph.noise":"show noise",
  "strings.explain":"The Strings tab extracts readable text from the binary and groups it by signal: URLs, paths, registry keys, commands, diagnostics, and possible secrets. It does not prove a vulnerability by itself: it helps find clues, configuration, endpoints, and keywords to connect to functions, imports, and findings in the Evidence Graph.",
  "strings.workflow.title":"Strings Workflow",
  "strings.workflow.body":"Start from high-signal strings, search the reference in the Evidence Graph, then verify which function, import, or finding uses it. Strings are clues: they become evidence only when connected to callsites, evidence, or runtime behavior.",
  "strings.search.placeholder":"filter strings by URL, path, API, token, error...",
  "imports.explain":"Keep the Imports tab because it exposes the binary's static attack surface: process, file, network, crypto, memory, and dynamic loading APIs. It does not confirm a bug alone, but it tells you which primitives deserve callsite, source-to-sink, and playbook review.",
  "imports.workflow.title":"Why Keep Imports",
  "imports.workflow.body":"Imports guide the Evidence Graph: when exec, file, network, crypto, or memory APIs appear, the useful next step is to find where they are called and which inputs reach them. This tab is the fast inventory of the static attack surface.",
  "imports.search.placeholder":"filter imports by API, DLL, risk class...",
  "playbooks.explain":"Repeatable analysis procedures. Starting one guides the agent through the planned steps while respecting the safety mode.",
  "jobs.explain":"Background work separated from chat: static analysis, source-to-sink, finding validation, reporting.",
  "empty.node":"Click a map node to open the investigative dossier.",
  "how.title":"How ReTrace Works",
  "how.subtitle":"ReTrace is a local binary-audit workspace that combines deterministic static analysis, MCP tools, and an optional LLM agent.",
  "how.1.title":"Project","how.1.body":"Create or open a project. Each project stores chat, findings, evidence, tool logs, and LLM usage estimates in SQLite, with a JSON compatibility mirror.",
  "how.2.title":"Target","how.2.body":"Set the binary in Projects. Offline static analysis starts immediately: hashes, strings, imports, hardening, attack surface, and initial findings.",
  "how.3.title":"Optional AI","how.3.body":"With Anthropic or a local model you can ask for deeper analysis. The agent uses available tools, updates findings, and shows operational reasoning in chat.",
  "how.4.title":"MCP Tools","how.4.body":"MCP servers expose functions such as decompilation, xrefs, advanced strings, mitigation audits, diffing, and debugging. Enable or disable them from Servers & tools.",
  "how.5.title":"Findings and Evidence","how.5.body":"Findings carry status, severity, CWE, location, and stable evidence references. The Evidence section preserves technical proof outside the chat flow.",
  "how.6.title":"Report","how.6.body":"The Report button generates an exportable draft. Pre-export warnings help separate confirmed findings, hypotheses, and weak observations.",
  "how.cost.title":"Claude API Cost Estimate",
  "how.cost.body1":"When the provider is Anthropic, the API returns token usage for each request. ReTrace stores it and shows an estimate in the top bar and as a chat note after each call.",
  "how.cost.body2":"The estimate is calculated locally from the configured model's per-million-token price list. It does not include discounts, marketplace pricing, enterprise plans, or server-side tool costs not used by ReTrace."
});
Object.assign(I18N.en, {
  "common.localAi":"Local AI","common.full":"Full","common.close":"Close","common.loading":"Loading...",
  "common.none":"No items.","common.create":"Create","common.apply":"Apply","common.cancel":"Cancel",
  "common.newProject":"New project","common.lightDark":"Light/dark theme",
  "banner.noLlm":"No LLM configured - set it from the settings panel. Offline static analysis still works.",
  "banner.llmUnreachable":"Local LLM configured ({model}) but {url} is not reachable - start the local server (Ollama: open the app or run `ollama serve`), then retry. Offline static analysis still works.",
  "banner.llmProblem":"Local LLM at {url}: {error}",
  "chat.empty.body":"Open or create a project, set the target binary, then use the buttons to start an analysis or ask a question. You will see the agent reasoning in real time.",
  "launcher.static":"Static analysis","launcher.dynamic":"Dynamic analysis","launcher.modeLabel":"manual chat messages use:",
  "launcher.mode.auto":"auto","launcher.mode.static":"static","launcher.mode.dynamic":"dynamic",
  "findings.validate":"Validate with AI","findings.validate.title":"Ask the AI to confirm or refute findings discovered offline",
  "findings.empty":"No findings yet.","findings.ask":"Ask AI for details",
  "findings.ask.hint":"opens the chat and shows the LLM reasoning",
  "findings.plain":"Plain language","findings.noValidate":"No findings to validate: set a target or start an analysis.",
  "findings.summary.one":"1 total","findings.summary.many":"{n} total",
  "findings.field.type":"Type","findings.field.cwe":"CWE","findings.field.location":"Location",
  "findings.field.description":"Technical description","findings.field.evidence":"Evidence","findings.field.impact":"Impact",
  "findings.field.recommendation":"Recommendation","findings.field.references":"References",
  "findings.field.evidenceRefs":"Evidence","findings.field.confidence":"Confidence",
  "playbooks.none":"No playbooks.","playbooks.loadError":"Error loading playbooks.",
  "playbooks.run":"Run","playbooks.dynamic":"dynamic","playbooks.startError":"Could not start the playbook.",
  "playbooks.networkError":"Network error.",
  "graph.head.desc":"Queryable analysis database: binaries, functions, imports, sinks, sources, evidence, findings, and relationships. Synced from the project state.",
  "graph.canvas.hint":"click+drag background to move - mouse wheel to zoom - click a node to focus",
  "graph.dossier.empty":"Click a map node to open the investigative dossier: why it matters, relationships, linked evidence, and quick actions.",
  "graph.map":"Interactive map","graph.sinks":"Unvalidated sinks","graph.runtime":"Runtime / Procmon summary","graph.artifactsGraph":"Uploaded artifacts in the graph",
  "graph.highSignal":"High-signal nodes","graph.weak":"HIGH/CRITICAL findings with insufficient proof (< 2 evidence items)",
  "graph.chains":"Source -> sink chains","graph.diff":"Version diff (Evidence Graph)",
  "graph.diff.placeholder":"- choose the previous project (A) -","graph.compare":"Compare",
  "graph.severity.all":"Severity: all","graph.status.all":"Status: all","graph.source.all":"Source: all",
  "graph.type.binary":"Binaries","graph.type.function":"Functions","graph.type.import":"Imports","graph.type.sink":"Sinks",
  "graph.type.source":"Sources","graph.type.finding":"Findings","graph.type.evidence":"Evidence","graph.type.component":"Components",
  "graph.type.string":"Strings","graph.type.artifact":"Artifacts","graph.type.toolcall":"Tool calls","graph.type.process":"Processes",
  "graph.type.procmon_op":"Operations","graph.type.file_path":"Files","graph.type.registry_key":"Registry",
  "graph.type.network_endpoint":"Network","graph.type.dynamic_event":"Dynamic events","graph.type.risk":"Risk",
  "playbooks.empty":"Loading...","evidence.explain":"Each evidence item has a stable ID (E-NNNN) and records which tool/source produced it. Findings cite it through evidence_refs.",
  "evidence.search.placeholder":"filter by ID, source, location, text...","evidence.empty":"No evidence yet.",
  "toollog.explain":"History of MCP tool calls for this investigation, without rereading the chat.",
  "toollog.search.placeholder":"filter by tool, arguments, result...","toollog.empty":"No calls recorded.",
  "artifacts.explain":"Upload files to analyze (Procmon XML, pcap, logs, dumps). Files stay inside the project and can be passed to MCP servers or the agent. No file is executed.",
  "artifacts.drop.strong":"Drop a file here","artifacts.drop.or":"or","artifacts.drop.browse":"choose from computer",
  "artifacts.drop.note":"Procmon XML, pcap, logs, binary dumps...","artifacts.empty":"No artifacts uploaded.",
  "imports.shortExplain":"APIs imported by the binary. Risky APIs are highlighted by CWE class.","imports.empty":"No imports available - set the target.",
  "strings.shortExplain":"Strings extracted statically from the binary (minimum 6 chars). Search paths, URLs, keys, commands, and tokens.",
  "strings.empty":"No strings available - set the target.",
  "servers.title":"MCP servers & tools","servers.explain":"Enable only the servers you need; expand each one to inspect the available tools.",
  "projects.explain":"Stored in local SQLite, with a compatibility JSON mirror.","projects.new.placeholder":"new project name...",
  "projects.target.label":"Target binary for the active project (static analysis starts automatically):",
  "projects.target.placeholder":"C:\\path\\to\\target.exe","projects.target.button":"Set & analyze",
  "projects.target.drop.strong":"Drop the binary here","projects.target.drop.or":"or","projects.target.drop.browse":"choose from computer",
  "projects.target.drop.note":"The file is copied into the project workspace and analyzed immediately.",
  "projects.diff.label":"Patch diff - compare two versions (A = old, B = new):",
  "projects.diffA.placeholder":"A: C:\\path\\to\\old.exe","projects.diffB.placeholder":"B: C:\\path\\to\\new.exe",
  "settings.title":"Settings","settings.provider":"LLM provider","settings.local":"Local (Ollama / OpenAI-compatible)",
  "settings.model":"Model","settings.baseUrl":"Base URL","settings.apiKey":"API key","settings.safety":"Safety mode",
  "settings.none":"None","settings.safeNote":"Safe = approve every non-read action - Assisted = approve run/patch/write/network - Autonomous = no approvals (not recommended).",
  "settings.persist":"Save in config.py","finding.detail":"Vulnerability case file"
});
/* English only. The product is English-only by design (see the README); the bilingual machinery
   that used to live here - a language switch, a second catalogue, a per-browser preference - was
   removed rather than left switchable, because a language the product ships and does not want is
   a second set of strings to keep correct for no one's benefit.

   Nothing here is translated at render time: every string is written in English where it is used. */
function t(key){ return I18N.en[key] || key; }
const PLAYBOOK_COPY = {
  artifact_intake_triage: ["Artifact Intake Triage", "Classify an uploaded artifact and connect it to the Evidence Graph: parser, summary, evidence, and generated nodes."],
  dynamic_confirmation: ["Dynamic Confirmation", "Confirm priority static hypotheses at runtime with breakpoints, real arguments, and observed evidence."],
  vuln_triage: ["Vulnerability Triage", "Rapid vulnerability triage of a benign binary: attack surface, dangerous sinks, input sources, components with known CVEs."],
  patch_diff: ["Patch Diff", "Compare two versions of the same binary to identify security-relevant changes."],
  procmon_runtime_investigation: ["Procmon Runtime Investigation", "Analyze a Procmon XML and link processes, files, registry, and network activity to findings, evidence, and artifacts."],
  report_only: ["Report Only", "Generate reporting only from the findings and evidence already collected."],
  source_to_sink_audit: ["Source-to-Sink Audit", "Reconstruct chains from controllable input to dangerous sinks with callsites, confidence, and limitations."],
  supply_chain_audit: ["Supply-chain Binary Audit", "Identify embedded libraries/components, likely versions, and risk from outdated components."],
  evidence_graph_review: ["Evidence Graph Review", "Guided review of the Evidence Graph: critical nodes, noisy clusters, weak evidence, and next actions."],
  vulnerability_audit: ["Vulnerability Audit", "Binary vulnerability audit: attack surface, sinks, source-to-sink paths, and validation."],
  x64dbg_state_validation: ["x64dbg State Validation", "Confirm process state, modules, breakpoints, and critical API arguments in the debugger."]
};
const PLAYBOOK_STEP_LABELS = {
  artifact_identification:"identify artifact",
  parser_selection:"select parser",
  safe_metadata_extraction:"extract metadata safely",
  graph_projection:"project into graph",
  evidence_linking:"link evidence",
  node_dossier_review:"review node dossier",
  select_hypotheses:"select hypotheses",
  set_breakpoints:"set breakpoints",
  dynamic_trace:"runtime trace",
  confirm_source_to_sink:"confirm source-to-sink",
  finding_validation:"validate findings",
  report_generation:"generate report",
  static_triage:"static triage",
  floss_strings:"FLOSS strings",
  load_both_versions:"load both versions",
  binary_diff:"binary diff",
  changed_function_review:"review changed functions",
  procmon_parse:"parse Procmon",
  process_tree_reconstruction:"reconstruct process tree",
  operation_clustering:"cluster operations",
  object_hotspot_review:"review object hotspots",
  finding_runtime_validation:"runtime-validate findings",
  source_inventory:"source inventory",
  sink_inventory:"sink inventory",
  xref_walk:"xref walk",
  dataflow_hypothesis:"dataflow hypothesis",
  callsite_review:"review callsites",
  component_fingerprinting:"component fingerprinting",
  known_libs_lookup:"known library lookup",
  crypto_inventory:"crypto inventory",
  sbom_export:"SBOM export",
  graph_health_check:"graph health check",
  high_signal_node_review:"review high-signal nodes",
  weak_finding_review:"review weak findings",
  source_sink_chain_review:"review source-sink chains",
  artifact_gap_analysis:"artifact gap analysis",
  next_action_plan:"next action plan",
  source_to_sink:"source-to-sink",
  ghidra_function_review:"Ghidra function review",
  debugger_attach_or_launch:"attach/launch debugger",
  module_inventory:"module inventory",
  breakpoint_plan:"breakpoint plan",
  argument_capture:"capture arguments",
  runtime_evidence_capture:"capture runtime evidence",
  finding_update:"update findings"
};
function playbookLabel(id, field, fallback){
  const row = PLAYBOOK_COPY[id];
  if(!row) return fallback || id || "";
  return field === "description" ? row[1] : row[0];
}
function playbookStepLabel(step){
  const row = PLAYBOOK_STEP_LABELS[step];
  if(row) return row;
  return String(step || "").replace(/_/g, " ");
}
function safetyModeLabel(mode){
  const labels = {safe:"Safe", assisted:"Assisted", autonomous:"Autonomous", dangerous:"Dangerous"};
  return labels[mode] || mode || "";
}
function findingStatusLabel(status){
  const s = String(status || "").toLowerCase();
  const labels = {
    confirmed:"confirmed", rejected:"rejected", false_positive:"false positive", hypothesis:"hypothesis",
    suspicious:"suspicious", needs_validation:"needs validation",
    needs_dynamic_validation:"needs dynamic validation", open:"open", fixed:"fixed"
  };
  return labels[s] || status || "";
}
function ensureInfoPanel(viewId, panelId, titleKey, bodyKey){
  const view=$(viewId); if(!view) return;
  let panel=$("#"+panelId);
  if(!panel){
    panel=document.createElement("div");
    panel.id=panelId;
    panel.className="analysis-note";
    const head=view.querySelector(".view-head");
    if(head && head.parentNode) head.parentNode.insertBefore(panel, head.nextSibling);
    else view.prepend(panel);
  }
  panel.innerHTML=`<strong>${esc(t(titleKey))}</strong><span>${esc(t(bodyKey))}</span>`;
}
function applyLang(){
  // English only. Runs once at start-up and fills every [data-i18n] element from the catalogue.
  document.documentElement.setAttribute("lang", "en");
  document.querySelectorAll("[data-i18n]").forEach(el=>{
    const k=el.getAttribute("data-i18n"); const v=t(k); if(!v) return;
    // Buttons carry an <svg> icon plus their label. Assigning textContent
    // would drop the icon on every language refresh, so when the element has
    // element children only the trailing text node is rewritten.
    if(el.firstElementChild){
      const tn=[...el.childNodes].reverse().find(n=>n.nodeType===Node.TEXT_NODE);
      if(tn) tn.nodeValue=v; else el.append(v);
    } else {
      el.textContent=v;
    }
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el=>{
    const k=el.getAttribute("data-i18n-placeholder"); const v=t(k); if(v) el.setAttribute("placeholder",v);
  });
  document.querySelectorAll("[data-i18n-title]").forEach(el=>{
    const k=el.getAttribute("data-i18n-title"); const v=t(k); if(v) el.setAttribute("title",v);
  });
  const setText=(sel,k)=>{const el=$(sel); if(el) el.textContent=t(k);};
  const setPlaceholder=(sel,k)=>{const el=$(sel); if(el) el.setAttribute("placeholder",t(k));};
  const setTitle=(sel,k)=>{const el=$(sel); if(el) el.setAttribute("title",t(k));};
  const setTextValue=(sel,v)=>{const el=$(sel); if(el) el.textContent=v;};
  const setAllText=(sel,k)=>document.querySelectorAll(sel).forEach(el=>{ el.textContent=t(k); });
  const setTailText=(sel,k)=>{
    const el=$(sel); if(!el) return;
    const tn=[...el.childNodes].reverse().find(n=>n.nodeType===Node.TEXT_NODE);
    if(tn) tn.nodeValue=" "+t(k); else el.append(" "+t(k));
  };
  const setOptionText=(sel,k)=>{const el=$(sel); if(el) el.textContent=t(k);};
  setTailText("#gvReset","graph.resetFilters"); setTitle("#gvReset","graph.resetFilters.title");
  setText("#graphAskBtn","graph.ask.button"); setPlaceholder("#graphAskInput","graph.ask.placeholder");
  setPlaceholder("#graphSearch","graph.search.placeholder"); setPlaceholder("#strSearch","strings.search.placeholder"); setPlaceholder("#impSearch","imports.search.placeholder");
  setText(".graph-ai-kicker","graph.ask.kicker"); setText(".gv-help","graph.help");
  setTailText("#gvResetLayout","graph.resetLayout");
  setTailText("#gvFit","graph.fit");
  setTailText("#gvFullscreen","graph.fullscreen"); setTitle("#gvFullscreen","graph.fullscreen");
  setTailText("#graphRefresh","graph.refresh");
  setPlaceholder("#evSearch","evidence.search.placeholder"); setPlaceholder("#tlSearch","toollog.search.placeholder");
  setPlaceholder("#projName","projects.new.placeholder"); setPlaceholder("#targetPath","projects.target.placeholder");
  setPlaceholder("#diffA","projects.diffA.placeholder"); setPlaceholder("#diffB","projects.diffB.placeholder");
  setText(".tm-ai-kicker","graph.ask.kicker"); setText(".tm-canvas-hint","graph.canvas.hint");
  setText("#evLocalAi","common.localAi"); setText("#strLocalAi","common.localAi");
  setTitle("#settingsBtn","settings.title"); setTitle("#railNew","common.newProject"); setTitle("#themeToggle","common.lightDark");
  setText("#llmBanner","banner.noLlm");
  setText("#view-chat .empty p","chat.empty.body");
  setTailText(".launch-btn.static","launcher.static"); setTailText(".launch-btn.dynamic","launcher.dynamic");
  setText(".mode-pills-label","launcher.modeLabel");
  setAllText(".modepill[data-mode='auto']","launcher.mode.auto");
  setAllText(".modepill[data-mode='static']","launcher.mode.static");
  setAllText(".modepill[data-mode='dynamic']","launcher.mode.dynamic");
  setText("#validateAll","findings.validate"); setTitle("#validateAll","findings.validate.title");
  setText("#findingsList .findings-empty","findings.empty");
  const graphHead=$("#view-graph .view-head p"); if(graphHead) graphHead.textContent=t("graph.head.desc");
  // Headings are bound to their key via data-i18n in the markup. They used to
  // be assigned positionally from a 7-item list over 8 headings, so every
  // section carried the title of the one below it.
  setOptionText("#graphSeverity option[value='']","graph.severity.all");
  setOptionText("#graphStatus option[value='']","graph.status.all");
  setOptionText("#graphSource option[value='']","graph.source.all");
  setOptionText("#diffOther option[value='']","graph.diff.placeholder");
  setText("#runGraphDiff","graph.compare");
  const noise=$("#graphShowNoise")?.closest("label"); if(noise){ const tn=[...noise.childNodes].find(n=>n.nodeType===Node.TEXT_NODE); if(tn) tn.nodeValue=" "+t("graph.noise"); }
  document.querySelectorAll(".tm-type-chip").forEach(chip=>{
    const key="graph.type."+chip.dataset.t;
    const tn=[...chip.childNodes].reverse().find(n=>n.nodeType===Node.TEXT_NODE);
    if(tn && I18N.en[key]) tn.nodeValue=t(key);
  });
  const dossierEmpty=$("#graphNodeDetails .tm-dossier-empty"); if(dossierEmpty) dossierEmpty.textContent=t("graph.dossier.empty");
  setText("#view-playbooks .view-head p","playbooks.explain");
  setText("#view-playbooks .findings-empty","playbooks.empty");
  const evidenceHead=$("#view-evidence .view-head p"); if(evidenceHead) evidenceHead.innerHTML=t("evidence.explain").replace("evidence_refs","<code>evidence_refs</code>");
  setText("#evidenceList .findings-empty","evidence.empty");
  setText("#view-toollog .view-head p","toollog.explain");
  setText("#toollogList .findings-empty","toollog.empty");
  const artifactsHead=$("#view-artifacts .view-head p"); if(artifactsHead) artifactsHead.textContent=t("artifacts.explain");
  setText(".art-drop-text strong","artifacts.drop.strong"); setText("#artBrowse","artifacts.drop.browse"); setText(".art-drop-inner .faint-note","artifacts.drop.note");
  const artDropText=$(".art-drop-text"); if(artDropText){ const tn=[...artDropText.childNodes].find(n=>n.nodeType===Node.TEXT_NODE && n.nodeValue.trim()); if(tn) tn.nodeValue=" "+t("artifacts.drop.or")+" "; }
  setText("#artifactsList .findings-empty","artifacts.empty");
  const stringsHead=$("#view-strings .view-head p"); if(stringsHead) stringsHead.textContent=t("strings.explain");
  const importsHead=$("#view-imports .view-head p"); if(importsHead) importsHead.textContent=t("imports.explain");
  setText("#stringsList .findings-empty","strings.empty"); setText("#importsList .findings-empty","imports.empty");
  const srvH=$("#view-servers .view-head h2"); if(srvH) srvH.textContent=t("servers.title");
  const srvP=$("#view-servers .view-head p"); if(srvP) srvP.textContent=t("servers.explain");
  const howHead=$("#view-howto .view-head h2"); if(howHead) howHead.textContent=t("how.title");
  const howSub=$("#view-howto .view-head p"); if(howSub) howSub.textContent=t("how.subtitle");
  document.querySelectorAll("#view-howto .how-card").forEach((card,i)=>{
    const idx=i+1, h=card.querySelector("h3"), p=card.querySelector("p");
    if(h) h.textContent=t(`how.${idx}.title`);
    if(p) p.textContent=t(`how.${idx}.body`);
  });
  const howPanel=$("#view-howto .how-panel");
  if(howPanel){
    const h=howPanel.querySelector("h3"); if(h) h.textContent=t("how.cost.title");
    const ps=howPanel.querySelectorAll("p");
    if(ps[0]) ps[0].textContent=t("how.cost.body1");
    if(ps[1]) ps[1].textContent=t("how.cost.body2");
  }
  ensureInfoPanel("#view-strings","stringsExplainPanel","strings.workflow.title","strings.workflow.body");
  ensureInfoPanel("#view-imports","importsExplainPanel","imports.workflow.title","imports.workflow.body");
  const projectsP=$("#view-projects .view-head p"); if(projectsP) projectsP.textContent=t("projects.explain");
  setText("#projCreate","common.create"); setText("#targetBtn","projects.target.button");
  const targetLabels=document.querySelectorAll("#view-projects .target-box label");
  if(targetLabels[0]) targetLabels[0].textContent=t("projects.target.label");
  if(targetLabels[1]) targetLabels[1].textContent=t("projects.diff.label");
  setText("#targetDrop .art-drop-text strong","projects.target.drop.strong");
  setText("#targetBrowse","projects.target.drop.browse");
  setText("#targetDrop .art-drop-inner .faint-note","projects.target.drop.note");
  const targetDropText=$("#targetDrop .art-drop-text");
  if(targetDropText){ const tn=[...targetDropText.childNodes].find(n=>n.nodeType===Node.TEXT_NODE && n.nodeValue.trim()); if(tn) tn.nodeValue=" "+t("projects.target.drop.or")+" "; }
  const settingsTitle=$("#settingsModal .modal-top span"); if(settingsTitle) settingsTitle.textContent=t("settings.title");
  const findingTitle=$("#findingModal .modal-top span"); if(findingTitle) findingTitle.textContent=t("finding.detail");
  const setSections=document.querySelectorAll("#settingsModal .set-section h3");
  if(setSections[0]) setSections[0].textContent=t("settings.provider");
  if(setSections[1]) setSections[1].textContent=t("settings.local");
  if(setSections[3]) setSections[3].textContent=t("settings.safety");
  const settingsLabels=document.querySelectorAll("#settingsModal .field label");
  if(settingsLabels[0]) settingsLabels[0].textContent=t("settings.model");
  if(settingsLabels[1]) settingsLabels[1].textContent=t("settings.baseUrl");
  if(settingsLabels[2]) settingsLabels[2].textContent=t("settings.model");
  if(settingsLabels[3]) settingsLabels[3].textContent=t("settings.apiKey");
  const safeNote=$("#settingsModal .set-section .muted"); if(safeNote) safeNote.textContent=t("settings.safeNote");
  const persistLabel=$("#setPersist")?.closest("label"); if(persistLabel){ const tn=[...persistLabel.childNodes].find(n=>n.nodeType===Node.TEXT_NODE && n.nodeValue.trim()); if(tn) tn.nodeValue=" "+t("settings.persist"); }
  setText("#closeSettings2","common.cancel"); setText("#saveSettings","common.apply");
  const inp=$("#input"); if(inp) inp.placeholder=t("chat.placeholder");
  const dt=$("#dlTemplate"); if(dt) dt.textContent=t("report.template");
  try{ renderSafety(currentSafetyMode); }catch(e){}
  try{ if(Array.isArray(playbooksData) && playbooksData.length) renderPlaybooks(); }catch(e){}
  try{ renderFindings(); }catch(e){}
  try{ if(Array.isArray(stringsData) && stringsData.length) renderStrings($("#strSearch")?.value||""); }catch(e){}
  try{ if(Array.isArray(importsData) && importsData.length) renderImports($("#impSearch")?.value||""); }catch(e){}
}
(function initLang(){
})();

/* ---------- icons ----------
   Every glyph in generated markup resolves through here, so the set stays
   one library at one size instead of drifting back into emoji. */
function icon(name, cls){ return `<svg class="ic ${cls||"ic-sm"}" aria-hidden="true"><use href="#i-${name}"/></svg>`; }

/* ---------- theme ---------- */
function applyTheme(t){
  document.documentElement.setAttribute("data-theme", t);
  const btn = $("#themeToggle");
  if(btn){
    // The control shows the theme you would switch TO, which is the thing
    // the operator is deciding about.
    btn.innerHTML = icon(t==="dark" ? "sun" : "moon", "ic");
    btn.setAttribute("aria-label", t==="dark" ? "Switch to the light theme" : "Switch to the dark theme");
    btn.title = btn.getAttribute("aria-label");
  }
}
(function initTheme(){
  let t;
  try { t = localStorage.getItem("reforge-theme"); } catch(e){}
  if(!t) t = "dark"; // graphite is the primary working theme
  document.documentElement.setAttribute("data-theme", t);
})();
function toggleTheme(){
  const cur = document.documentElement.getAttribute("data-theme")==="dark" ? "light":"dark";
  applyTheme(cur);
  try { localStorage.setItem("reforge-theme", cur); } catch(e){}
}

const stream = $("#stream");
let sessionId = null, evSource = null, currentAssistant = null;
const findingsData = [];
const sevColor = {CRITICAL:"var(--sev-crit)",HIGH:"var(--sev-high)",MEDIUM:"var(--sev-med)",LOW:"var(--sev-low)",INFO:"var(--sev-info)"};
const esc = (s) => (s ?? "").toString().replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const scrollDown = () => stream.scrollTop = stream.scrollHeight;
const EMPTY_HTML = `<div class="empty" id="empty"><div class="eyebrow">reverse engineering · agent</div>`+
  `<h1>Ready to investigate.</h1><p>Open or create a project, set the target binary (static analysis starts on its own) and describe what to audit.</p></div>`;
const clearEmpty = () => { const e=$("#empty"); if(e) e.remove(); };

/* ---------- markdown (con tabelle) ---------- */
function md(src, opts){
  opts = opts || {};
  src = src || "";
  const blocks=[];
  src = src.replace(/```(\w+)?\n?([\s\S]*?)```/g,(m,l,c)=>{blocks.push(`<pre><code>${esc(c.replace(/\n$/,""))}</code></pre>`);return `\u0000${blocks.length-1}\u0000`;});
  src = esc(src);
  src = src.replace(/`([^`]+)`/g,(m,c)=>`<code>${c}</code>`);
  src = src.replace(/\*\*([^*]+)\*\*/g,"<strong>$1</strong>").replace(/(^|[^*])\*([^*\n]+)\*/g,"$1<em>$2</em>");
  src = src.replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g,'<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  const lines=src.split("\n"); let html="",list=null,para=[],i=0;
  const flushP=()=>{ if(para.length){html+=`<p>${para.join("<br>")}</p>`;para=[];} };
  const closeL=()=>{ if(list){html+=`</${list}>`;list=null;} };
  while(i<lines.length){
    const line=lines[i], t=line.trim();
    if(/^\u0000\d+\u0000$/.test(t)){flushP();closeL();html+=blocks[+t.replace(/\u0000/g,"")];i++;continue;}
    // tabella markdown
    if(/^\|.*\|$/.test(t) && i+1<lines.length && /^\|[\s:|-]+\|$/.test(lines[i+1].trim())){
      flushP();closeL();
      const head=t.slice(1,-1).split("|").map(x=>x.trim());
      let rows=[]; i+=2;
      while(i<lines.length && /^\|.*\|$/.test(lines[i].trim())){ rows.push(lines[i].trim().slice(1,-1).split("|").map(x=>x.trim())); i++; }
      if(!rows.length || rows.every(r=>r.every(c=>c===""))){ html+=`<p>${esc(t)}</p>`; continue; }
      html+="<table><thead><tr>"+head.map(h=>`<th>${h}</th>`).join("")+"</tr></thead><tbody>"+
        rows.map(r=>"<tr>"+r.map(c=>`<td>${c}</td>`).join("")+"</tr>").join("")+"</tbody></table>";
      continue;
    }
    let m;
    if(t.startsWith("&gt;")){flushP();closeL();const buf=[];while(i<lines.length&&lines[i].trim().startsWith("&gt;")){buf.push(lines[i].replace(/^\s*&gt;\s?/,""));i++;}html+=`<blockquote class="callout">${buf.join("<br>")}</blockquote>`;continue;}
    if(m=line.match(/^(#{1,4})\s+(.*)$/)){flushP();closeL();const n=m[1].length;html+=`<h${n}>${m[2]}</h${n}>`;i++;continue;}
    if(/^\s*[-*]\s+/.test(line)){flushP();if(list!=="ul"){closeL();html+="<ul>";list="ul";}html+=`<li>${line.replace(/^\s*[-*]\s+/,"")}</li>`;i++;continue;}
    if(/^\s*\d+\.\s+/.test(line)){flushP();if(list!=="ol"){closeL();html+="<ol>";list="ol";}html+=`<li>${line.replace(/^\s*\d+\.\s+/,"")}</li>`;i++;continue;}
    if(/^\s*[-_*=─—]{3,}\s*$/.test(line)){flushP();closeL();if(!opts.chat)html+="<hr>";i++;continue;}
    if(t===""){flushP();closeL();i++;continue;}
    closeL();para.push(line);i++;
  }
  flushP();closeL();
  return html;
}


/* ---------- Claude usage / cost estimate ---------- */
function fmtUsd(v){
  if(v==null || Number.isNaN(Number(v))) return "—";
  const n = Number(v);
  return n < 0.01 ? "$" + n.toFixed(6) : "$" + n.toFixed(4);
}
function usageSummaryFromRows(rows){
  const out={calls:0,input_tokens:0,output_tokens:0,cache_creation_input_tokens:0,cache_read_input_tokens:0,estimated_cost_usd:null};
  let cost=0, hasCost=false;
  for(const r of (rows||[])){
    out.calls++;
    const u=r.usage||{};
    out.input_tokens += Number(u.input_tokens||0);
    out.output_tokens += Number(u.output_tokens||0);
    out.cache_creation_input_tokens += Number(u.cache_creation_input_tokens||0);
    out.cache_read_input_tokens += Number(u.cache_read_input_tokens||0);
    if(r.estimated_cost_usd!=null){ hasCost=true; cost += Number(r.estimated_cost_usd||0); }
  }
  if(hasCost) out.estimated_cost_usd = cost;
  return out;
}
function renderUsage(summary, last){
  summary = summary || {};
  const badge = $("#costBadge"); if(!badge) return;
  const calls = Number(summary.calls||0);
  if(!calls){ badge.hidden=true; return; }
  const cost = summary.estimated_cost_usd;
  const nf = "en-US";
  const inTok = Number(summary.input_tokens||0).toLocaleString(nf);
  const outTok = Number(summary.output_tokens||0).toLocaleString(nf);
  badge.hidden=false;
  badge.innerHTML = cost!=null
    ? `Claude&nbsp;<b>${esc(fmtUsd(cost))}</b>`
    : `LLM&nbsp;<b>${calls}</b>&nbsp;${"calls"}`;
  badge.title = `${calls} calls · ${inTok} input tokens · ${outTok} output tokens`;
  if(last && last.estimated_cost_usd!=null){
    const u=last.usage||{};
    addNote(`Claude API: ${fmtUsd(last.estimated_cost_usd)} estimated (${Number(u.input_tokens||0).toLocaleString(nf)} input tokens, ${Number(u.output_tokens||0).toLocaleString(nf)} output tokens). Project total: ${fmtUsd(cost)}.`);
  }
}

/* ---------- tabs ---------- */
/* ---------- navigation (rail) ---------- */
document.querySelectorAll(".nav-item").forEach(b=>b.addEventListener("click",()=>switchTab(b.dataset.view)));
function switchTab(name){
  document.querySelectorAll(".nav-item").forEach(t=>t.classList.toggle("active",t.dataset.view===name));
  document.querySelectorAll(".view").forEach(p=>p.classList.toggle("active",p.id==="view-"+name));
  if(name==="assessment") loadAssessment();
  if(name==="posture") loadPosture();
  if(name==="reports") loadReports();
  if(name==="jobs") loadJobs();
  if(name==="servers") loadServers();
  if(name==="projects") loadProjects();
  if(name==="evidence") loadEvidence();
  if(name==="toollog") loadToollog();
  if(name==="strings") loadStrings();
  if(name==="graph") loadGraph();
  if(name==="playbooks") loadPlaybooks();
  if(name==="imports") loadImports();
  if(name==="artifacts") loadArtifacts();
  // Per-module playbook launcher: views whose id matches a playbook module key get a dropdown+Run.
  injectModulePlaybooks(name);
  // A view keeps its scroll offset, so switching sections used to drop you
  // halfway down a page you had never seen. Start every section at its top.
  const view = document.getElementById("view-"+name);
  if(view && view.classList.contains("scroll")) view.scrollTop = 0;
  if(window.innerWidth<=1024) closeRail();
}

/* Escape closes whatever is on top: the palette owns its own handler, so here
   we only dismiss the modal layer — previously the case file could only be
   closed by hitting its ✕, which is the one thing a keyboard user cannot find. */
document.addEventListener("keydown", e => {
  if(e.key !== "Escape") return;
  const open = [...document.querySelectorAll(".modal:not([hidden])")].pop();
  if(open){ e.preventDefault(); closeModal(open); }
});
function closeModal(el){
  el.hidden = true;
  if(!document.querySelector(".modal:not([hidden])")) document.body.style.removeProperty("overflow");
  const opener = el.__opener;
  if(opener && document.contains(opener)) opener.focus();
}
/* Clicking the backdrop is the other way out of a dialog people expect. */
document.addEventListener("mousedown", e => {
  if(e.target.classList?.contains("modal")) closeModal(e.target);
});
const PLAYBOOK_MODULE_VIEWS = new Set(["strings","imports","graph","artifacts","findings","evidence"]);
async function injectModulePlaybooks(module){
  if(!PLAYBOOK_MODULE_VIEWS.has(module)) return;
  const view=document.getElementById("view-"+module); if(!view) return;
  const head=view.querySelector(".view-head"); if(!head) return;
  let bar=head.querySelector(".module-pb-bar");
  if(!bar){ bar=document.createElement("div"); bar.className="module-pb-bar"; head.appendChild(bar); }
  bar.innerHTML=`<span class="faint-note">${esc("Playbook:")}</span><span class="faint-note">${esc("loading...")}</span>`;
  try{
    const r=await (await fetch(`/api/playbooks/for-module/${module}`)).json();
    const pbs=r.playbooks||[];
    if(!pbs.length){ bar.innerHTML=`<span class="faint-note">${esc("No playbook for this module.")}</span>`; return; }
    const opts=pbs.map(p=>`<option value="${esc(p.id)}">${esc(playbookLabel(p.id,"name",p.name))}${p.requires_dynamic?` · ${"dynamic"}`:""}${p.custom?` · ${"custom"}`:""}</option>`).join("");
    bar.innerHTML=`<span class="faint-note">${esc("Playbook:")}</span>`+
      `<select class="module-pb-select">${opts}</select>`+
      `<button class="btn-sm module-pb-run" type="button">${esc("Run")}</button>`;
    const sel=bar.querySelector(".module-pb-select");
    bar.querySelector(".module-pb-run").addEventListener("click",()=>{ if(sel&&sel.value) runPlaybook(sel.value); });
  }catch(e){ bar.innerHTML=`<span class="faint-note">${esc("Playbook error.")}</span>`; }
}
/* mobile rail toggle */
$("#navToggle").addEventListener("click",(e)=>{
  const open = $("#rail").classList.toggle("open");
  $("#railScrim").classList.toggle("open", open);
  e.currentTarget.setAttribute("aria-expanded", String(open));
});
$("#railScrim").addEventListener("click",()=>{ closeRail(); });
function closeRail(){
  $("#rail").classList.remove("open");
  $("#railScrim").classList.remove("open");
  $("#navToggle")?.setAttribute("aria-expanded","false");
}

/* ---------- boot ---------- */
async function boot(){
  const st = await (await fetch("/api/status")).json();
  renderModel(st.provider, st.model);
  renderSafety(st.safety_mode);
  renderLlmBanner(st);
  // progetti: l'app lavora sempre dentro un progetto locale
  let list = await fetchProjects();
  if(!list.length){
    const r = await (await fetch("/api/projects",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:"Assessment 1"})})).json();
    await openProject(r.id);
  } else {
    await openProject(list[0].id);
  }
}
let currentSafetyMode = "assisted";
const SAFETY = {safe:{t:"Safe",c:"ok"}, assisted:{t:"Assisted",c:"warn"}, autonomous:{t:"Autonomous",c:"danger"}};
function renderSafety(mode){
  const el=$("#safetyBadge"); if(!el) return;
  currentSafetyMode = mode || "assisted";
  const m=SAFETY[mode]||SAFETY.assisted;
  const label = mode==="safe" ? "Safe" : (mode==="autonomous" ? "Autonomous" : "Assisted");
  el.innerHTML = icon(mode==="autonomous" ? "shield-alert" : "posture")
    + `<span>${"Safety"}</span>&nbsp;<b>${esc(label)}</b>`;
  el.className="safety-badge "+m.c;
  el.title = mode==="autonomous"
    ? "Autonomous mode: risky actions (run/patch/write/network) run WITHOUT approval."
    : (mode==="safe" ? "Safe mode: every non-read action requires approval."
                     : "Assisted mode: risky actions require your approval.");
}
function renderModel(provider, model){
  $("#model").innerHTML = `<span class="pill">${esc(provider)}</span>${esc(model||"")}`;
}
/* Every way a turn can end goes through here: "done", "error", "stopped", a refused POST, and a
   stream that reconnects to a server with no turn running (a restart mid-turn left the bar on
   "Sending…" with the composer disabled, forever). */
function setIdle(){
  const sb=$("#status"); if(sb){ sb.classList.remove("busy"); sb.hidden=true; }
  const st=$("#statusText"); if(st) st.textContent="Ready";
  enable(true); const stop=$("#stopBtn"); if(stop) stop.hidden=true;
}
function setBusy(text){
  const sb=$("#status"); if(sb){ sb.hidden=false; sb.classList.add("busy"); }
  const st=$("#statusText"); if(st) st.textContent=text||"Working\u2026";
  enable(false); const stop=$("#stopBtn"); if(stop) stop.hidden=false;
}
async function resyncTurnState(id){
  try{
    const r=await fetch(`/api/projects/${id}`); if(!r.ok) return;
    const p=await r.json();
    if(p.busy) setBusy("Working\u2026"); else setIdle();
  }catch(e){ /* the next event will tell */ }
}
function connect(id){
  if(evSource) evSource.close();
  evSource = new EventSource(`/api/stream/${id}`);
  evSource.onmessage = (m)=>handle(JSON.parse(m.data));
  // Fires on the first connection and on every automatic reconnect (server restarted, network
  // blip). The server's view of "is a turn running" wins over whatever the bar was showing.
  evSource.onopen = ()=>resyncTurnState(id);
}

/* ---------- chat rendering ---------- */
function endAssistant(){ currentAssistant=null; }
let _deltaRenderPending=null;
function appendDelta(text){
  clearEmpty();
  if(!currentAssistant){
    currentAssistant=document.createElement("div");
    currentAssistant.className="msg assistant"; currentAssistant.dataset.raw="";
    currentAssistant.innerHTML=`<div class="body md"></div>`;
    stream.appendChild(currentAssistant);
  }
  const el=currentAssistant;
  el.dataset.raw+=text;
  rgCaptureAnswerDelta(text);
  // Render once per frame rather than once per token. Each render re-parses the whole message
  // and replaces its DOM, so a long streamed answer cost O(tokens × length) in parsing and
  // layout. The element is captured so the last frame still paints after the turn has ended.
  if(_deltaRenderPending===el) return;
  _deltaRenderPending=el;
  const paint=()=>{ _deltaRenderPending=null; el.querySelector(".body").innerHTML=md(el.dataset.raw,{chat:true}); scrollDown(); };
  if(document.hidden) setTimeout(paint,80); else requestAnimationFrame(paint);
}
/* When the assistant cites an evidence ID, make it reachable. The pattern is deterministic
   (E-0001), so this never guesses: an ID the project does not hold is left as plain text.
   Runs on already-escaped markdown output, and only touches text outside tags. */
function linkifyEvidence(html){
  if(!html) return html;
  const known=new Set((evidenceData||[]).map(e=>e && e.id).filter(Boolean));
  if(!known.size) return html;
  return html.replace(/(>|^)([^<]+)/g,(m,lead,text)=>lead+text.replace(/\bE-\d{4}\b/g, id=>
    known.has(id)
      ? `<button class="ev-ref" type="button" data-ev-open="${id}" title="Open evidence ${id}">${id}</button>`
      : id));
}

function addMsg(role,text){
  clearEmpty(); endAssistant();
  const d=document.createElement("div"); d.className="msg "+role;
  d.innerHTML = role==="assistant"
    ? `<div class="body md">${linkifyEvidence(md(text,{chat:true}))}</div>`
    : `<div class="body">${esc(text)}</div><button class="msg-resend" type="button" title="Send this message again" aria-label="Send this message again">${icon("refresh","ic ic-sm")}</button>`;
  if(role==="user") d.dataset.text=text;
  stream.appendChild(d); scrollDown();
}
// Resend is a plain re-send: same text, current mode, a new turn. Refused while a turn runs.
document.addEventListener("click",(e)=>{
  const b=e.target.closest(".msg-resend"); if(!b) return;
  const bubble=b.closest(".msg.user"); if(!bubble) return;
  if($("#send").disabled){ addNote("A turn is still running - wait for it or press Stop.","warn"); return; }
  sendMessage(bubble.dataset.text||"");
});

/* One delegated handler serves every evidence reference the app renders — chat, case file,
   or anywhere else that emits [data-ev-open]. */
document.addEventListener("click",(e)=>{
  const b=e.target.closest("[data-ev-open]");
  if(!b) return;
  const modal=$("#findingModal"); if(modal) modal.hidden=true;
  switchTab("evidence");
  const box=$("#evSearch");
  if(box){ box.value=b.dataset.evOpen; renderEvidence(b.dataset.evOpen); }
});
function addNote(text,cls){
  clearEmpty();
  const n=document.createElement("div"); n.className="note"+(cls?" "+cls:""); n.textContent=text;
  stream.appendChild(n); scrollDown(); return n;
}
const cards={};
function addKnowledge(e){
  clearEmpty(); endAssistant();
  const ps=e.passages||[];
  const card=document.createElement("div"); card.className="tool know";
  const refs=ps.length?ps.map(p=>`${p.source} p.${p.page}`).join(" · "):"no excerpt";
  card.innerHTML=`<div class="tool-head"><span class="tool-name">Knowledge${e.query?(" — «"+esc(e.query)+"»"):""}</span>`+
    `<span class="tool-badge">${ps.length} excerpts</span><span class="tool-status">sources</span></div>`+
    `<div class="tool-out know-body">`+
    (ps.length? ps.map(p=>`<div class="kpassage"><div class="ksrc">【${esc(p.source)} — p.${esc(String(p.page))}】</div><div class="ktext">${esc(p.text)}</div></div>`).join("")
              : `<div class="muted">No passage found in the knowledge base.</div>`)+
    `</div>`;
  card.querySelector(".tool-head").onclick=()=>card.classList.toggle("open");
  card.title=refs;
  stream.appendChild(card); scrollDown(); return card;
}
function addTool(e){
  clearEmpty(); endAssistant();
  const card=document.createElement("div"); card.className="tool"+(e.gated?" gated":"");
  card.innerHTML=`<div class="tool-head"><span class="tool-name">${esc(e.tool)}</span>`+
    `<span class="tool-badge">${e.gated?"gated":"read"}</span><span class="tool-status">…</span></div>`+
    `<div class="tool-args">${esc(JSON.stringify(e.args,null,2))}</div><div class="tool-out"></div>`;
  card.querySelector(".tool-head").onclick=()=>card.classList.toggle("open");
  stream.appendChild(card); scrollDown(); cards.last=card; return card;
}

/* ---------- strings explorer ---------- */
let stringsData = [];
const DANGEROUS_APIS = {
  exec: ["createprocessa","createprocessw","winexec","shellexecute","system","popen","execve"],
  load: ["loadlibrarya","loadlibraryw","loadlibraryexa","getprocaddress"],
  mem:  ["strcpy","strcat","gets","sprintf","memcpy","memmove","scanf"],
  file: ["createfilea","createfilew","writefile","readfile","deletefilea"],
  net:  ["wsaconnect","connect","send","recv","internetopen","winhttp"],
  crypt:["cryptencrypt","cryptdecrypt","cryptacquirecontext"],
};
const API_CLASS = {}; Object.entries(DANGEROUS_APIS).forEach(([cl,arr])=>arr.forEach(a=>API_CLASS[a]=cl));
// High-signal for vulnerability research: remote endpoints, IPC surfaces, command
// interpreters reachable as execution sinks, format specifiers and path traversal.
const SUSPICIOUS_PATTERNS = [/https?:\/\//i,/\\\\\.\\pipe\\/i,/cmd\.exe/i,/powershell/i,/\/bin\/(?:sh|bash)/i,/%[sn]\b/,/\.\.[\/\\]/,/\d+\.\d+\.\d+\.\d+/];
const STR_KIND_ORDER = ["secret","crypto","url","network","command","registry","dll","ipc","path","format","identity","diagnostic","config","api","generic"];
const STR_KIND_ALIASES = {
  endpoints:"url", endpoint:"url", urls:"url", host:"network", hosts:"network", ip:"network",
  urlendpoint:"url", hostip:"network", reg:"registry", registrykey:"registry", registrykeys:"registry",
  autorun:"registry", startup:"path", runkey:"registry",
  cmd:"command", shell:"command", token:"secret", secrets:"secret", credential:"secret", credentials:"secret",
  secretstokens:"secret", module:"dll", modules:"dll", library:"dll", libraries:"dll", dllmodule:"dll",
  pipe:"ipc", mutex:"ipc", service:"ipc", ipcservices:"ipc",
  user:"identity", email:"identity", emails:"identity", identityaccount:"identity",
  cert:"crypto", encoding:"crypto", cryptoencoding:"crypto",
  parser:"format", protocol:"format", formatprotocol:"format", symbol:"api", apisymbols:"api",
  log:"diagnostic", logs:"diagnostic", error:"diagnostic", diagnostics:"diagnostic",
  setting:"config", settings:"config", option:"config", options:"config", configoptions:"config",
  file:"path", filepath:"path", pathfile:"path", other:"generic"
};
let strAiOverrides = new Map();
let strAiOverrideMeta = new Map();

function isSuspiciousStr(s){ return SUSPICIOUS_PATTERNS.some(p=>p.test(s)); }
function normalizeStrKind(k){
  const raw=(k||"").toString().trim().toLowerCase().replace(/[^a-z0-9_ -]/g,"").replace(/\s+/g,"_");
  const flat=raw.replace(/[_-]/g,"");
  const val=STR_KIND_ALIASES[raw] || STR_KIND_ALIASES[flat] || raw;
  return STR_KIND_ORDER.includes(val) ? val : "";
}
// Bands group the categories into a few readable sections, ordered by relevance to finding
// vulnerabilities. Each band gets a header in the Strings tab so the view reads top-down:
// "what could be a finding" → "where untrusted input flows" → "supporting context" → "noise".
const STR_BANDS = [
  { key:"findings", kinds:["secret","crypto"],
    en:["Likely findings", "Strings that can BE a vulnerability: cleartext credentials/keys and weak crypto. Verify by xref."] },
  { key:"remote", kinds:["url","network"],
    en:["Remote surface", "Endpoints and addresses: relevant to SSRF, host validation, and traffic to correlate."] },
  { key:"sinks", kinds:["command","registry","dll","ipc","path"],
    en:["Sinks & filesystem", "Where data can land: shell/exec, paths, modules, registry, IPC. Trace an untrusted source here to confirm a bug."] },
  { key:"input", kinds:["format","identity"],
    en:["Input & context", "Formats/protocols the program parses (input surfaces) and accounts/identity."] },
  { key:"noise", kinds:["diagnostic","config","api","generic"],
    en:["Context / noise", "Diagnostic messages, config flags, and low-signal strings: useful for orientation, rarely vulnerabilities."] },
];
const STR_KIND_COPY = {
  en:{
    secret:["Secrets / credentials","Keys, tokens, passwords, or sensitive material in cleartext in the binary: potential hardcoded credential (CWE-798)."],
    crypto:["Crypto","References to crypto algorithms/primitives: check whether they are weak (MD5/SHA1/RC4/DES/ECB) or misused (CWE-327/328)."],
    url:["URL / endpoint","Remote endpoints, update servers, or webhooks: correlate with HTTP code and assess for SSRF."],
    network:["Host / IP","IP addresses/ports: connect with sockets and runtime traffic."],
    command:["Commands / exec","Interpreters or tools that may be launched: command-injection candidates (CWE-78) if an argument derives from input."],
    registry:["Registry","Windows keys/hives: configuration, execution control, or input-influenced values."],
    dll:["DLL / module","Named or loaded modules: DLL search-order / side-loading candidates (CWE-427)."],
    ipc:["IPC","Named pipes, mutexes, semaphores: local attack surface and communication channels."],
    path:["Path / file","Paths and filenames: path-traversal / arbitrary-write candidates (CWE-22) if the path derives from input."],
    format:["Format / protocol","Data formats and parser markers: input surfaces through which untrusted data can enter."],
    identity:["Identity / account","Users, emails, SIDs, or DOMAIN\\user: operating context and expected privileges."],
    diagnostic:["Diagnostics","Error/log messages: help reconstruct code branches and error conditions."],
    config:["Config / flags","Configuration flags and keys: operating modes and hidden features."],
    api:["API / symbols","References to symbols/APIs (assigned manually or by the AI)."],
    generic:["Other","Low-signal strings: shown when you search or when no stronger signals exist."]
  }
};
function strKindStatic(s){
  const x=(s||"").toString();
  // Mirror of reforge/string_signal.py classify(). ORDER MATTERS — keep the two in lockstep.
  // -- secrets & crypto (likely findings) --
  if(/-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----/.test(x)) return "secret";
  if(/\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?key|refresh[_-]?token|auth[_-]?token|bearer|password|passwd|\bpwd\b|passphrase|credentials?|session[_-]?id)\b/i.test(x)) return "secret";
  if(/\b(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{20,}|xox[baprs]-[0-9A-Za-z-]{6,}|ghp_[0-9A-Za-z]{10,}|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.)/.test(x)) return "secret";
  if(/\b(md5|md4|sha-?1|sha-?256|sha-?512|aes(?:-\d{3})?|3des|\bdes\b|rc4|rc2|blowfish|chacha20|rsa|ecdsa|ed25519|hmac|pbkdf2|bcrypt|scrypt|argon2|x509|ecb\b|cbc\b|gcm\b)\b/i.test(x)) return "crypto";
  // -- remote surface --
  if(/(?:https?|ftp|wss?):\/\//i.test(x)) return "url";
  if(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b/.test(x) || /\[[a-f0-9:]{6,}\]/i.test(x)) return "network";
  // -- execution / filesystem / module sinks --
  if(/\bcmd\.exe\b|\bpowershell(?:\.exe)?\b|\bpwsh\b|\bwscript\b|\bcscript\b|\/bin\/(?:sh|bash|zsh)\b|\bsystem\(|\bpopen\b|\bexec[lv]p?\(|\bShellExecute\w*|\bCreateProcess\w*|\bWinExec\b/i.test(x)) return "command";
  if(/\bhkey_[a-z_]+|\bhk(?:lm|cu|cr|u)\\|\\registry\\|\\software\\|\\system\\currentcontrolset\\/i.test(x)) return "registry";
  if(/\.(?:dll|sys|ocx|drv|cpl)\b/i.test(x)) return "dll";
  if(/\\\\\.\\pipe\\|\\BaseNamedObjects\\|(?:^|[^\\A-Za-z0-9])(?:Global|Local|Session)\\[A-Za-z0-9_.{}-]{2,}|\bnamed pipe\b|\bmutex\b|\bsemaphore\b/i.test(x)) return "ipc";
  if(/[a-z]:\\|%(?:appdata|temp|programdata|userprofile|systemroot|windir)%|\\\\[^\\/:*?"<>|\r\n]+\\|\/(?:usr|etc|var|tmp|home|opt|bin|sbin|lib|proc)\/|\.(?:exe|dat|cfg|conf|ini|log|tmp|pdb|bak|db|sqlite)\b/i.test(x)) return "path";
  // -- input formats / accounts / diagnostics --
  if(/\b(json|xml|yaml|ini|csv|zip|rar|7z|gzip|tar|content-type|user-agent|multipart|application\/[a-z0-9.+-]+|sqlite|protobuf|msgpack|asn\.?1|base64)\b/i.test(x)) return "format";
  if(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i.test(x) || /\bS-\d-\d+(?:-\d+){2,}\b/.test(x) || /\b[A-Z][A-Z0-9-]{1,14}\\[A-Za-z][A-Za-z0-9._$-]{1,30}\b/.test(x)) return "identity";
  if(/\b(error|failed|failure|exception|denied|invalid|warning|fatal|assert(?:ion)?|cannot|unable|unexpected|not found|overflow|out of (?:range|bounds|memory))\b/i.test(x)) return "diagnostic";
  // -- config: only flag-like tokens or a short whitelist (tight) --
  if(/^[-/]{1,2}[a-z][a-z0-9_-]{1,32}$/i.test(x)) return "config";
  if(/^.{0,48}\b(enable|disable|timeout|retry|verbose|maxsize|threshold|loglevel|configuration)\b.{0,16}$/i.test(x)) return "config";
  // domain-like (no scheme) -> url, unless it is a module/object filename
  if(/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,}\b(?::\d{2,5})?(?:\/[^\s]*)?/i.test(x) && !/\.(dll|exe|pdb|obj|lib|sys|dat|cfg|ini|log)$/i.test(x)) return "url";
  return "generic";
}
function strKind(s){
  const x=(s||"").toString();
  return strAiOverrides.get(x) || strKindStatic(x);
}
function setCount(id,n){ const e=$(id); if(!e) return;
  const v=(n===0||n==="0"||n===""||n==null)?"":String(n);
  e.textContent=v; e.hidden=!v; }
function renderStrings(filter){
  const box=$("#stringsList"); if(!box) return;
  const q=(filter||"").toLowerCase();
  const all=stringsData.map(s=>({s,kind:strKind(s)}));
  let rows=all.filter(o=>!q||o.s.toLowerCase().includes(q)||o.kind.includes(q));
  const hasQuery=!!q;
  if(!hasQuery){
    const signal=rows.filter(o=>o.kind!=="generic" || isSuspiciousStr(o.s));
    if(signal.length) rows=signal;
  }
  const order=STR_KIND_ORDER;
  rows.sort((a,b)=>order.indexOf(a.kind)-order.indexOf(b.kind) || a.s.length-b.s.length || a.s.localeCompare(b.s));
  if(!rows.length){
    box.innerHTML=stringsData.length
      ? `<div class="empty-state"><div class="empty-state-ic">${icon("search","ic ic-lg")}</div>`+
        `<h3>No string matches this filter</h3>`+
        `<p>${stringsData.length} string${stringsData.length===1?"":"s"} were extracted from this binary.</p></div>`
      : `<div class="empty-state"><div class="empty-state-ic">${icon("strings","ic ic-lg")}</div>`+
        `<h3>No strings extracted</h3>`+
        `<p>Load a target to extract readable text from the binary. Strings are clues: they become `+
        `evidence only once connected to a call site, an import or a runtime observation.</p>`+
        `<div class="empty-state-actions"><button class="solid-btn" type="button" data-empty-action="projects">Load a target</button></div></div>`;
    return;
  }
  const visibleSet=new Set(rows.map(o=>o.s));
  const aiVisible=[...strAiOverrides.keys()].filter(s=>visibleSet.has(s)).length;
  setCount("#strTotal",`${rows.length} / ${stringsData.length}${hasQuery?"":" high-signal"}${aiVisible?` · ${aiVisible} AI`:``}`);
  const by={};
  rows.slice(0,500).forEach(o=>{ (by[o.kind]||(by[o.kind]=[])).push(o); });
  const renderKindSection=(k)=>{
    const copy=STR_KIND_COPY.en?.[k] || STR_KIND_COPY.en[k] || [k,""];
    return `<section class="str-section"><div class="str-section-h"><strong>${esc(copy[0])}</strong><span>${by[k].length}</span></div>`+
      `<p class="str-why">${esc(copy[1])}</p>`+
      by[k].slice(0,80).map(o=>{
        const meta=strAiOverrideMeta.get(o.s);
        const ai=!!meta;
        const fromCopy=meta ? (STR_KIND_COPY.en?.[meta.from] || STR_KIND_COPY.en[meta.from] || [meta.from]) : null;
        const aiBadge=ai ? `<span class="str-ai-badge" title="${esc("Reclassified by local AI")}">AI ${esc(fromCopy?.[0]||meta.from)} -> ${esc(copy[0])}</span>` : "";
        return `<div class="str-row${isSuspiciousStr(o.s)?" susp":""}${ai?" ai-reassigned":""}"><span class="str-kind">${esc(copy[0])}</span>${aiBadge}<code>${esc(o.s)}</code></div>`;
      }).join("")+
      (by[k].length>80?`<div class="faint-note">${esc(`... ${by[k].length-80} more in this group`)}</div>`:"")+
    `</section>`;
  };
  box.innerHTML=STR_BANDS.map(band=>{
    const kinds=band.kinds.filter(k=>by[k]?.length);
    if(!kinds.length) return "";
    const bc=(band.en) || band.en;
    const n=kinds.reduce((a,k)=>a+by[k].length,0);
    return `<div class="str-band"><div class="str-band-h"><span class="str-band-title">${esc(bc[0])}</span><span class="str-band-count">${n}</span></div>`+
      `<p class="str-band-why">${esc(bc[1])}</p>`+
      kinds.map(renderKindSection).join("")+
    `</div>`;
  }).join("")+(rows.length>500?`<div class="faint-note">${esc(`... and ${rows.length-500} more filtered results`)}</div>`:"");
}
async function loadStrings(){
  if(!sessionId) return;
  if(stringsData.length){ renderStrings($("#strSearch")?$("#strSearch").value:""); return; }
  try{ const r=await (await fetch(`/api/projects/${sessionId}/strings`)).json();
    stringsData=r.strings||[]; setCount("#scount",stringsData.length); renderStrings(""); }catch(e){}
}
const _ss=$("#strSearch"); if(_ss) _ss.addEventListener("input",e=>renderStrings(e.target.value));
const _strAi=$("#strLocalAi"); if(_strAi) _strAi.addEventListener("click",async()=>{
  if(!sessionId) return;
  const q=($("#strSearch")?.value||"").trim();
  const out=$("#strAiOut");
  if(out){ out.hidden=false; out.innerHTML='<span class="faint-note">'+esc("Local AI: reclassifying strings...")+'</span>'; }
  try{
    // Authoritative path: the backend forces strict JSON from the local LLM, validates every move
    // against the real strings + allowed categories, and PERSISTS it. The move actually happens.
    const r=await fetch(`/api/projects/${sessionId}/strings/reclassify`,
      {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:q,limit:160})});
    const j=await r.json();
    if(!r.ok){ if(out) out.innerHTML=`<div class="findings-empty">${esc(j.detail||"Reclassification failed.")}</div>`; return; }
    // Mirror persisted overrides into the live map and re-render so the strings visibly move.
    hydrateStringOverrides(j.overrides||{});
    renderStrings($("#strSearch")?$("#strSearch").value:"");
    const applied=j.applied||[];
    const note = applied.length
      ? stringAiAppliedHtml({applied, skipped:j.skipped||[]})
      : `<div class="analysis-note compact"><strong>0</strong><span>${esc(`No strings to fix out of ${j.submitted||0} analysed.`)}</span></div>`;
    if(out) out.innerHTML=`<div class="local-ai-head">Local AI · ${esc(j.note||"reclassification")}</div>${note}${stringAiScopeHtml(j.submitted||0,q)}`;
  }catch(e){ if(out) out.innerHTML=`<div class="findings-empty">${esc("Local AI error: ")+(e.message||e)}</div>`; }
});

function cleanAiStringRef(value){
  return (value||"").toString().trim()
    .replace(/^[-*]\s*/,"")
    .replace(/^REASSIGN\s*:\s*/i,"")
    .replace(/^\s*(stringa|string|string value|valore)\s*[:=]\s*/i,"")
    .replace(/^["'`]+|["'`]+$/g,"")
    .replace(/^\*\*|\*\*$/g,"")
    .trim();
}
function findStringForAiReassign(value){
  const v=cleanAiStringRef(value);
  if(!v) return null;
  const exact=stringsData.find(s=>s===v);
  if(exact) return exact;
  const lower=stringsData.filter(s=>s.toLowerCase()===v.toLowerCase());
  if(lower.length===1) return lower[0];
  const compact=(x)=>x.replace(/\s+/g," ").trim().toLowerCase();
  const vc=compact(v);
  const normalized=stringsData.filter(s=>compact(s)===vc);
  if(normalized.length===1) return normalized[0];
  if(v.length>=8){
    const partial=stringsData.filter(s=>s.includes(v) || v.includes(s));
    if(partial.length===1) return partial[0];
    const partialLower=stringsData.filter(s=>s.toLowerCase().includes(v.toLowerCase()) || v.toLowerCase().includes(s.toLowerCase()));
    if(partialLower.length===1) return partialLower[0];
  }
  return null;
}
function stringAiAppliedHtml(result){
  const rows=result.applied.slice(0,8).map(x=>{
    const from=STR_KIND_COPY.en?.[x.from]?.[0] || STR_KIND_COPY.en[x.from]?.[0] || x.from;
    const to=STR_KIND_COPY.en?.[x.to]?.[0] || STR_KIND_COPY.en[x.to]?.[0] || x.to;
    return `<li><code>${esc(x.value)}</code><span>${esc(from)} -> ${esc(to)}</span></li>`;
  }).join("");
  const skipped=result.skipped.length ? `<div class="faint-note">${esc(`${result.skipped.length} reassignments ignored because they did not match one unique string.`)}</div>` : "";
  return `<div class="str-ai-applied"><div class="analysis-note compact"><strong>${result.applied.length}</strong><span>${esc("reclassifications applied: the Strings list has been updated.")}</span></div><ul>${rows}</ul>${skipped}</div>`;
}
function stringAiScopeHtml(n, query){
  const body = query
    ? `Analysis based on the ${n} strings matching filter "${query}". Backticked values should match strings listed below.`
    : `Analysis based on the ${n} high-signal strings shown in this tab. Backticked values should match strings listed below.`;
  return `<div class="analysis-note compact str-ai-scope"><strong>Strings AI</strong><span>${esc(body)}</span></div>`;
}
// Rebuild the override map from the server-persisted {string: category} dict on project load,
// so a reassignment made in a previous session is restored (the string stays MOVED).
function hydrateStringOverrides(overrides){
  strAiOverrides = new Map(); strAiOverrideMeta = new Map();
  Object.entries(overrides||{}).forEach(([s,cat])=>{
    const k=normalizeStrKind(cat); if(!k) return;
    const staticKind=strKindStatic(s);
    if(k===staticKind) return;           // not actually a move
    strAiOverrides.set(s,k);
    strAiOverrideMeta.set(s,{from:staticKind,to:k,line:"(persisted)"});
  });
}

/* ---------- evidence graph ---------- */
function gtable(headers, rows){
  if(!rows.length) return '<div class="findings-empty">No items.</div>';
  return `<table class="gt"><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join("")}</tr></thead>`+
    `<tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}
function graphNodeAttrs(n){ return n?.attrs || n?.properties || {}; }
function graphEdgeSrc(e){ return e?.src ?? e?.source ?? e?.from; }
function graphEdgeDst(e){ return e?.dst ?? e?.target ?? e?.to; }
function renderGraphDerivedSections(g){
  const nodes=g?.nodes||[], edges=g?.edges||[];
  const byType=(t)=>nodes.filter(n=>n.type===t);
  let panel=$("#graphIntelPanel");
  if(!panel){
    // The panel used to anchor to .graph-viz-wrap, a container that no longer
    // exists in the markup, so it was never mounted. It belongs under the map.
    const wrap=document.querySelector("#tmRoot");
    if(wrap){
      const section=document.createElement("section");
      section.className="graph-intel-section";
      section.innerHTML=`<div class="graph-intel-head"><div><h3 class="sub-h">${esc("Investigation summary")}</h3>`+
        `<p class="muted">${esc("Operational context derived from the graph: what exists, what is missing, and where it is worth clicking.")}</p>`+
        `</div></div><div id="graphIntelPanel" class="graph-intel-grid"></div>`;
      wrap.insertAdjacentElement("afterend", section);
      panel=$("#graphIntelPanel");
    }
  }
  const score=(n)=>{ try{return tmScore(n);}catch(e){return 0;} };
  const topOps=byType("procmon_op").sort((a,b)=>(graphNodeAttrs(b).count||0)-(graphNodeAttrs(a).count||0)).slice(0,5);
  const topObjects=["file_path","registry_key","network_endpoint"].flatMap(t=>byType(t)).sort((a,b)=>(graphNodeAttrs(b).count||0)-(graphNodeAttrs(a).count||0)).slice(0,5);
  const artifacts=byType("artifact");
  const highNodes=nodes.filter(n=>n.type!=="node_cluster").sort((a,b)=>score(b)-score(a)).slice(0,6);
  const findings=byType("finding");
  const needsValidation=nodes.filter(n=>{
    const st=tmStatus(n)||"";
    return st.includes("validation") || st==="hypothesis" || st==="suspicious";
  }).slice(0,6);
  if(panel){
    const card=(title,kicker,body,empty)=>`<article class="graph-intel-card"><div class="gic-k">${esc(kicker)}</div><h4>${esc(title)}</h4>${body||`<p class="gic-empty">${esc(empty)}</p>`}</article>`;
    const list=(items,fmt)=>items.length?`<ul class="gic-list">${items.map(fmt).join("")}</ul>`:"";
    panel.innerHTML=[
      card("Runtime activity","Procmon / dynamic",
        list(topOps,(n)=>`<li><button class="gic-node" data-node="${esc(n.id)}">${esc(n.label||n.id)}</button><span>${esc(String(graphNodeAttrs(n).count||""))}</span></li>`),
        "No runtime events loaded. Upload a Procmon XML and press Parse."),
      card("Uploaded artifacts","Evidence intake",
        list(artifacts,(n)=>`<li><button class="gic-node" data-node="${esc(n.id)}">${esc(n.label||n.id)}</button><span>${esc(graphNodeAttrs(n).atype||graphNodeAttrs(n).type||"artifact")}</span></li>`),
        "No artifact is linked to the graph."),
      card("Objects touched","Files / Registry / Network",
        list(topObjects,(n)=>`<li><button class="gic-node" data-node="${esc(n.id)}">${esc(n.label||n.id)}</button><span>${esc(tmTypeLabel(n.type))}</span></li>`),
        "No file, registry key or endpoint observed."),
      card("High-priority nodes","Investigation queue",
        list(highNodes,(n)=>`<li><button class="gic-node" data-node="${esc(n.id)}">${esc(tmSafeLabel(n,42))}</button><span>score ${score(n)}</span></li>`),
        "Run static analysis or import artifacts to fill the queue."),
      card("Validation","What is missing",
        list(needsValidation,(n)=>`<li><button class="gic-node" data-node="${esc(n.id)}">${esc(tmSafeLabel(n,42))}</button><span>${esc(tmStatus(n)||tmTypeLabel(n.type))}</span></li>`),
        findings.length?"No suspicious or unvalidated node in the current view.":"No finding has been created yet.")
    ].join("");
    panel.querySelectorAll(".gic-node").forEach(b=>b.addEventListener("click",()=>tmShowNode(b.dataset.node)));
  }
  const runtime=$("#graphRuntime"), arts=$("#graphArtifacts"), high=$("#graphHighSignal");
  if(runtime){
    const rows=[
      ...byType("process").slice(0,8).map(n=>[esc(n.label||n.id), "process", esc(String(graphNodeAttrs(n).events||"—"))]),
      ...byType("procmon_op").sort((a,b)=>(graphNodeAttrs(b).count||0)-(graphNodeAttrs(a).count||0)).slice(0,14)
        .map(n=>[esc(n.label||n.id), "operation cluster", esc(String(graphNodeAttrs(n).count||"—"))]),
      ...["file_path","registry_key","network_endpoint"].flatMap(t=>byType(t).slice(0,8).map(n=>[esc(n.label||n.id), t, esc(String(graphNodeAttrs(n).count||"—"))]))
    ];
    runtime.innerHTML=rows.length?gtable(["Node","Type","Events"],rows):'<div class="findings-empty">No Procmon events loaded. Upload a Procmon XML and use Parse.</div>';
  }
  if(arts){
    const rows=byType("artifact").map(n=>{
      const a=graphNodeAttrs(n);
      const deg=edges.filter(e=>graphEdgeSrc(e)===n.id||graphEdgeDst(e)===n.id).length;
      return [esc(n.label||n.id), esc(a.atype||a.type||"artifact"), esc(String(a.size||"—")), `<span class="g-conf">${deg}</span>`];
    });
    arts.innerHTML=rows.length?gtable(["Artifact","Type","Size","Relations"],rows):'<div class="findings-empty">No artifacts uploaded.</div>';
  }
  if(high){
    const score=(n)=>{ try{return tmScore(n);}catch(e){return 0;} };
    const rows=nodes.filter(n=>n.type!=="node_cluster").sort((a,b)=>score(b)-score(a)).slice(0,18)
      .map(n=>[esc(n.label||n.id), esc(NODE_TYPE_LABEL[n.type]||n.type), `<span class="g-conf">${score(n)}</span>`, esc((graphNodeAttrs(n).source||graphNodeAttrs(n).status||"").toString())]);
    high.innerHTML=rows.length?gtable(["Node","Type","Score","Source/Status"],rows):'<div class="findings-empty">Run static analysis or import artifacts first.</div>';
  }
}
async function loadGraph(){
  if(!sessionId) return;
  const stats=$("#graphStats"), sinks=$("#graphSinks"), weak=$("#graphWeak"), chains=$("#graphChains");
  if(stats) stats.innerHTML=`<span class="faint-note">${esc(t("common.loading"))}</span>`;
  let g=null;
  try{
    g=await (await fetch(`/api/projects/${sessionId}/graph`)).json();
    if(!g || !(g.nodes||[]).length){
      g=await loadProjectFallbackGraph();
    }
    const st=g.stats||{};
    // Labels come from the shared graph vocabulary so the chips, the insight
    // bar and the dossier always name a node type the same way.
    const chips=[["binary",tmTypeLabel("binary")],["artifact",tmTypeLabel("artifact")],
      ["process",tmTypeLabel("process")],["procmon_op",tmTypeLabel("procmon_op")],
      ["function",tmTypeLabel("function")],["import",tmTypeLabel("import")],
      ["sink",tmTypeLabel("sink")],["evidence",tmTypeLabel("evidence")],
      ["finding",tmTypeLabel("finding")],["edges","Relationships"]];
    if(stats) stats.innerHTML=chips.map(([k,l])=>`<span class="g-chip"><b>${st[k]||0}</b> ${esc(l)}</span>`).join("");
    renderGraphViz(g);
    renderGraphDerivedSections(g);
  }catch(e){
    g=await loadProjectFallbackGraph();
    if(stats) stats.innerHTML=`<span class="faint-note">${esc("Primary graph unavailable — falling back to the project snapshot.")}</span>`;
    renderGraphViz(g);
    renderGraphDerivedSections(g);
  }
  // Le tabelle sotto sono indipendenti: se un endpoint fallisce non deve svuotare tutto il pannello.
  if(sinks){
    try{
      const us=await (await fetch(`/api/projects/${sessionId}/graph/unvalidated-sinks`)).json();
      sinks.innerHTML=gtable(["Sink","Classe","Stato"],
        (us.sinks||[]).map(n=>[esc(n.label), esc((n.attrs||{}).klass||"—"), '<span class="g-bad">non validato</span>']));
    }catch(e){ sinks.innerHTML='<div class="findings-empty">Error loading the sinks.</div>'; }
  }
  if(weak){
    try{
      const wf=await (await fetch(`/api/projects/${sessionId}/graph/weak-findings`)).json();
      weak.innerHTML=gtable(["Finding","Severity","Evidence"],
        (wf.findings||[]).map(f=>[esc((f.attrs||{}).title||f.id), esc((f.attrs||{}).severity||"—"),
          `<span class="g-bad">${f.evidence_count||0}</span>`]));
    }catch(e){ weak.innerHTML='<div class="findings-empty">Error loading weak findings.</div>'; }
  }
  if(chains){
    try{
      const s2s=await (await fetch(`/api/projects/${sessionId}/source-to-sink`)).json();
      chains.innerHTML=gtable(["Source","Sink","Argument","Call site","Confidence"],
        (s2s.chains||[]).slice(0,100).map(c=>[esc(c.source),esc(c.sink),esc(c.argument||"—"),
          esc(c.callsite||"—"),`<span class="g-conf">${Math.round(Number(c.confidence||0)*100)}%</span>`]));
    }catch(e){ chains.innerHTML='<div class="findings-empty">Error loading the source→sink chains.</div>'; }
  }
  try{
    const sel=$("#diffOther"); if(sel){
      const list=await fetchProjects();
      const cur=sel.value;
      sel.innerHTML='<option value="">— choose the previous project (A) —</option>'+
        list.filter(p=>p.id!==sessionId).map(p=>`<option value="${esc(p.id)}">${esc(p.name||p.id.slice(0,8))}</option>`).join("");
      sel.value=cur;
    }
  }catch(e){}
  tmEnhanceGraphSubmodules();
}

{const b=$("#graphRefresh"); if(b) b.addEventListener("click",loadGraph);}

/* ---------- interactive force-directed graph (no deps) ---------- */
const GV_COLORS={
  /* Field Instrument ramp: hue carries the ROLE, lightness separates types
     inside a role, so a node is readable by family at a glance. */
  /* critical path — warm */
  sink:"#f0902f",risk:"#f0556b",finding:"#f0556b",
  /* evidence chain — teal means verified */
  source:"#5fa8d6",evidence:"#2fa08c",component:"#46bda7",
  /* binary anatomy — neutral, the subject itself is the brightest */
  binary:"#e6e4df",artifact:"#c9ccd0",function:"#b4babe",import:"#99a0a5",
  /* runtime — amber means something executed */
  process:"#d9bb4a",procmon_op:"#c0a63f",dynamic_event:"#e0a030",
  /* filesystem/net — cool */
  file_path:"#89b8d0",registry_key:"#a8c4d4",network_endpoint:"#3d8ab8",
  /* misc */
  string:"#8a9298",report:"#46bda7"};
const GV_R={
  binary:16,finding:13,sink:12,source:11,artifact:13,
  component:10,evidence:10,function:9,process:11,
  procmon_op:8,file_path:7,registry_key:7,network_endpoint:8,
  risk:11,dynamic_event:9,import:7,string:5,report:8};
/* Graph vocabulary: human-readable labels for node and relation types. These surface on node
   labels, the insight bar, the dossier and every relationship row.

   They used to be ["italian","english"] pairs read through a picker that always took index 1, so
   half of every entry was unreachable data that still had to be kept in step - and an entry added
   as a bare string would have rendered as the empty label the picker returns for a missing row.
   One language, one string. */
const NODE_TYPE_LABELS={
  binary:"Binary", function:"Function", import:"Import/API",
  sink:"Dangerous sink", source:"Input source",
  finding:"Finding", evidence:"Evidence", component:"Component",
  string:"String", report:"Report",
  dynamic_event:"Dynamic event", risk:"Risk",
  artifact:"Artifact", process:"Process",
  procmon_op:"Procmon operation", file_path:"File path",
  registry_key:"Registry key", network_endpoint:"Network endpoint",
  toolcall:"Tool call", node_cluster:"Cluster"};
const EDGE_TYPE_LABELS={
  FUNCTION_CALLS_FUNCTION:"calls", FUNCTION_REFERENCES_STRING:"references string",
  FUNCTION_CALLS_IMPORT:"calls import", SOURCE_FLOWS_TO_SINK:"flows to sink",
  TOOLCALL_GENERATED_EVIDENCE:"produced", EVIDENCE_SUPPORTS_FINDING:"supports",
  FINDING_VALIDATED_BY_EVIDENCE:"validated by", BINARY_CONTAINS_COMPONENT:"contains component",
  FINDING_AFFECTS_FUNCTION:"affects function", DYNAMIC_EVENT_CONFIRMS_FINDING:"confirms",
  BINARY_HAS_FUNCTION:"has function", BINARY_HAS_IMPORT:"imports",
  BINARY_HAS_STRING:"has string", FINDING_HAS_RISK:"has risk",
  ARTIFACT_PARSED_BY_TOOL:"parsed by", ARTIFACT_OBSERVED_PROCESS:"observed process",
  PROCESS_PERFORMED_OP:"performed", PROCESS_ACCESSED_FILE:"accessed file",
  PROCESS_ACCESSED_REGISTRY:"accessed registry",
  PROCESS_CONNECTED_ENDPOINT:"connected to", ARTIFACT_PRODUCED_EVIDENCE:"produced evidence"};
const NODE_TYPE_LABEL = new Proxy({}, { get:(_,k)=>NODE_TYPE_LABELS[k] || "" });
const EDGE_TYPE_LABEL = new Proxy({}, { get:(_,k)=>EDGE_TYPE_LABELS[k] || "" });
let _gvState=null;
function gvActiveTypes(){
  const set=new Set();
  document.querySelectorAll(".gv-filter").forEach(c=>{ if(c.checked) set.add(c.dataset.t); });
  if(!set.size){
    ["binary","artifact","component","import","source","function","sink","process","procmon_op","file_path","registry_key","network_endpoint","dynamic_event","evidence","finding","risk","toolcall"].forEach(t=>set.add(t));
  }
  return set;
}
function toastNd(msg){ const b=$("#graphNodeDetails"); if(!b) return; let t=b.querySelector(".nd-toast"); if(!t){ t=document.createElement("div"); t.className="nd-toast"; b.appendChild(t);} t.textContent=msg; t.style.opacity="1"; setTimeout(()=>{ if(t) t.style.opacity="0"; },1500); }
function sendPromptSafe(text){
  // Use the app's real send pipeline; switch to chat so the user sees the response.
  try{ switchTab("chat"); }catch(e){}
  if(typeof sendMessage==="function" && sessionId){ sendMessage(text); return; }
  const inp=$("#input"); const btn=$("#send");
  if(inp){ inp.value=text; if(btn) btn.click(); }
}
async function localAssist(kind, question, context, outSel){
  if(!sessionId) return null;
  const out = outSel ? $(outSel) : null;
  if(out){ out.hidden=false; out.innerHTML='<span class="faint-note">Local AI running...</span>'; }
  try{
    const r = await fetch("/api/local-assist",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({session_id:sessionId,kind,question,context})
    });
    const j = await r.json();
    if(!r.ok) throw new Error(j.detail||"local LLM unavailable");
    if(out) out.innerHTML=`<div class="local-ai-head">Local AI · ${esc(j.model||"local")}</div><div class="md">${md(j.text||"",{})}</div>`;
    _lastLocalAssist = j;
    return j.text || "";
  }catch(e){
    _lastLocalAssist = null;
    if(out) out.innerHTML=`<div class="findings-empty">Local AI unavailable: ${esc(e.message||e)}</div>`;
    return null;
  }
}
let _lastLocalAssist = null;

function downloadJson(obj, name){
  const blob=new Blob([JSON.stringify(obj,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob); const a=document.createElement("a");
  a.href=url; a.download=name; document.body.appendChild(a); a.click();
  a.remove(); URL.revokeObjectURL(url);
}
async function exportGraphArtifact(kind){
  if(!sessionId) return;
  let url=`/api/projects/${sessionId}/export/${kind}`;
  if(kind==="cyclonedx" && confirm("Enrich the SBOM with known CVEs (requires a connection to NVD)? Cancel for an offline export.")){
    url+="?online=true";
  }
  try{
    const r=await fetch(url);
    if(!r.ok){ alert("Export failed."); return; }
    downloadJson(await r.json(), kind==="sarif"?`reforge_findings.sarif.json`:`reforge_sbom.cdx.json`);
  }catch(e){ alert("Network error during the export."); }
}
{const a=$("#exportSarif"); if(a) a.addEventListener("click",()=>exportGraphArtifact("sarif"));
 const b=$("#exportCdx"); if(b) b.addEventListener("click",()=>exportGraphArtifact("cyclonedx"));}

function downloadText(text, name, mime){
  const blob=new Blob([text],{type:mime||"text/plain"});
  const url=URL.createObjectURL(blob); const a=document.createElement("a");
  a.href=url; a.download=name; document.body.appendChild(a); a.click();
  a.remove(); URL.revokeObjectURL(url);
}
function neo4jModal(){
  let m=$("#neo4jModal");
  if(!m){
    m=document.createElement("div"); m.id="neo4jModal"; m.className="n4j-modal"; m.hidden=true;
    m.innerHTML=`<div class="n4j-box"><div class="n4j-head"><strong>${esc("Neo4j — investigation graph")}</strong><button class="n4j-close" type="button" aria-label="${esc(t("common.close"))}">${icon("close","ic")}</button></div><div class="n4j-body" id="n4jBody"></div></div>`;
    document.body.appendChild(m);
    m.addEventListener("click",e=>{ if(e.target===m||e.target.classList.contains("n4j-close")) m.hidden=true; });
  }
  return m;
}
async function openNeo4j(){
  if(!sessionId) return;
  const m=neo4jModal(); const body=$("#n4jBody"); m.hidden=false;
  body.innerHTML=`<p class="faint-note">${esc("Checking Neo4j status...")}</p>`;
  let st;
  try{ st=await (await fetch("/api/graph/neo4j/status")).json(); }
  catch(e){ body.innerHTML=`<p class="n4j-err">${esc("Could not reach the backend.")}</p>`; return; }
  const badge=(ok,onText,offText)=>`<span class="n4j-badge ${ok?'on':'off'}">${ok?onText:offText}</span>`;
  const explain=`<p class="n4j-explain">${esc("The graph always lives locally (SQLite) and is the one shown in the Evidence Graph above. Neo4j is an optional backend: sync the same graph to Neo4j to explore it with Cypher and Neo4j Browser (native node/relationship visualization).")}</p>`;
  const status=`<div class="n4j-status">
    ${badge(st.enabled,"Enabled","Disabled")}
    ${badge(st.driver_installed,"Driver installed","Driver missing")}
    ${badge(st.reachable===true,"Server reachable",st.reachable===false?"Server unreachable":"Not checked")}
    <span class="faint-note mono">${esc(st.uri||"")}</span>
  </div>`;
  const ready = st.enabled && st.driver_installed && st.reachable===true;
  let actions;
  if(ready){
    actions=`<button class="solid-btn" id="n4jSyncBtn" type="button">${esc("Sync graph to Neo4j")}</button>
      <a class="ghost-btn" id="n4jOpen" href="${esc(st.browser_url||'#')}" target="_blank" rel="noopener">${esc("Open Neo4j Browser")}</a>
      <button class="ghost-btn" id="n4jCypher" type="button">${esc("Download Cypher")}</button>`;
  }else{
    const hint = !st.enabled ? "Enable Neo4j: set NEO4J_ENABLED=True (or env REFORGE_NEO4J_ENABLED=1) and credentials in config.py / Settings."
      : !st.driver_installed ? "Install the driver: pip install neo4j, then restart."
      : `Server unreachable: ${st.error||""}. Start Neo4j and check URI/credentials.`;
    actions=`<p class="n4j-hint">${esc(hint)}</p>
      <button class="ghost-btn" id="n4jCypher" type="button">${esc("Download Cypher script (manual load)")}</button>`;
  }
  body.innerHTML=explain+status+`<div class="n4j-actions">${actions}</div><div id="n4jResult" class="n4j-result"></div>`;
  const cypherBtn=$("#n4jCypher");
  if(cypherBtn) cypherBtn.addEventListener("click",async()=>{
    const r=await fetch(`/api/projects/${sessionId}/graph/neo4j/cypher`);
    if(r.ok){ downloadText(await r.text(), `reforge_${sessionId}.cypher`); }
  });
  const syncBtn=$("#n4jSyncBtn");
  if(syncBtn) syncBtn.addEventListener("click",async()=>{
    const res=$("#n4jResult"); syncBtn.disabled=true; syncBtn.textContent="Syncing...";
    try{
      const r=await (await fetch(`/api/projects/${sessionId}/graph/neo4j/sync`,{method:"POST"})).json();
      if(r.ok){
        const q=encodeURIComponent(r.match_cypher||"");
        // Neo4j Browser supports a deep link that pre-fills the editor with a query.
        const deep=`${r.browser_url||st.browser_url||""}?cmd=edit&arg=${q}`;
        res.innerHTML=`<p class="n4j-ok">${esc(`Synced ${r.nodes} nodes and ${r.edges} edges to Neo4j (db ${r.database}).`)}</p>
          <a class="solid-btn" href="${esc(deep)}" target="_blank" rel="noopener">${esc("View this project in Neo4j Browser")}</a>
          <details class="n4j-q"><summary>${esc("Cypher query for this project")}</summary><pre>${esc(r.match_cypher||"")}</pre></details>`;
      }else{
        downloadText(r.cypher||"", `reforge_${sessionId}.cypher`);
        res.innerHTML=`<p class="n4j-err">${esc(`Sync failed (${r.reason||"error"}). Cypher script downloaded.`)}</p>`;
      }
    }catch(e){ res.innerHTML=`<p class="n4j-err">${esc("Error: ")+(e.message||e)}</p>`; }
    finally{ syncBtn.disabled=false; syncBtn.textContent="Sync graph to Neo4j"; }
  });
}
{const b=$("#neo4jBtn"); if(b) b.addEventListener("click",openNeo4j);}
async function exportRaw(ev){
  if(!sessionId){ alert("No active project: open or create a project before exporting."); return; }
  const btn=(ev&&ev.currentTarget)||$("#exportRawTop")||$("#exportRaw"); const old=btn?btn.textContent:"";
  if(btn){ btn.disabled=true; btn.textContent="…"; }
  try{
    const r=await fetch(`/api/projects/${sessionId}/raw-export?download=1`);
    if(!r.ok){ alert("Export failed."); return; }
    downloadText(await r.text(), `reforge_${sessionId}.md`, "text/markdown");
  }catch(e){ alert("Export error: "+(e.message||e)); }
  finally{ if(btn){ btn.disabled=false; btn.textContent=old; } }
}
{const b=$("#exportRaw"); if(b) b.addEventListener("click",exportRaw);}
{const b=$("#exportRawTop"); if(b) b.addEventListener("click",exportRaw);}

async function runGraphDiff(){
  const box=$("#graphDiff"), sel=$("#diffOther"); if(!box||!sel) return;
  const other=sel.value;
  if(!other){ box.innerHTML='<div class="findings-empty">Choose the project to compare first.</div>'; return; }
  box.innerHTML='<span class="faint-note">Confronto in corso…</span>';
  try{
    const d=await (await fetch("/api/graph/diff",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({session_a:other,session_b:sessionId})})).json();
    const s=d.summary||{};
    const summary=`<div class="diff-summary">`+
      `<span class="g-chip"><b>${s.nodes_added||0}</b> added</span>`+
      `<span class="g-chip"><b>${s.nodes_removed||0}</b> removed</span>`+
      `<span class="g-chip"><b>${s.nodes_changed||0}</b> changed</span>`+
      `<span class="g-chip"><b>${s.new_findings||0}</b> new findings</span>`+
      `<span class="g-chip"><b>${s.new_sinks||0}</b> new sinks</span>`+
      `<span class="g-chip"><b>${s.new_source_to_sink||0}</b> new chains</span></div>`;
    const hl=(d.highlights||[]);
    const hlHtml=hl.length?`<ul class="diff-hl">${hl.map(h=>`<li>${esc(h)}</li>`).join("")}</ul>`
      :'<div class="faint-note">No security-relevant changes.</div>';
    box.innerHTML=summary+'<h3 class="sub-h" style="margin-top:12px">Relevant changes</h3>'+hlHtml;
  }catch(e){ box.innerHTML='<div class="findings-empty">Error comparing the two versions.</div>'; }
}
{const b=$("#runGraphDiff"); if(b) b.addEventListener("click",runGraphDiff);}

function fallbackGraphFromProject(p){
  const nodes=[], edges=[], seen=new Set(), seenE=new Set();
  const addNode=(type,id,label,attrs={})=>{
    id=`${type}:${id||label||nodes.length}`;
    if(seen.has(id)) return id;
    seen.add(id); nodes.push({id,type,label:label||id.split(":").pop(),attrs}); return id;
  };
  const addEdge=(src,dst,type,attrs={})=>{
    if(!src||!dst||src===dst) return;
    const k=`${src}|${dst}|${type}`;
    if(seenE.has(k)) return;
    seenE.add(k); edges.push({src,dst,source:src,target:dst,type,attrs});
  };
  const prof=p?.target_profile||{};
  const target=p?.target_path||prof.path||prof.file||p?.name||"target";
  const bId=addNode("binary", prof.sha256||target, prof.file||String(target).split(/[\\/]/).pop()||"binary", {...prof,path:target});
  for(const imp of (p?.static_imports||p?.imports||[]).slice(0,250)){
    const name=typeof imp==="string"?imp:(imp?.name||String(imp));
    if(!name) continue;
    const iId=addNode("import", name.toLowerCase(), name, {source:"static"});
    addEdge(bId,iId,"BINARY_HAS_IMPORT");
    const cl=(typeof API_CLASS!=="undefined" && API_CLASS[name.toLowerCase()]) || "";
    if(cl){
      const sId=addNode("sink", name.toLowerCase(), name, {klass:cl,status:"needs_validation",source:"static"});
      addEdge(iId,sId,"FUNCTION_CALLS_IMPORT");
    }
  }
  for(const ev of (p?.evidence||[])){
    const eid=ev?.id; if(!eid) continue;
    addNode("evidence", eid, eid, {source:ev.source, tool:ev.tool_name, summary:ev.summary, location:ev.location});
  }
  for(const f of (p?.findings||[])){
    const fid=f.id||f.title||`finding-${nodes.length}`;
    const fId=addNode("finding", fid, f.title||fid, {severity:f.severity,status:f.status,vuln_type:f.vuln_type,location:f.location,confidence:f.confidence});
    addEdge(bId,fId,"BINARY_HAS_FINDING");
    if(f.location){
      const fn=addNode("function", f.location, f.location, {source:"finding_location"});
      addEdge(bId,fn,"BINARY_HAS_FUNCTION");
      addEdge(fId,fn,"FINDING_AFFECTS_FUNCTION");
    }
    for(const ref of (f.evidence_refs||[])){
      const eId=`evidence:${ref}`;
      if(!seen.has(eId)) addNode("evidence", ref, ref, {source:"finding_ref"});
      addEdge(eId,fId,"EVIDENCE_SUPPORTS_FINDING");
    }
  }
  for(const s of (p?.static_strings||[]).slice(0,80)){
    if(!/(https?:\/\/|hklm|hkcu|password|secret|token|cmd\.exe|powershell|createprocess|loadlibrary|\\windows\\|error|failed|exception)/i.test(String(s))) continue;
    const sid=addNode("string", String(s).slice(0,120), String(s).slice(0,120), {source:"static"});
    addEdge(bId,sid,"BINARY_HAS_STRING");
  }
  return {schema:"fallback-project",nodes,edges,stats:{nodes:nodes.length,edges:edges.length},summary:{fallback:true}};
}
async function loadProjectFallbackGraph(){
  if(!sessionId) return {nodes:[],edges:[]};
  try{
    const p=await (await fetch(`/api/projects/${sessionId}`)).json();
    return fallbackGraphFromProject(p);
  }catch(e){ return {nodes:[],edges:[]}; }
}

/* ---------- playbook runner ---------- */
const SAFETY_LBL={safe:"Safe",assisted:"Assisted",autonomous:"Autonomous",dangerous:"Dangerous"};
async function loadPlaybooks(){
  const box=$("#playbooksList"); if(!box) return;
  try{
    const r=await (await fetch("/api/playbooks")).json();
    const pbs=r.playbooks||[];
    if(!pbs.length){ box.innerHTML='<div class="findings-empty">No playbooks.</div>'; return; }
    box.innerHTML=pbs.map(p=>`<div class="pb-card">
      <div class="pb-top"><span class="pb-name">${esc(p.name)}</span>
        <span class="pb-safe safe-${esc(p.safety_mode)}">${esc(SAFETY_LBL[p.safety_mode]||p.safety_mode)}</span>
        ${p.requires_dynamic?'<span class="pb-dyn">dynamic</span>':""}</div>
      <div class="pb-desc">${esc(p.description||"")}</div>
      <div class="pb-steps">${(p.steps||[]).map(s=>`<span class="pb-step">${esc(s)}</span>`).join(`<span class="pb-sep">${icon("chevron-right","ic ic-sm")}</span>`)}</div>
      <button class="solid-btn pb-run" data-pb="${esc(p.id)}" type="button">${icon("playbooks")}${esc("Run")}</button>
    </div>`).join("");
    box.querySelectorAll(".pb-run").forEach(b=>b.addEventListener("click",()=>runPlaybook(b.dataset.pb)));
  }catch(e){ box.innerHTML='<div class="findings-empty">Error loading the playbooks.</div>'; }
}
async function runPlaybook(id){
  if(!sessionId) return;
  try{
    const r=await fetch("/api/playbooks/run",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({session_id:sessionId,playbook_id:id})});
    if(!r.ok){ const e=await r.json(); alert(e.detail||"Could not start the playbook."); return; }
    switchTab("chat");
  }catch(e){ alert("Network error."); }
}

let playbooksData = [];
function renderPlaybooks(){
  const box=$("#playbooksList"); if(!box) return;
  const pbs = playbooksData || [];
  if(!pbs.length){
    box.innerHTML=`<div class="empty-state"><div class="empty-state-ic">${icon("playbooks","ic ic-lg")}</div>`+
      `<h3>No playbooks available</h3>`+
      `<p>Playbooks are repeatable assessment procedures loaded from <code>reforge/playbooks/*.yaml</code>. `+
      `None were found — check that the directory exists and that the files are readable.</p>`+
      `<div class="empty-state-actions"><button class="btn-sm" type="button" id="pbRetry">Retry</button></div></div>`;
    const r=$("#pbRetry"); if(r) r.onclick=()=>loadPlaybooks();
    return;
  }
  box.innerHTML=pbs.map(p=>{
    const id = p.id || "";
    const steps = (p.steps||[]).map(s=>`<span class="pb-step">${esc(playbookStepLabel(s))}</span>`)
      .join(`<span class="pb-sep">${icon("chevron-right","ic ic-sm")}</span>`);
    const mods = (p.modules||[]).map(m=>`<span class="pb-mod">${esc(m)}</span>`).join("");
    const outs = (p.expected_outputs||[]).map(o=>`<span class="pb-out">${esc(String(o).replace(/_/g," "))}</span>`).join("");
    return `<div class="pb-card">
      <div class="pb-top"><span class="pb-name">${esc(playbookLabel(id, "name", p.name))}</span>
        <span class="pb-safe safe-${esc(p.safety_mode)}">${esc(safetyModeLabel(p.safety_mode))}</span>
        ${p.requires_dynamic?`<span class="pb-dyn">${esc(t("playbooks.dynamic"))}</span>`:""}
        ${p.custom?`<span class="pb-custom">custom</span>`:""}</div>
      <div class="pb-desc">${esc(playbookLabel(id, "description", p.description||""))}</div>
      <div class="pb-steps">${steps}</div>
      ${outs?`<div class="pb-outs"><span class="pb-meta-k">${esc("Produces:")}</span> ${outs}</div>`:""}
      ${mods?`<div class="pb-mods"><span class="pb-meta-k">${esc("Modules:")}</span> ${mods}</div>`:""}
      ${p.requires_dynamic?`<p class="pb-warn">
        <strong>${esc("Runs dynamic analysis.")}</strong>
        ${esc("This playbook can perform actions that change the state of the target process. Each risky action asks for your approval unless the safety mode is set to autonomous.")}</p>`:""}
      <div class="pb-card-actions">
        <button class="solid-btn pb-run" data-pb="${esc(id)}" type="button">${esc(t("playbooks.run"))}</button>
        ${p.custom?`<button class="btn-sm pb-del" data-pb="${esc(id)}" type="button">${esc("Delete")}</button>`:""}
        <span class="pb-stepcount">${(p.steps||[]).length} ${esc("steps")}</span>
      </div>
    </div>`;
  }).join("");
  box.querySelectorAll(".pb-run").forEach(b=>b.addEventListener("click",()=>runPlaybook(b.dataset.pb)));
  box.querySelectorAll(".pb-del").forEach(b=>b.addEventListener("click",()=>deleteCustomPlaybook(b.dataset.pb)));
}
loadPlaybooks = async function(){
  const box=$("#playbooksList"); if(!box) return;
  try{
    const r=await (await fetch("/api/playbooks")).json();
    playbooksData=r.playbooks||[];
    _pbModules=r.modules||[];
    renderPlaybooks();
  }catch(e){ box.innerHTML=`<div class="findings-empty">${esc(t("playbooks.loadError"))}</div>`; }
};
let _pbModules=[];
function pbModuleChecks(){
  const box=$("#pbModules"); if(!box) return;
  box.innerHTML=(_pbModules||[]).map(m=>`<label class="pb-mod-check"><input type="checkbox" value="${esc(m)}"> ${esc(m)}</label>`).join("");
}
function openPbEditor(){
  const ed=$("#pbEditor"); if(!ed) return;
  pbModuleChecks();
  ["#pbName","#pbId","#pbDesc","#pbSteps","#pbPrompt"].forEach(s=>{const e=$(s); if(e) e.value="";});
  const dyn=$("#pbDynamic"); if(dyn) dyn.checked=false;
  const msg=$("#pbEditorMsg"); if(msg) msg.textContent="";
  ed.hidden=false; ed.scrollIntoView({behavior:"smooth",block:"nearest"});
}
function closePbEditor(){ const ed=$("#pbEditor"); if(ed) ed.hidden=true; }
async function saveCustomPlaybook(){
  const msg=$("#pbEditorMsg");
  const name=($("#pbName")?.value||"").trim();
  const steps=($("#pbSteps")?.value||"").split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  if(!name){ if(msg) msg.textContent="Name is required."; return; }
  if(!steps.length){ if(msg) msg.textContent="Add at least one step."; return; }
  const modules=[...document.querySelectorAll("#pbModules input:checked")].map(c=>c.value);
  const payload={name, id:($("#pbId")?.value||"").trim()||undefined,
    description:($("#pbDesc")?.value||"").trim(),
    safety_mode:$("#pbSafety")?.value||"safe",
    requires_dynamic:!!$("#pbDynamic")?.checked,
    steps, modules,
    system_prompt:($("#pbPrompt")?.value||"").trim()||undefined};
  if(msg) msg.textContent="Saving...";
  try{
    const r=await fetch("/api/playbooks/custom",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const j=await r.json();
    if(!r.ok){ if(msg) msg.textContent=j.detail||"Save error."; return; }
    closePbEditor(); await loadPlaybooks();
  }catch(e){ if(msg) msg.textContent="Network error."; }
}
async function deleteCustomPlaybook(id){
  if(!confirm(`Delete custom playbook "${id}"?`)) return;
  try{
    const r=await fetch(`/api/playbooks/custom/${encodeURIComponent(id)}`,{method:"DELETE"});
    if(!r.ok){ const e=await r.json(); alert(e.detail||"Could not delete."); return; }
    await loadPlaybooks();
  }catch(e){ alert("Network error."); }
}
{const b=$("#pbNewBtn"); if(b) b.addEventListener("click",openPbEditor);}
{const b=$("#pbSaveBtn"); if(b) b.addEventListener("click",saveCustomPlaybook);}
{const b=$("#pbCancelBtn"); if(b) b.addEventListener("click",closePbEditor);}
runPlaybook = async function(id){
  if(!sessionId) return;
  try{
    const r=await fetch("/api/playbooks/run",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({session_id:sessionId,playbook_id:id})});
    if(!r.ok){ const e=await r.json(); alert(e.detail||t("playbooks.startError")); return; }
    switchTab("chat");
  }catch(e){ alert(t("playbooks.networkError")); }
};

/* ---------- job system ---------- */
const JOB_ST={queued:"Queued",running:"Running",completed:"Completed",failed:"Failed",cancelled:"Cancelled"};
const JOB_KIND_LBL={
  xref_enrich:"Ghidra xref enrichment", source_to_sink:"Source→sink analysis",
  finding_validation:"Finding validation", graph_sync:"Evidence Graph sync",
  static_analysis:"Static analysis", report_generation:"Report generation",
};
function jobOutcome(j){
  if(j.error) return `<span class="job-err">${esc(String(j.error).slice(0,160))}</span>`;
  if(j.status==="completed"){
    const o=j.output||{};
    const bits=Object.entries(o).filter(([,v])=>typeof v!=="object")
      .map(([k,v])=>`${k}: ${v}`).slice(0,3).join(" · ");
    return esc(bits||"completed");
  }
  if(j.status==="running") return `<span class="job-prog"><span class="pulse"></span>working…</span>`;
  return "—";
}
async function loadJobs(){
  const box=$("#jobsList"); if(!box) return;
  try{
    const r=await (await fetch("/api/jobs")).json();
    const jobs=r.jobs||[];
    const badge=$("#jcount");
    const active=jobs.filter(j=>j.status==="queued"||j.status==="running").length;
    if(badge){ badge.hidden=!active; badge.textContent=String(active); }
    if(!jobs.length){
      box.innerHTML=`<div class="empty-state"><div class="empty-state-ic">${icon("jobs","ic ic-lg")}</div>`+
        `<h3>No jobs yet</h3><p>Queue background work above. Jobs are persisted to disk and `+
        `restored when ReTrace restarts, so a long enrichment survives a reload.</p></div>`;
      return;
    }
    box.innerHTML=jobs.map(j=>`<article class="job-card st-${esc(j.status)}">
      <header class="job-head">
        <span class="job-kind">${esc(JOB_KIND_LBL[j.kind]||j.kind)}</span>
        <span class="job-st st-${esc(j.status)}">${esc(JOB_ST[j.status]||j.status)}</span>
        <span class="job-id mono">${esc(j.id)}</span>
      </header>
      <div class="job-meta">
        <span>${j.duration!=null?esc(j.duration+"s"):"—"}</span>
        <span class="job-out">${jobOutcome(j)}</span>
      </div>
      ${(j.status==="queued"||j.status==="running")
        ? `<button class="btn-sm job-cancel" type="button" data-job-cancel="${esc(j.id)}">Cancel</button>` : ""}
    </article>`).join("");
  }catch(e){
    box.innerHTML=`<div class="empty-state"><div class="empty-state-ic">${icon("alert","ic ic-lg")}</div>`+
      `<h3>Could not load jobs</h3><p>${esc(e.message||String(e))}</p></div>`;
  }
}
async function cancelJob(id){
  try{ await fetch(`/api/jobs/${id}/cancel`,{method:"POST"}); }catch(e){}
  setTimeout(loadJobs,300);
}
document.addEventListener("click",(e)=>{
  const b=e.target.closest("[data-job-cancel]");
  if(b) cancelJob(b.dataset.jobCancel);
});
async function submitJob(){
  if(!sessionId) return;
  const sel=$("#jobKind"); const kind=sel?sel.value:"static_analysis";
  const btn=$("#jobSubmit"); const old=btn?btn.textContent:"";
  if(btn){ btn.disabled=true; btn.textContent="Queueing…"; }
  try{
    const r=await fetch("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({session_id:sessionId,kind})});
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||`HTTP ${r.status}`);
    }
    setTimeout(loadJobs,400);
  }catch(e){
    if(btn){ btn.classList.add("btn-err"); btn.textContent=String(e.message).slice(0,40);
      setTimeout(()=>{ btn.classList.remove("btn-err"); btn.textContent=old; },3500); }
  } finally { if(btn){ btn.disabled=false; if(!btn.classList.contains("btn-err")) btn.textContent=old; } }
}
{const a=$("#jobSubmit"); if(a) a.addEventListener("click",submitJob);
 const b=$("#jobsRefresh"); if(b) b.addEventListener("click",loadJobs);}

/* ---------- imports explorer ---------- */
let importsData = [];
const IMPORT_CLASS_COPY = {
  en:{
    exec:"process or command execution",
    load:"dynamic loading and plugins",
    mem:"memory, copies, and buffers",
    file:"filesystem access",
    net:"network communications",
    crypt:"cryptography and sensitive material"
  }
};
const IMPORT_CLASS_GENERIC = {
  en:{
    exec:"Can launch processes or commands. Check inputs, quoting, working directory, and privileges at the callsite.",
    load:"Can load DLLs or resolve functions at runtime. Useful for plugin, evasion, or search-order hijacking review.",
    mem:"Memory primitive. Look for unchecked sizes, fixed buffers, and external input.",
    file:"File or path access. Correlate it with strings, runtime artifacts, and target permissions.",
    net:"Network surface. Look for endpoints, protocols, input parsing, and received data.",
    crypt:"Crypto or secret handling. Review key management, storage, and weak algorithms."
  }
};
const API_DESCRIPTIONS = {
  createprocessa:"Starts a new process using ANSI strings. Critical when command line or path comes from untrusted input.",
  createprocessw:"Starts a new process using Unicode strings. Check quoting and executable/argument separation.",
  winexec:"Legacy command execution API. Often fragile around quoting and path search.",
  shellexecute:"Opens files, URLs, or commands through the shell. Check verb, path, and file associations.",
  shellexecutea:"Opens files, URLs, or commands through the shell. Check verb, path, and file associations.",
  shellexecutew:"Opens files, URLs, or commands through the shell. Check verb, path, and file associations.",
  system:"Runs a string through the C runtime shell. High risk if the string is built dynamically.",
  popen:"Runs a command and opens a pipe. Check injection and data flow.",
  execve:"Executes a program on POSIX systems. Check controllable argv, env, and path.",
  loadlibrarya:"Loads an ANSI DLL. Check absolute paths, search directories, and DLL hijacking.",
  loadlibraryw:"Loads a Unicode DLL. Check absolute paths, search directories, and DLL hijacking.",
  loadlibraryexa:"Loads a DLL with extra flags. Flags define DLL search safety.",
  getprocaddress:"Resolves exported functions at runtime. Indicates dynamic loading or APIs hidden from static imports.",
  createfilea:"Opens or creates files/devices using ANSI paths. Correlate with path strings and permissions.",
  createfilew:"Opens or creates files/devices using Unicode paths. Correlate with path strings and permissions.",
  readfile:"Reads from files, pipes, or devices. Useful for tracing input into parsers or sinks.",
  writefile:"Writes to files, pipes, or devices. Check sensitive output, logs, and artifact drops.",
  deletefilea:"Deletes files through ANSI paths. Check controllable path and operational impact.",
  virtualalloc:"Allocates virtual memory. Relevant for unpacking, JIT, shellcode, or large buffers.",
  heapalloc:"Allocates heap memory. Check calculated sizes and integer overflows.",
  memcpy:"Copies memory without intrinsic bounds checks. Verify size and destination buffer.",
  memmove:"Moves memory with overlap allowed. Verify size and destination buffer.",
  strcpy:"Copies strings without a limit. Overflow risk if the source is not bounded.",
  strcat:"Concatenates strings without a limit. Check remaining destination buffer space.",
  sprintf:"Formats into a buffer without a limit. Check lengths and controllable format strings.",
  scanf:"Reads formatted input. Check widthless specifiers and destinations.",
  gets:"Reads input without a limit: inherently dangerous function.",
  getcommandlinea:"Returns the process ANSI command line. Useful for runtime input and option analysis.",
  getcommandlinew:"Returns the process Unicode command line. Useful for runtime input and option analysis.",
  wsprintfa:"Formats ANSI text into a buffer. Check overflow and controllable strings.",
  wsprintfw:"Formats Unicode text into a buffer. Check overflow and controllable strings.",
  wsaconnect:"Opens a socket connection. Correlate with hosts, IPs, ports, and runtime behavior.",
  connect:"Connects a socket. Look for endpoints and network-received data.",
  send:"Sends data through a socket. Check exfiltration, protocols, and sensitive data.",
  recv:"Receives socket data. Trace parsing and sanitization of remote input.",
  internetopen:"Initializes WinINet. Indicates possible HTTP/FTP communication or proxy awareness.",
  winhttp:"WinHTTP API. Correlate with URLs, certificates, and TLS handling."
};
function apiBaseName(s){
  let x=(s||"").toString().trim().toLowerCase();
  x=x.split(/[!(\s]/)[0];
  x=x.replace(/^.*[!.]/,"").replace(/@\d+$/,"");
  return x;
}
function importDescription(s, cl){
  const key=apiBaseName(s);
  const d=API_DESCRIPTIONS[key];
  if(d) return d;
  return (IMPORT_CLASS_GENERIC.en?.[cl] || IMPORT_CLASS_GENERIC.en[cl] || ("Static import surface. Review callsites and data flow before treating it as a risk."));
}
function importClassOf(s){
  const x=(s||"").toString().toLowerCase();
  const base=apiBaseName(x);
  for(const [api,cl] of Object.entries(API_CLASS)){
    if(base===api) return cl;
    if(x===api || x.endsWith("!"+api) || x.endsWith("."+api) || x.includes(api+"@") || x.includes(api+"(")) return cl;
    if(x.includes(api) && api.length>=7) return cl;
  }
  return "";
}
/* Rendering every import of a large binary builds thousands of description-carrying rows at once.
   Cap the DOM and let the analyst pull in more; the security-relevant ones sort to the top, so the
   first page is the page that matters. */
const IMPORTS_PAGE = 300;
let importsShown = IMPORTS_PAGE;

function renderImports(filter){
  const box=$("#importsList"); if(!box) return;
  const q=(filter||"").toLowerCase();
  const rows=importsData.map(s=>({s,cl:importClassOf(s),base:apiBaseName(s)}))
    .filter(o=>!q||o.s.toLowerCase().includes(q)||o.cl.includes(q)||o.base.includes(q));
  if(!rows.length){
    box.innerHTML=importsData.length
      ? `<div class="empty-state"><div class="empty-state-ic">${icon("search","ic ic-lg")}</div>`+
        `<h3>No import matches this filter</h3>`+
        `<p>${importsData.length} imported symbol${importsData.length===1?"":"s"} in this binary.</p></div>`
      : `<div class="empty-state"><div class="empty-state-ic">${icon("imports","ic ic-lg")}</div>`+
        `<h3>No import table available</h3>`+
        `<p>Either no target is loaded, or the binary has no readable import table (it may be `+
        `packed, statically linked, or a format without one). Static triage records this; it is `+
        `not an error.</p>`+
        `<div class="empty-state-actions"><button class="solid-btn" type="button" data-empty-action="projects">Load a target</button></div></div>`;
    return;
  }
  const counts={}; rows.forEach(o=>{ if(o.cl) counts[o.cl]=(counts[o.cl]||0)+1; });
  const summary=Object.entries(counts).length
    ? `<div class="imp-summary">${Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([cl,n])=>
        // Each class is a discrete pill. Concatenating them produced the
        // unreadable "file4 - filesystem accessload3 - dynamic loading" run.
        `<span class="imp-sum-item"><span class="imp-cls cls-${esc(cl)}">${esc(cl)}</span>`+
        `<span class="imp-sum-n">${n}</span>`+
        `<span>${esc(IMPORT_CLASS_COPY.en?.[cl]||cl)}</span></span>`).join("")}</div>`
    : `<div class="analysis-note compact"><strong>Surface</strong><span>${"No import is classified as dangerous, but still review custom wrappers and dynamically resolved APIs."}</span></div>`;
  rows.sort((a,b)=>(!!b.cl-!!a.cl)||a.base.localeCompare(b.base)||a.s.localeCompare(b.s));
  const shown=Math.min(importsShown, rows.length);
  const more=rows.length-shown;
  box.innerHTML=summary+rows.slice(0,shown).map(o=>{
    const cl=o.cl || "surface";
    return `<div class="imp-row${o.cl?' hot':''}">`+
      `<div class="imp-main"><span class="imp-name">${esc(o.s)}</span><p class="imp-desc">${esc(importDescription(o.s,o.cl))}</p></div>`+
      `<span class="imp-cls ${o.cl?`cls-${esc(o.cl)}`:"muted-cls"}">${esc(cl)}</span>`+
    `</div>`;
  }).join("")+(more>0
    ? `<button class="btn-sm show-more" type="button" id="impMore">Show ${Math.min(more,IMPORTS_PAGE)} more (${more} remaining)</button>`
    : "");
  const mb=$("#impMore");
  if(mb) mb.onclick=()=>{ importsShown+=IMPORTS_PAGE; renderImports(filter); };
}
async function loadImports(){
  if(!sessionId) return;
  if(importsData.length){ renderImports($("#impSearch")?$("#impSearch").value:""); return; }
  try{ const r=await (await fetch(`/api/projects/${sessionId}/imports`)).json();
    importsData=r.imports||[]; setCount("#icount",importsData.length); renderImports(""); }catch(e){}
}
const _is=$("#impSearch"); if(_is) _is.addEventListener("input",e=>{ importsShown=IMPORTS_PAGE; renderImports(e.target.value); });

/* ---------- Artifacts ---------- */
let artifactsData = [];
const ART_TYPE_LABEL = {
  procmon_xml:"Procmon XML", pcap:"PCAP", pe_binary:"PE (Windows)", elf_binary:"ELF (Linux)",
  xml:"XML", json:"JSON", text:"Text", binary:"Binary"
};
function fmtBytes(n){
  n=Number(n)||0; if(n<1024) return n+" B";
  if(n<1048576) return (n/1024).toFixed(1)+" KB";
  if(n<1073741824) return (n/1048576).toFixed(1)+" MB";
  return (n/1073741824).toFixed(2)+" GB";
}
function artStatus(msg,kind){
  const el=$("#artStatus"); if(!el) return;
  if(!msg){ el.hidden=true; el.textContent=""; return; }
  el.hidden=false; el.className="art-status"+(kind?(" "+kind):""); el.textContent=msg;
}
function artOverviewHtml(a){
  const ov=a.overview; const st=a.overview_status;
  if(st==="deferred" && !ov){
    return `<div class="art-overview deferred"><span class="faint-note">${esc("Offline overview not computed (large file).")}</span> <button class="btn-sm art-ov" data-id="${esc(a.id)}">${esc("Analyze offline")}</button></div>`;
  }
  if(!ov) return "";
  if(ov.error){ return `<div class="art-overview err"><strong>${esc("Overview")}:</strong> ${esc(ov.error)}</div>`; }
  const rows=[];
  if(ov.headline) rows.push(`<div class="art-ov-headline">${esc(ov.headline)}</div>`);
  const chips=(label,pairs)=> (pairs&&pairs.length)?`<div class="art-ov-line"><span class="art-ov-k">${esc(label)}</span>${pairs.slice(0,6).map(p=>`<span class="art-ov-chip">${esc(Array.isArray(p)?`${p[0]} · ${p[1]}`:p)}</span>`).join("")}</div>`:"";
  if(ov.kind==="procmon"){
    rows.push(chips("Operations",ov.top_operations));
    rows.push(chips("Processes",ov.top_processes));
    rows.push(chips("Files",ov.top_file_paths));
    rows.push(chips("Registry",ov.top_registry_paths));
    rows.push(chips("Network",ov.top_network));
  } else if(ov.kind==="pcap"){
    rows.push(chips("Talkers",ov.top_talkers));
    rows.push(chips("Ports",ov.top_ports));
    rows.push(chips("Protocols",ov.l3_protocols));
    if(ov.note) rows.push(`<div class="faint-note">${esc(ov.note)}</div>`);
  } else if(ov.kind==="binary"){
    rows.push(chips("Sink classes",ov.sink_classes));
    rows.push(chips("Input sources",ov.input_sources));
    rows.push(chips("Notable findings",ov.notable_findings));
  } else if(ov.json_keys){
    rows.push(chips("Keys",ov.json_keys));
  } else if(ov.csv_columns){
    rows.push(chips("Columns",ov.csv_columns));
  }
  if(ov.sample){ rows.push(`<details class="art-ov-sample"><summary>${esc("Sample")}</summary><pre>${esc(ov.sample)}</pre></details>`); }
  return `<div class="art-overview">${rows.filter(Boolean).join("")}</div>`;
}
const SEV_RANK={critical:4,high:3,medium:2,low:1,info:0};
function artHeuristicsHtml(a){
  const he=a.heuristics;
  if(!he) return "";
  if(he.error){ return `<div class="art-heur err"><strong>${esc("Heuristic analysis")}:</strong> ${esc(he.error)}</div>`; }
  const fs=he.findings||[];
  if(!fs.length){
    if(he.note) return `<div class="art-heur"><span class="faint-note">${esc(he.note)}</span></div>`;
    return `<div class="art-heur"><span class="faint-note">${esc("No relevant weakness detected offline in the trace.")}</span></div>`;
  }
  const items=fs.map(f=>{
    const cwe=(f.cwe||f.attck||[]).join(", ");
    const ev=(f.evidence||[]).slice(0,6).map(e=>`<div class="heur-ev mono">${esc(e)}</div>`).join("");
    return `<details class="heur-f sev-${esc(f.severity)}">
      <summary><span class="heur-sev sev-${esc(f.severity)}">${esc((f.severity||"info").toUpperCase())}</span>
        <span class="heur-title">${esc(f.title)}</span>
        ${cwe?`<span class="heur-attck">${esc(cwe)}</span>`:""}
        <span class="heur-count">×${f.count||(f.evidence||[]).length}</span></summary>
      ${f.summary?`<div class="heur-sum">${esc(f.summary)}</div>`:""}
      ${ev?`<div class="heur-evs">${ev}</div>`:""}
    </details>`;
  }).join("");
  return `<div class="art-heur"><div class="art-heur-head">${esc("Offline heuristic analysis")} · ${esc(he.headline||"")}</div>${items}</div>`;
}
function renderArtifacts(){
  const box=$("#artifactsList"); if(!box) return;
  setCount("#acount",artifactsData.length);
  if(!artifactsData.length){ box.innerHTML='<div class="findings-empty">No artifacts uploaded.</div>'; return; }
  box.innerHTML=artifactsData.map(a=>{
    const routing=a.routing||{};
    const canParse=routing.server&&routing.tool;
    const tlabel=ART_TYPE_LABEL[a.type]||a.type;
    return `<div class="art-card" data-id="${esc(a.id)}">
      <div class="art-card-main">
        <div class="art-card-name">${esc(a.name)}</div>
        <div class="art-card-meta">
          <span class="art-type-badge art-type-${esc(a.type)}">${esc(tlabel)}</span>
          <span class="faint-note">${fmtBytes(a.size)}</span>
          <span class="faint-note mono">${esc(a.id)}</span>
        </div>
        ${artOverviewHtml(a)}
        ${artHeuristicsHtml(a)}
        <div class="art-card-result" id="artres-${esc(a.id)}" hidden></div>
      </div>
      <div class="art-card-actions">
        ${canParse?`<button class="btn-sm art-parse" data-id="${esc(a.id)}">Parse</button>`:`<span class="faint-note">no parser</span>`}
        <button class="btn-sm art-askai" data-id="${esc(a.id)}" data-name="${esc(a.name)}" data-type="${esc(a.type)}" title="${esc("Ask the agent for a deeper analysis of this artifact")}">${esc("Analyze in chat")}</button>
      </div>
    </div>`;
  }).join("");
  box.querySelectorAll(".art-parse").forEach(b=>b.addEventListener("click",()=>parseArtifact(b.dataset.id)));
  box.querySelectorAll(".art-ov").forEach(b=>b.addEventListener("click",()=>computeArtifactOverview(b.dataset.id)));
  box.querySelectorAll(".art-askai").forEach(b=>b.addEventListener("click",()=>askAgentAboutArtifact(b.dataset.id,b.dataset.name,b.dataset.type)));
}
// "Analyze in chat": hand the artifact to the agent (which has the LLM/MCP). No local LLM here.
function askAgentAboutArtifact(aid,name,type){
  const prompt=`Deeply analyze the ${type} artifact "${name}" (id ${aid}). Start from the offline heuristic analysis already available, confirm or refute the findings, reconstruct the attack chain, and project the evidence into the graph.`;
  switchTab("chat");
  if(typeof sendMessage==="function"){ try{ sendMessage(prompt); }catch(e){} }
}
async function computeArtifactOverview(aid){
  if(!sessionId) return;
  const btn=document.querySelector(`.art-ov[data-id="${CSS.escape(aid)}"]`);
  if(btn){ btn.disabled=true; btn.textContent="Analyzing..."; }
  try{
    const r=await (await fetch(`/api/projects/${sessionId}/artifacts/${aid}/overview`,{method:"POST"})).json();
    const a=artifactsData.find(x=>x.id===aid); if(a){ a.overview=r.overview; a.overview_status=r.overview_status; }
    renderArtifacts();
  }catch(e){ if(btn){ btn.disabled=false; btn.textContent="Analyze offline"; } }
}
async function loadArtifacts(){
  if(!sessionId){ artifactsData=[]; renderArtifacts(); return; }
  try{
    const r=await (await fetch(`/api/projects/${sessionId}/artifacts`)).json();
    artifactsData=r.artifacts||[]; renderArtifacts();
  }catch(e){ artStatus("Error loading the artifact list.","err"); }
}
async function uploadArtifact(file){
  if(!sessionId){ artStatus("Create or select a project before uploading.","err"); return; }
  if(!file) return;
  artStatus(`Uploading "${file.name}" (${fmtBytes(file.size)})…`,"busy");
  try{
    const fd=new FormData(); fd.append("file",file,file.name);
    const r=await fetch(`/api/projects/${sessionId}/artifacts`,{method:"POST",body:fd});
    if(!r.ok){ const t=await r.text(); throw new Error(t||r.status); }
    const data=await r.json();
    const a=data.artifact;
    const tlabel=ART_TYPE_LABEL[a.type]||a.type;
    artStatus(`Uploaded "${a.name}" — detected type: ${tlabel}.`,"ok");
    await loadArtifacts();
  }catch(e){ artStatus("Upload failed: "+(e.message||e),"err"); }
}
async function parseArtifact(aid){
  const resEl=$("#artres-"+CSS.escape(aid));
  const btn=document.querySelector(`.art-parse[data-id="${CSS.escape(aid)}"]`);
  if(btn){ btn.disabled=true; btn.textContent="…"; }
  try{
    const r=await fetch(`/api/projects/${sessionId}/artifacts/${aid}/parse`,
      {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({})});
    const data=await r.json();
    if(resEl){
      resEl.hidden=false;
      const out=(data.result&&data.result.text)?data.result.text:JSON.stringify(data.result||data,null,2);
      const ok=data.ok&&!(data.result&&data.result.is_error);
      resEl.className="art-card-result"+(ok?" ok":" err");
      resEl.innerHTML=`<div class="art-result-head">${icon(ok?"check":"alert")}${esc(ok?"Parsed":"Failed")} · ${esc(data.tool||"")}</div>`+
                      `<pre class="art-result-pre">${esc(out.slice(0,4000))}</pre>`;
    }
    if(data.graph_projected){ await loadArtifacts(); await loadGraph(); }
  }catch(e){
    if(resEl){ resEl.hidden=false; resEl.className="art-card-result err"; resEl.textContent="Parse failed: "+(e.message||e); }
  }finally{
    if(btn){ btn.disabled=false; btn.textContent="Parse"; }
  }
}
/* upload wiring: the "choose from this computer" control is a native <label for="artFile">, so the
   OS file picker opens reliably without JS. We only handle the resulting file selection here,
   plus drag & drop on the zone. Delegated on document so it survives re-renders / load order. */
document.addEventListener("change", function(e){
  if(e.target && e.target.id === "artFile"){
    const f = e.target.files && e.target.files[0];
    if(f) uploadArtifact(f);
    e.target.value = "";
  } else if(e.target && e.target.id === "targetFile"){
    const f = e.target.files && e.target.files[0];
    if(f) uploadTargetBinary(f);
    e.target.value = "";
  }
});
/* drag & drop on the drop zone (delegated so it binds even after re-render) */
document.addEventListener("dragover", function(e){
  const dz = e.target.closest && e.target.closest("#artDrop,#targetDrop");
  if(dz){ e.preventDefault(); dz.classList.add("drag"); }
});
document.addEventListener("dragleave", function(e){
  const dz = e.target.closest && e.target.closest("#artDrop,#targetDrop");
  if(dz) dz.classList.remove("drag");
});
document.addEventListener("drop", function(e){
  const dz = e.target.closest && e.target.closest("#artDrop,#targetDrop");
  if(dz){
    e.preventDefault(); dz.classList.remove("drag");
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if(f && dz.id==="targetDrop") uploadTargetBinary(f);
    else if(f) uploadArtifact(f);
  }
});

/* ---------- tool log ---------- */
let toollogData = [];
function setTcount(n){ setCount("#tcount", n); }
function fmtTime(ts){ try{ return new Date(ts*1000).toLocaleTimeString(); }catch(e){ return ""; } }
function renderToollog(filter){
  const box=$("#toollogList"); if(!box) return; const q=(filter||"").toLowerCase();
  const rows=toollogData.filter(e=>!q || JSON.stringify(e).toLowerCase().includes(q));
  if(!rows.length){ box.innerHTML=`<div class="findings-empty">${esc("No calls recorded.")}</div>`; return; }
  box.innerHTML=rows.map((e,i)=>{
    const args=e.args?esc(JSON.stringify(e.args)):"";
    const st=e.is_error
      ? `<span class="tl-err">${icon("alert")}${esc("failed")}</span>`
      : `<span class="tl-ok">${icon("check")}${esc("ok")}</span>`;
    // Approval is only worth showing when a human actually made the call.
    const appr = e.approved===true
      ? `<span class="tl-appr">${icon("check")}${esc("approved")}</span>`
      : (e.approved===false ? `<span class="tl-deny">${icon("x")}${esc("denied")}</span>` : "");
    return `<div class="tl-row ${e.is_error?'err':''}"><div class="tl-top"><span class="tl-n">#${i+1}</span>`+
      `<span class="tl-tool">${esc(e.tool||"?")}</span>${st}${appr}<span class="tl-time">${esc(fmtTime(e.ts))}</span></div>`+
      (args?`<div class="tl-args">${args}</div>`:"")+
      (e.result_preview?`<pre class="tl-out">${esc(e.result_preview)}</pre>`:"")+`</div>`;
  }).join("");
}
async function loadToollog(){
  if(!sessionId) return;
  try{ const r=await (await fetch(`/api/projects/${sessionId}/toollog`)).json();
    toollogData=r.log||[]; setTcount(toollogData.length); renderToollog($("#tlSearch")?$("#tlSearch").value:""); }
  catch(e){}
}
const _tlSearch=$("#tlSearch"); if(_tlSearch) _tlSearch.addEventListener("input",e=>renderToollog(e.target.value));

/* ---------- workflow phases ---------- */
// The visual phase bar was removed: it was a theoretical guide that could fail to reflect
// the actual analysis. The workflow stays server-side to help tool retrieval.
let _lastPhase = null;
function renderPhase(g){
  _lastPhase = g;
  const chip = $("#phaseChip"); if(chip) chip.hidden = true;
}
function togglePhasePop(){
  return;
  const ex = $("#phasePop"); if(ex){ ex.remove(); return; }
  const g = _lastPhase; if(!g) return;
  const chip = $("#phaseChip"); const r = chip.getBoundingClientRect();
  const steps = (g.phases||[]).map((p,i)=>{
    const cls = p.key===g.phase ? "cur" : (p.done ? "done" : "");
    const mark = p.done ? icon("check","ic") : (i+1);
    return `<li class="${cls}"><span class="pp-n">${mark}</span>${esc(p.title)}</li>`;
  }).join("");
  const next = (g.next_steps||[]).slice(0,2).join("; ");
  const pop = document.createElement("div");
  pop.id = "phasePop"; pop.className = "phase-pop";
  pop.innerHTML = `<h4>Phase ${(g.index??0)+1}/${g.total}: ${esc(g.title)}</h4>`+
    `<div class="pp-obj">${esc(g.objective||"")}</div><ol>${steps}</ol>`+
    (next?`<div class="pp-next">${icon("arrow-right")}${esc(next)}</div>`:"")+
    `<div class="pp-hint">Methodology guide: phases only advance when the agent actually performs those activities. You can ignore them and work freely.</div>`;
  document.body.appendChild(pop);
  pop.style.top = (r.bottom+8)+"px";
  pop.style.left = Math.max(12, Math.min(r.left, window.innerWidth - pop.offsetWidth - 12))+"px";
  setTimeout(()=>document.addEventListener("click", function h(e){
    if(!pop.contains(e.target) && e.target!==chip){ pop.remove(); document.removeEventListener("click",h); }
  }),0);
}
async function loadPhase(){
  if(!sessionId) return;
  try{
    const g = await (await fetch(`/api/projects/${sessionId}/workflow`)).json();
    renderPhase(g);
  }catch(e){ const c=$("#phaseChip"); if(c) c.hidden=true; }
}

/* ---------- evidence ---------- */
function evidenceLocation(loc){
  if(loc == null) return "";
  if(typeof loc === "string") return loc;
  if(Array.isArray(loc)) return loc.map(v=>String(v)).join(" · ");
  if(typeof loc === "object"){
    return Object.entries(loc)
      .filter(([,v]) => v != null && v !== "")
      .map(([k,v]) => `${k}=${v}`).join(" · ");
  }
  return String(loc);
}
let evidenceData = [];
function setEcount(n){ setCount("#ecount", n); }
function renderEvidence(filter){
  const box=$("#evidenceList"); if(!box) return; const q=(filter||"").toLowerCase();
  const rows=evidenceData.filter(e=>!q || JSON.stringify(e).toLowerCase().includes(q));
  if(!rows.length){ box.innerHTML=`<div class="findings-empty">${esc("No evidence.")}</div>`; return; }
  box.innerHTML=rows.map(e=>{
    const loc=evidenceLocation(e.location);
    return `<div class="ev-card"><div class="ev-top"><span class="ev-id">${esc(e.id||"")}</span>`+
      `<span class="ev-src">${esc(e.source||"")}</span>`+
      (loc?`<span class="ev-loc" title="${esc(loc)}">${esc(loc)}</span>`:"")+
      (e.truncated?`<span class="ev-trunc">${esc("truncated")}</span>`:'')+`</div>`+
      `<div class="ev-sum">${esc(e.summary||"")}</div>`+
      // The raw output is the proof, not the headline: it opens when doubted.
      (e.raw_excerpt?`<details class="ev-more"><summary>${icon("chevron-right")}${esc("Show raw output")}</summary>`+
        `<pre class="ev-ex">${esc(e.raw_excerpt)}</pre></details>`:"")+`</div>`;
  }).join("");
}
async function loadEvidence(){
  if(!sessionId) return;
  try{ const r=await (await fetch(`/api/projects/${sessionId}/evidence`)).json();
    evidenceData=r.evidence||[]; setEcount(evidenceData.length); renderEvidence($("#evSearch")?$("#evSearch").value:""); }
  catch(e){}
}
const _evSearch=$("#evSearch"); if(_evSearch) _evSearch.addEventListener("input",e=>renderEvidence(e.target.value));
const _evAi=$("#evLocalAi"); if(_evAi) _evAi.addEventListener("click",()=>{
  const q=($("#evSearch")?.value||"").trim().toLowerCase();
  const rows=evidenceData.filter(e=>!q||JSON.stringify(e).toLowerCase().includes(q))
    .slice(0,80)
    .map(e=>({id:e.id,source:e.source,tool:e.tool_name,summary:e.summary,location:e.location,truncated:e.truncated,excerpt:(e.raw_excerpt||"").slice(0,500)}));
  localAssist("evidence","Separate facts, gaps and useful links to findings/sinks/sources.",{query:q,total:evidenceData.length,evidence:rows},"#evAiOut");
});

/* ---------- findings ---------- */
const findingKeyIdx = new Map();

function localizeFindingText(text){
  text = text == null ? "" : String(text);
  if(!text) return text;
  const missing = text.match(/^Mitigazione assente:\s*(.+)$/i);
  if(missing) return `Missing mitigation: ${missing[1]}`;
  const mitigationDesc = text.match(/^(.+?):\s*la mitigazione non risulta attiva nel binario analizzato\.$/i);
  if(mitigationDesc) return `${mitigationDesc[1]}: this mitigation does not appear to be enabled in the analyzed binary.`;
  if(text.includes("e' come lasciare una porta") || text.includes("come lasciare una porta") || text.includes("non e' un buco") || text.includes("non è un buco")){
    return "This is a standard security protection that the program has not enabled. By itself it is not a vulnerability, but if another defect exists it can make exploitation much easier.";
  }
  if(text.startsWith("Abilita la mitigazione nella toolchain")){
    return "Enable the mitigation in the toolchain (for MSVC: /GS, /DYNAMICBASE, /NXCOMPAT, /guard:cf, /SAFESEH) and verify again with checksec. By itself this does not introduce a vulnerability, but it increases exploitability of memory-corruption bugs.";
  }
  const replacements = [
    [/mitigazione non risulta attiva nel binario analizzato/gi, "mitigation does not appear to be enabled in the analyzed binary"],
    [/La sola presenza non e una vulnerabilita/gi, "Presence alone is not a vulnerability"],
    [/La sola presenza non è una vulnerabilità/gi, "Presence alone is not a vulnerability"],
    [/occorre verificare/gi, "you must verify"],
    [/Da confermare/gi, "To be confirmed"],
    [/Possibile/gi, "Possible"],
    [/pericolos[oa]/gi, "dangerous"],
    [/vulnerabilita/gi, "vulnerability"],
    [/vulnerabilità/gi, "vulnerability"],
    [/evidenza/gi, "evidence"],
    [/raccomandazione/gi, "recommendation"],
    [/binario analizzato/gi, "analyzed binary"],
    [/input controllabile/gi, "controllable input"],
    [/validazione dinamica/gi, "dynamic validation"],
    [/confermato/gi, "confirmed"],
    [/ipotesi/gi, "hypothesis"]
  ];
  for(const [re, repl] of replacements) text = text.replace(re, repl);
  return text;
}
/* ---------- findings: list, filters and the case file ----------
   A finding is a case, not a row. The list is a triage surface (filter by severity, status and
   class); the detail view is the case file an analyst would hand to a developer: what it is, where
   it is, what supports it, what is still missing, and what to do about it. */

const FINDING_CLASS_LABEL = {
  vulnerability: "Vulnerability", hardening: "Hardening weakness",
  informational: "Informational", rejected: "Rejected",
};

/* Mirrors reforge/assessment.py:classify() so the list and the dashboard never disagree. */
function findingClass(f){
  const st=(f.status||"").trim().toLowerCase();
  if(st==="rejected"||st==="false_positive") return "rejected";
  if((f.vuln_type||"").trim().toLowerCase()==="hardening") return "hardening";
  if(st==="indicator"||st==="observation") return "informational";
  if(f.evidence_bundle && f.evidence_bundle.isolated_only) return "informational";
  if((f.severity||"INFO").toUpperCase()==="INFO") return "informational";
  return "vulnerability";
}

const SEV_ORDER={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
let findingFilter={q:"",severity:"",cls:"",status:""};

/* One finding = one row, in a fixed column order: severity, what it is,
   how it is classified, how well it is backed. Reading down the list is the
   whole job, so nothing may reflow between rows. */
function findingCardHTML(f){
  const cls=findingClass(f);
  const conf=f.confidence!=null?Math.round(findingConfidence(f)*100):null;
  const evCount=(f.evidence_refs||[]).length;
  const sev=esc((f.severity||"INFO").toUpperCase());
  return `<div class="f-top">`+
      `<span class="sev sev-${sev}">${esc(f.severity||"INFO")}</span>`+
    `</div>`+
    `<div class="f-main">`+
      `<div class="f-title">${esc(localizeFindingText(f.title||""))}</div>`+
      (f.location?`<div class="f-loc" title="${esc(f.location)}">${esc(f.location)}</div>`:"")+
    `</div>`+
    `<div class="f-meta">`+
      `<span class="f-class f-class-${cls}">${esc(FINDING_CLASS_LABEL[cls])}</span>`+
      (f.cwe?`<span class="cwe">${esc(f.cwe)}</span>`:"")+
    `</div>`+
    `<div class="f-foot">`+
      `<span class="f-status" title="${esc("Validation status")}">${esc(findingStatusLabel(f.status))}</span>`+
      (conf!=null?`<span class="f-conf" title="${esc("Deterministic confidence from evidence signals")}">${conf}% ${esc("conf.")}</span>`:"")+
      `<span class="f-ev" title="${esc("Linked evidence records")}">${icon("evidence")}${evCount}</span>`+
    `</div>`;
}

function findingConfidence(f){
  const v=f.confidence;
  if(v==null||v==="") return 0;
  const n=Number(v);
  if(!Number.isFinite(n)) return 0;
  return n>1 ? Math.min(1,n/100) : Math.max(0,n);
}

function findingMatchesFilter(f){
  const g=findingFilter;
  if(g.severity && (f.severity||"INFO").toUpperCase()!==g.severity) return false;
  if(g.cls && findingClass(f)!==g.cls) return false;
  if(g.status && findingStatusLabel(f.status)!==g.status) return false;
  if(g.q){
    const hay=`${f.title||""} ${f.cwe||""} ${f.location||""} ${f.description||""} ${f.vuln_type||""}`.toLowerCase();
    if(!hay.includes(g.q.toLowerCase())) return false;
  }
  return true;
}

function renderFindings(){
  const box=$("#findingsList"); if(!box) return;
  setCount("#fcount", findingsData.length);

  const visible=findingsData
    .map((f,idx)=>({f,idx}))
    .filter(x=>findingMatchesFilter(x.f))
    .sort((a,b)=>(SEV_ORDER[(a.f.severity||"INFO").toUpperCase()]??4)-(SEV_ORDER[(b.f.severity||"INFO").toUpperCase()]??4));

  const counts=findingsData.reduce((acc,f)=>{ const c=findingClass(f); acc[c]=(acc[c]||0)+1; return acc; },{});
  const sum=$("#findingsSummary");
  if(sum){
    sum.textContent=findingsData.length
      ? `${counts.vulnerability||0} vulnerabilities · ${counts.hardening||0} hardening · `
        + `${counts.informational||0} informational${counts.rejected?` · ${counts.rejected} rejected`:""}`
        + (visible.length!==findingsData.length?`  —  showing ${visible.length}`:"")
      : "";
  }

  if(!findingsData.length){
    box.innerHTML=`<div class="empty-state"><div class="empty-state-ic">${icon("flag","ic ic-lg")}</div>`+
      `<h3>No findings yet</h3>`+
      `<p>No vulnerability has been identified for this target. Run a vulnerability audit, or `+
      `review the attack surface to decide where to look first.</p>`+
      `<div class="empty-state-actions">`+
        `<button class="solid-btn" type="button" data-empty-action="playbooks">Run a playbook</button>`+
        `<button class="btn-sm" type="button" data-empty-action="posture">Review attack surface</button>`+
      `</div></div>`;
    return;
  }
  if(!visible.length){
    box.innerHTML=`<div class="empty-state"><div class="empty-state-ic">${icon("search","ic ic-lg")}</div>`+
      `<h3>No finding matches these filters</h3>`+
      `<p>${findingsData.length} finding${findingsData.length===1?"":"s"} exist in this project.</p>`+
      `<div class="empty-state-actions"><button class="btn-sm" type="button" id="fClearFilters">Clear filters</button></div></div>`;
    const c=$("#fClearFilters");
    if(c) c.onclick=()=>{ findingFilter={q:"",severity:"",cls:"",status:""}; syncFindingFilterUI(); renderFindings(); };
    return;
  }

  box.innerHTML="";
  visible.forEach(({f,idx})=>{
    const el=document.createElement("button");
    el.type="button";
    el.className="finding sev-"+((f.severity||"INFO").toUpperCase());
    el.dataset.fidx=idx;
    el.innerHTML=findingCardHTML(f);
    el.onclick=()=>openFinding(idx);
    box.appendChild(el);
  });
}

function syncFindingFilterUI(){
  const q=$("#fSearch"); if(q) q.value=findingFilter.q;
  const sv=$("#fSeverity"); if(sv) sv.value=findingFilter.severity;
  const cl=$("#fClass"); if(cl) cl.value=findingFilter.cls;
}

function addFinding(f, replay){
  const key=((f.title||"")+"|"+(f.location||"")).toLowerCase();
  if(findingKeyIdx.has(key)){
    const idx=findingKeyIdx.get(key);
    findingsData[idx]=Object.assign({},findingsData[idx],f);
    if(replay) return;
    renderFindings();
    const el=$(`#findingsList [data-fidx="${idx}"]`);
    if(el){ el.classList.add("flash"); setTimeout(()=>el.classList.remove("flash"),900); }
    return;
  }
  const idx=findingsData.push(f)-1;
  findingKeyIdx.set(key,idx);
  // A project load replays every stored finding and renders once at the end; rendering here
  // rebuilt the whole list once per finding.
  if(replay) return;
  renderFindings();
  // New evidence changes what the dashboard and the search index should show.
  if(typeof invalidatePaletteIndex==="function") invalidatePaletteIndex();
}

function resetFindings(){
  findingsData.length=0; findingKeyIdx.clear();
  renderFindings();
}

/* ---------- case file ---------- */

let _findingAux={validator:null, chains:null, forSession:null};

/* Validator verdicts and candidate source→sink chains are fetched once per project and reused by
   every case file. A failure in either narrows the case file; it never blocks it. */
async function ensureFindingAux(){
  if(_findingAux.forSession===sessionId) return _findingAux;
  _findingAux={validator:null, chains:null, forSession:sessionId};
  try{
    const r=await fetch(`/api/projects/${sessionId}/validate-findings`);
    if(r.ok) _findingAux.validator=await r.json();
  }catch(e){}
  try{
    const r=await fetch(`/api/projects/${sessionId}/source-to-sink`);
    if(r.ok) _findingAux.chains=(await r.json()).chains||[];
  }catch(e){}
  return _findingAux;
}

function evidenceById(id){
  return (evidenceData||[]).find(e=>e && e.id===id) || null;
}

/* Evidence records carry `location` as a dict ({function|address: "..."}), so stringify it
   explicitly rather than letting it render as [object Object]. */
function evidenceLocationText(loc){
  if(!loc) return "";
  if(typeof loc==="string") return loc;
  if(typeof loc!=="object") return String(loc);
  return Object.entries(loc).filter(([,v])=>v!=null&&v!=="")
    .map(([k,v])=>`${k} ${v}`).join(", ");
}

/* Candidate chains whose sink actually appears in this finding. `from_session` enumerates
   sources × sinks, so these are hypotheses — the UI must say so unless a call site was resolved. */
function chainsForFinding(f, chains){
  if(!chains || !chains.length) return [];
  const hay=`${f.title||""} ${f.description||""} ${f.location||""}`.toLowerCase();
  return chains.filter(c=>c.sink && hay.includes(String(c.sink).toLowerCase())).slice(0,6);
}

function sourceSinkHtml(f, chains){
  const rows=chainsForFinding(f, chains);
  if(!rows.length){
    return `<p class="cf-note">No source→sink path has been established for this finding. A path is
      what distinguishes a dangerous API that is reachable from untrusted input from one that is
      not — resolving it is the single most valuable next step.</p>`;
  }
  return rows.map(c=>{
    const demonstrated=!!(c.function||c.callsite);
    const steps=[
      {k:"Input source", v:c.source, kind:"src"},
      c.function?{k:"Function", v:c.function, kind:"fn"}:null,
      c.callsite?{k:"Call site", v:c.callsite, kind:"cs"}:null,
      {k:"Dangerous sink", v:c.sink, kind:"sink"},
    ].filter(Boolean);
    return `<div class="s2s ${demonstrated?"demonstrated":"candidate"}">
      <div class="s2s-head">
        <span class="s2s-state">${demonstrated?"Call site resolved":"Candidate — not demonstrated"}</span>
        ${c.confidence!=null?`<span class="s2s-conf">confidence ${Math.round(Number(c.confidence)*100)}%</span>`:""}
        ${c.confirmed_dynamic?`<span class="s2s-dyn">confirmed at runtime</span>`:""}
      </div>
      <ol class="s2s-path">${steps.map(st=>`<li class="s2s-step k-${st.kind}">
        <span class="s2s-k">${esc(st.k)}</span><span class="s2s-v mono">${esc(String(st.v))}</span></li>`).join("")}</ol>
      ${c.argument?`<p class="cf-note">Tainted argument: <code>${esc(c.argument)}</code></p>`:""}
      ${c.notes?`<p class="cf-note">${esc(c.notes)}</p>`:""}
    </div>`;
  }).join("");
}

function validationHtml(f, verdict){
  if(!verdict){
    return `<p class="cf-note">The deterministic validator is unavailable for this project, so the
      status shown is the one recorded on the finding itself.</p>`;
  }
  const missing=(verdict.warnings||[]);
  return `
    <div class="cf-verdict">
      <div class="cf-verdict-main">
        <span class="cf-verdict-status st-${esc((verdict.status||"").toLowerCase())}">${esc(verdict.status||"")}</span>
        <span class="cf-verdict-conf">${Math.round((verdict.confidence||0)*100)}% confidence</span>
        <span class="cf-verdict-exp ${verdict.exportable_as_confirmed?"yes":"no"}">
          ${verdict.exportable_as_confirmed?"Exportable as CONFIRMED":"Not exportable as CONFIRMED"}</span>
      </div>
      <p class="cf-note">Status is gated deterministically — the model cannot promote a finding by
      asserting it. Each requirement below has to be satisfied by a real record.</p>
    </div>
    ${missing.length
      ? `<h4 class="cf-h4">What is still missing</h4>
         <ul class="cf-missing">${missing.map(w=>`<li>${esc(w)}</li>`).join("")}</ul>
         <p class="cf-note">Satisfying these promotes the finding automatically on the next
         validation pass; nothing has to be set by hand.</p>`
      : `<p class="cf-ok">Every validation requirement is satisfied for this finding.</p>`}`;
}

function evidenceHtml(f){
  const refs=f.evidence_refs||[];
  if(!refs.length){
    const inline=f.evidence || [f.evidence_source,f.evidence_type].filter(Boolean).join(" — ");
    return inline
      ? `<p class="cf-inline-ev">${esc(Array.isArray(inline)?inline.join("; "):String(inline))}</p>
         <p class="cf-note">This finding cites its source but has no stored evidence record. Linking
         one makes it traceable and quotable in the report.</p>`
      : `<p class="cf-note">No evidence is linked to this finding. It cannot be defended in a
         report until something supports it.</p>`;
  }
  return `<ul class="cf-ev-list">${refs.map(id=>{
    const e=evidenceById(id);
    return `<li class="cf-ev">
      <button class="cf-ev-id mono" type="button" data-ev-open="${esc(id)}" title="Open in the Evidence view">${esc(id)}</button>
      ${e?`<span class="cf-ev-body">
             <strong>${esc(e.summary||"")}</strong>
             <span class="cf-ev-meta">${esc([e.source,e.tool_name,evidenceLocationText(e.location)].filter(Boolean).join(" · "))}</span>
           </span>`
        :`<span class="cf-ev-body"><span class="cf-ev-meta">Record not loaded in this view.</span></span>`}
    </li>`;
  }).join("")}</ul>`;
}

function relatedHtml(f){
  const vt=(f.vuln_type||"").toLowerCase();
  const related=findingsData
    .map((x,i)=>({x,i}))
    .filter(({x})=>x!==f && ((x.vuln_type||"").toLowerCase()===vt || (x.cwe && x.cwe===f.cwe)))
    .slice(0,6);
  const imports=(importsData||[]).filter(n=>{
    const hay=`${f.title||""} ${f.description||""}`.toLowerCase();
    return hay.includes(String(n).toLowerCase());
  }).slice(0,8);

  if(!related.length && !imports.length) return "";
  return `
    ${related.length?`<h4 class="cf-h4">Related findings</h4>
      <ul class="cf-related">${related.map(({x,i})=>`<li>
        <button type="button" data-open-finding="${i}">
          <span class="sev sev-${esc((x.severity||"INFO").toUpperCase())}">${esc(x.severity||"INFO")}</span>
          ${esc(localizeFindingText(x.title||""))}</button></li>`).join("")}</ul>`:""}
    ${imports.length?`<h4 class="cf-h4">Related imports</h4>
      <div class="api-chips">${imports.map(n=>`<button class="api-chip" type="button" data-api="${esc(n)}">${esc(n)}</button>`).join("")}</div>`:""}`;
}

async function openFinding(idx){
  const f=findingsData[idx]; if(!f) return;
  const modal=$("#findingModal"), body=$("#findingBody");
  if(!modal||!body) return;
  const cls=findingClass(f);
  const sevUp=(f.severity||"INFO").toUpperCase();

  // Render what we already have immediately; enrich once the auxiliary data arrives.
  const shell=(extra)=>`
    <article class="case-file">
      <header class="cf-head sev-${esc(sevUp)}">
        <div class="cf-badges">
          <span class="cf-sev sev-${esc(sevUp)}">${esc(sevUp)}</span>
          <span class="f-class f-class-${cls}">${esc(FINDING_CLASS_LABEL[cls])}</span>
          <span class="cf-status">${esc(findingStatusLabel(f.status))}</span>
          ${f.cwe?`<span class="cf-cwe">${esc(f.cwe)}</span>`:""}
          ${f.cvss?`<span class="cf-cvss" title="${esc(f.cvss_vector||"CVSS")}">CVSS ${esc(String(f.cvss))}</span>`:""}
          ${f.potential_severity&&f.potential_severity!==sevUp
            ? `<span class="cf-pot" title="Worst case if this is reachable from untrusted input">worst case ${esc(f.potential_severity)}</span>`:""}
        </div>
        <h2 class="cf-title">${esc(localizeFindingText(f.title||""))}</h2>
        ${f.location?`<div class="cf-loc mono">${esc(f.location)}</div>`:""}
      </header>

      <div class="cf-cols">
      <div class="cf-col">
      ${f.plain?`<section class="cf-sec cf-plain">
        <h3 class="cf-h">Summary</h3>
        <p>${esc(localizeFindingText(f.plain))}</p></section>`:""}

      ${f.description?`<section class="cf-sec">
        <h3 class="cf-h">Technical analysis</h3>
        <p>${esc(localizeFindingText(f.description))}</p></section>`:""}

      ${f.impact?`<section class="cf-sec">
        <h3 class="cf-h">Impact</h3><p>${esc(localizeFindingText(f.impact))}</p></section>`:""}

      ${(f.recommendation||f.remediation)?`<section class="cf-sec cf-fix">
        <h3 class="cf-h">Remediation</h3>
        <p>${esc(localizeFindingText(f.recommendation||f.remediation))}</p></section>`
        :`<section class="cf-sec"><h3 class="cf-h">Remediation</h3>
          <p class="cf-note">No remediation recorded yet. A finding without one is incomplete for a
          developer audience.</p></section>`}

      ${f.references?`<section class="cf-sec">
        <h3 class="cf-h">References</h3><p class="wrap">${esc(Array.isArray(f.references)?f.references.join(", "):String(f.references))}</p></section>`:""}
      </div>

      <div class="cf-col">
      <section class="cf-sec">
        <h3 class="cf-h">Location</h3>
        <dl class="kv-grid">
          ${currentTargetName()?`<dt>Binary</dt><dd class="mono">${esc(currentTargetName())}</dd>`:""}
          ${f.location?`<dt>Function / address</dt><dd class="mono wrap">${esc(f.location)}</dd>`:`<dt>Function / address</dt><dd class="cf-unknown">not resolved</dd>`}
          ${f.vuln_type?`<dt>Class</dt><dd>${esc(f.vuln_type)}</dd>`:""}
          ${f.evidence_source?`<dt>Discovered by</dt><dd>${esc(f.evidence_source)}</dd>`:""}
        </dl>
      </section>

      <section class="cf-sec">
        <h3 class="cf-h">Source → sink</h3>
        ${extra.s2s}
      </section>

      <section class="cf-sec">
        <h3 class="cf-h">Evidence</h3>
        ${evidenceHtml(f)}
      </section>

      <section class="cf-sec">
        <h3 class="cf-h">Validation</h3>
        ${extra.validation}
      </section>

      ${relatedHtml(f)?`<section class="cf-sec">${relatedHtml(f)}</section>`:""}
      </div>
      </div>

      <footer class="cf-actions">
        <button id="askFinding" class="ask-ai" type="button">${icon("sparkle")}Investigate with the assistant</button>
        <span class="fd-hint">Opens the assistant with this case as context.</span>
      </footer>
    </article>`;

  body.innerHTML=shell({
    s2s:`<p class="cf-note">Loading dataflow candidates…</p>`,
    validation:`<p class="cf-note">Loading validation verdict…</p>`,
  });
  modal.hidden=false;
  const card=modal.querySelector(".modal-card");
  if(card) card.classList.add("wide");

  const bind=()=>{
    const ask=$("#askFinding");
    if(ask) ask.onclick=()=>{ modal.hidden=true; askFindingDetail(f); };
    body.querySelectorAll("[data-open-finding]").forEach(b=>{
      b.onclick=()=>openFinding(Number(b.dataset.openFinding));
    });
  };
  bind();

  const aux=await ensureFindingAux();
  if(modal.hidden) return;                      // the operator closed it while we were loading
  const verdict=aux.validator && aux.validator.results
    ? aux.validator.results[idx] || null : null;
  body.innerHTML=shell({
    s2s: sourceSinkHtml(f, aux.chains),
    validation: validationHtml(f, verdict),
  });
  bind();
}

/* findings filter wiring */
{
  const q=$("#fSearch");
  if(q) q.addEventListener("input",e=>{ findingFilter.q=e.target.value; renderFindings(); });
  const sv=$("#fSeverity");
  if(sv) sv.addEventListener("change",e=>{ findingFilter.severity=e.target.value; renderFindings(); });
  const cl=$("#fClass");
  if(cl) cl.addEventListener("change",e=>{ findingFilter.cls=e.target.value; renderFindings(); });
}

function currentTargetName(){
  const el=$("#targetPath");
  const p=el && el.value ? el.value : "";
  return p ? p.split(/[\\/]/).pop() : "";
}

function askFindingDetail(f){
  sendMessage(
    "Analyze this finding in detail: root cause, whether it is exploitable in the target's context, "
    + "one concrete attack scenario, and the remediation. If useful, inspect or decompile the "
    + "surrounding code to support the analysis.\n\n"
    + `Finding: "${f.title||""}" - ${f.cwe||"no CWE"} - severity ${f.severity||"INFO"} - location ${f.location||"n/a"}.\n`
    + `Current description: ${f.description||"(none)"}`);
}

/* ---------- SSE ---------- */
function handle(e){
  switch(e.kind){
    case "assistant_delta": appendDelta(e.text); break;
    case "assistant_end": rgFinishAnswer(); endAssistant(); break;
    case "assistant": addMsg("assistant",e.text); rgCaptureAnswerFull(e.text); rgFinishAnswer(); break;
    case "note": addNote(e.text); break;
    case "static_done": addNote(`Static analysis complete: ${e.summary||""}`,"static"); break;
    case "tools_loaded": addNote(`Loaded ${e.count} tools`+(e.tools&&e.tools.length?": "+e.tools.join(", "):"")); break;
    case "consult": addKnowledge(e); break;
    case "ctx_warning": addNote(`Context at ${Math.round(e.pct*100)}% of ${e.ctx} tokens — truncation is possible.`,"warn"); break;
    case "finding": addFinding(e.finding||{}); break;
    case "evidence": if(e.evidence){ evidenceData.push(e.evidence); setEcount(evidenceData.length); if($("#view-evidence").classList.contains("active")) renderEvidence($("#evSearch")?$("#evSearch").value:""); } break;
    case "phase": renderPhase(e); break;
    case "usage": renderUsage(e.summary, e.last); break;
    case "tool_call": if(e.meta){endAssistant();break;} addTool(e); break;
    case "tool_result": {
      if(e.meta) break;
      setTcount((parseInt($("#tcount").textContent,10)||0)+1);
      if($("#view-toollog") && $("#view-toollog").classList.contains("active")) loadToollog();
      const card=cards.last; if(!card) break;
      const out=card.querySelector(".tool-out"); out.textContent=e.text||"(no output)";
      if(e.is_error||e.denied) out.classList.add("err");
      card.querySelector(".tool-status").textContent=e.denied?"denied":(e.is_error?"error":"ok");
      break;
    }
    case "awaiting_approval": renderApproval(e); break;
    case "awaiting_reload": renderReloadWait(e); break;
    case "status": { const b=$("#status"); b.hidden=false; $("#statusText").textContent=e.text; b.classList.toggle("busy",!!e.busy); break; }
    case "error": addMsg("assistant",e.text); setIdle(); break;
    case "stopped": addNote("Turn stopped.","warn"); setIdle(); break;
    case "user_message": {
      // The sending tab drew its bubble before the POST and expects exactly one echo of that
      // text; every other tab draws it. Comparing with the last visible bubble was wrong: a
      // resend of the same text looked like "already drawn" everywhere.
      if(pendingEcho===e.text){ pendingEcho=null; break; }
      addMsg("user",e.text);
      break; }
    case "done": endAssistant(); setIdle(); break;
  }
}
function renderReloadWait(e){
  clearEmpty(); endAssistant();
  const card=document.createElement("div");
  card.className="reload-wait";
  card.innerHTML=`<div class="rw-icon">${icon("alert","ic ic-lg")}</div><div class="rw-body">`+
    `<strong>Waiting for the binary to be reloaded</strong>`+
    `<span>${esc(e.reason||"The process has terminated.")}</span>`+
    (e.next_plan?`<span class="rw-plan">On reload: ${esc(e.next_plan)}</span>`:"")+
    `<span class="rw-hint">Reload the target in x64dbg and send a message (e.g. «reloaded») to continue.</span>`+
    `</div>`;
  stream.appendChild(card); scrollDown();
}
/* ---------- approval gate ----------
   An approval is informed consent, not a confirmation dialog. The card has to answer, without the
   operator opening anything: which tool, what operation, on what target, why it was requested, and
   what approving it permits. Deny is the resting state — it holds focus, and Approve is styled as
   the deliberate, consequential action it is. */

const RISK_TONE = {HIGH:"crit", MEDIUM:"high", LOW:"info"};

/* Arguments that name the thing being acted on, most specific first. */
const APPROVAL_TARGET_KEYS = ["address","addr","va","rva","offset","path","file","file_path",
  "filename","target","module","dll","process","pid","key","registry","url","host","endpoint",
  "function","name","symbol"];

function approvalTarget(args){
  if(!args || typeof args!=="object") return null;
  for(const k of APPROVAL_TARGET_KEYS){
    if(args[k]!=null && args[k]!==""){
      const v=args[k];
      return {key:k, value:(typeof v==="object")?JSON.stringify(v):String(v)};
    }
  }
  return null;
}

/* A one-line description of the operation, derived from the tool name and its arguments.
   Falls back to the bare tool name — it never invents an operation it cannot read. */
function approvalOperation(tool, args){
  const base=(tool||"").split("__").pop();
  const a=args||{};
  const size=a.size ?? a.length ?? a.count ?? a.bytes ?? null;
  const data=a.data ?? a.value ?? a.bytes_data ?? null;
  const n = size!=null ? size : (typeof data==="string" ? Math.ceil(data.length/2) : null);
  const t=approvalTarget(a);
  const where=t?` at ${t.value}`:"";
  const verb=base.toLowerCase();
  if(verb.includes("memorywrite")||verb.includes("writememory"))
    return `Write${n!=null?` ${n} bytes`:""} to target process memory${where}`;
  if(verb.includes("assemble")) return `Assemble and patch instructions${where}`;
  if(verb.includes("patch")) return `Patch the binary${where}`;
  if(verb.includes("registerset")||verb.includes("flagset")) return `Set CPU register/flag state${where}`;
  if(verb.includes("setprotect")||verb.includes("pagerights")) return `Change memory page protection${where}`;
  if(verb.includes("alloc")) return `Allocate memory in the target process${where}`;
  if(verb.includes("free")) return `Free memory in the target process${where}`;
  if(verb.startsWith("debugrun")||verb==="run"||verb.includes("continue")) return `Resume execution of the target process`;
  if(verb.includes("step")) return `Single-step the target process`;
  if(verb.includes("execcommand")) return `Execute a debugger command: ${esc(String(a.command??a.cmd??"")).slice(0,80)}`;
  if(verb.includes("delete")||verb.includes("remove")) return `Delete${where||" the referenced item"}`;
  if(verb.includes("export")) return `Write results to a file on disk${where}`;
  if(verb.includes("download")||verb.includes("fetch")||verb.includes("http")) return `Contact a remote service${where}`;
  return `Run ${base}${where}`;
}

function renderApproval(e){
  clearEmpty(); endAssistant();
  const [server, toolName] = (e.tool||"").includes("__")
    ? e.tool.split("__") : ["", e.tool||""];
  const level=(e.risk_level||"").toUpperCase();
  const tone=RISK_TONE[level]||"high";
  const target=approvalTarget(e.args);
  const operation=approvalOperation(e.tool, e.args);
  const argsJson=JSON.stringify(e.args??{}, null, 2);

  const card=document.createElement("div");
  card.className=`approval-card tone-${tone}`;
  card.setAttribute("role","alertdialog");
  card.setAttribute("aria-label","Action requires approval");
  card.innerHTML=`
    <div class="ap-head">
      <span class="ap-flag">${icon("alert","ic ic-lg")}</span>
      <span class="ap-title">Action requires approval</span>
      ${level?`<span class="ap-risk tone-${tone}">Risk: ${esc(level)}</span>`:""}
    </div>
    <div class="ap-route">
      ${server?`<span class="ap-server">${esc(server)}</span><span class="ap-arrow">${icon("arrow-right")}</span>`:""}
      <span class="ap-tool mono">${esc(toolName)}</span>
      ${e.risk_class?`<span class="ap-class">${esc(String(e.risk_class).replace(/_/g," "))}</span>`:""}
    </div>
    <dl class="ap-grid">
      ${target?`<dt>Target</dt><dd class="mono">${esc(target.value)}</dd>`:""}
      <dt>Operation</dt><dd>${esc(operation)}</dd>
      ${e.reason?`<dt>Reason</dt><dd>${esc(e.reason)}</dd>`:""}
    </dl>
    ${e.consequence?`<p class="ap-consequence"><strong>What approving this permits:</strong> ${esc(e.consequence)}</p>`:""}
    <details class="ap-args">
      <summary>Full arguments (${Object.keys(e.args||{}).length})</summary>
      <pre class="mono">${esc(argsJson)}</pre>
    </details>`;

  const bar=document.createElement("div");
  bar.className="ap-actions";
  bar.innerHTML=`<button class="ap-btn ap-deny" type="button">Deny</button>`+
    `<button class="ap-btn ap-approve" type="button">Approve</button>`;

  let resolved=false;
  const decide=async(d)=>{
    if(resolved) return; resolved=true;
    bar.querySelectorAll("button").forEach(b=>b.disabled=true);
    try{
      const r=await fetch("/api/approve",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({session_id:sessionId,approval_id:e.approval_id,decision:d})});
      const j=await r.json().catch(()=>({}));
      if(!j.ok){   // approval expired / turn already ended: let the operator retry
        resolved=false; bar.querySelectorAll("button").forEach(b=>b.disabled=false);
        addNote("This approval is no longer valid — the turn ended or it expired.","warn"); return;
      }
    }catch(err){
      resolved=false; bar.querySelectorAll("button").forEach(b=>b.disabled=false);
      addNote("Network error sending the decision: "+err,"warn"); return;
    }
    bar.remove();
    const res=document.createElement("div");
    res.className="ap-resolved "+(d==="approve"?"yes":"no");
    res.innerHTML=icon(d==="approve"?"check":"x")+esc(d==="approve"
      ? "Approved — the action was executed"
      : "Denied — the action was not executed");
    card.appendChild(res);
  };
  bar.querySelector(".ap-approve").onclick=()=>decide("approve");
  bar.querySelector(".ap-deny").onclick=()=>decide("deny");
  card.appendChild(bar);
  stream.appendChild(card); cards.last=card; scrollDown();
  // Deny holds focus: an accidental Enter must never authorize a state-changing action.
  bar.querySelector(".ap-deny").focus({preventScroll:true});
}
function enable(on){ $("#send").disabled=!on; $("#input").disabled=!on; }

/* ---------- projects ---------- */
function resetChat(){ stream.innerHTML=EMPTY_HTML; currentAssistant=null; cards.last=null;}
/* `GET /api/projects` answers `{"projects": [...]}` (an envelope, like every list endpoint since
   P0-S5). Four call sites here still expected a bare array and crashed with `list.map is not a
   function` - on first load, which is to say the project list never rendered. One reader. */
async function fetchProjects(){
  const j = await (await fetch("/api/projects")).json();
  return Array.isArray(j) ? j : (j && Array.isArray(j.projects) ? j.projects : []);
}
/* The banner used to mean "no provider configured". A configured local server that is not
   running is the more common case, and it looked like everything was fine until the first turn
   died with "Connection error". `llm_reachable` is null when the question does not apply. */
function renderLlmBanner(st){
  const el=$("#llmBanner"); if(!el) return;
  if(!st.llm_available){ el.textContent=t("banner.noLlm"); el.hidden=false; return; }
  if(st.llm_reachable===false){
    el.textContent=t("banner.llmUnreachable").replace("{model}", st.model||"?").replace("{url}", st.llm_base_url||"");
    el.hidden=false; return;
  }
  if(st.llm_error){   // SDK missing, model not pulled, …: anything the status knows is wrong
    el.textContent=t("banner.llmProblem").replace("{url}", st.llm_base_url||"").replace("{error}", st.llm_error);
    el.hidden=false; return;
  }
  el.hidden=true;
}

async function loadProjects(){
  const list=await fetchProjects();
  // rail quick-selector
  const rp=$("#railProj");
  if(rp){ rp.innerHTML=list.map(p=>`<option value="${p.id}" ${p.id===sessionId?"selected":""}>${esc(p.name||("project "+p.id.slice(0,6)))}</option>`).join(""); }
  const box=$("#projects"); box.innerHTML="";
  if(!list.length){ box.innerHTML='<div class="findings-empty">No projects.</div>'; return; }
  for(const p of list){
    const el=document.createElement("div"); el.className="proj"+(p.id===sessionId?" active":"");
    const name=p.name||("unnamed · "+p.id.slice(0,6));
    el.innerHTML=`<span class="pn">${esc(name)}</span><span class="pmeta">${p.findings} ${esc("findings")} · ${p.messages||0} msg</span><button class="pdel" type="button" title="${esc("Delete project")}" aria-label="${esc("Delete project")}">${icon("close","ic")}</button>`;
    el.querySelector(".pn").onclick=()=>openProject(p.id);
    el.querySelector(".pmeta").onclick=()=>openProject(p.id);
    el.querySelector(".pdel").onclick=(ev)=>{ev.stopPropagation();deleteProject(p.id);};
    box.appendChild(el);
  }
}
async function openProject(id){
  const p=await (await fetch(`/api/projects/${id}`)).json();
  sessionId=id; connect(id);
  $("#activeProj").textContent=p.name||("project "+id.slice(0,6));
  $("#targetPath").value=p.target_path||"";
  setMode(p.mode||"auto");
  resetChat(); resetFindings();
  const items=p.transcript||[]; if(items.length) clearEmpty();
  for(const it of items){
    if(it.t==="user"){ addMsg("user",it.text); lastUserText=it.text; }
    else if(it.t==="assistant") addMsg("assistant",it.text);
    else if(it.t==="tool"){ const c=addTool({tool:it.tool,args:it.args,gated:false});
      if(it.result!=null){ const o=c.querySelector(".tool-out"); o.textContent=it.result; if(it.error)o.classList.add("err");
        c.querySelector(".tool-status").textContent=it.error?"error":"ok"; } }
  }
  (p.findings||[]).forEach(f=>addFinding(f,true)); renderFindings();
  evidenceData = p.evidence||[]; setEcount(evidenceData.length); renderEvidence("");
  toollogData = []; setTcount((p.transcript||[]).filter(it=>it.t==="tool").length);
  stringsData = p.static_strings||[]; strAiOverrides = new Map(); strAiOverrideMeta = new Map(); setCount("#scount",stringsData.length);
  // Re-hydrate persisted high-signal reassignments so the move survives reload.
  hydrateStringOverrides(p.string_overrides||{});
  importsData = p.static_imports||[]; importsShown=IMPORTS_PAGE; setCount("#icount",importsData.length);
  artifactsData = p.artifacts||[]; setCount("#acount",artifactsData.length||"");
  renderUsage(p.usage_summary || usageSummaryFromRows(p.llm_usage||[]));
  loadPhase();
  // The global search index is a snapshot of one project: drop it so a search never returns
  // findings belonging to the project the operator just left.
  if(typeof invalidatePaletteIndex==="function") invalidatePaletteIndex();
  // Keep the landing view current whichever tab is open when the project changes.
  if(typeof loadAssessment==="function") loadAssessment();
  enable(true); loadProjects();
}
async function createProject(){
  const name=$("#projName").value.trim()||null;
  const r=await (await fetch("/api/projects",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name})})).json();
  $("#projName").value=""; await openProject(r.id);
}
async function deleteProject(id){
  if(!confirm("Permanently delete this project (local file)?")) return;
  await fetch(`/api/projects/${id}`,{method:"DELETE"});
  if(id===sessionId){ const list=await fetchProjects();
    if(list.length) await openProject(list[0].id);
    else { const r=await (await fetch("/api/projects",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:"Assessment 1"})})).json(); await openProject(r.id); } }
  else loadProjects();
}
async function setTarget(){
  const path=$("#targetPath").value.trim(); if(!path||!sessionId) return;
  const btn=$("#targetBtn"); btn.textContent="Analyzing..."; btn.disabled=true;
  try{
    await fetch(`/api/projects/${sessionId}/target`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path})});
    strAiOverrides = new Map(); strAiOverrideMeta = new Map();
    switchTab("findings");  // the static findings arrive over SSE
  } finally { btn.textContent=t("projects.target.button"); btn.disabled=false; }
}
function targetStatus(msg,kind){
  const el=$("#targetUploadStatus"); if(!el) return;
  if(!msg){ el.hidden=true; el.textContent=""; return; }
  el.hidden=false; el.className="art-status"+(kind?(" "+kind):""); el.textContent=msg;
}
async function uploadTargetBinary(file){
  if(!sessionId){ targetStatus("Create or select a project before uploading.","err"); return; }
  if(!file) return;
  targetStatus(`${"Uploading"} "${file.name}" (${fmtBytes(file.size)})...`,"busy");
  try{
    const fd=new FormData(); fd.append("file",file,file.name);
    const r=await fetch(`/api/projects/${sessionId}/upload`,{method:"POST",body:fd});
    if(!r.ok){ const t=await r.text(); throw new Error(t||r.status); }
    const data=await r.json();
    $("#targetPath").value=data.path||"";
    targetStatus(`${"Uploaded and ready for analysis"}: ${data.name||file.name}.`,"ok");
    await setTarget();
  }catch(e){ targetStatus("Target upload failed: "+(e.message||e),"err"); }
}
$("#projCreate").addEventListener("click",createProject);
$("#projName").addEventListener("keydown",e=>{if(e.key==="Enter")createProject();});
$("#railProj").addEventListener("change",e=>{ if(e.target.value && e.target.value!==sessionId) openProject(e.target.value); });
$("#railNew").addEventListener("click",()=>{ switchTab("projects"); setTimeout(()=>$("#projName").focus(),50); });
$("#targetBtn").addEventListener("click",setTarget);
$("#targetPath").addEventListener("keydown",e=>{if(e.key==="Enter")setTarget();});
const _targetDrop=$("#targetDrop"); if(_targetDrop){
  _targetDrop.addEventListener("click",e=>{ if(!e.target.closest("label")) $("#targetFile")?.click(); });
  _targetDrop.addEventListener("keydown",e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); $("#targetFile")?.click(); } });
}
$("#diffBtn").addEventListener("click",async()=>{
  const a=$("#diffA").value.trim(), b=$("#diffB").value.trim();
  if(!a||!b) return;
  const btn=$("#diffBtn"); btn.textContent="Diff…"; btn.disabled=true;
  try{
    const r=await (await fetch("/api/diff",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path_a:a,path_b:b})})).json();
    showReport(r.text||r.error||"(empty)");
  } finally { btn.textContent="Diff"; btn.disabled=false; }
});

/* ---------- servers ---------- */
async function loadServers(){
  const list=await (await fetch("/api/servers")).json();
  const box=$("#serversList"); box.innerHTML="";
  for(const s of list){
    const card=document.createElement("div");
    card.className="srv-card "+(s.connected?"up":(s.enabled?"down":""));
    const tools=(s.tools||[]).map(t=>`<div class="srv-tool"><span class="tn">${esc(t.name)}</span><span class="td">${esc(t.description||"")}</span></div>`).join("")||'<div class="muted">no tools</div>';
    card.innerHTML=
      // A row states what the server IS. Nine identical stack traces printed
      // inline told the operator nothing and buried the one row that differed,
      // so the trace moves behind a disclosure and the row carries a word.
      `<div class="srv-row"><span class="led"></span><span class="srv-name">${esc(s.name)}</span>`+
      `<span class="srv-state">${esc(s.connected ? "Connected"
          : (s.enabled ? "Offline" : "Disabled"))}</span>`+
      `<span class="srv-meta">${s.connected ? `${s.tool_count} ${s.tool_count===1?"tool":"tools"} · ` : ""}${esc(s.transport)}</span>`+
      `<button class="srv-toggle-tools" type="button"${s.connected?"":" disabled"}>`+
        `${icon("chevron-down")}${esc("Tools")}</button>`+
      `<label class="switch" title="${esc("Enable or disable this server")}">`+
        `<input type="checkbox" ${s.enabled?"checked":""} aria-label="${esc(s.name)}"><span class="slider"></span></label></div>`+
      (s.error ? `<details class="srv-err"><summary>${icon("chevron-right")}${esc("Why it is offline")}</summary>`+
                 `<pre>${esc(s.error)}</pre></details>` : "")+
      `<div class="srv-tools">${tools}</div>`;
    card.querySelector(".srv-toggle-tools").onclick=()=>card.classList.toggle("open");
    card.querySelector(".switch input").onchange=(ev)=>toggleServer(s.name,ev.target.checked);
    box.appendChild(card);
  }
}
async function toggleServer(name,enabled){
  await fetch(`/api/servers/${name}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled})});
  loadServers();
}

/* ---------- composer ---------- */
/* ---------- composer / launcher ---------- */
let currentMode = "auto";
function setMode(m){ currentMode = m; document.querySelectorAll(".modepill").forEach(p=>p.classList.toggle("active",p.dataset.mode===m)); }
let lastUserText = "";
let pendingEcho = null;   // the user_message event this tab expects back for its own send
async function sendMessage(text){
  if(!text||!sessionId) return;
  switchTab("chat"); clearEmpty(); addMsg("user",text); lastUserText=text; pendingEcho=text;
  setBusy("Sending\u2026");
  let r;
  try{
    r=await fetch("/api/message",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({session_id:sessionId,text,mode:currentMode,llm_route:"api"})});
  }catch(e){ pendingEcho=null; addNote("Could not reach the server: "+(e.message||e),"warn"); setIdle(); return; }
  if(!r.ok){
    // The envelope carries a code and a message; 409 is "a turn is still running".
    let detail=""; try{ const j=await r.json(); detail=(j.error&&j.error.message)||j.detail||""; }catch(e){}
    addNote(r.status===409 ? "A turn is still running - wait for it or press Stop, then send again."
                           : `Message not accepted (HTTP ${r.status}${detail?": "+detail:""}).`,"warn");
    pendingEcho=null; setIdle();
  }
}
const CANNED = {
  static: "Start a complete static analysis of the configured target binary. Use existing static findings as a baseline, map the attack surface, trace source-to-sink paths by decompiling callers of dangerous sinks, locate hardcoded paths or commands, assess exploitability considering missing mitigations, and record findings with exact location and code evidence. Do not execute the target. Show your reasoning step by step.",
  dynamic: "Start a dynamic analysis of the target with x64dbg. Select candidate sinks from the findings, confirm them at runtime with breakpoints and argument inspection, assess reachability and controllability, calculate exploitability, and record confirmed findings. Remove breakpoints after inspection. Show your reasoning step by step.",
  validate: "Validate the findings discovered by offline deterministic analysis. For each HYPOTHESIS finding, use tools to decide whether it is real: decompile call sites, trace source-to-sink arguments with xrefs, and confirm at runtime when needed. Then update the same finding with status, description, impact, evidence, and recommendation. Show your reasoning step by step."
};
function cannedPrompt(mode){ return CANNED[mode] || ""; }
function launch(mode){ setMode(mode); sendMessage(cannedPrompt(mode)); }
$("#composer").addEventListener("submit",ev=>{
  ev.preventDefault();
  const text=$("#input").value.trim(); if(!text) return;
  $("#input").value=""; $("#input").style.height="auto"; sendMessage(text);
});
document.querySelectorAll(".launch-btn").forEach(b=>b.addEventListener("click",()=>launch(b.dataset.launch)));
document.querySelectorAll(".modepill").forEach(b=>b.addEventListener("click",()=>setMode(b.dataset.mode)));
$("#validateAll").addEventListener("click",()=>{ if(!findingsData.length){ alert(t("findings.noValidate")); return; } sendMessage(cannedPrompt("validate")); });
$("#input").addEventListener("input",e=>{e.target.style.height="auto";e.target.style.height=e.target.scrollHeight+"px";});
$("#input").addEventListener("keydown",e=>{
  if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();$("#composer").requestSubmit();return;}
  // ArrowUp in an empty composer recalls the last message sent, to edit or resend.
  if(e.key==="ArrowUp"&&!e.target.value&&lastUserText){ e.preventDefault(); e.target.value=lastUserText; e.target.dispatchEvent(new Event("input")); e.target.setSelectionRange(lastUserText.length,lastUserText.length); }
});
$("#stopBtn").addEventListener("click",async()=>{ $("#stopBtn").disabled=true;
  try{ await fetch("/api/stop",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({session_id:sessionId})}); }
  finally{ $("#stopBtn").disabled=false; } });

/* ---------- report ---------- */
let lastReportMd = "";
function showReport(mdText, warnings){
  lastReportMd = mdText || "";
  let banner="";
  if(warnings && warnings.length){
    const items=warnings.map(w=>`<li class="${w.level}">${esc(w.msg)}</li>`).join("");
    banner=`<div class="rep-warn"><strong>Pre-export validation (${warnings.length})</strong><ul>${items}</ul>`+
      `<span class="rep-warn-note">You can still export; the warnings exist so weak findings are not promoted.</span></div>`;
  }
  $("#reportBody").innerHTML=banner+md(lastReportMd||"(empty)");
  $("#reportModal").hidden=false;
}
async function generateReport(){
  if(!sessionId) return;
  $("#reportBtn").textContent="Generating…"; $("#reportBtn").disabled=true;
  try{
    const r=await (await fetch(`/api/report/${sessionId}`,{method:"POST"})).json();
    showReport(r.markdown||"(empty)", r.warnings);
    if(r.usage_summary) renderUsage(r.usage_summary); loadPhase();
  } finally { $("#reportBtn").textContent="Report"; $("#reportBtn").disabled=false; }
}
$("#reportBtn").addEventListener("click", generateReport);

document.querySelectorAll(".rx[data-fmt]").forEach(b=>b.addEventListener("click",async()=>{
  if(!lastReportMd) return;
  const fmt=b.dataset.fmt; const prev=b.textContent; b.disabled=true; b.textContent="…";
  const nm=($("#activeProj").textContent||"report");
  try{
    const r=await fetch("/api/report/export",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({markdown:lastReportMd, fmt, name:nm})});
    if(!r.ok){ const e=await r.json().catch(()=>({detail:"error"})); alert(e.detail||"Export unavailable"); return; }
    const blob=await r.blob(); const url=URL.createObjectURL(blob);
    const a=document.createElement("a"); a.href=url; a.download=`${nm}.${fmt}`; document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
  } finally { b.disabled=false; b.textContent=prev; }
}));
$("#dlTemplate").addEventListener("click",async()=>{
  const b=$("#dlTemplate"); const prev=b.textContent; b.disabled=true; b.textContent="…";
  try{
    const r=await fetch("/api/report/template?fmt=docx");
    if(!r.ok){ alert("Template unavailable (python-docx is required)"); return; }
    const blob=await r.blob(); const url=URL.createObjectURL(blob);
    const a=document.createElement("a"); a.href=url; a.download="template_relazione.docx"; document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
  } finally { b.disabled=false; b.textContent=prev; }
});
$("#closeReport").addEventListener("click",()=>$("#reportModal").hidden=true);
$("#closeFinding").addEventListener("click",()=>$("#findingModal").hidden=true);

/* ---------- settings ---------- */
$("#settingsBtn").addEventListener("click",async()=>{
  const s=await (await fetch("/api/settings")).json();
  const r=document.querySelector(`input[name=prov][value="${s.provider_setting}"]`); if(r) r.checked=true;
  $("#setLocalModel").value=s.local_model||""; $("#setLocalUrl").value=s.local_base_url||"";
  $("#setAnthModel").value=s.anthropic_model||""; $("#setAnthKey").value="";
  $("#setAnthKey").placeholder=s.has_anthropic_key?(s.anthropic_key_masked||"•••• (impostata)"):"sk-ant-…";
  const sm=document.querySelector(`input[name=safety][value="${s.safety_mode||"assisted"}"]`); if(sm) sm.checked=true;
  $("#setMsg").textContent=""; $("#setPersist").checked=false; $("#settingsModal").hidden=false;
});
$("#closeSettings").addEventListener("click",()=>$("#settingsModal").hidden=true);
$("#closeSettings2").addEventListener("click",()=>$("#settingsModal").hidden=true);
$("#saveSettings").addEventListener("click",async()=>{
  const prov=document.querySelector("input[name=prov]:checked"); const key=$("#setAnthKey").value;
  const safety=document.querySelector("input[name=safety]:checked");
  const body={provider:prov?prov.value:null,local_model:$("#setLocalModel").value.trim()||null,
    local_base_url:$("#setLocalUrl").value.trim()||null,anthropic_model:$("#setAnthModel").value.trim()||null,
    anthropic_api_key:key||null,safety_mode:safety?safety.value:null,persist:$("#setPersist").checked};
  $("#saveSettings").textContent="Applico…"; $("#saveSettings").disabled=true;
  try{ const r=await (await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
    const model=r.provider_resolved==="local"?r.local_model:r.anthropic_model;
    renderModel(r.provider_resolved,model); renderSafety(r.safety_mode); $("#llmBanner").hidden=r.provider_resolved!=="none"?true:false;
    $("#setMsg").textContent=r.persist_error?("Error: "+r.persist_error):(body.persist?"Applied and saved":"Applied");
  } catch(e){ $("#setMsg").textContent="Error: "+e; }
  finally{ $("#saveSettings").textContent="Apply"; $("#saveSettings").disabled=false; }
});
for(const id of ["reportModal","findingModal","settingsModal"]) $("#"+id).addEventListener("click",e=>{if(e.target.id===id)$("#"+id).hidden=true;});

$("#themeToggle").addEventListener("click", toggleTheme);
applyTheme(document.documentElement.getAttribute("data-theme")||"light");
applyLang();
$("#phaseChip").addEventListener("click", togglePhasePop);

boot();


/* ================================================================
   EVIDENCE GRAPH v6 — grafo investigativo
   Layout force-directed reale, legenda persistente, dossier laterale
   a sezioni chiare. Sostituisce tutte le implementazioni precedenti
   (lane-based / layered) accumulate nelle iterazioni passate.
   ================================================================ */

/* ---------- stato globale ---------- */
let _graphIndex = { nodes: new Map(), edges: [] };
let _gvFullGraph = { nodes: [], edges: [] };
let _gvSelectedId = null;
let _tmState = { mode: "investigation", filtered: { nodes: [], edges: [], matches: new Set() }, hiddenSummary: {} };
let _tmPos = new Map();      // id -> {x,y}
let _tmVel = new Map();      // id -> {x,y} (simulation velocity)
let _tmManual = new Set();   // nodi posizionati manualmente (pin)
const TM_CANVAS_W = 1320;
const TM_CANVAS_H = 820;
let _tmViewBox = { x: 0, y: 0, w: TM_CANVAS_W, h: TM_CANVAS_H };
let _tmDrag = null;
let _tmPan = null;
let _tmSimHandle = null;
let _tmLastSig = "";
let _tmUIBound = false;
let _tmPendingResponse = null;
let _tmSuppressNodeClickUntil = 0;

const TM_MODE_LABELS = {
  investigation: "Full Investigation", evidence: "Evidence Chain", runtime: "Runtime Activity",
  artifact: "Artifact View", attack: "Attack Surface", compact: "Compact View"
};
const TM_SOURCE_KEYS = ["source", "tool", "tool_name", "provider", "origin", "generated_by"];
const TM_CLUSTER_TYPES = new Set(["node_cluster"]);

/* ---------- piccole utility condivise ---------- */
function _shortLabel(label, n) { label = (label || "").toString(); return label.length > n ? label.slice(0, n - 1) + "…" : label; }
function escSvg(s) { return (s ?? "").toString().replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function _nodeColor(t) { return GV_COLORS[t] || "#99a0a5"; }
function tmTypeLabel(t) { return NODE_TYPE_LABEL[t] || t || "node"; }
function tmEdgeSrc(e) { return e?.src ?? e?.source ?? e?.from; }
function tmEdgeDst(e) { return e?.dst ?? e?.target ?? e?.to; }
function tmSafeLabel(n, max = 28) { return _shortLabel((n?.label || (n?.id || "").split(":").pop() || n?.id || "").toString(), max); }
function tmRelLabel(t) { return EDGE_TYPE_LABEL[t] || (t || "").toLowerCase().replaceAll("_", " "); }

function tmAttrs(n) { return n?.attrs || n?.properties || {}; }
function tmNorm(v) { return (v ?? "").toString().toLowerCase().trim().replace(/[\s-]+/g, "_"); }
function tmText(n) {
  const a = tmAttrs(n);
  return `${n?.id || ""} ${n?.type || ""} ${n?.label || ""} ${JSON.stringify(a)}`.toLowerCase();
}
function tmSource(n) {
  const a = tmAttrs(n);
  for (const k of TM_SOURCE_KEYS) { if (a[k]) return tmNorm(a[k]); }
  if ((n.id || "").startsWith("artifact:")) return "user_upload";
  if (["procmon_op", "process", "file_path", "registry_key", "network_endpoint"].includes(n.type)) return "procmon";
  return "";
}
function tmSeverity(n) { const a = tmAttrs(n); return tmNorm(a.severity || a.risk || a.level || ""); }
function tmStatus(n) { const a = tmAttrs(n); return tmNorm(a.status || (a.validated === true ? "confirmed" : (a.validated === false ? "needs_validation" : "")) || ""); }
function tmConfidence(n) {
  const a = tmAttrs(n); let c = a.confidence;
  if (c == null || c === "") return null;
  if (typeof c === "string") {
    const x = c.toLowerCase().trim();
    if (x.endsWith("%")) return Math.max(0, Math.min(1, Number(x.slice(0, -1)) / 100));
    if (x === "critical") return .9; if (x === "high") return .8; if (x === "medium") return .55; if (x === "low") return .3;
  }
  c = Number(c); if (Number.isNaN(c)) return null; return c > 1 ? c / 100 : c;
}
function tmCount(n) { const a = tmAttrs(n); const c = Number(a.count ?? a.events ?? a.event_count ?? a.hits ?? 0); return Number.isFinite(c) ? c : 0; }
function tmIsHighSignalString(n) {
  const txt = tmText(n);
  return /(https?:\/\/|hklm|hkcu|hkey_|password|secret|token|api[_-]?key|cmd\.exe|powershell|createprocess|loadlibrary|private|bearer|\\windows\\|\\appdata\\|error|failed|exception)/i.test(txt);
}
function tmScore(n) {
  const sev = tmSeverity(n), status = tmStatus(n), conf = tmConfidence(n), cnt = tmCount(n);
  let s = { finding: 95, evidence: 78, sink: 78, source: 72, artifact: 70, binary: 68, process: 64, procmon_op: 58, function: 52, import: 50, component: 45, dynamic_event: 60, network_endpoint: 55, registry_key: 42, file_path: 38, string: 18, toolcall: 32, risk: 64 }[n.type] ?? 30;
  if (["critical"].includes(sev)) s += 35; else if (sev === "high") s += 28; else if (sev === "medium") s += 16; else if (sev === "low") s += 5;
  if (["confirmed"].includes(status)) s += 22; else if (status.includes("validation")) s += 15; else if (status === "suspicious") s += 10; else if (status === "false_positive") s -= 40;
  if (conf != null) s += Math.round(conf * 20);
  if (cnt > 0) s += Math.min(26, Math.log10(cnt + 1) * 8);
  if (n.type === "string" && tmIsHighSignalString(n)) s += 40;
  if ((n.label || "").length > 160 && n.type === "string") s -= 12;
  return Math.max(0, Math.round(s));
}
function tmModeTypes(mode) {
  const m = {
    investigation: new Set(["binary", "artifact", "component", "import", "source", "function", "sink", "process", "procmon_op", "file_path", "registry_key", "network_endpoint", "dynamic_event", "evidence", "finding", "risk", "string", "toolcall"]),
    evidence: new Set(["finding", "evidence", "sink", "source", "function", "import", "artifact", "binary", "dynamic_event", "risk"]),
    runtime: new Set(["artifact", "process", "procmon_op", "file_path", "registry_key", "network_endpoint", "dynamic_event", "evidence", "finding"]),
    artifact: new Set(["artifact", "toolcall", "process", "procmon_op", "file_path", "registry_key", "network_endpoint", "evidence", "finding", "binary", "string", "component"]),
    attack: new Set(["binary", "component", "import", "source", "function", "sink", "evidence", "finding", "risk"]),
    compact: new Set(["finding", "evidence", "sink", "source", "artifact", "process", "procmon_op", "binary", "network_endpoint", "registry_key"])
  };
  return m[mode] || m.investigation;
}

/* ---------- controlli / filtri ---------- */
function tmGraphControls() {
  return {
    mode: (document.querySelector(".tm-view-btn.active")?.dataset.mode) || "investigation",
    q: ($("#graphSearch")?.value || "").trim().toLowerCase(),
    severity: ($("#graphSeverity")?.value || "").toLowerCase(),
    status: ($("#graphStatus")?.value || "").toLowerCase(),
    source: ($("#graphSource")?.value || "").toLowerCase(),
    showNoise: !!$("#graphShowNoise")?.checked,
    activeTypes: gvActiveTypes()
  };
}
function tmPassesControls(n, ctrl) {
  if (!ctrl.activeTypes.has(n.type) && !TM_CLUSTER_TYPES.has(n.type)) return false;
  if (!tmModeTypes(ctrl.mode).has(n.type) && !TM_CLUSTER_TYPES.has(n.type)) return false;
  if (ctrl.severity && tmSeverity(n) !== ctrl.severity) return false;
  if (ctrl.status && tmStatus(n) !== ctrl.status) return false;
  if (ctrl.source && !tmSource(n).includes(ctrl.source)) return false;
  if (ctrl.q && !tmText(n).includes(ctrl.q)) return false;
  return true;
}
function tmNoiseGate(nodes, edges, ctrl) {
  const degree = new Map(nodes.map(n => [n.id, 0]));
  for (const e of edges) { if (degree.has(e.src)) degree.set(e.src, degree.get(e.src) + 1); if (degree.has(e.dst)) degree.set(e.dst, degree.get(e.dst) + 1); }
  const hidden = {};
  let kept = nodes.filter(n => {
    if (ctrl.showNoise || ctrl.q) return true;
    const score = tmScore(n), deg = degree.get(n.id) || 0;
    let keep = true;
    if (n.type === "string") keep = tmIsHighSignalString(n) && score >= 45;
    else if (["file_path", "registry_key", "network_endpoint"].includes(n.type)) keep = (score >= 42 || deg > 1);
    else if (n.type === "function") keep = (score >= 50 || deg > 1);
    else if (n.type === "import") keep = (score >= 52 || deg > 1);
    else keep = score >= 28 || deg > 0 || ["binary", "artifact", "finding", "evidence", "sink", "source", "process"].includes(n.type);
    if (!keep) hidden[n.type] = (hidden[n.type] || 0) + 1;
    return keep;
  });
  const caps = {
    string: ctrl.showNoise ? 180 : 18,
    file_path: ctrl.showNoise ? 220 : 30,
    registry_key: ctrl.showNoise ? 220 : 30,
    network_endpoint: ctrl.showNoise ? 140 : 26,
    procmon_op: ctrl.showNoise ? 120 : 22,
    function: ctrl.showNoise ? 220 : 44,
    import: ctrl.showNoise ? 180 : 12,
    evidence: ctrl.showNoise ? 180 : 34,
    finding: ctrl.showNoise ? 140 : 28,
    sink: ctrl.showNoise ? 120 : 24,
    source: ctrl.showNoise ? 80 : 16,
    risk: ctrl.showNoise ? 120 : 24
  };
  const grouped = {}; for (const n of kept) { (grouped[n.type] ||= []).push(n); }
  kept = [];
  for (const [t, arr] of Object.entries(grouped)) {
    arr.sort((a, b) => tmScore(b) - tmScore(a));
    const cap = caps[t] ?? 99999;
    kept.push(...arr.slice(0, cap));
    if (arr.length > cap) hidden[t] = (hidden[t] || 0) + (arr.length - cap);
  }
  const clusterNodes = Object.entries(hidden).filter(([, c]) => c > 0).map(([t, c]) => ({
    id: `cluster:${t}`, type: "node_cluster", label: `+${c} ${tmTypeLabel(t)} filtrati`,
    attrs: { reason: "anti-noise", hidden_type: t, hidden_count: c, hint: "Enable 'show noise' or use the search to expand." }
  }));
  _tmState.hiddenSummary = hidden;
  return kept.concat(clusterNodes);
}
function tmFilterGraph(graph) {
  const ctrl = tmGraphControls();
  const nodes0 = (graph.nodes || []).map(n => ({ ...n, type:n.type||n.kind||"node", attrs: tmAttrs(n) }));
  const edges0 = (graph.edges || []).map((e, i) => ({ ...e, id: e.id || `edge:${i}`, src: tmEdgeSrc(e), dst: tmEdgeDst(e) })).filter(e=>e.src&&e.dst);
  const nodeById0 = new Map(nodes0.map(n => [n.id, n]));
  let nodes = nodes0.filter(n => tmPassesControls(n, ctrl));
  let idset = new Set(nodes.map(n => n.id));
  let edges = edges0.filter(e => idset.has(e.src) && idset.has(e.dst));

  if (ctrl.mode === "evidence") {
    const related = new Set();
    for (const e of edges) {
      const a = nodeById0.get(e.src), b = nodeById0.get(e.dst);
      if ([a?.type, b?.type].some(t => ["finding", "evidence", "sink", "source"].includes(t))) { related.add(e.src); related.add(e.dst); }
    }
    if (related.size) { nodes = nodes.filter(n => related.has(n.id) || ["finding", "evidence"].includes(n.type)); }
  }
  if (ctrl.mode === "compact") { nodes = nodes.sort((a, b) => tmScore(b) - tmScore(a)).slice(0, 80); }

  idset = new Set(nodes.map(n => n.id)); edges = edges0.filter(e => idset.has(e.src) && idset.has(e.dst));
  nodes = tmNoiseGate(nodes, edges, ctrl);
  idset = new Set(nodes.map(n => n.id)); edges = edges0.filter(e => idset.has(e.src) && idset.has(e.dst));
  const matches = new Set();
  if (ctrl.q) { for (const n of nodes) { if (!TM_CLUSTER_TYPES.has(n.type) && tmText(n).includes(ctrl.q)) matches.add(n.id); } }
  return { nodes, edges, ctrl, matches };
}

/* ---------- visuals: icone, colori archi, dimensioni ---------- */
function tmNodeIcon(t) {
  return {
    binary: "B", artifact: "A", function: "fn", import: "api",
    sink: "!!", source: "src", finding: "!", evidence: "E",
    component: "C", string: "str", toolcall: "T",
    process: "P", procmon_op: "M", file_path: "F",
    registry_key: "R", network_endpoint: "N",
    dynamic_event: "D", risk: "X", node_cluster: "+"
  }[t] || "?";
}
function tmEdgeColor(t) {
  if (["SOURCE_FLOWS_TO_SINK", "FINDING_VALIDATED_BY_EVIDENCE", "DYNAMIC_EVENT_CONFIRMS_FINDING"].includes(t)) return "#f0556b";
  if ((t || "").includes("EVIDENCE")) return "#2fa08c";
  if ((t || "").includes("ARTIFACT")) return "#5fa8d6";
  if ((t || "").includes("PROCESS") || (t || "").includes("PROC")) return "#d9bb4a";
  if ((t || "").includes("BINARY")) return "#e6e4df";
  if ((t || "").includes("FINDING") || (t || "").includes("RISK")) return "#f0902f";
  return "#99a0a5";
}
const TM_IMPORTANT_EDGES = new Set(["SOURCE_FLOWS_TO_SINK", "EVIDENCE_SUPPORTS_FINDING", "ARTIFACT_PARSED_BY_TOOL", "PROCESS_PERFORMED_OP", "FINDING_VALIDATED_BY_EVIDENCE", "DYNAMIC_EVENT_CONFIRMS_FINDING"]);

/* ---------- layout force-directed ---------- */
function tmGraphSignature(nodes, edges, ctrl) {
  return `${ctrl?.mode || ""}|${nodes.length}|${edges.length}|${nodes.map(n => n.id).slice(0, 220).join(",")}`;
}
function tmTypeAnchor(t, W, H) {
  /* ancore "morbide" per tipo, cosi' i cluster si separano visivamente senza corsie rigide */
  const ring = {
    binary: [0.09, 0.50], artifact: [0.12, 0.14], component: [0.12, 0.86],
    import: [0.27, 0.24], source: [0.29, 0.72], function: [0.44, 0.52], string: [0.28, 0.91], toolcall: [0.24, 0.12],
    sink: [0.58, 0.43], evidence: [0.76, 0.76],
    process: [0.56, 0.88], procmon_op: [0.67, 0.90], file_path: [0.84, 0.80], registry_key: [0.88, 0.58], network_endpoint: [0.90, 0.90],
    dynamic_event: [0.72, 0.56],
    finding: [0.82, 0.25], risk: [0.92, 0.42],
    node_cluster: [0.18, 0.82]
  }[t] || [0.5, 0.5];
  return { x: ring[0] * W, y: ring[1] * H };
}
function tmInitPositions(nodes, W, H, sig) {
  if (sig !== _tmLastSig) {
    const ids = new Set(nodes.map(n => n.id));
    for (const id of [..._tmPos.keys()]) if (!ids.has(id)) { _tmPos.delete(id); _tmVel.delete(id); _tmManual.delete(id); }
    _tmLastSig = sig;
  }
  for (const n of nodes) {
    if (!_tmPos.has(n.id)) {
      const anchor = tmTypeAnchor(n.type, W, H);
      _tmPos.set(n.id, { x: anchor.x + (Math.random() - .5) * 70, y: anchor.y + (Math.random() - .5) * 70 });
      _tmVel.set(n.id, { x: 0, y: 0 });
    }
  }
}
function tmSimulationStep(nodes, edges, W, H) {
  const rep = 6200, k = 0.026, restLen = 170, centerPull = 0.0008, anchorPull = 0.045, damping = 0.68;
  const pos = _tmPos, vel = _tmVel;
  // repulsione tra tutti i nodi (O(n^2) ma n e' tipicamente <250 dopo i filtri)
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i], pa = pos.get(a.id); if (!pa) continue;
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j], pb = pos.get(b.id); if (!pb) continue;
      let dx = pa.x - pb.x, dy = pa.y - pb.y, d2 = dx * dx + dy * dy || 0.01;
      if (d2 > 360000) continue; // oltre 600px la repulsione e' trascurabile: risparmia calcoli
      const d = Math.sqrt(d2), ar = (GV_R[a.type] || 8) + 34, br = (GV_R[b.type] || 8) + 34;
      const minD = ar + br;
      const f = (rep / d2) + (d < minD ? (minD - d) * 0.18 : 0);
      const fx = f * dx / d, fy = f * dy / d;
      const va = vel.get(a.id), vb = vel.get(b.id);
      if (!_tmManual.has(a.id)) { va.x += fx; va.y += fy; }
      if (!_tmManual.has(b.id)) { vb.x -= fx; vb.y -= fy; }
    }
  }
  // molle sugli archi
  for (const e of edges) {
    const pa = pos.get(tmEdgeSrc(e)), pb = pos.get(tmEdgeDst(e)); if (!pa || !pb) continue;
    let dx = pb.x - pa.x, dy = pb.y - pa.y, d = Math.sqrt(dx * dx + dy * dy) || 0.01;
    const localRest = restLen + (TM_IMPORTANT_EDGES.has(e.type) ? 10 : 34);
    const f = (d - localRest) * k, fx = f * dx / d, fy = f * dy / d;
    const va = vel.get(tmEdgeSrc(e)), vb = vel.get(tmEdgeDst(e));
    if (va && !_tmManual.has(tmEdgeSrc(e))) { va.x += fx; va.y += fy; }
    if (vb && !_tmManual.has(tmEdgeDst(e))) { vb.x -= fx; vb.y -= fy; }
  }
  // richiamo verso ancora di tipo + verso centro, integrazione
  for (const n of nodes) {
    if (_tmManual.has(n.id)) continue;
    const p = pos.get(n.id), v = vel.get(n.id); if (!p || !v) continue;
    const anchor = tmTypeAnchor(n.type, W, H);
    v.x += (anchor.x - p.x) * anchorPull + (W / 2 - p.x) * centerPull;
    v.y += (anchor.y - p.y) * anchorPull + (H / 2 - p.y) * centerPull;
    v.x *= damping; v.y *= damping;
    p.x += Math.max(-14, Math.min(14, v.x));
    p.y += Math.max(-14, Math.min(14, v.y));
    p.x = Math.max(28, Math.min(W - 28, p.x));
    p.y = Math.max(28, Math.min(H - 28, p.y));
  }
}
function tmSettleLayout(nodes, edges, W, H, iterations = 140) {
  for (let i = 0; i < iterations; i++) tmSimulationStep(nodes, edges, W, H);
}
function tmShouldShowLabel(n, ctrl, degree){
  if (ctrl.q || _tmState.selected === n.id) return true;
  const score = tmScore(n), deg = degree.get(n.id)||0;
  if (["binary","node_cluster"].includes(n.type)) return true;
  if (n.type === "finding") return score >= 95 || deg >= 2;
  if (n.type === "sink") return score >= 82 || deg >= 2;
  if (n.type === "source") return score >= 88 || deg >= 3;
  if (n.type === "evidence") return score >= 92;
  if (["function","artifact","process","network_endpoint"].includes(n.type)) return deg > 2 || score >= 78;
  return false;
}

/* ---------- legenda e insight bar ---------- */
function tmRenderLegend(nodes) {
  const box = $("#tmLegend"); if (!box) return;
  const present = new Set(nodes.filter(n => !TM_CLUSTER_TYPES.has(n.type)).map(n => n.type));
  const order = ["binary", "artifact", "component", "import", "source", "function", "sink", "process", "procmon_op", "file_path", "registry_key", "network_endpoint", "dynamic_event", "evidence", "finding", "risk", "string", "toolcall"];
  const items = order.filter(t => present.has(t));
  box.innerHTML = items.map(t => `<span class="tm-legend-item"><span class="tm-legend-dot" style="background:${_nodeColor(t)}"></span>${escSvg(tmTypeLabel(t))}</span>`).join("")
    || '<span class="tm-legend-item">No visible nodes</span>';
}
function tmRenderInsight(data) {
  const box = $("#graphInsight"); if (!box) return;
  const nodes = data.nodes || [], edges = data.edges || [], ctrl = data.ctrl || tmGraphControls();
  const counts = {}; nodes.forEach(n => counts[n.type] = (counts[n.type] || 0) + 1);
  const hidden = Object.entries(_tmState.hiddenSummary || {}).filter(([, c]) => c > 0).map(([t, c]) => `${c} ${tmTypeLabel(t)}`).join(" · ");
  const topTypes = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([t, c]) => `<span class="tm-chip-mini">${escSvg(tmTypeLabel(t))} <b>${c}</b></span>`).join("");
  const matchTxt = ctrl.q ? `<span class="tm-chip-mini"><b>${(data.matches || new Set()).size}</b> ${escSvg("matches")}</span>` : "";
  box.innerHTML = `<b>${escSvg(TM_MODE_LABELS[ctrl.mode] || ctrl.mode)}</b>`
    + `<span class="tm-chip-mini"><b>${nodes.length}</b> ${escSvg("nodes")}</span>`
    + `<span class="tm-chip-mini"><b>${edges.length}</b> ${escSvg("edges")}</span>${matchTxt}${topTypes}`
    + (hidden ? `<span class="tm-hidden-note">${escSvg("collapsed")}: ${escSvg(hidden)}</span>` : "");
}

/* ---------- viewBox / pan / zoom ---------- */
function tmSetViewBox(svg, vb) { _tmViewBox = { ...vb }; svg.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`); }
function tmFit() { const svg = $("#graphViz"); if (svg) tmSetViewBox(svg, { x: 0, y: 0, w: TM_CANVAS_W, h: TM_CANVAS_H }); }
function tmCenterOnPoint(x, y, zoomFactor = 1) {
  const svg = $("#graphViz"); if (!svg) return;
  const w = Math.max(260, Math.min(2600, _tmViewBox.w * zoomFactor));
  const h = Math.max(180, Math.min(1700, _tmViewBox.h * zoomFactor));
  tmSetViewBox(svg, { x: x - w / 2, y: y - h / 2, w, h });
}
function tmCenterOnNode(id, zoomFactor = 0.92) {
  const p = _tmPos.get(id); if (!p) return;
  tmCenterOnPoint(p.x, p.y, zoomFactor);
}
function tmSvgPoint(svg, evt) {
  const r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal;
  const cx = (evt.touches ? evt.touches[0].clientX : evt.clientX) - r.left;
  const cy = (evt.touches ? evt.touches[0].clientY : evt.clientY) - r.top;
  return { x: vb.x + cx / r.width * vb.width, y: vb.y + cy / r.height * vb.height };
}
function tmEdgePath(e) {
  const a = _tmPos.get(tmEdgeSrc(e)), b = _tmPos.get(tmEdgeDst(e)); if (!a || !b) return "";
  const dx = b.x - a.x, dy = b.y - a.y, dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
  const bend = Math.min(46, dist * 0.18);
  const nx = -dy / dist * bend, ny = dx / dist * bend;
  const mx = (a.x + b.x) / 2 + nx, my = (a.y + b.y) / 2 + ny;
  return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${mx.toFixed(1)} ${my.toFixed(1)}, ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
}

/* ---------- rendering principale ---------- */
function renderGraphViz(graph) {
  const svg = $("#graphViz"), details = $("#graphNodeDetails"); if (!svg) return;
  _gvFullGraph = graph || { nodes: [], edges: [] };
  const data = tmFilterGraph(_gvFullGraph);
  _tmState.filtered = data; _tmState.graph = _gvFullGraph;
  const rawNodes = data.nodes || [], rawEdges = data.edges || [], ctrl = data.ctrl;
  _graphIndex = { nodes: new Map(rawNodes.map(n => [n.id, n])), edges: rawEdges };
  tmRenderInsight(data);
  tmRenderLegend(rawNodes);
  if (details && !_tmState.selected) details.innerHTML = '<div class="tm-dossier-empty">Click a map node to open the investigative dossier: why it matters, relationships, linked evidence and quick actions.</div>';
  const panel = $("#tmCanvasPanel");
  if (!rawNodes.length) {
    svg.innerHTML = "";
    if (panel && !panel.querySelector(".tm-canvas-empty")) {
      const div = document.createElement("div"); div.className = "tm-canvas-empty";
      div.textContent = "No visible nodes with these filters. Relax the filters, enable “show noise” or run an analysis.";
      panel.appendChild(div);
    }
    return;
  }
  panel?.querySelector(".tm-canvas-empty")?.remove();

  const W = TM_CANVAS_W, H = TM_CANVAS_H;
  const sig = tmGraphSignature(rawNodes, rawEdges, ctrl);
  tmInitPositions(rawNodes, W, H, sig);
  if (sig !== _tmRenderedSig) { tmSettleLayout(rawNodes, rawEdges, W, H, 220); _tmRenderedSig = sig; }
  if (!_tmViewBox.w) tmSetViewBox(svg, { x: 0, y: 0, w: W, h: H });
  else svg.setAttribute("viewBox", `${_tmViewBox.x} ${_tmViewBox.y} ${_tmViewBox.w} ${_tmViewBox.h}`);

  const degree = new Map(rawNodes.map(n=>[n.id,0]));
  for(const e of rawEdges){ if(degree.has(e.src)) degree.set(e.src,(degree.get(e.src)||0)+1); if(degree.has(e.dst)) degree.set(e.dst,(degree.get(e.dst)||0)+1); }
  const edgeScore = e => {
    const a = _graphIndex.nodes.get(tmEdgeSrc(e)), b = _graphIndex.nodes.get(tmEdgeDst(e));
    let s = (TM_IMPORTANT_EDGES.has(e.type) ? 1000 : 0) + (tmScore(a) || 0) + (tmScore(b) || 0);
    if (_tmState.selected && (tmEdgeSrc(e) === _tmState.selected || tmEdgeDst(e) === _tmState.selected)) s += 1200;
    return s;
  };
  const maxEdges = ctrl.showNoise ? 700 : (_tmState.selected ? 220 : 145);
  const visibleEdges = [...rawEdges].sort((a,b)=>edgeScore(b)-edgeScore(a)).slice(0, maxEdges);
  const edgeEls = visibleEdges.map((e, i) => {
    const src = tmEdgeSrc(e), dst = tmEdgeDst(e);
    if (!_tmPos.has(src) || !_tmPos.has(dst)) return "";
    const relatedToSelection = _tmState.selected && (src === _tmState.selected || dst === _tmState.selected);
    const emph = TM_IMPORTANT_EDGES.has(e.type) || relatedToSelection;
    const a = _tmPos.get(src), b = _tmPos.get(dst), midx = (a.x + b.x) / 2, midy = (a.y + b.y) / 2;
    const showLabel = relatedToSelection && visibleEdges.length <= 220 && TM_IMPORTANT_EDGES.has(e.type);
    const label = showLabel ? `<text class="tm-edge-label" data-src="${escSvg(src)}" data-dst="${escSvg(dst)}" x="${midx.toFixed(1)}" y="${(midy - 5).toFixed(1)}">${escSvg(_shortLabel(tmRelLabel(e.type), 18))}</text>` : "";
    const col = tmEdgeColor(e.type);
    const arrow = ["SOURCE_FLOWS_TO_SINK", "FINDING_VALIDATED_BY_EVIDENCE", "DYNAMIC_EVENT_CONFIRMS_FINDING"].includes(e.type) ? "tmArrowRed" : ((e.type || "").includes("EVIDENCE") ? "tmArrowPurple" : "tmArrow");
    return `<path class="tm-edge${emph ? " emph" : ""}${relatedToSelection ? " selected-edge" : ""}" data-src="${escSvg(src)}" data-dst="${escSvg(dst)}" data-type="${escSvg(e.type || "related_to")}" d="${tmEdgePath(e)}" stroke="${col}" stroke-width="${emph ? 1.8 : .7}" stroke-opacity="${relatedToSelection ? .82 : (emph ? .42 : .08)}"${TM_IMPORTANT_EDGES.has(e.type) ? ' stroke-dasharray="6 5"' : ""} marker-end="url(#${arrow})"/>${label}`;
  }).join("");

  const nodeEls = rawNodes.map(n => {
    const p = _tmPos.get(n.id); if (!p) return "";
    const isCluster = TM_CLUSTER_TYPES.has(n.type);
    const score = tmScore(n);
    const r = isCluster ? 17 : (GV_R[n.type] || 8) + (score > 85 ? 3 : score > 65 ? 1 : 0);
    const color = isCluster ? "#2a3238" : _nodeColor(n.type);
    const sev = tmSeverity(n), status = tmStatus(n), match = data.matches.has(n.id);
    const dim = ctrl.q && !match ? " dim" : "";
    const selected = _tmState.selected === n.id ? " selected" : "";
    const pinned = _tmManual.has(n.id) ? " pinned" : "";
    const label = tmSafeLabel(n, isCluster ? 28 : (["binary","finding","sink"].includes(n.type)?28:18));
    const showNodeLabel = tmShouldShowLabel(n, ctrl, degree);
    const strokeColor = match ? "#e0a030" : sev === "critical" ? "#f0556b" : sev === "high" ? "#f0902f" : "rgba(255,255,255,.28)";
    const strokeW = match ? 3 : sev === "critical" ? 2.2 : sev === "high" ? 1.8 : 1.2;
    const badge = sev ? `<text class="tm-node-badge" x="${r + 5}" y="-${r * .2 + 6}" fill="${color}">${escSvg(sev.slice(0, 4).toUpperCase())}</text>` : "";
    const pinIcon = pinned ? `<circle cx="-${r + 7}" cy="-${r - 5}" r="2.6" fill="var(--sev-med)"/>` : "";
    return `<g class="tm-node${selected}${match ? " match" : ""}${dim}${isCluster ? " tm-cluster" : ""}" data-id="${escSvg(n.id)}" transform="translate(${p.x.toFixed(1)},${p.y.toFixed(1)})">`
      + `<circle class="tm-node-core" r="${r}" fill="${color}" stroke="${strokeColor}" stroke-width="${strokeW}"/>`
      + `<text class="tm-node-icon" x="0" y="0.5">${escSvg(tmNodeIcon(n.type))}</text>`
      + (showNodeLabel ? `<text class="tm-node-label" x="${r + 7}" y="3.5">${escSvg(label)}</text>` : "")
      + `${badge}${pinIcon}`
      + `<title>${escSvg(tmTypeLabel(n.type) + " · score " + score + " · " + (n.label || n.id))}</title></g>`;
  }).join("");

  svg.innerHTML = `<defs>
    <marker id="tmArrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0.5 L0,5.5 L8,3 z" fill="#99a0a5" opacity=".65"/></marker>
    <marker id="tmArrowRed" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0.5 L0,5.5 L8,3 z" fill="#f0556b" opacity=".85"/></marker>
    <marker id="tmArrowPurple" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0.5 L0,5.5 L8,3 z" fill="#2fa08c" opacity=".8"/></marker>
  </defs><rect class="tm-pan-plane" x="-6000" y="-6000" width="12000" height="12000" fill="transparent"/>${edgeEls}${nodeEls}`;
  tmBindSvgInteractions(svg);
  if (_tmState.selected && _graphIndex.nodes.has(_tmState.selected)) tmRenderDossier(_graphIndex.nodes.get(_tmState.selected));
}
let _tmRenderedSig = "";

/* ---------- interactions: node drag, background pan, wheel zoom ---------- */
function tmUpdateConnectedEdges(id) {
  const svg = $("#graphViz"); if (!svg) return;
  svg.querySelectorAll(`.tm-edge[data-src="${CSS.escape(id)}"],.tm-edge[data-dst="${CSS.escape(id)}"]`).forEach(p => {
    const e = { src: p.dataset.src, dst: p.dataset.dst }; const d = tmEdgePath(e); if (d) p.setAttribute("d", d);
  });
  svg.querySelectorAll(`.tm-edge-label[data-src="${CSS.escape(id)}"],.tm-edge-label[data-dst="${CSS.escape(id)}"]`).forEach(t => {
    const a = _tmPos.get(t.dataset.src), b = _tmPos.get(t.dataset.dst); if (!a || !b) return;
    t.setAttribute("x", ((a.x + b.x) / 2).toFixed(1)); t.setAttribute("y", (((a.y + b.y) / 2) - 5).toFixed(1));
  });
}
function tmBindSvgInteractions(svg) {
  svg.querySelectorAll(".tm-node").forEach(g => {
    g.addEventListener("click", ev => {
      ev.stopPropagation();
      if (Date.now() < _tmSuppressNodeClickUntil) return;
      tmShowNode(g.dataset.id, { center: true });
    });
    g.addEventListener("pointerdown", ev => {
      ev.stopPropagation(); const id = g.dataset.id; const p = tmSvgPoint(svg, ev); const cur = _tmPos.get(id) || { x: 0, y: 0 };
      _tmDrag = { id, dx: p.x - cur.x, dy: p.y - cur.y, node: g, moved:false, clientX:ev.clientX, clientY:ev.clientY };
      g.setPointerCapture(ev.pointerId); g.classList.add("dragging");
    });
  });
  svg.onpointerdown = ev => {
    if (ev.target.closest && ev.target.closest(".tm-node")) return;
    const r = svg.getBoundingClientRect();
    _tmPan = { clientX: ev.clientX, clientY: ev.clientY, rectW: r.width || 1, rectH: r.height || 1, vb: { ..._tmViewBox }, moved:false };
    svg.setPointerCapture(ev.pointerId);
    svg.classList.add("panning");
  };
  svg.onpointermove = ev => {
    if (_tmDrag) {
      const p = tmSvgPoint(svg, ev); const pos = { x: p.x - _tmDrag.dx, y: p.y - _tmDrag.dy };
      if (Math.abs(ev.clientX - _tmDrag.clientX) + Math.abs(ev.clientY - _tmDrag.clientY) > 4) _tmDrag.moved = true;
      _tmPos.set(_tmDrag.id, pos); _tmManual.add(_tmDrag.id);
      _tmDrag.node.setAttribute("transform", `translate(${pos.x.toFixed(1)},${pos.y.toFixed(1)})`);
      tmUpdateConnectedEdges(_tmDrag.id); return;
    }
    if (_tmPan) {
      const dx = (ev.clientX - _tmPan.clientX) / _tmPan.rectW * _tmPan.vb.w;
      const dy = (ev.clientY - _tmPan.clientY) / _tmPan.rectH * _tmPan.vb.h;
      if (Math.abs(dx) + Math.abs(dy) > 2) _tmPan.moved = true;
      tmSetViewBox(svg, { ..._tmPan.vb, x: _tmPan.vb.x - dx, y: _tmPan.vb.y - dy });
    }
  };
  const end = () => {
    if (_tmDrag) {
      if (_tmDrag.moved) _tmSuppressNodeClickUntil = Date.now() + 180;
      _tmDrag.node.classList.remove("dragging"); _tmDrag = null;
    }
    _tmPan = null; svg.classList.remove("panning");
  };
  svg.onpointerup = end; svg.onpointercancel = end; svg.onmouseleave = end;
  svg.onwheel = ev => {
    ev.preventDefault(); const p = tmSvgPoint(svg, ev); const factor = ev.deltaY < 0 ? .86 : 1.16;
    const nw = Math.max(260, Math.min(2600, _tmViewBox.w * factor)), nh = Math.max(180, Math.min(1700, _tmViewBox.h * factor));
    const rx = (p.x - _tmViewBox.x) / _tmViewBox.w, ry = (p.y - _tmViewBox.y) / _tmViewBox.h;
    tmSetViewBox(svg, { x: p.x - rx * nw, y: p.y - ry * nh, w: nw, h: nh });
  };
}
function tmShowNode(id, opts = {}) {
  const n = _graphIndex?.nodes.get(id); if (!n) return;
  _tmState.selected = id; _gvSelectedId = id;
  if (opts.center) tmCenterOnNode(id);
  if (_gvFullGraph?.nodes?.length) { renderGraphViz(_gvFullGraph); return; }
  document.querySelectorAll("#graphViz .tm-node").forEach(g => g.classList.toggle("selected", g.dataset.id === id));
  document.querySelectorAll("#graphViz .tm-edge").forEach(e => e.classList.toggle("selected-edge", e.dataset.src === id || e.dataset.dst === id));
  tmRenderDossier(n);
}

/* ---------- node context / narrative (why it matters, next checks) ---------- */
function tmNodeContext(n, depth = 1) {
  const rels = (_graphIndex.edges || []).filter(e => tmEdgeSrc(e) === n.id || tmEdgeDst(e) === n.id);
  const neighborIds = new Set(); rels.forEach(e => { neighborIds.add(tmEdgeSrc(e)); neighborIds.add(tmEdgeDst(e)); });
  const neighbors = [...neighborIds].filter(id => id !== n.id).slice(0, 40).map(id => _graphIndex.nodes.get(id)).filter(Boolean)
    .map(x => ({ id: x.id, type: x.type, label: x.label, attrs: tmAttrs(x) }));
  return { node: { id: n.id, type: n.type, label: n.label, attrs: tmAttrs(n) }, relations: rels.map(e => ({ type: e.type, src: tmEdgeSrc(e), dst: tmEdgeDst(e) })), neighbors };
}
function tmNodeNarrative(n, rels) {
  const attrs = tmAttrs(n), incoming = rels.filter(e => tmEdgeDst(e) === n.id), outgoing = rels.filter(e => tmEdgeSrc(e) === n.id);
  const other = e => _graphIndex.nodes.get(tmEdgeSrc(e) === n.id ? tmEdgeDst(e) : tmEdgeSrc(e));
  const linkedFindings = rels.filter(e => other(e)?.type === "finding");
  const linkedEvidence = rels.filter(e => other(e)?.type === "evidence");
  const linkedRuntime = rels.filter(e => ["process", "procmon_op", "file_path", "registry_key", "network_endpoint", "dynamic_event"].includes(other(e)?.type));
  const count = attrs.count || attrs.events || attrs.event_count || attrs.hits;
  const whyByType = {
    artifact: "File uploaded by the user or produced by a tool: it's the entry point from which parsers, runtime events and observables derive.",
    process: "Process observed during runtime analysis: connects artifact, Procmon, operations and touched objects.",
    procmon_op: "Aggregated cluster of Procmon events: shows a behavior class without exploding into thousands of raw events.",
    file_path: "Observed or extracted file path: useful to understand input, output, configuration and side writes.",
    registry_key: "Observed registry key: a configuration input. If the key is writable by an unprivileged user, whatever reads it is reading untrusted data.",
    network_endpoint: "Network endpoint observed at runtime: a remote input source worth tracing back to the parsing code that handles it.",
    sink: "Dangerous API or primitive: matters when reachable from controllable input or dynamically confirmed.",
    source: "Potential origin of controllable data: becomes relevant if it flows into a sink.",
    function: "Binary function: useful if it contains sinks, string references, calls or evidence.",
    import: "Imported API: describes static attack surface, but alone does not confirm a vulnerability.",
    evidence: "Technical proof collected by a tool/analysis: used to support or validate a finding.",
    finding: "Tracked hypothesis or vulnerability: should be read together with evidence, status and confidence.",
    string: "High-signal string only if it links a path/API/config/secret to functions or evidence.",
    component: "Detected library or component: useful for supply-chain, CVE and attack surface.",
    binary: "Main target of the analysis: contains imports, functions, strings, components and findings."
  };
  const why = [whyByType[n.type] || "Investigative graph node: its value depends on its relationships with evidence, findings and artifacts."];
  if (count) why.push(`Observed frequency/volume: ${count}. High volumes indicate dominant behavior or noise to aggregate.`);
  if (linkedFindings.length) why.push(`Linked to ${linkedFindings.length} finding(s): check whether the link is backed by concrete evidence.`);
  if (linkedEvidence.length) why.push(`Linked to ${linkedEvidence.length} evidence item(s): open the relationships to see which proofs support it.`);
  if (linkedRuntime.length) why.push(`Has runtime context: links Procmon/debug events to observed objects or behavior.`);
  const next = [];
  if (n.type === "artifact") next.push("Parse/summarize the artifact, then check processes, operation clusters and extracted objects.");
  if (n.type === "procmon_op") next.push("Filter similar events in Procmon, look at top paths and check whether the operation supports a finding.");
  if (["file_path", "registry_key", "network_endpoint"].includes(n.type)) next.push("Open neighbors to understand which process/tool produced it and whether it supports an evidence chain.");
  if (n.type === "sink") next.push("Look for a controllable source, callsite/function, input validation and dynamic proof.");
  if (n.type === "source") next.push("Follow the path toward the sink/finding and check whether the data is attacker-controllable.");
  if (n.type === "finding") next.push("Check status, evidence_refs, confidence and what's missing to move to CONFIRMED.");
  if (!next.length) next.push("Isolate the neighbors, then use the AI dossier if you want a reasoned read of the subgraph.");
  const relationSummary = [
    `${incoming.length} incoming relationships`, `${outgoing.length} outgoing relationships`,
    linkedEvidence.length ? `${linkedEvidence.length} linked evidence` : null,
    linkedFindings.length ? `${linkedFindings.length} linked findings` : null
  ].filter(Boolean);
  return { why, next, relationSummary };
}
function tmRelationExplanation(e, n) {
  const otherId = tmEdgeSrc(e) === n.id ? tmEdgeDst(e) : tmEdgeSrc(e), other = _graphIndex.nodes.get(otherId) || {};
  const dir = tmEdgeSrc(e) === n.id ? "produce/porta a" : "deriva da/arriva da";
  return `${tmRelLabel(e.type)}: ${dir} ${tmTypeLabel(other.type)} "${tmSafeLabel(other, 48)}"`;
}

function tmOpenModuleFullscreen(title, html) {
  document.querySelector(".tm-module-overlay")?.remove();
  const ov = document.createElement("div");
  ov.className = "tm-module-overlay";
  ov.innerHTML = `<div class="tm-module-fullscreen"><div class="tm-module-top"><strong>${esc(title || "Detail")}</strong><button class="tm-module-close" type="button">${esc(t("common.close"))}</button></div><div class="tm-module-body">${html}</div></div>`;
  ov.querySelector(".tm-module-close").addEventListener("click", () => ov.remove());
  ov.addEventListener("click", e => { if (e.target === ov) ov.remove(); });
  document.addEventListener("keydown", function h(e){
    if(e.key === "Escape"){ ov.remove(); document.removeEventListener("keydown", h); }
  });
  document.body.appendChild(ov);
}
function tmCloneCleanHtml(el) {
  const clone = el.cloneNode(true);
  clone.querySelectorAll(".tm-module-full-btn,.tm-d-full,.tm-d-close").forEach(x => x.remove());
  return clone.innerHTML;
}
function tmEnhanceFullscreenModules(scope) {
  (scope || document).querySelectorAll(".tm-section").forEach((sec, i) => {
    const head = sec.querySelector(".tm-section-h");
    if (!head || head.querySelector(".tm-module-full-btn")) return;
    const title = head.querySelector("span")?.textContent?.trim() || `Sezione ${i + 1}`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "tm-module-full-btn";
    btn.textContent = t("common.full");
    btn.title = "Open this section fullscreen";
    btn.addEventListener("click", e => {
      e.stopPropagation();
      tmOpenModuleFullscreen(title, tmCloneCleanHtml(sec));
    });
    head.appendChild(btn);
  });
}
function tmUpdateTypeCount(){
  const el = $("#tmTypeCount"); if (!el) return;
  const all = document.querySelectorAll(".gv-filter");
  const on = [...all].filter(c => c.checked).length;
  el.textContent = on === all.length ? `${all.length}` : `${on} / ${all.length}`;
}
function tmEnhanceGraphSubmodules() {
  const view = $("#view-graph"); if (!view) return;
  view.querySelectorAll("h3.sub-h").forEach((h, i) => {
    if (h.querySelector(".tm-module-full-btn")) return;
    const target = h.nextElementSibling;
    if (!target || target.classList.contains("tm-root")) return;
    const title = h.textContent.trim() || `Modulo ${i + 1}`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "tm-module-full-btn";
    btn.textContent = t("common.full");
    btn.title = "Open this module fullscreen";
    btn.addEventListener("click", e => {
      e.stopPropagation();
      tmOpenModuleFullscreen(title, tmCloneCleanHtml(target));
    });
    h.appendChild(btn);
  });
}

/* ---------- AI requests persisted per node (history in the dossier) ---------- */
function tmQueryKey() { return `reforge:graph-queries:${sessionId || "no-session"}`; }
function tmLoadQueries() { try { return JSON.parse(localStorage.getItem(tmQueryKey()) || '{"byNode":{},"global":[]}'); } catch (e) { return { byNode: {}, global: [] }; } }
function tmSaveQueries(data) { try { localStorage.setItem(tmQueryKey(), JSON.stringify(data)); } catch (e) { } }
function tmRememberQuery(n, kind, question, prompt) {
  const data = tmLoadQueries();
  const entry = { id: `req_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, node_id: n?.id || null, kind, question, prompt, at: new Date().toLocaleString(), response: "", response_status: "pending" };
  if (n?.id) { (data.byNode[n.id] ||= []).unshift(entry); data.byNode[n.id] = data.byNode[n.id].slice(0, 30); }
  else { data.global.unshift(entry); data.global = data.global.slice(0, 30); }
  tmSaveQueries(data); return entry;
}
function tmUpdateQuery(entryId, patch) {
  const data = tmLoadQueries();
  let found = null;
  for (const arr of [data.global, ...Object.values(data.byNode)]) { const f = arr.find(x => x.id === entryId); if (f) { Object.assign(f, patch); found = f; break; } }
  if (found) tmSaveQueries(data);
}
function tmStartAnswer(entry, n) {
  _tmPendingResponse = { entryId: entry.id, nodeId: n?.id || null, text: "", started: Date.now(), lastRender: 0 };
  tmUpdateQuery(entry.id, { response_status: "running", updated_at: new Date().toLocaleString() });
}
function rgCaptureAnswerDelta(text) {
  if (!_tmPendingResponse || !text) return;
  _tmPendingResponse.text += text;
  const now = Date.now();
  if (now - _tmPendingResponse.lastRender > 1200) {
    _tmPendingResponse.lastRender = now;
    tmUpdateQuery(_tmPendingResponse.entryId, { response: _tmPendingResponse.text, response_status: "running", updated_at: new Date().toLocaleString() });
    if (_tmState?.selected === _tmPendingResponse.nodeId && _graphIndex?.nodes?.has(_tmPendingResponse.nodeId)) tmRenderDossier(_graphIndex.nodes.get(_tmPendingResponse.nodeId));
  }
}
function rgCaptureAnswerFull(text) { if (!_tmPendingResponse || !text) return; _tmPendingResponse.text = text; }
function rgFinishAnswer() {
  if (!_tmPendingResponse) return;
  const p = _tmPendingResponse;
  tmUpdateQuery(p.entryId, { response: p.text, response_status: "done", updated_at: new Date().toLocaleString() });
  if (_tmState?.selected === p.nodeId && _graphIndex?.nodes?.has(p.nodeId)) tmRenderDossier(_graphIndex.nodes.get(p.nodeId));
  _tmPendingResponse = null;
}
function tmRequestsForNode(n) { const data = tmLoadQueries(); return n?.id ? (data.byNode[n.id] || []) : data.global; }
function tmRequestsHtml(n) {
  const rows = tmRequestsForNode(n).slice(0, 8);
  if (!rows.length) return '<p class="tm-rel-empty">No AI requests from the Evidence Graph are linked to this node.</p>';
  return `<div class="tm-ai-history">${rows.map(r => {
    const hasResponse = r.response_status === "done" && r.response;
    return `<div class="tm-ai-history-item"><div class="tm-ai-q">${esc(r.question || r.kind || "Request from the graph")}</div><div class="tm-ai-meta">${esc(r.updated_at || r.at || "")} · ${esc(r.response_status || "pending")}</div>${tmAiResponseHtml(r.response)}</div>`;
  }).join("")}</div>`;
}

function tmAiResponseHtml(text) {
  text = (text || "").trim();
  if (!text) return "";
  text = text.replace(/^Based on .*?:\s*/i, "").replace(/^Here is .*?:\s*/i, "");
  const lines = text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  const cards = [];
  let cur = null;
  const push = () => { if (cur) cards.push(cur); cur = null; };
  for (const line of lines) {
    const h = line.match(/^#{2,4}\s+(.+?)\s*:?\s*$/) || line.match(/^\*\*(.+?)\*\*:?\s*$/);
    if (h) { push(); cur = { title: h[1].replace(/[:.]+$/, ""), rows: [] }; continue; }
    if (!cur) cur = { title: "Summary", rows: [] };
    cur.rows.push(line.replace(/^[-*]\s+/, "").replace(/^\d+\.\s+/, "").replace(/\*\*/g, "").replace(/^#{1,6}\s+/, "").trim());
  }
  push();
  const html = cards.slice(0, 5).map(c =>
    `<section class="tm-ai-card"><h4>${esc(c.title)}</h4><ul>${c.rows.slice(0, 4).map(r => `<li>${esc(r).slice(0, 260)}</li>`).join("")}</ul></section>`
  ).join("");
  return `<div class="tm-ai-a structured">${html || `<p>${esc(text).slice(0, 900)}</p>`}</div>`;
}

/* ---------- riepilogo grafo per l'AI + invio domande ---------- */
function tmGraphSummaryForAI() {
  const data = _tmState?.filtered || { nodes: [], edges: [] };
  const byType = {}; for (const n of data.nodes || []) byType[n.type] = (byType[n.type] || 0) + 1;
  const findings = (data.nodes || []).filter(n => n.type === "finding").slice(0, 12).map(n => ({ id: n.id, label: n.label, severity: tmSeverity(n), status: tmStatus(n), confidence: tmConfidence(n) }));
  const high = (data.nodes || []).filter(n => tmScore(n) >= 80).slice(0, 18).map(n => ({ id: n.id, type: n.type, label: n.label, score: tmScore(n) }));
  return { view: tmGraphControls().mode, nodes: (data.nodes || []).length, edges: (data.edges || []).length, byType, selected: _tmState?.selected || null, findings, high_signal_nodes: high };
}

function tmAskAI(kind, n, extra) {
  const ctx = n ? tmNodeContext(n, 2) : null;
  const summary = tmGraphSummaryForAI();
  const conciseRules = [
    `Answer in English, concisely, operationally and readably.`,
    "Do not start with 'Based on', 'Here is' or similar formulas.",
    "Do not include raw JSON, long markdown tables, or generic explanations.",
    "Use exactly these markdown sections:",
    "## Summary",
    "- at most 2 bullets",
    "## Main risks",
    "- at most 3 bullets with severity, impact and why it matters",
    "## Useful relationships",
    "- at most 3 node -> evidence/finding/sink/source links",
    "## Next steps",
    "- at most 3 verifiable actions"
  ].join("\n");
  let prompt = "";
  if (kind === "global") {
    const q = ($("#graphAskInput")?.value || "Analyze the map and point out the most useful next investigative moves.").trim();
    prompt = `${conciseRules}\n\nQuestion about the Evidence Graph: ${q}\n\nContext graph summary JSON:\n${JSON.stringify(summary, null, 2)}`;
  } else if (kind === "node") {
    prompt = `${conciseRules}\n\nGenerate a short dossier on the selected node: why it matters, what connects it to the rest of the map, and what to verify next.\n\nNode context JSON:\n${JSON.stringify(ctx, null, 2)}\n\nGraph summary JSON:\n${JSON.stringify(summary, null, 2)}`;
  } else if (kind === "subgraph") {
    prompt = `${conciseRules}\n\nAnalyze only the subgraph around the selected node. Highlight chains toward findings, evidence, sinks, sources or runtime events.\n\nSelected node and neighborhood JSON:\n${JSON.stringify(ctx, null, 2)}\n\nGraph summary JSON:\n${JSON.stringify(summary, null, 2)}`;
  } else if (kind === "validate") {
    prompt = `${conciseRules}\n\nAssess whether the node or finding is supported by sufficient evidence. Do not confirm a vulnerability if source-to-sink, callsite, controllable input or dynamic proof are missing.\n\nContext JSON:\n${JSON.stringify(ctx, null, 2)}`;
  } else if (kind === "custom") {
    const q = (extra || "").trim() || "What does this node mean in the context of the analysis?";
    prompt = `${conciseRules}\n\nQuestion about the selected node: ${q}\n\nNode context JSON:\n${JSON.stringify(ctx, null, 2)}\n\nGraph summary JSON:\n${JSON.stringify(summary, null, 2)}`;
  }
  if (!prompt) return;
  const label = kind === "global" ? (($("#graphAskInput")?.value || "Global request about the Evidence Graph").trim())
    : ((extra || "").trim() || ({ node: "Generate AI dossier on the selected node", subgraph: "Analyze subgraph and neighbors of the selected node", validate: "Validate evidence and limits of the selected node", custom: "Custom question about the selected node" }[kind] || "Request from the Evidence Graph"));
  const entry = tmRememberQuery(n || null, kind, label, label);
  tmUpdateQuery(entry.id, { response_status: "running", updated_at: new Date().toLocaleString() });
  toastNd("Request sent to the local AI");
  if (n?.id && _graphIndex?.nodes?.has(n.id)) tmRenderDossier(_graphIndex.nodes.get(n.id));
  localAssist(n ? "node" : "graph", label, {prompt, node:ctx, graph:summary}, null).then(text=>{
    tmUpdateQuery(entry.id, { response: text || "", response_status: text ? "done" : "error", updated_at: new Date().toLocaleString() });
    if (n?.id && _graphIndex?.nodes?.has(n.id)) tmRenderDossier(_graphIndex.nodes.get(n.id));
  });
}

/* ---------- dossier laterale: sezioni chiare, niente tab nascosti per le info core ---------- */
function tmRenderDossier(n) {
  const box = $("#graphNodeDetails"); if (!box || !n) return;
  const attrs = tmAttrs(n), score = tmScore(n), sev = tmSeverity(n), status = tmStatus(n), src = tmSource(n), conf = tmConfidence(n);
  const idx = _graphIndex || { nodes: new Map(), edges: [] };
  const rels = (idx.edges || []).filter(e => tmEdgeSrc(e) === n.id || tmEdgeDst(e) === n.id);
  const out = rels.filter(e => tmEdgeSrc(e) === n.id), inc = rels.filter(e => tmEdgeDst(e) === n.id);
  const narrative = tmNodeNarrative(n, rels);
  const findingRels = rels.filter(e => { const o = idx.nodes.get(tmEdgeSrc(e) === n.id ? tmEdgeDst(e) : tmEdgeSrc(e)); return ["finding", "evidence", "sink", "source"].includes(o?.type); });
  const L = {
    close:t("common.close"), full:t("common.full"),
    quick:"Quick facts", why:"Why it matters",
    context:"Linked context", next:"Next checks",
    rels:"Relationships", actions:"Quick actions",
    askNode:"Ask AI about this node", raw:"Raw attributes",
    noRel:"No visible relationships with the current filters.",
    noSummary:"No visible relationships",
    noDirect:"No direct link to finding/evidence/sink/source in the current view.",
    out:"Outgoing", inc:"Incoming",
    isolate:"Isolate neighbors", path:"Path to findings", copy:"Copy ID",
    pin:_tmManual.has(n.id) ? "Unpin position" : "Pin position",
    parse:"Analyze artifact", useChat:"Use in chat", report:"Add to report",
    dossier:"Generate AI dossier for this node",
    askPlaceholder:"E.g. explain why this node matters, which evidence is missing, and which tool to use next...",
    subgraph:"Analyze subgraph", validate:"Validate evidence", send:"Send question",
    type:"Type", relCount:"Relationships"
  };

  const relItem = (e, dir) => {
    const oid = dir === "out" ? tmEdgeDst(e) : tmEdgeSrc(e), on = idx.nodes.get(oid) || {}, oc = _nodeColor(on.type);
    return `<div class="tm-rel-row" data-id="${esc(oid)}"><span class="tm-rel-arrow">${icon("arrow-right","ic ic-sm")}</span><span class="tm-rel-type">${esc(tmRelLabel(e.type))}</span><span class="tm-rel-dot" style="background:${oc}"></span><span class="tm-rel-label">${esc(tmSafeLabel(on, 50))}</span><span class="tm-rel-kind">${esc(tmTypeLabel(on.type))}</span></div>`;
  };
  const relList = (arr, dir, limit = 80) => arr.length ? arr.slice(0, limit).map(e => relItem(e, dir)).join("") : `<div class="tm-rel-empty">${esc(L.noRel)}</div>`;

  const chips = [`<span class="tm-chip">score ${score}</span>`, `<span class="tm-chip">degree ${rels.length}</span>`];
  if (sev) chips.push(`<span class="tm-chip tm-chip-sev-${esc(sev)}">${esc(sev.toUpperCase())}</span>`);
  if (status) chips.push(`<span class="tm-chip">${esc(status)}</span>`);
  if (src) chips.push(`<span class="tm-chip">source ${esc(src)}</span>`);
  if (conf != null) chips.push(`<span class="tm-chip">confidence ${Math.round(conf * 100)}%</span>`);

  const facts = [["Type", tmTypeLabel(n.type)], ["Source", src || "—"], ["Severity", sev || "—"], ["Status", status || "—"], ["Confidence", conf == null ? "—" : `${Math.round(conf * 100)}%`], ["Relations", String(rels.length)]];

  facts[0][0] = L.type;
  facts[5][0] = L.relCount;
  const attrEntries = Object.entries(attrs).filter(([, v]) => v !== null && v !== undefined && v !== "");
  const attrRowsAll = attrEntries.slice(0, 60).map(([k, v]) => {
    const val = typeof v === "object" ? JSON.stringify(v, null, 2) : String(v);
    return `<tr><td>${esc(k)}</td><td>${esc(val).slice(0, 2400)}</td></tr>`;
  }).join("");

  box.innerHTML = `<div class="tm-dossier">`
    + `<div class="tm-d-head">`
    +   `<div class="tm-d-head-row"><span class="tm-d-type-badge" style="background:${_nodeColor(n.type)}">${esc(tmTypeLabel(n.type))}</span><span class="tm-d-title">${esc(n.label || n.id)}</span><button class="tm-d-close" type="button" title="${esc(t("common.close"))}" aria-label="${esc(t("common.close"))}">${icon("close","ic")}</button></div>`
    +   `<div class="tm-d-id">${esc(n.id)}</div>`
    +   `<div class="tm-d-chips">${chips.join("")}</div>`
    + `</div>`
    + `<div class="tm-d-body">`

    +   `<div class="tm-section"><div class="tm-section-h"><span>Quick facts</span></div><div class="tm-fact-grid">${facts.map(([k, v]) => `<div class="tm-fact"><b>${esc(k)}</b><span>${esc(v)}</span></div>`).join("")}</div></div>`

    +   `<div class="tm-section"><div class="tm-section-h"><span>Why it matters</span></div><ul class="tm-why-list">${narrative.why.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>`

    +   `<div class="tm-section"><div class="tm-section-h"><span>Linked context</span></div><div class="tm-rel-pills">${narrative.relationSummary.map(x => `<span class="tm-rel-pill">${esc(x)}</span>`).join("") || '<span class="tm-rel-pill">No visible relationships</span>'}</div>`
    +     (findingRels.length ? `<div class="tm-rel-panel active" style="display:flex">${findingRels.slice(0, 10).map(e => `<div class="tm-rel-row" data-id="${esc(tmEdgeSrc(e) === n.id ? tmEdgeDst(e) : tmEdgeSrc(e))}"><span class="tm-rel-label">${esc(tmRelationExplanation(e, n))}</span></div>`).join("")}</div>` : '<p class="tm-rel-empty" style="margin-top:6px">No direct link to a finding/evidence/sink/source in the current view.</p>')
    +   `</div>`

    +   `<div class="tm-section"><div class="tm-section-h"><span>Next checks</span></div><ul class="tm-next-list">${narrative.next.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>`

    +   `<div class="tm-section"><div class="tm-section-h"><span>Relationships</span><span class="tm-count">${out.length} outgoing · ${inc.length} incoming</span></div>`
    +     `<div class="tm-rel-tabs"><button class="tm-rel-tab active" data-tab="out">Outgoing (${out.length})</button><button class="tm-rel-tab" data-tab="in">Incoming (${inc.length})</button></div>`
    +     `<div class="tm-rel-panel active" data-panel="out">${relList(out, "out")}</div>`
    +     `<div class="tm-rel-panel" data-panel="in">${relList(inc, "in")}</div>`
    +   `</div>`

    +   `<div class="tm-section"><div class="tm-section-h"><span>Quick actions</span></div><div class="tm-actions-grid">`
    +     `<button class="tm-action-btn" data-act="neighbors">Isolate neighbors</button><button class="tm-action-btn" data-act="path">Path to finding</button>`
    +     `<button class="tm-action-btn" data-act="copy">Copy ID</button><button class="tm-action-btn" data-act="pin">${_tmManual.has(n.id) ? "Unlock position" : "Lock position"}</button>`
    +     (n.type === "artifact" ? `<button class="tm-action-btn" data-act="parse">Analyze artifact</button><button class="tm-action-btn" data-act="llm">Use in chat</button>` : "")
    +     (n.type === "finding" ? `<button class="tm-action-btn" data-act="report">Add to report</button>` : "")
    +     `<button class="tm-action-btn tm-action-primary" data-act="ask-node">Generate AI dossier on this node</button>`
    +   `</div></div>`

    +   `<div class="tm-section"><div class="tm-section-h"><span>Ask the AI about this node</span></div>`
    +     `<div class="tm-ai-box"><textarea id="nodeAskInput" rows="2" placeholder="E.g. explain why this node matters, what evidence is missing, which tool to use next…"></textarea>`
    +       `<div class="tm-actions-grid"><button class="tm-action-btn" data-act="ask-subgraph">Analyze subgraph</button><button class="tm-action-btn" data-act="ask-validate">Validate evidence</button><button class="tm-action-btn tm-action-primary" data-act="ask-custom">Send question</button></div>`
    +       `${tmRequestsHtml(n)}</div>`
    +   `</div>`

    +   (attrRowsAll ? `<div class="tm-section"><div class="tm-section-h"><span>Raw attributes</span><span class="tm-count">${attrEntries.length}</span></div><table class="tm-raw-table">${attrRowsAll}</table></div>` : "")

    + `</div></div>`;
  box.innerHTML = box.innerHTML.replace('<button class="tm-d-close"', '<button class="tm-d-full" data-act="dossier-fullscreen" title="Open the dossier full screen">Full</button><button class="tm-d-close"');
  box.querySelector(".tm-d-close")?.setAttribute("title", L.close);
  const fullBtn = box.querySelector(".tm-d-full");
  if (fullBtn) { fullBtn.textContent = L.full; fullBtn.title = "Open dossier fullscreen"; }
  const sectionHeads = box.querySelectorAll(".tm-section > .tm-section-h > span:first-child");
  [L.quick, L.why, L.context, L.next, L.rels, L.actions, L.askNode, L.raw].forEach((label, i) => { if (sectionHeads[i]) sectionHeads[i].textContent = label; });
  const relSection = sectionHeads[4]?.closest(".tm-section");
  if (relSection) {
    const count = relSection.querySelector(".tm-count");
    if (count) count.textContent = `${out.length} ${L.out.toLowerCase()} · ${inc.length} ${L.inc.toLowerCase()}`;
    const outTab = relSection.querySelector('.tm-rel-tab[data-tab="out"]');
    const inTab = relSection.querySelector('.tm-rel-tab[data-tab="in"]');
    if (outTab) outTab.textContent = `${L.out} (${out.length})`;
    if (inTab) inTab.textContent = `${L.inc} (${inc.length})`;
  }
  const actionLabels = {neighbors:L.isolate, path:L.path, copy:L.copy, pin:L.pin, parse:L.parse, llm:L.useChat, report:L.report, "ask-node":L.dossier, "ask-subgraph":L.subgraph, "ask-validate":L.validate, "ask-custom":L.send};
  box.querySelectorAll(".tm-action-btn[data-act]").forEach(btn => { if(actionLabels[btn.dataset.act]) btn.textContent = actionLabels[btn.dataset.act]; });
  const nodeAsk = box.querySelector("#nodeAskInput"); if (nodeAsk) nodeAsk.placeholder = L.askPlaceholder;
  box.querySelectorAll(".tm-rel-empty").forEach(el => {
    const text = el.textContent || "";
    if (text.includes("current filters")) el.textContent = L.noRel;
    else if (text.includes("finding/evidence/sink/source")) el.textContent = L.noDirect;
    else if (text.includes("AI requests")) el.textContent = "No AI requests from the Evidence Graph are linked to this node.";
  });
  box.querySelectorAll(".tm-rel-pill").forEach(el => { if ((el.textContent || "").includes("No visible relationships")) el.textContent = L.noSummary; });

  box.querySelectorAll(".tm-rel-row[data-id]").forEach(el => el.addEventListener("click", () => tmShowNode(el.dataset.id)));
  box.querySelectorAll(".tm-rel-tab").forEach(btn => btn.addEventListener("click", () => {
    box.querySelectorAll(".tm-rel-tab").forEach(b => b.classList.toggle("active", b === btn));
    box.querySelectorAll(".tm-rel-panel[data-panel]").forEach(p => p.classList.toggle("active", p.dataset.panel === btn.dataset.tab));
  }));
  tmEnhanceFullscreenModules(box);
  const close = box.querySelector(".tm-d-close");
  if (close) close.addEventListener("click", () => { document.body.classList.remove("tm-dossier-fullscreen-active"); box.classList.remove("tm-dossier-fullscreen"); }, {capture:true});
  if (close) close.addEventListener("click", () => { _tmState.selected = null; box.innerHTML = '<div class="tm-dossier-empty">Click a map node to open the investigative dossier: why it matters, relationships, linked evidence and quick actions.</div>'; renderGraphViz(_gvFullGraph); });
  if (close) close.addEventListener("click", () => { const empty = box.querySelector(".tm-dossier-empty"); if (empty) empty.textContent = t("graph.dossier.empty"); });
  box.querySelectorAll(".tm-action-btn,.tm-d-full").forEach(btn => btn.addEventListener("click", () => tmNodeAction(btn.dataset.act, n)));
}

/* ---------- azioni sui nodi ---------- */
function tmNodeAction(act, n) {
  if (act === "dossier-fullscreen") {
    document.body.classList.toggle("tm-dossier-fullscreen-active");
    $("#graphNodeDetails")?.classList.toggle("tm-dossier-fullscreen");
    return;
  }
  if (act === "copy") { navigator.clipboard && navigator.clipboard.writeText(n.id); toastNd("ID copiato"); return; }
  if (act === "pin") {
    if (_tmManual.has(n.id)) { _tmManual.delete(n.id); toastNd("Position unlocked"); }
    else { _tmManual.add(n.id); toastNd("Position locked"); }
    renderGraphViz(_gvFullGraph); setTimeout(() => tmShowNode(n.id), 0); return;
  }
  if (act === "neighbors") {
    const nb = new Set([n.id]); (_graphIndex.edges || []).forEach(e => { if (tmEdgeSrc(e) === n.id) nb.add(tmEdgeDst(e)); if (tmEdgeDst(e) === n.id) nb.add(tmEdgeSrc(e)); });
    const base = _tmState.graph || _gvFullGraph; const nodes = (base.nodes || []).filter(x => nb.has(x.id)); const edges = (base.edges || []).filter(e => nb.has(e.src) && nb.has(e.dst));
    renderGraphViz({ nodes, edges, stats: base.stats || {} }); setTimeout(() => tmShowNode(n.id), 0); toastNd("Neighbour subgraph isolated"); return;
  }
  if (act === "path") {
    const base = _tmState.graph || _gvFullGraph; const focus = new Set([n.id]); let changed = true;
    while (changed) { changed = false; for (const e of (base.edges || [])) { if (focus.has(e.src) || focus.has(e.dst)) { if (!focus.has(e.src)) { focus.add(e.src); changed = true; } if (!focus.has(e.dst)) { focus.add(e.dst); changed = true; } } } }
    const nodes = (base.nodes || []).filter(x => focus.has(x.id) && ["finding", "evidence", "sink", "source", "function", "artifact", "dynamic_event", "risk", "process", "procmon_op"].includes(x.type));
    const ids = new Set(nodes.map(x => x.id));
    renderGraphViz({ nodes, edges: (base.edges || []).filter(e => ids.has(e.src) && ids.has(e.dst)), stats: base.stats || {} });
    setTimeout(() => tmShowNode(n.id), 0); toastNd("Investigative path filtered"); return;
  }
  if (act === "ask-node") { tmAskAI("node", n); return; }
  if (act === "ask-subgraph") { tmAskAI("subgraph", n); return; }
  if (act === "ask-validate") { tmAskAI("validate", n); return; }
  if (act === "ask-custom") { tmAskAI("custom", n, $("#nodeAskInput")?.value || ""); return; }
  if (act === "parse") { const p = `Analyze artifact ${n.id.split(":").pop()} with the most appropriate tool, create a summary and update the graph.`; const e = tmRememberQuery(n, "parse_artifact", "Analyze artifact from the Evidence Graph", p); tmStartAnswer(e, n); sendPromptSafe(p); tmRenderDossier(n); return; }
  if (act === "llm") { const p = `Use artifact ${n.id.split(":").pop()} as context: show me what it contains and which graph nodes/evidence it generates.`; const e = tmRememberQuery(n, "use_artifact", "Use artifact in chat from the Evidence Graph", p); tmStartAnswer(e, n); sendPromptSafe(p); tmRenderDossier(n); return; }
  if (act === "report") { const p = `Add finding ${n.id} to the report with linked evidence, confidence and limits.`; const e = tmRememberQuery(n, "report", "Add finding to the report from the Evidence Graph", p); tmStartAnswer(e, n); sendPromptSafe(p); tmRenderDossier(n); return; }
}

/* ---------- fullscreen, reset, binding UI generale ---------- */
function tmToggleFullscreen() {
  const root = $("#tmRoot"); if (!root) return;
  root.classList.toggle("tm-fullscreen");
  document.body.classList.toggle("tm-fullscreen-active", root.classList.contains("tm-fullscreen"));
  setTimeout(() => { tmFit(); if (_gvFullGraph) renderGraphViz(_gvFullGraph); }, 60);
}
function tmResetFilters() {
  document.querySelectorAll(".tm-view-btn").forEach(b => b.classList.toggle("active", b.dataset.mode === "investigation"));
  if ($("#graphSearch")) $("#graphSearch").value = ""; if ($("#graphSeverity")) $("#graphSeverity").value = ""; if ($("#graphStatus")) $("#graphStatus").value = ""; if ($("#graphSource")) $("#graphSource").value = ""; if ($("#graphShowNoise")) $("#graphShowNoise").checked = false;
  document.querySelectorAll(".gv-filter").forEach(c => { c.checked = c.dataset.t !== "string"; c.closest(".tm-type-chip")?.classList.toggle("active", c.checked); c.closest(".tm-type-chip")?.classList.toggle("inactive", !c.checked); });
  tmUpdateTypeCount();
  _tmState.selected = null; if (sessionId) loadGraph();
}
function tmBindGraphUI() {
  if (_tmUIBound) return; _tmUIBound = true;
  document.querySelectorAll(".tm-view-btn").forEach(b => b.addEventListener("click", () => {
    document.querySelectorAll(".tm-view-btn").forEach(x => x.classList.remove("active")); b.classList.add("active");
    _tmState.selected = null; if (_gvFullGraph) renderGraphViz(_gvFullGraph);
  }));
  ["#graphSearch", "#graphSeverity", "#graphStatus", "#graphSource", "#graphShowNoise"].forEach(sel => {
    const el = $(sel); if (el) { const ev = sel === "#graphSearch" ? "input" : "change"; el.addEventListener(ev, () => { if (_gvFullGraph) renderGraphViz(_gvFullGraph); }); }
  });
  tmUpdateTypeCount();
  document.querySelectorAll(".tm-type-chip").forEach(chip => {
    chip.addEventListener("click", ev => {
      ev.preventDefault();
      const input = chip.querySelector(".gv-filter"); if (!input) return;
      input.checked = !input.checked;
      chip.classList.toggle("active", input.checked); chip.classList.toggle("inactive", !input.checked);
      tmUpdateTypeCount();
      if (_gvFullGraph) renderGraphViz(_gvFullGraph);
    });
  });
  const r = $("#gvReset"); if (r) r.addEventListener("click", tmResetFilters);
  const fit = $("#gvFit"); if (fit) fit.addEventListener("click", () => tmFit());
  const resetLayout = $("#gvResetLayout"); if (resetLayout) resetLayout.addEventListener("click", () => {
    _tmPos.clear(); _tmVel.clear(); _tmManual.clear(); _tmViewBox = { x: 0, y: 0, w: TM_CANVAS_W, h: TM_CANVAS_H }; _tmRenderedSig = "";
    if (_gvFullGraph) renderGraphViz(_gvFullGraph); toastNd("Layout reset");
  });
  const fs = $("#gvFullscreen"); if (fs) fs.addEventListener("click", tmToggleFullscreen);
  const fsIcon = $("#gvFullscreenIcon"); if (fsIcon) fsIcon.addEventListener("click", tmToggleFullscreen);
  const ask = $("#graphAskBtn"); if (ask) ask.addEventListener("click", () => { const n = _tmState?.selected ? _graphIndex?.nodes.get(_tmState.selected) : null; tmAskAI(n ? "custom" : "global", n, $("#graphAskInput")?.value || ""); });
  const askInput = $("#graphAskInput"); if (askInput) askInput.addEventListener("keydown", ev => { if (ev.key === "Enter") { ev.preventDefault(); $("#graphAskBtn")?.click(); } });
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") { const root = $("#tmRoot"); if (root?.classList.contains("tm-fullscreen")) tmToggleFullscreen(); } });
}
tmBindGraphUI();

/* ---------- back-compat aliases: code outside this module calls these names ---------- */
const tiShowNode = tmShowNode;
const tiNodeAction = tmNodeAction;

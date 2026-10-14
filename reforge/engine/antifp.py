"""Anti-false-positive rules (prompt §11).

Each rule caps a finding that rests only on a weak signal. A rule fires when the *trigger* is
present but the *required corroboration* is absent; when it fires it forces the finding down to a
non-confirmed status and records why. These mirror the exact patterns the spec calls out.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from . import status as st

# rule: (name, trigger_regex over evidence text, required corroboration keys in evidence_bundle,
#        explanation)
RULES = [
    ("packing_from_rsrc_entropy",
     re.compile(r"(?i)high entropy .*\.rsrc|\.rsrc .*entropy|packed\?.*rsrc"),
     ["entropy_whole_image_high", "import_table_tiny", "unpacking_stub_observed"],
     "High .rsrc entropy alone does not prove packing (resources are often compressed media)."),
    ("input_capture_claim_from_getkeystate",
     re.compile(r"(?i)getkeystate|getkeyboardstate"),
     ["untrusted_input_reaches_sink", "unbounded_copy_observed"],
     "GetKeyState/GetKeyboardState are ordinary input APIs. They matter only as an input SOURCE: "
     "the defect, if any, is in how the captured data is then handled."),
    ("registry_write_claim_from_regsetvalue",
     re.compile(r"(?i)regsetvalueex|regsetvalue"),
     ["weak_key_acl_observed", "untrusted_input_reaches_value"],
     "RegSetValueEx alone is not a vulnerability. It matters if the key is writable by an "
     "unprivileged user (CWE-732) or if the written value comes from untrusted input."),
    ("dll_hijack_from_loadlibrary",
     re.compile(r"(?i)\bloadlibrary"),
     ["unqualified_path_observed", "writable_search_dir_observed"],
     "LoadLibrary presence is not DLL hijacking without an unqualified/writable search path."),
    ("path_traversal_from_dotdot_string",
     re.compile(r"(?i)\.\.\\|\.\./|\bpath traversal\b"),
     ["untrusted_input_reaches_path", "no_canonicalization_observed"],
     "A literal '..\\Texts\\' string is not traversal without untrusted input reaching the path."),
    ("toctou_from_gettempfilename",
     re.compile(r"(?i)gettempfilename"),
     ["check_use_gap_observed"],
     "GetTempFileNameW is not TOCTOU without an observed check-to-use race window."),
    ("arbitrary_write_from_createfile",
     re.compile(r"(?i)createfilew?\b"),
     ["untrusted_path_to_createfile", "no_validation_observed"],
     "CreateFileW is not arbitrary file write without a controllable path reaching it."),
    ("overflow_from_strcpy_import",
     re.compile(r"(?i)\b(strcpy|strcat|memcpy|sprintf)\b"),
     ["call_site", "reachable", "dataflow_complete"],
     "An imported strcpy/memcpy is not an overflow without a reachable, unbounded call site."),
    ("sqli_from_sql_string_and_sprintf",
     re.compile(r"(?i)\b(select|insert|update|delete)\b|sql inject"),
     ["untrusted_input_into_query", "no_parameterization_observed"],
     "SQL strings + sprintf are not SQL injection without untrusted input flowing into the query."),
]


def _text(f: Dict[str, Any]) -> str:
    ev = f.get("evidence")
    ev = " ".join(str(x) for x in ev) if isinstance(ev, (list, tuple)) else str(ev or "")
    return " ".join([str(f.get("title") or ""), str(f.get("description") or ""),
                     str(f.get("vuln_type") or ""), ev, str(f.get("location") or "")])


def apply_rules(f: Dict[str, Any]) -> Dict[str, Any]:
    """Cap `f` if any anti-FP rule fires. Mutates and returns f, recording fired rules."""
    text = _text(f)
    bundle = f.get("evidence_bundle") or {}
    fired: List[str] = []
    for name, trigger, required, why in RULES:
        if not trigger.search(text):
            continue
        if all(bundle.get(k) for k in required):
            continue  # corroborated: do not cap.
        fired.append(name)
        cg = list(f.get("coverage_gaps") or [])
        note = f"anti-FP[{name}]: {why}"
        if note not in cg:
            cg.append(note)
        f["coverage_gaps"] = cg
    if fired:
        f["antifp_fired"] = fired
        # Force the finding to not-confirmed: strip any confirming bundle keys so the state model
        # cannot promote it past HYPOTHESIS on this weak signal.
        capped_bundle = dict(bundle)
        for k in ("reachable", "dataflow_complete", "control_absent", "runtime_observed"):
            capped_bundle[k] = False
        capped_bundle.setdefault("string_context", True)
        f["evidence_bundle"] = capped_bundle
        st.apply(f, None)
    return f

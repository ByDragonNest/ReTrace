"""Playbook loader.

Loads the analysis playbooks from `reforge/playbooks/*.yaml` (or `.json`). A playbook describes
a repeatable procedure: the tools/steps to run, the recommended order, the safety mode it needs,
the expected outputs, the minimum validation criteria, the system prompt and whether it requires
dynamic actions.

PyYAML is preferred but optional: without it, `.json` playbooks still load and a minimal parser
is attempted for `.yaml`. No hard dependency.
"""
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

PLAYBOOK_DIR = Path(__file__).resolve().parent / "playbooks"
CUSTOM_DIR = PLAYBOOK_DIR / "custom"          # user-authored playbooks (writable, never bundled)

REQUIRED_FIELDS = ("id", "name", "steps", "safety_mode")
VALID_SAFETY = {"safe", "assisted", "autonomous", "dangerous"}

# Canonical UI module keys a playbook can be attached to (drives the per-module "Run" launchers).
VALID_MODULES = {
    "dashboard", "analysis", "graph", "artifacts", "findings", "evidence",
    "runtime", "strings", "imports", "reports", "servers",
}


def _load_yaml(text: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except Exception:
        # Fallback minimale: prova come JSON (alcuni playbook potrebbero essere .json).
        try:
            return json.loads(text)
        except Exception:
            return _load_yaml_minimal(text)


def _scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x.strip()) for x in inner.split(",")]
    return value


def _load_yaml_minimal(text: str) -> Dict[str, Any]:
    """Small YAML subset used by bundled playbooks when PyYAML is unavailable."""
    data: Dict[str, Any] = {}
    active_key: Optional[str] = None
    multiline_key: Optional[str] = None
    multiline: List[str] = []

    def flush_multiline() -> None:
        nonlocal multiline_key, multiline
        if multiline_key:
            data[multiline_key] = " ".join(x.strip() for x in multiline).strip()
            multiline_key = None
            multiline = []

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if multiline_key and indent > 0:
            multiline.append(line)
            continue
        flush_multiline()
        if indent == 0 and ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            active_key = key
            if value in {">", "|"}:
                multiline_key = key
                multiline = []
            elif value:
                data[key] = _scalar(value)
            else:
                data[key] = {}
            continue
        if active_key and indent > 0 and line.startswith("- "):
            if not isinstance(data.get(active_key), list):
                data[active_key] = []
            data[active_key].append(_scalar(line[2:]))
            continue
        if active_key and indent > 0 and ":" in line:
            if not isinstance(data.get(active_key), dict):
                data[active_key] = {}
            key, value = line.split(":", 1)
            data[active_key][key.strip()] = _scalar(value.strip())
    flush_multiline()
    return data


def _validate(pb: Dict[str, Any], source: str) -> List[str]:
    errs = []
    for f in REQUIRED_FIELDS:
        if not pb.get(f):
            errs.append(f"{source}: required field '{f}' is missing")
    sm = pb.get("safety_mode")
    if sm and sm not in VALID_SAFETY:
        errs.append(f"{source}: invalid safety_mode '{sm}' (expected {sorted(VALID_SAFETY)})")
    if pb.get("steps") and not isinstance(pb["steps"], list):
        errs.append(f"{source}: 'steps' must be a list")
    mods = pb.get("modules")
    if mods is not None:
        if not isinstance(mods, list):
            errs.append(f"{source}: 'modules' must be a list")
        else:
            bad = [m for m in mods if m not in VALID_MODULES]
            if bad:
                errs.append(f"{source}: unknown modules {bad} (valid: {sorted(VALID_MODULES)})")
    return errs


def load_all(directory: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Load every valid playbook (bundled + custom). Returns {id: playbook}.

    Playbooks in `playbooks/custom/` are marked `_custom=True` and may override a bundled one
    with the same id (the operator has the last word on their own procedures).
    """
    out: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    dirs = [Path(directory)] if directory else [PLAYBOOK_DIR, CUSTOM_DIR]
    for d in dirs:
        if not d.is_dir():
            continue
        is_custom = (d == CUSTOM_DIR)
        for p in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml")) + list(d.glob("*.json"))):
            try:
                data = _load_yaml(p.read_text(encoding="utf-8"))
            except Exception as exc:
                errors.append(f"{p.name}: {exc}")
                continue
            errs = _validate(data, p.name)
            if errs:
                errors.extend(errs)
                continue
            data["_source"] = p.name
            data["_custom"] = is_custom
            out[data["id"]] = data
    if errors:
        out["_errors"] = errors  # type: ignore
    return out


def get(playbook_id: str) -> Optional[Dict[str, Any]]:
    return load_all().get(playbook_id)


def list_summaries() -> List[Dict[str, Any]]:
    """Lightweight summary for the UI (without the full system prompt)."""
    out = []
    for pid, pb in load_all().items():
        if pid == "_errors":
            continue
        out.append({
            "id": pb["id"], "name": pb.get("name", pid),
            "description": pb.get("description", ""),
            "safety_mode": pb.get("safety_mode"),
            "requires_dynamic": bool(pb.get("requires_dynamic")),
            "steps": pb.get("steps", []),
            "expected_outputs": pb.get("expected_outputs", []),
            "modules": pb.get("modules", []),
            "custom": bool(pb.get("_custom")),
        })
    out.sort(key=lambda x: x["id"])
    return out


def for_module(module: str) -> List[Dict[str, Any]]:
    """Playbook attached to a given UI module (data-driven via each playbook's `modules` field)."""
    module = (module or "").strip().lower()
    return [s for s in list_summaries() if module in (s.get("modules") or [])]


# --------------------------------------------------------------------------- custom CRUD
_ID_RX = re.compile(r"^[a-z0-9][a-z0-9_-]{2,48}$")


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").strip().lower()).strip("_")
    return s[:48] or "playbook"


def validate_payload(pb: Dict[str, Any]) -> List[str]:
    """Validate a user-submitted custom playbook before saving (UI editor / API)."""
    errs = _validate(pb, "custom")
    pid = pb.get("id", "")
    if pid and not _ID_RX.match(str(pid)):
        errs.append("invalid id: use lowercase letters, digits, '-' or '_' (3-48 characters)")
    if not isinstance(pb.get("steps", []), list) or not pb.get("steps"):
        errs.append("steps: at least one step is required")
    return errs


def save_custom(pb: Dict[str, Any]) -> Dict[str, Any]:
    """Persist a custom playbook to playbooks/custom/<id>.yaml. Returns the stored record.

    Bundled playbooks are never overwritten on disk: a custom playbook with a bundled id simply
    shadows it (load_all gives custom precedence). LLM/user input is validated and the steps are
    treated as free-text guidance to the agent — NOT executable code.
    """
    pb = dict(pb)
    if not pb.get("id"):
        pb["id"] = _slugify(pb.get("name", "playbook"))
    pb.setdefault("safety_mode", "safe")
    errs = validate_payload(pb)
    if errs:
        raise ValueError("; ".join(errs))
    # Whitelist the persisted fields (drop runtime/internal keys).
    allowed = ("id", "name", "description", "safety_mode", "requires_dynamic", "steps",
               "expected_outputs", "modules", "system_prompt", "min_validation")
    clean = {k: pb[k] for k in allowed if k in pb}
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    dest = CUSTOM_DIR / f"{_slugify(clean['id'])}.yaml"
    dest.write_text(_dump_yaml(clean), encoding="utf-8")
    clean["_source"] = dest.name
    clean["_custom"] = True
    return clean


def delete_custom(playbook_id: str) -> bool:
    """Delete a custom playbook by id. Bundled playbooks cannot be deleted. Returns True if removed."""
    slug = _slugify(playbook_id)
    for ext in (".yaml", ".yml", ".json"):
        p = CUSTOM_DIR / f"{slug}{ext}"
        if p.is_file():
            p.unlink()
            return True
    return False


def _dump_yaml(pb: Dict[str, Any]) -> str:
    """Serialize a playbook to YAML (PyYAML if present, else a deterministic minimal writer)."""
    try:
        import yaml  # type: ignore
        return yaml.safe_dump(pb, allow_unicode=True, sort_keys=False)
    except Exception:
        lines: List[str] = []
        for k, v in pb.items():
            if isinstance(v, list):
                lines.append(f"{k}:")
                for item in v:
                    lines.append(f"  - {json.dumps(item, ensure_ascii=False)}")
            elif isinstance(v, dict):
                lines.append(f"{k}:")
                for ik, iv in v.items():
                    lines.append(f"  {ik}: {json.dumps(iv, ensure_ascii=False)}")
            elif isinstance(v, bool):
                lines.append(f"{k}: {'true' if v else 'false'}")
            else:
                lines.append(f"{k}: {json.dumps(v, ensure_ascii=False)}")
        return "\n".join(lines) + "\n"

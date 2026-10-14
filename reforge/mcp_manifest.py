"""Versioned MCP server manifests, and risk resolution that fails closed (slice P2-S3, ADR 0003).

**The defect this closes (threat T-4).** `policy.risk_class()` decided how dangerous a tool is by
running regexes over its *unqualified name* — a string the MCP server itself chooses. A server
exposing a destructive operation under the name `analyze_report` was classified `safe_read` and,
in `assisted` mode, executed **without approval**. The catalogue was deny-by-exception: any tool
any connected server offered was callable.

Three inversions:

1. **Risk comes from a manifest, not from a name.** A manifest is written by whoever packages the
   server, is versioned, and declares per tool what it does and what class of risk it carries.
2. **An unmanifested tool is treated as the HIGHEST risk its name suggests, never the lowest.**
   Previously, a name matching no dangerous pattern meant `safe_read`. Now, absence of a
   declaration is absence of evidence that it is safe. The name heuristic survives only as a
   floor-raiser.
3. **A manifested server is an allow-list.** Once a server declares its tools, a tool it did not
   declare is refused — a server that grows a new capability after review does not get to use it
   silently.

The manifest also carries the version recorded into every piece of evidence a call produces, so a
finding can say which build of which tool produced it (threat T-11).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger("reforge.mcp_manifest")

MANIFEST_VERSION = 1

#: Ordered least to most dangerous. The order is what makes "take the higher of the two" meaningful.
RISK_ORDER = ["safe_read", "sensitive_read", "network", "dynamic_execution", "write_or_patch"]


def unmanifested_floor() -> str:
    """Minimum risk class for a server that ships no manifest. Configurable, fail-closed default."""
    from . import config

    value = getattr(config, "UNMANIFESTED_RISK_FLOOR", "sensitive_read")
    return value if value in RISK_ORDER else "sensitive_read"


def higher_risk(a: str, b: str) -> str:
    """The more dangerous of two classes. Unknown values are treated as the most dangerous."""
    ia = RISK_ORDER.index(a) if a in RISK_ORDER else len(RISK_ORDER)
    ib = RISK_ORDER.index(b) if b in RISK_ORDER else len(RISK_ORDER)
    pick = a if ia >= ib else b
    return pick if pick in RISK_ORDER else RISK_ORDER[-1]


class ToolDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    risk_class: str = Field(description="One of RISK_ORDER.")
    capability: str = Field("", description="What it does, in one line, for the approval card.")
    cost: str = Field("medium", description="fast | medium | slow | high")
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = Field(
        None,
        description="Shape of a successful result. Validating the reply matters more than "
                    "validating the call: the arguments come from us, the reply comes from the "
                    "server, and the reply is what flows on into the evidence.")
    max_output_chars: Optional[int] = Field(
        None, ge=1,
        description="Per-tool output ceiling, below the global one. A tool that should return a "
                    "verdict has no business returning a megabyte.")
    requires_approval_always: bool = Field(
        False,
        description="Force approval regardless of safety mode. For a tool whose risk the class "
                    "system understates - an irreversible action that happens to be a 'read'.")


class ServerManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_version: int = MANIFEST_VERSION
    server: str = Field(min_length=1)
    version: str = Field("0.0.0", description="Of the server, recorded into evidence.")
    author: str = ""
    description: str = ""
    prerequisites: List[str] = Field(default_factory=list)
    allow_undeclared_tools: bool = Field(
        False,
        description="For a third-party server whose full tool list cannot be enumerated. The "
                    "manifest then classifies rather than allow-lists: undeclared tools get "
                    "`default_risk_class` instead of being refused. Inventing an allow-list for a "
                    "server you cannot enumerate would refuse legitimate tools, which operators "
                    "fix by turning the whole mechanism off.")
    default_risk_class: str = Field(
        "write_or_patch",
        description="Applied to a declared tool that omits its own class. Defaults to the most "
                    "dangerous value on purpose: forgetting to classify a tool must not make it "
                    "safe.")
    tools: List[ToolDeclaration] = Field(default_factory=list)

    def tool(self, name: str) -> Optional[ToolDeclaration]:
        for declared in self.tools:
            if declared.name == name:
                return declared
        return None

    def declares_tools(self) -> bool:
        return bool(self.tools)


class ManifestRegistry:
    """Loaded manifests, keyed by server name."""

    def __init__(self, directory: Optional[Path] = None):
        self.dir = Path(directory) if directory else (Path(__file__).resolve().parent / "manifests")
        self._manifests: Dict[str, ServerManifest] = {}
        self._errors: Dict[str, str] = {}
        self.load()

    def load(self) -> None:
        self._manifests.clear()
        self._errors.clear()
        if not self.dir.is_dir():
            return
        for path in sorted(self.dir.glob("*.json")):
            try:
                manifest = ServerManifest(**json.loads(path.read_text(encoding="utf-8")))
            except Exception as exc:
                # A malformed manifest is NOT ignored into "no manifest": that would silently
                # downgrade a reviewed server to the unmanifested path. It is recorded as an error
                # and the server stays unmanifested, which is the stricter state.
                self._errors[path.stem] = f"{type(exc).__name__}: {exc}"
                log.error("manifest %s is invalid and will not be used: %s", path.name, exc)
                continue
            self._manifests[manifest.server] = manifest

    def get(self, server: str) -> Optional[ServerManifest]:
        return self._manifests.get(server)

    @property
    def errors(self) -> Dict[str, str]:
        return dict(self._errors)

    def servers(self) -> List[str]:
        return sorted(self._manifests)

    # ------------------------------------------------------------------ the decision
    def resolve(self, server: str, tool: str, *, catalogue_hint: str = "",
                name_heuristic: str = "") -> Dict[str, Any]:
        """Decide the risk class for one tool, and whether it is allowed at all.

        Returns {allowed, risk_class, source, reason, server_version, capability,
        requires_approval_always}.
        """
        manifest = self.get(server)

        if manifest is None:
            # No manifest. Both the catalogue hint and the tool name come from the same untrusted
            # place - the server itself - so taking the higher of the two closes nothing: a server
            # that names a destructive operation `analyze_report` and declares `safe_read` would
            # still be classified safe. That IS threat T-4.
            #
            # So an unmanifested server also gets a FLOOR, independent of anything it says about
            # itself. Nothing from a server nobody has reviewed is treated as fully safe; in
            # `assisted` mode that floor is gated, so it surfaces as an approval rather than a
            # silent execution. A reviewed server gets a manifest and stops paying this cost.
            floor = unmanifested_floor()
            resolved = higher_risk(
                higher_risk(catalogue_hint or "safe_read", name_heuristic or "safe_read"), floor)
            return {
                "allowed": True,
                "risk_class": resolved,
                "source": "unmanifested",
                "reason": (f"server '{server}' ships no manifest, so nothing it says about itself "
                           f"is trusted: risk is at least {floor} (its catalogue hint was "
                           f"{catalogue_hint or 'none'}, its name heuristic {name_heuristic or 'none'})"),
                "server_version": "",
                "capability": "",
                "requires_approval_always": False,
            }

        declared = manifest.tool(tool)
        if declared is None:
            if manifest.declares_tools() and not manifest.allow_undeclared_tools:
                # Allow-list: a manifested server that did not declare this tool does not get to
                # use it. A server growing a capability after review must be re-reviewed.
                return {
                    "allowed": False,
                    "risk_class": RISK_ORDER[-1],
                    "source": "manifest",
                    "reason": (f"'{tool}' is not declared in the manifest for server '{server}' "
                               f"(version {manifest.version}); the manifest is an allow-list"),
                    "server_version": manifest.version,
                    "capability": "",
                    "requires_approval_always": True,
                }
            resolved = higher_risk(manifest.default_risk_class, name_heuristic or "safe_read")
            return {
                "allowed": True, "risk_class": resolved, "source": "manifest_default",
                "reason": (f"not individually declared; server default "
                           f"{manifest.default_risk_class} from manifest {manifest.version}"
                           + ("" if resolved == manifest.default_risk_class
                              else f", raised to {resolved} by the name heuristic")),
                "server_version": manifest.version, "capability": "",
                "requires_approval_always": False,
            }

        # A declared tool still cannot talk its way *below* what its name suggests. The manifest
        # is the authority on what a tool does; it is not a licence to relabel `memory_write` as
        # a read.
        resolved = higher_risk(declared.risk_class, name_heuristic or "safe_read")
        return {
            "allowed": True,
            "risk_class": resolved,
            "source": "manifest" if resolved == declared.risk_class else "manifest+heuristic",
            "reason": (f"declared {declared.risk_class} in manifest {manifest.version}"
                       + ("" if resolved == declared.risk_class
                          else f"; raised to {resolved} by the name heuristic")),
            "server_version": manifest.version,
            "capability": declared.capability,
            "requires_approval_always": declared.requires_approval_always,
            "input_schema": declared.input_schema,
            "output_schema": declared.output_schema,
            "max_output_chars": declared.max_output_chars,
        }


_registry: Optional[ManifestRegistry] = None


def registry() -> ManifestRegistry:
    global _registry
    if _registry is None:
        _registry = ManifestRegistry()
    return _registry


def reload() -> ManifestRegistry:
    global _registry
    _registry = ManifestRegistry()
    return _registry


# --------------------------------------------------------------------------- I/O validation
#: Why validate at the gateway when the server also validates?
#:
#: Because the two protect different people. The server validates to protect itself from a
#: malformed call; the gateway validates to protect the *host* from a server, and to catch a model
#: that invented an argument before that argument reaches a debugger attached to a live process.
#: They are not redundant, and only one of them is under our control.
_MAX_VALIDATION_ERRORS = 5


class SchemaViolation(ValueError):
    """Arguments or a result did not match the declared schema."""

    def __init__(self, direction: str, tool: str, problems: List[str]):
        super().__init__(f"{direction} for '{tool}' does not match its declared schema: "
                         + "; ".join(problems[:_MAX_VALIDATION_ERRORS]))
        self.direction = direction
        self.tool = tool
        self.problems = problems


def validate_against(schema: Optional[Dict[str, Any]], payload: Any,
                     *, direction: str, tool: str) -> None:
    """Validate `payload` against a JSON Schema. No schema means no check - and that is reported.

    Uses `jsonschema` when it is installed (it arrives with `mcp`), and falls back to a small
    structural check when it is not. The fallback is deliberately narrow: it verifies required
    properties and primitive types, which is most of what a tool schema says, and it never claims
    to have validated more than it did.
    """
    if not schema:
        return
    try:
        import jsonschema
    except ImportError:
        problems = _structural_check(schema, payload)
        if problems:
            raise SchemaViolation(direction, tool, problems)
        return

    validator = jsonschema.Draft7Validator(schema)
    problems = []
    for error in validator.iter_errors(payload):
        location = ".".join(str(p) for p in error.absolute_path) or "(root)"
        problems.append(f"{location}: {error.message}")
        if len(problems) >= _MAX_VALIDATION_ERRORS:
            break
    if problems:
        raise SchemaViolation(direction, tool, problems)


def _structural_check(schema: Dict[str, Any], payload: Any) -> List[str]:
    """Required properties and primitive types, for when jsonschema is absent."""
    problems: List[str] = []
    if schema.get("type") == "object":
        if not isinstance(payload, dict):
            return [f"(root): expected an object, got {type(payload).__name__}"]
        for name in schema.get("required", []) or []:
            if name not in payload:
                problems.append(f"{name}: required property is missing")
        types: Dict[str, Any] = {"string": str, "integer": int, "number": (int, float),
                                 "boolean": bool, "array": list, "object": dict}
        for name, spec in (schema.get("properties") or {}).items():
            if name not in payload or not isinstance(spec, dict):
                continue
            expected = types.get(spec.get("type", ""))
            if expected and not isinstance(payload[name], expected):
                problems.append(
                    f"{name}: expected {spec.get('type')}, got {type(payload[name]).__name__}")
    return problems

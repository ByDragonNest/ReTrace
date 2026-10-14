"""Typed, layered, validated configuration (slice P0-S2, ADR 0001).

Precedence, lowest to highest:

    1. safe defaults          - the field defaults in `Settings` below, all fail-closed
    2. legacy USER SETTINGS   - one-time migration out of reforge/config.py (see `migrate_legacy`)
    3. settings file          - STATE_ROOT/settings.json, written by `Settings.save()`
    4. environment            - REFORGE_<FIELD>, plus the historical aliases
    5. deployment profile     - a hardening pass that can only tighten, never relax

Secrets are deliberately NOT part of this model. Provider keys and the access token live in the
secrets store under STATE_ROOT (`config.save_secrets`) and must never be written into a settings
file that an operator might copy, diff or attach to a support bundle.

Why this module exists: configuration used to be the source file `reforge/config.py`, rewritten
in place by `persist_to_file()` at runtime. That made every install a divergent fork, made
upgrades overwrite customer settings, and made a packaged or read-only install impossible.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

log = logging.getLogger("reforge.settings")

SETTINGS_FILENAME = "settings.json"

Provider = Literal["auto", "anthropic", "local", "none"]
SafetyMode = Literal["safe", "assisted", "autonomous"]
Profile = Literal["workstation", "team"]

# Safety-relevant settings are never carried forward by the legacy migration. An install that was
# running fully autonomous with no workspace confinement must not silently stay that way across
# an upgrade whose entire purpose is to close that gap. The operator re-grants, explicitly.
NEVER_MIGRATED = frozenset({
    "safety_mode", "allow_outside_workspace", "auth_required", "auth_trust_localhost",
})


class Settings(BaseModel):
    """Every non-secret setting, validated. Defaults are the shipped, fail-closed posture."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # ---- deployment ------------------------------------------------------------------------
    deployment_profile: Profile = Field(
        "workstation",
        description="`workstation` is one analyst on one machine. `team` is a shared install, and "
                    "forces the hardened posture regardless of the other values (see "
                    "_harden_for_profile).\n\n"
                    "There used to be an `enterprise` value as well. It behaved identically to "
                    "`team` - the hardening branch only ever asked 'is this workstation?' - so it "
                    "was a label that implied a distinction the code did not make. ReTrace targets "
                    "a single analyst and small teams; two profiles is the whole range.")

    # ---- LLM provider ----------------------------------------------------------------------
    llm_provider: Provider = "auto"
    anthropic_model: str = "claude-sonnet-4-5"
    local_base_url: str = "http://127.0.0.1:11434/v1"
    local_model: str = "qwen2.5:14b"
    local_api_key: str = "ollama"          # placeholder; most local servers ignore it
    local_num_ctx: int = Field(16384, ge=512)
    local_stream: bool = False
    local_max_tools: int = Field(6, ge=1)
    local_temperature: float = Field(0.2, ge=0.0, le=2.0)
    local_keep_alive: str = "30m"

    # ---- generation ------------------------------------------------------------------------
    max_tokens: int = Field(4096, ge=256)
    llm_timeout_s: int = Field(
        120, ge=5, le=3600,
        description="Wall-clock ceiling for one provider request. The SDK defaults (10 minutes "
                    "for Anthropic) are sized for batch jobs; a turn that hangs that long on a "
                    "stalled provider is indistinguishable from a hung product (prompt §9.2).")
    llm_max_retries: int = Field(2, ge=0, le=10,
                                 description="Retries the SDK may make on transport errors and 429/5xx.")
    local_timeout_s: int = Field(
        600, ge=5, le=7200,
        description="Ceiling for one request to the LOCAL provider. Separate from llm_timeout_s "
                    "because a local model is slow in ways a cloud one is not: the first call "
                    "loads weights from disk, and replies are not streamed, so a 2,000-token answer "
                    "at 20 tok/s is 100 s of wall clock before anything comes back.")
    max_agent_steps: int = Field(40, ge=1)
    repeat_call_limit: int = Field(3, ge=1)
    loop_stall_limit: int = Field(3, ge=1)
    tool_result_max_chars: int = Field(6000, ge=256)
    preload_queries: List[str] = Field(default_factory=lambda: [
        "decompile function", "list functions", "cross references xref",
        "list imports", "strings"])
    cost_aware_tool_loading: bool = True
    intent_tool_budget: int = Field(2, ge=1)

    # ---- external lookups ------------------------------------------------------------------
    nvd_online_lookup: bool = False        # fail-closed: no egress unless asked for

    # ---- reporting -------------------------------------------------------------------------
    report_use_llm_enrichment: bool = False

    # ---- safety ----------------------------------------------------------------------------
    safety_mode: SafetyMode = Field(
        "assisted",
        description="FAIL-CLOSED DEFAULT. Was shipped as 'autonomous', which disabled the "
                    "approval gate entirely while the README promised it was on.")

    # ---- language --------------------------------------------------------------------------
    #: English only, by design. It is a field rather than a constant so the value is reported in
    #: the settings payload like everything else, and so a second language - if one were ever
    #: wanted - has somewhere to go. It is not a switch today.
    ui_lang: Literal["en"] = "en"

    # ---- API access control ----------------------------------------------------------------
    auth_required: bool = True
    auth_trust_localhost: bool = Field(
        True,
        description="Profile-dependent. On `workstation` this is True: the analyst's own browser "
                    "reaches the API with no friction, which is the whole point of that profile. "
                    "`team` forces it False and it cannot be relaxed there, because "
                    "the loopback interface is shared with other processes and other people.\n\n"
                    "It was briefly shipped False for every profile. That broke the bundled SPA, "
                    "which carries no token, and the resulting 401s were invisible to the user: "
                    "every API call failed and the UI looped on an undefined project. The real "
                    "lesson was not the default but the missing handling - see the bootstrap "
                    "cookie set by `GET /` and the 401 banner in the SPA.")

    # ---- model egress --------------------------------------------------------------------------
    operating_profile: Literal[
        "offline_deterministic", "local_only", "hybrid", "frontier"] = Field(
        "frontier",
        description="What may leave this machine when a model is called.\n\n"
                    "`offline_deterministic` calls no model at all; `local_only` calls one running "
                    "here; `hybrid` lets minimized, redacted context reach a frontier provider but "
                    "keeps raw bytes and decompiled code local; `frontier` permits cloud use, "
                    "still classified, redacted and recorded.\n\n"
                    "The default is `frontier` on a workstation - the analyst's own machine, their "
                    "own call, with every request in the ledger - and forced to `hybrid` on `team` "
                    "on a shared install, because a shared default must not let a customer's "
                    "decompiled code reach an external provider (prompt §9.1).")

    project_budget_usd: float = Field(
        0.0, ge=0.0,
        description="Estimated model spend a single project may reach before further requests are "
                    "refused. 0 means unlimited, which is the workstation default - an analyst "
                    "paying for their own key does not need the tool second-guessing them.\n\n"
                    "Checked BEFORE a request goes out. A budget only checked afterwards is an "
                    "invoice, not a limit. The figure is estimated locally from the model's price "
                    "list, because the provider's actual number arrives too late to enforce.")

    # ---- retention -----------------------------------------------------------------------------
    retention_days: int = Field(
        0, ge=0,
        description="Days after a project's last update before it is marked for deletion. "
                    "0 - the default - keeps everything forever.\n\n"
                    "Expiry **soft-deletes**: the project is hidden and recoverable, not erased. "
                    "Automatically destroying an engagement's findings is not something a tool "
                    "should do on a timer; `purge_expired()` is the separate, deliberate step "
                    "that actually removes them.")
    backup_retention_count: int = Field(
        10, ge=1,
        description="Pre-migration backups kept. They accumulate beside the database, each a full "
                    "copy, and an unbounded series of them eventually fills the disk the product "
                    "is trying to protect. The backup just taken is never pruned.")

    # ---- identity ----------------------------------------------------------------------------
    identity_provider: Literal["local", "oidc_bearer"] = Field(
        "local",
        description="`local` is the workstation profile's single implicit operator. Any other "
                    "profile must use `oidc_bearer`; `identity_providers.resolve()` refuses to "
                    "mint a local operator outside `workstation`, so a misconfigured deployment "
                    "answers 401 rather than handing every caller administrator.")
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = Field("", description="Leave empty to discover it from the issuer.")
    oidc_roles_claim: str = Field(
        "roles", description="Claim holding the caller's groups; dotted for nested, e.g. "
                             "`realm_access.roles` on Keycloak.")
    oidc_role_map: Dict[str, str] = Field(
        default_factory=dict,
        description="Maps provider group names onto ReTrace roles, e.g. "
                    "{\"sec-team\": \"security_manager\"}. An unmapped group grants nothing: "
                    "inferring a role from a group name is how someone ends up with permissions "
                    "nobody granted.")
    oidc_default_role: str = Field(
        "", description="Role for an authenticated caller whose groups map to nothing. Empty "
                        "means no permissions, which is the fail-closed choice.")

    # ---- browser-facing request policy -----------------------------------------------------
    cors_allow_origins: List[str] = Field(
        default_factory=list,
        description="Extra origins allowed to call the API from a browser. Empty - the default - "
                    "means same-origin only, which is what a bundled SPA needs. Only set this when "
                    "the UI is genuinely served from another origin.")
    rate_limit_per_minute: int = Field(
        600, ge=0,
        description="Per-client API requests per minute; 0 disables it. The SPA is chatty (polling "
                    "plus SSE), so this is set to bound abuse rather than to shape traffic.")

    # ---- workspace -------------------------------------------------------------------------
    workspace_dir: str = "workspace"
    allow_outside_workspace: bool = Field(
        False,
        description="FAIL-CLOSED DEFAULT. When off, only the workspace and `external_roots` are "
                    "reachable. Turning it on falls back to a deny-list of sensitive locations, "
                    "which is structurally incomplete - prefer naming the roots you need.")
    external_roots: List[str] = Field(
        default_factory=list,
        description="Absolute directories, besides the workspace, whose files may be analyzed.\n\n"
                    "This is the allow-list that replaces the deny-list. A deny-list at a security "
                    "boundary can only enumerate what someone thought of: the shipped one covers "
                    "/etc, /root, /proc, /sys, /boot, /dev, the Windows system directories and "
                    "~/.ssh, and misses ~/.aws, ~/.config, ~/Library/Keychains, ~/.docker and /var. "
                    "Naming the two or three directories where samples actually live is both "
                    "safer and less work than enumerating everywhere they do not.")

    # ---- upload and storage limits ---------------------------------------------------------
    # Uploads used to stream to disk with no bound of any kind: no size cap, no file count, no
    # per-project quota, no free-space check. A single request could fill the analyst's disk.
    max_upload_bytes: int = Field(
        1 << 30, ge=1024,
        description="Largest single upload. 1 GiB covers a big Procmon export; raise it "
                    "deliberately for firmware dumps rather than leaving it unbounded.")
    max_artifacts_per_project: int = Field(500, ge=1)
    max_project_bytes: int = Field(
        20 * (1 << 30), ge=1 << 20,
        description="Total bytes an single project may hold on disk.")
    min_free_disk_bytes: int = Field(
        1 << 30, ge=0,
        description="Headroom kept free. An upload that would eat into it is refused before the "
                    "first byte is written, so filling the disk cannot take the host down with it.")

    # ---- where dangerous work may run ----------------------------------------------------------
    allow_unisolated_execution: bool = Field(
        True,
        description="Whether work that asks for isolation this deployment cannot provide may run "
                    "anyway, in the ReTrace process.\n\n"
                    "True on a workstation by default: one analyst, their own machine, their own "
                    "decision to debug a sample there - and refusing would just mean they do it "
                    "outside the tool with no record at all. Every such run is logged as a "
                    "warning. `team` forces this to False: running a client's binary in "
                    "the same process that serves everyone else is not a tradeoff, it is a "
                    "defect (threat T-3).")

    # ---- MCP tool risk -----------------------------------------------------------------------
    unmanifested_risk_floor: Literal[
        "safe_read", "sensitive_read", "network", "dynamic_execution", "write_or_patch"] = Field(
        "sensitive_read",
        description="Minimum risk class for a tool from a server that ships no manifest.\n\n"
                    "Both the tool name and the catalogue's own `risk_class` come from the server "
                    "itself, so neither can establish that a tool is safe. A floor is what makes "
                    "an unreviewed server surface as an approval instead of running silently - "
                    "threat T-4. Lowering this to `safe_read` restores the pre-P2-S3 behaviour and "
                    "the gap with it.")

    # ---- MCP tool execution limits ---------------------------------------------------------
    tool_call_timeout: int = Field(120, ge=1)
    tool_output_max_chars: int = Field(200_000, ge=1024)
    tool_breaker_threshold: int = Field(4, ge=1)
    tool_breaker_cooldown: int = Field(60, ge=1)

    # ---- logging ---------------------------------------------------------------------------
    log_format: Literal["text", "json"] = Field(
        "text",
        description="`json` emits one structured object per line with the correlation id, actor "
                    "and project - what a log collector needs. `text` stays readable in a "
                    "terminal, which is what a workstation needs.")
    verbose: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ---- optional Neo4j mirror -------------------------------------------------------------
    neo4j_enabled: bool = False
    neo4j_uri: str = "bolt://127.0.0.1:7687"
    neo4j_user: str = "neo4j"
    neo4j_database: str = "neo4j"

    # ---- web server ------------------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = Field(8000, ge=1, le=65535)
    reload: bool = False

    # ---- paths -----------------------------------------------------------------------------
    knowledge_dir: str = "knowledge"

    # -------------------------------------------------------------------------- validation
    @field_validator("local_base_url")
    @classmethod
    def _url_shape(cls, v: str) -> str:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("local_base_url must start with http:// or https://")
        return v

    @model_validator(mode="after")
    def _harden_for_profile(self) -> "Settings":
        """A non-workstation profile can only tighten the posture, never relax it.

        Enforced in the model rather than at the call sites so there is exactly one place where
        'is this allowed in this profile' is decided, and it cannot be bypassed by setting a
        field afterwards (validate_assignment re-runs this).
        """
        if self.deployment_profile == "workstation":
            return self
        forced: List[str] = []
        if not self.auth_required:
            object.__setattr__(self, "auth_required", True)
            forced.append("auth_required=True")
        if self.auth_trust_localhost:
            object.__setattr__(self, "auth_trust_localhost", False)
            forced.append("auth_trust_localhost=False")
        if self.allow_outside_workspace:
            object.__setattr__(self, "allow_outside_workspace", False)
            forced.append("allow_outside_workspace=False")
        if self.safety_mode == "autonomous":
            object.__setattr__(self, "safety_mode", "assisted")
            forced.append("safety_mode=assisted")
        if self.allow_unisolated_execution:
            object.__setattr__(self, "allow_unisolated_execution", False)
            forced.append("allow_unisolated_execution=False")
        if self.operating_profile == "frontier":
            # §9.1: a shared install must prevent the binary or a full decompilation from
            # reaching an external provider. `hybrid` still allows the model to help.
            object.__setattr__(self, "operating_profile", "hybrid")
            forced.append("operating_profile=hybrid")
        if forced:
            log.warning("deployment_profile=%s overrode: %s",
                        self.deployment_profile, ", ".join(forced))
        return self

    # -------------------------------------------------------------------------- derived
    @property
    def require_approval(self) -> bool:
        return self.safety_mode != "autonomous"

    @property
    def effective_log_level(self) -> str:
        return "DEBUG" if self.verbose else self.log_level

    def resolve_provider(self, has_anthropic_key: bool) -> str:
        """'auto' resolves against what is actually configured; everything else is taken as-is."""
        if self.llm_provider != "auto":
            return self.llm_provider
        if has_anthropic_key:
            return "anthropic"
        if self.local_base_url:
            return "local"
        return "none"

    # -------------------------------------------------------------------------- persistence
    def save(self, state_root: Path) -> Path:
        """Write to STATE_ROOT/settings.json. Never touches the source tree."""
        path = Path(state_root) / SETTINGS_FILENAME
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.model_dump(mode="json")
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path


# ------------------------------------------------------------------------------ env layer
# Historical names kept working so an existing deployment's environment does not break.
_ENV_ALIASES = {
    "REFORGE_NEO4J_ENABLED": "neo4j_enabled",
    "REFORGE_NEO4J_URI": "neo4j_uri",
    "REFORGE_NEO4J_USER": "neo4j_user",
    "REFORGE_NEO4J_DATABASE": "neo4j_database",
}

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _coerce(field: str, raw: str) -> Any:
    """Turn an environment string into the field's type. Raises ValueError with a usable message."""
    annotation = Settings.model_fields[field].annotation
    if annotation is bool:
        low = raw.strip().lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
        raise ValueError(f"expected a boolean (one of {sorted(_TRUE | _FALSE)}), got {raw!r}")
    if annotation is int:
        return int(raw)
    if annotation is float:
        return float(raw)
    if annotation == List[str]:
        return [p.strip() for p in raw.split(",") if p.strip()]
    return raw


def env_overrides(environ: Dict[str, str] | None = None) -> Tuple[Dict[str, Any], List[str]]:
    """Collect REFORGE_<FIELD> overrides. Returns (values, problems); never raises."""
    env = dict(os.environ if environ is None else environ)
    out: Dict[str, Any] = {}
    problems: List[str] = []
    for field in Settings.model_fields:
        key = f"REFORGE_{field.upper()}"
        if key in env:
            try:
                out[field] = _coerce(field, env[key])
            except ValueError as exc:
                problems.append(f"{key}: {exc}")
    for alias, field in _ENV_ALIASES.items():
        if alias in env and field not in out:
            try:
                out[field] = _coerce(field, env[alias])
            except ValueError as exc:
                problems.append(f"{alias}: {exc}")
    return out, problems


# ------------------------------------------------------------------------------ legacy layer
def read_legacy_block(config_path: Path) -> Dict[str, Any]:
    """Parse the literals in the USER SETTINGS block of a legacy reforge/config.py.

    Uses `ast` on the source text - the file is never imported or executed, and only plain
    literals are accepted, so a config.py carrying anything else contributes nothing.
    """
    import ast

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    start = text.find("USER SETTINGS")
    end = text.find("END USER SETTINGS")
    if start == -1 or end == -1 or end <= start:
        return {}
    block = text[start:end]
    try:
        tree = ast.parse("\n".join(block.splitlines()[1:]))
    except SyntaxError:
        return {}

    legacy_to_field = {f.upper(): f for f in Settings.model_fields}
    # Legacy names that differ from the new field names.
    legacy_to_field.update({
        "WORKSPACE_DIR_SETTING": "workspace_dir",
        "KNOWLEDGE_DIR_SETTING": "knowledge_dir",
    })
    out: Dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        field = legacy_to_field.get(target.id)
        if not field or field in NEVER_MIGRATED:
            continue
        try:
            out[field] = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            continue
    return out


# ------------------------------------------------------------------------------ loader
def load(state_root: Path, legacy_config: Path | None = None,
         environ: Dict[str, str] | None = None) -> Tuple[Settings, List[str]]:
    """Build the effective Settings from all layers. Returns (settings, notes)."""
    notes: List[str] = []
    values: Dict[str, Any] = {}

    settings_file = Path(state_root) / SETTINGS_FILENAME
    if not settings_file.is_file() and legacy_config and legacy_config.is_file():
        legacy = read_legacy_block(legacy_config)
        defaults = Settings()
        carried = {k: v for k, v in legacy.items()
                   if getattr(defaults, k, object()) != v}
        if carried:
            values.update(carried)
            notes.append(
                "migrated from the legacy USER SETTINGS block in "
                f"{legacy_config.name}: {', '.join(sorted(carried))}. "
                f"Safety settings were NOT carried over ({', '.join(sorted(NEVER_MIGRATED))}) "
                "and are back at their fail-closed defaults.")

    if settings_file.is_file():
        try:
            values.update(json.loads(settings_file.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            notes.append(f"settings file {settings_file} is unreadable ({exc}); using defaults")

    env_values, env_problems = env_overrides(environ)
    values.update(env_values)
    notes.extend(env_problems)

    # Unknown keys (a stale settings file from an older version) must not take the app down.
    known = set(Settings.model_fields)
    unknown = sorted(set(values) - known)
    if unknown:
        notes.append(f"ignored unknown settings: {', '.join(unknown)}")
        values = {k: v for k, v in values.items() if k in known}

    try:
        settings = Settings(**values)
    except Exception as exc:
        notes.append(f"invalid configuration ({exc}); falling back to the safe defaults")
        settings = Settings()
    return settings, notes

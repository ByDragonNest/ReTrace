"""Egress control for model requests: profiles, classification, redaction, ledger (slice P2-S4).

**The defect (threat T-10).** Whether a customer's decompiled code went to a cloud provider was
decided by one setting — `llm_provider` — and nothing else. There was no classification of what
was about to be sent, no redaction on the outbound path (`redact.py` existed and was used for
*displaying* settings), no egress allow-list, and no record of what had been sent, to whom, or
why. An operator could not answer "did any of this customer's binary reach Anthropic", which for
a product handling material under NDA is the question.

Four operating profiles (prompt §9.1), each a statement about what may leave the machine:

* `offline_deterministic` — no model is called at all. The deterministic analyzers, the Evidence
  Graph and the report still work.
* `local_only` — a model is called, but only one running on this host. Nothing leaves.
* `hybrid` — raw artifact bytes and full decompilation stay local; only minimized, redacted
  context may reach a frontier provider.
* `frontier` — cloud use allowed, still classified, still redacted, still recorded.

**Enforcement is at the point of no return**, inside the remote provider, not at the call sites.
A check at the caller is a check a new caller forgets.

The ledger is the part that makes the rest checkable: every outbound request is recorded with what
class of data it carried, to which provider and model, for what purpose, and how many characters
were redacted. It records *that* data was sent and its shape — never the payload, because a ledger
you have to redact before showing it is not evidence of anything.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("reforge.model_gateway")


class Profile(str, Enum):
    OFFLINE_DETERMINISTIC = "offline_deterministic"
    LOCAL_ONLY = "local_only"
    HYBRID = "hybrid"
    FRONTIER = "frontier"


class DataClass(str, Enum):
    """What kind of customer-derived material a payload carries. Ordered by sensitivity."""
    METADATA = "metadata"                  # hashes, counts, tool names, findings titles
    FINDINGS = "findings"                  # finding text, evidence summaries
    DERIVED_ANALYSIS = "derived_analysis"  # strings, imports, disassembly, decompiled code
    ARTIFACT_BYTES = "artifact_bytes"      # the sample itself, or a large verbatim extract


_SENSITIVITY = [DataClass.METADATA, DataClass.FINDINGS,
                DataClass.DERIVED_ANALYSIS, DataClass.ARTIFACT_BYTES]

#: What each profile permits to leave the host. A profile absent from this map sends nothing.
_ALLOWED_REMOTE: Dict[Profile, List[DataClass]] = {
    Profile.OFFLINE_DETERMINISTIC: [],
    Profile.LOCAL_ONLY: [],
    # Hybrid is the shared-install default: context and conclusions may go, the customer's code
    # and the sample itself may not. This is the line prompt §9.1 draws.
    Profile.HYBRID: [DataClass.METADATA, DataClass.FINDINGS],
    Profile.FRONTIER: [DataClass.METADATA, DataClass.FINDINGS,
                       DataClass.DERIVED_ANALYSIS, DataClass.ARTIFACT_BYTES],
}


class EgressDenied(PermissionError):
    """The active profile forbids sending this class of data to this provider."""

    def __init__(self, profile: Profile, data_class: DataClass, provider: str, reason: str = ""):
        super().__init__(
            f"profile '{profile.value}' does not permit {data_class.value} to reach "
            f"provider '{provider}'" + (f": {reason}" if reason else ""))
        self.profile = profile
        self.data_class = data_class
        self.provider = provider


# --------------------------------------------------------------------------- classification
# Markers of decompiled/disassembled output and raw extraction. Deliberately coarse: this decides
# whether to REFUSE, so it is tuned to catch code rather than to avoid false alarms. A payload
# wrongly classified as code is refused under `hybrid`, which is a visible, correctable error; the
# opposite is a silent leak.
_CODE_MARKERS = (
    re.compile(r"\b(undefined[0-9]|FUN_[0-9a-f]{4,}|LAB_[0-9a-f]{4,}|DAT_[0-9a-f]{4,})\b"),
    re.compile(r"^\s*(?:0x)?[0-9a-f]{6,}\s*[:|]\s+[0-9a-f]{2}\s", re.MULTILINE),  # disassembly
    re.compile(r"\b(?:push|mov|lea|call|jmp|retn?)\s+(?:e|r)?[a-z]{2}\b", re.IGNORECASE),
    re.compile(r"__(?:cdecl|stdcall|fastcall|thiscall)\b"),
    re.compile(r"\bdecompil", re.IGNORECASE),
)
_HEXDUMP = re.compile(r"(?:[0-9a-fA-F]{2}[ \-]){16,}")
#: A braced block with a declaration or a statement inside it - the shape of decompiled C, which
#: prose about a finding does not have.
_C_BLOCK = re.compile(r"\{[^{}]*;[^{}]*\}", re.DOTALL)

#: Above this, a verbatim block is treated as an extract of the artifact rather than context.
BULK_EXTRACT_CHARS = 8000


def classify(text: str, *, declared: Optional[DataClass] = None) -> DataClass:
    """Classify an outbound payload. `declared` wins - a caller that knows is more reliable.

    A *single* code marker is not enough. A finding legitimately cites the function it was found
    in ("RC4 used in FUN_00401000"), and treating that as decompiled code would refuse almost
    every finding under `hybrid` - which is the profile being useless rather than strict. Two
    independent markers, or a code marker alongside C-like block structure, is the line.
    """
    if declared is not None:
        return declared
    if not text:
        return DataClass.METADATA
    if _HEXDUMP.search(text) or len(text) > BULK_EXTRACT_CHARS:
        return DataClass.ARTIFACT_BYTES

    hits = sum(1 for marker in _CODE_MARKERS if marker.search(text))
    looks_like_a_block = bool(_C_BLOCK.search(text))
    if hits >= 2 or (hits >= 1 and looks_like_a_block):
        return DataClass.DERIVED_ANALYSIS
    return DataClass.FINDINGS


def active_profile(cfg) -> Profile:
    """The operating profile in force, derived from configuration."""
    raw = str(getattr(cfg, "OPERATING_PROFILE", "") or "").strip().lower()
    try:
        return Profile(raw)
    except ValueError:
        return Profile.HYBRID            # unknown value: the stricter of the two usable defaults


def is_remote(provider: str) -> bool:
    """Whether calling this provider sends data off the host."""
    return str(provider or "").lower() in ("anthropic", "openai", "frontier")


# --------------------------------------------------------------------------- the decision
@dataclass
class EgressDecision:
    allowed: bool
    profile: Profile
    data_class: DataClass
    provider: str
    model: str
    purpose: str
    redacted_chars: int = 0
    payload_chars: int = 0
    reason: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_ledger_entry(self) -> Dict[str, Any]:
        """What goes in the ledger. Shape and provenance only - never the payload."""
        return {
            "allowed": self.allowed,
            "profile": self.profile.value,
            "data_class": self.data_class.value,
            "provider": self.provider,
            "model": self.model,
            "purpose": self.purpose,
            "payload_chars": self.payload_chars,
            "redacted_chars": self.redacted_chars,
            "reason": self.reason,
            **self.extra,
        }


def evaluate(text: str, *, provider: str, model: str, purpose: str, cfg,
             declared: Optional[DataClass] = None) -> EgressDecision:
    """Decide whether this payload may go to this provider under the active profile."""
    profile = active_profile(cfg)
    data_class = classify(text, declared=declared)

    if not is_remote(provider):
        return EgressDecision(True, profile, data_class, provider, model, purpose,
                              payload_chars=len(text or ""),
                              reason="local provider; nothing leaves the host")

    if profile is Profile.OFFLINE_DETERMINISTIC:
        return EgressDecision(False, profile, data_class, provider, model, purpose,
                              payload_chars=len(text or ""),
                              reason="no model may be called in this profile")

    permitted = _ALLOWED_REMOTE.get(profile, [])
    if data_class not in permitted:
        return EgressDecision(
            False, profile, data_class, provider, model, purpose,
            payload_chars=len(text or ""),
            reason=(f"{data_class.value} may not leave the host under '{profile.value}'; "
                    f"permitted: {', '.join(c.value for c in permitted) or 'nothing'}"))

    return EgressDecision(True, profile, data_class, provider, model, purpose,
                          payload_chars=len(text or ""), reason="permitted by profile")


def guard(text: str, *, provider: str, model: str, purpose: str, cfg,
          declared: Optional[DataClass] = None) -> Tuple[str, EgressDecision]:
    """Evaluate, redact and record. Returns the text to actually send.

    Raises EgressDenied when the profile forbids it. Both outcomes are recorded: a refusal is as
    much a fact about this deployment as a send, and a ledger of only successes cannot answer
    "did we ever try".
    """
    decision = evaluate(text, provider=provider, model=model, purpose=purpose, cfg=cfg,
                        declared=declared)

    outbound = text or ""
    if decision.allowed and is_remote(provider):
        from . import redact as _redact

        outbound = _redact.redact(outbound)
        # Count the redactions, not a character delta: the mask has its own length, so a delta is
        # neither the number of secrets removed nor their size, and would read as both.
        decision.extra["redactions"] = outbound.count(_redact._MASK)
        decision.redacted_chars = len(text or "") - len(outbound)

    record(decision)
    if not decision.allowed:
        raise EgressDenied(decision.profile, decision.data_class, provider, decision.reason)
    return outbound, decision


# --------------------------------------------------------------------------- the ledger
def record(decision: EgressDecision) -> None:
    """Append to the audit trail. Never raises; a ledger failure must not take the call down."""
    try:
        from . import audit

        audit.record("llm.egress" if decision.allowed else "llm.egress_denied",
                     outcome="ok" if decision.allowed else "denied",
                     **decision.as_ledger_entry())
    except Exception as exc:                 # noqa: BLE001 - never break a call over bookkeeping
        log.error("egress ledger write failed: %s", exc)


def ledger(limit: int = 200) -> List[Dict[str, Any]]:
    """What has been sent off this host, newest first."""
    from . import audit

    entries = audit.read(limit=limit * 2)
    return [e for e in entries
            if e.get("action") in ("llm.egress", "llm.egress_denied")][:limit]


def summary() -> Dict[str, Any]:
    """Aggregate for the UI: has anything left this machine, and of what kind."""
    sent = ledger(limit=1000)
    # Only REMOTE sends count as egress. A local-model call is recorded for completeness - the
    # ledger should show every model request - but counting it here would mean a `local_only`
    # deployment could never demonstrate that nothing left, which is the one claim this exists
    # to support.
    allowed = [e for e in sent
               if e.get("action") == "llm.egress"
               and is_remote(e.get("detail", {}).get("provider", ""))]
    by_class: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}
    for entry in allowed:
        detail = entry.get("detail", {})
        by_class[detail.get("data_class", "?")] = by_class.get(detail.get("data_class", "?"), 0) + 1
        by_provider[detail.get("provider", "?")] = by_provider.get(detail.get("provider", "?"), 0) + 1
    return {
        "requests_sent": len(allowed),
        "requests_refused": len(sent) - len(allowed),
        "by_data_class": by_class,
        "by_provider": by_provider,
        "nothing_has_left_this_host": not allowed,
    }


# --------------------------------------------------------------------------- budgets
"""Spend ceilings per project.

A budget that is only checked after the fact is an invoice. These are checked *before* a request
goes out, so exceeding the ceiling refuses the call rather than reporting it later — which is the
difference between a limit and a log.

Accounting is in US dollars, estimated locally from the configured model's price list
(`llm_cost.py`), because the provider's actual figure arrives too late to enforce anything.
"""


class BudgetExceeded(PermissionError):
    """The project has spent its allowance for the period."""

    def __init__(self, project_id: str, spent: float, ceiling: float):
        super().__init__(
            f"project '{project_id}' has spent an estimated ${spent:.2f} of its ${ceiling:.2f} "
            "allowance; further model requests are refused until the ceiling is raised")
        self.project_id = project_id
        self.spent = spent
        self.ceiling = ceiling


def project_spend(project_id: str) -> float:
    """Estimated spend for a project, summed from its recorded usage."""
    from .session import SessionStore

    try:
        session = SessionStore().get(project_id)
    except Exception:                        # noqa: BLE001
        return 0.0
    if session is None:
        return 0.0
    total = 0.0
    for entry in (getattr(session, "llm_usage", []) or []):
        try:
            total += float(entry.get("estimated_cost_usd") or 0.0)
        except (TypeError, ValueError):
            continue
    return round(total, 4)


def check_budget(project_id: str, cfg) -> Dict[str, Any]:
    """Raise BudgetExceeded when the project is over its ceiling. Returns the accounting.

    A ceiling of 0 means unlimited, which is the workstation default: an analyst paying for their
    own key does not need the tool second-guessing them. A team deployment sets a number.
    """
    ceiling = float(getattr(cfg, "PROJECT_BUDGET_USD", 0.0) or 0.0)
    spent = project_spend(project_id) if project_id else 0.0
    status = {"project_id": project_id, "spent_usd": spent, "ceiling_usd": ceiling,
              "unlimited": ceiling <= 0}
    if ceiling > 0 and spent >= ceiling:
        record(EgressDecision(False, active_profile(cfg), DataClass.METADATA, "budget", "",
                              "budget_check", reason=f"spent {spent} of {ceiling}"))
        raise BudgetExceeded(project_id, spent, ceiling)
    return status

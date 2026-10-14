"""Schema-validated, fail-closed structured output from a model (slice P1-S4).

Before this, structured output was *parsed*: `_first_json_object()` scraped the first brace-balanced
object out of whatever the model said, tolerating code fences and surrounding prose, and
`complete_json()` returned `{}` when nothing parsed. For the local provider that best-effort path
was the primary one, not a fallback. A model that answered with something unusable therefore
produced an empty dict that flowed on as if it were an answer - the failure mode of a tool whose
job is to not make things up.

Here, a response either validates against the declared schema or it is an error:

* validate with Pydantic - the schema is the contract, not a hope;
* on failure, retry a bounded number of times, feeding the validation error back so the model can
  correct itself - this is the one place a retry is useful, because the error is specific;
* when the attempts are spent, raise. Never return a partial object, never return `{}`.

The caller then decides what to do with a model that cannot answer; what it cannot do is mistake
silence for data.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

log = logging.getLogger("reforge.llm_schema")

T = TypeVar("T", bound=BaseModel)

#: Attempts in total, not retries after the first. Two is deliberate: a model that cannot satisfy
#: a schema twice, with the validation error in front of it, is not going to on the third try, and
#: every extra attempt is latency and tokens spent on a request that is already failing.
DEFAULT_MAX_ATTEMPTS = 2


class StructuredOutputError(RuntimeError):
    """The model did not produce output matching the schema within the allowed attempts."""

    def __init__(self, schema_name: str, attempts: int, last_error: str, raw: str = ""):
        super().__init__(
            f"{schema_name}: no schema-valid response after {attempts} attempt(s): {last_error}")
        self.schema_name = schema_name
        self.attempts = attempts
        self.last_error = last_error
        #: Truncated: useful for a log line, never large enough to dump a decompilation into one.
        self.raw = (raw or "")[:2000]


def schema_prompt(model: Type[BaseModel]) -> str:
    """The instruction fragment describing the required shape.

    The JSON Schema is given verbatim rather than described in prose: it is unambiguous, and it is
    the same artefact the response is validated against, so the instruction cannot drift from the
    check.
    """
    return (
        "Reply with a single JSON object and nothing else - no prose, no code fence, no "
        "explanation. It must validate against this JSON Schema:\n\n"
        + json.dumps(model.model_json_schema(), indent=2, sort_keys=True)
    )


def validate(model: Type[T], payload: Any) -> T:
    """Validate a parsed payload. Raises ValidationError; does not coerce a wrong shape."""
    if not isinstance(payload, dict):
        raise ValidationError.from_exception_data(
            model.__name__,
            [{"type": "dict_type", "loc": (), "input": payload}])
    return model.model_validate(payload)


async def structured(client: Any, model: Type[T], *, system: str, user: str,
                     max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                     prompt_version: str = "",
                     cache: Optional[Any] = None,
                     provider: str = "", model_name: str = "") -> T:
    """Ask the model for an object of type `model`. Raises StructuredOutputError on failure.

    `cache`, when given, is consulted and populated with the *validated* result only, keyed on the
    model, the prompt version and the input - so an edited prompt or a changed schema cannot serve
    a stale answer.
    """
    schema_name = model.__name__
    schema_version = _schema_version(model)
    key = None
    if cache is not None:
        key = cache.key(provider=provider, model=model_name, prompt_version=prompt_version,
                        schema=f"{schema_name}@{schema_version}", payload=system + "\x00" + user)
        hit = cache.get(key)
        if hit is not None:
            try:
                return validate(model, hit)
            except ValidationError:
                # A cached value that no longer validates means the schema changed under it.
                # Drop it rather than trusting it; the version in the key should have prevented
                # this, so it is worth a log line.
                log.warning("cached %s no longer validates; discarding", schema_name)
                cache.delete(key)

    instruction = f"{user}\n\n{schema_prompt(model)}"
    last_error = "no attempt was made"
    raw = ""

    for attempt in range(1, max_attempts + 1):
        try:
            payload = await client.complete_json(system, instruction)
        except Exception as exc:                       # transport/provider failure
            last_error = f"{type(exc).__name__}: {exc}"
            log.warning("%s attempt %d/%d failed: %s", schema_name, attempt, max_attempts, last_error)
            continue

        raw = json.dumps(payload, default=str)[:2000] if payload else ""
        try:
            result = validate(model, payload)
        except ValidationError as exc:
            last_error = _short(exc)
            log.warning("%s attempt %d/%d did not validate: %s",
                        schema_name, attempt, max_attempts, last_error)
            # Feed the specific failure back; a generic "try again" teaches the model nothing.
            instruction = (
                f"{user}\n\n{schema_prompt(model)}\n\n"
                f"Your previous reply was rejected: {last_error}\n"
                "Return only the corrected JSON object."
            )
            continue

        if cache is not None and key is not None:
            cache.put(key, result.model_dump(mode="json"))
        return result

    raise StructuredOutputError(schema_name, max_attempts, last_error, raw)


def _short(exc: ValidationError, limit: int = 400) -> str:
    parts = []
    for err in exc.errors()[:5]:
        loc = ".".join(str(p) for p in err.get("loc", ())) or "(root)"
        parts.append(f"{loc}: {err.get('msg', 'invalid')}")
    text = "; ".join(parts)
    return text[:limit]


def _schema_version(model: Type[BaseModel]) -> str:
    import hashlib

    blob = json.dumps(model.model_json_schema(), sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]

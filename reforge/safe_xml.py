"""Entity-safe XML reading for untrusted artifacts (slice P0-S3, threat T-2).

`xml.etree.ElementTree` does not fetch external entities, but it *does* expand internal ones, so
a few hundred bytes of declarations expand to gigabytes in memory - the "billion laughs" attack.
Three parsers read attacker-supplied XML, and two of them (`artifact_overview`, `heuristics`) run
**automatically on upload**, before any human looks at the file. An uploaded Procmon export is
therefore enough to take the process down.

The guard is a refusal, not a sanitiser: a document carrying a DOCTYPE or an ENTITY declaration is
rejected outright. Legitimate Sysinternals Procmon exports, pcap sidecars and the other XML this
product reads carry neither, so nothing is lost by refusing them, and refusing is the only
mitigation that does not depend on getting expansion accounting right.

No new dependency: `defusedxml` would also work, but it is one more thing to ship, pin, scan and
keep current for a check that is six lines.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as _ET
from pathlib import Path
from typing import Any, Iterator, Literal, Tuple

# A DOCTYPE must appear in the prolog, so scanning the head is sufficient and bounded.
PROLOG_SCAN_BYTES = 64 * 1024

_DANGEROUS = re.compile(rb"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)


class UnsafeXMLError(ValueError):
    """The document declares a DTD or entities and is refused before parsing."""


def assert_safe(path: str | Path, *, scan_bytes: int = PROLOG_SCAN_BYTES) -> None:
    """Refuse XML that declares a DTD or entities. Raises UnsafeXMLError."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(scan_bytes)
    except OSError:
        return                      # the parser below will raise a more useful error
    match = _DANGEROUS.search(head)
    if match:
        raise UnsafeXMLError(
            f"XML declares a {match.group(1).decode('ascii').upper()}; refused before parsing "
            "(entity expansion can exhaust memory). Re-export the file without a DTD."
        )


_Event = Literal["start", "end", "comment", "pi", "start-ns", "end-ns"]


def iterparse(source: str | Path, events: Tuple[_Event, ...] = ("end",)) -> Iterator[Any]:
    """`ET.iterparse` with the entity guard applied first. Same streaming behaviour."""
    assert_safe(source)
    # noqa justified: this is the one guarded entry point. assert_safe() has already refused any
    # DTD or entity declaration, which is the attack S314 is about. Every other parse site in the
    # product goes through here, so an unguarded ET.iterparse elsewhere stays visible to the linter.
    return _ET.iterparse(source, events=events)  # noqa: S314

# ReTrace — third-party and licence inventory

Baseline commit `89c721a`. ReTrace itself is **Apache-2.0** (`LICENSE`).

Two kinds of entries below:
- **Verified** — resolved into a clean virtualenv from `requirements.txt` and read from installed
  package metadata on 2026-10-13.
- **To verify** — imported by the source but not declared in any requirements file, or declared
  only in an optional file. These are exactly the packages that P0-1 is about. Their licences are
  stated as *expected* and must be confirmed by the SBOM step before any customer shipment.

---

## 1. Verified closure of `requirements.txt`

Installing the three declared packages (`mcp<2`, `pefile`, `requests`) resolves to 34
distributions. Note that `mcp` transitively supplies `starlette`, `uvicorn`, `python-multipart`,
`pydantic-settings`, `PyJWT` and `cryptography` — several of which ReTrace depends on directly.
**The application currently relies on transitive dependencies of an unrelated package.** That is
not a supportable position: a minor `mcp` release that drops `uvicorn` breaks the product.

| Package | Version | Licence |
|---|---|---|
| `annotated-types` | 0.8.0 | MIT |
| `anyio` | 4.15.1 | MIT |
| `attrs` | 26.1.0 | MIT |
| `certifi` | 2026.7.22 | MPL-2.0 |
| `cffi` | 2.1.1 | MIT-0 |
| `charset-normalizer` | 3.5.2 | MIT |
| `click` | 8.5.0 | BSD-3-Clause |
| `cryptography` | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| `h11` | 0.16.0 | MIT |
| `httpcore` | 1.0.9 | BSD-3-Clause |
| `httpx` | 0.28.1 | BSD-3-Clause |
| `httpx-sse` | 0.4.3 | MIT |
| `idna` | 3.20 | BSD-3-Clause |
| `jsonschema` | 4.26.0 | MIT |
| `jsonschema-specifications` | 2025.9.1 | MIT |
| `mcp` | 1.30.0 | MIT |
| `pefile` | 2024.8.26 | MIT |
| `pycparser` | 3.11 | BSD-3-Clause |
| `pydantic` | 2.14.1 | MIT |
| `pydantic-settings` | 2.15.0 | MIT |
| `pydantic_core` | 2.50.1 | MIT |
| `PyJWT` | 2.15.1 | MIT |
| `python-dotenv` | 1.2.4 | BSD-3-Clause |
| `python-multipart` | 0.0.32 | Apache-2.0 |
| `referencing` | 0.37.0 | MIT |
| `requests` | 2.34.2 | Apache-2.0 |
| `rpds-py` | 2026.9.1 | MIT |
| `sse-starlette` | 3.5.0 | BSD-3-Clause |
| `starlette` | 1.8.0 | BSD-3-Clause |
| `typing-inspection` | 0.4.4 | MIT |
| `typing_extensions` | 4.16.0 | PSF-2.0 |
| `urllib3` | 2.8.0 | MIT |
| `uvicorn` | 0.54.0 | BSD-3-Clause |

All permissive. No copyleft obligation in this closure.

> `mcp>=1.2.0,<2` — the pin is load-bearing and correctly documented in `requirements.txt`: all
> servers use `mcp.server.fastmcp`, removed in `mcp` 2.x. Keep the pin, and add a CI job that
> fails when a 2.x migration is attempted without updating the servers.

## 2. Imported by the source but **not declared** — must be resolved by P0-1

| Package | Imported by | Expected licence | Note |
|---|---|---|---|
| `fastapi` | `reforge/server.py` | MIT | **core runtime** — the app does not start without it |
| `uvicorn` | `reforge/__main__.py` | BSD-3-Clause | currently satisfied only transitively via `mcp` |
| `pydantic` | `reforge/server.py` | MIT | same |
| `python-multipart` | FastAPI `UploadFile` routes | Apache-2.0 | same |
| `PyYAML` | `reforge/playbook.py` | MIT | playbooks do not load without it |
| `openai` | `reforge/llm.py` | Apache-2.0 | local / OpenAI-compatible provider |
| `anthropic` | `reforge/llm.py` | MIT | cloud provider; declared only in `requirements-optional.txt`, for the unrelated `x64dbg.py claude` subcommand |
| `python-docx` (`docx`) | `reforge/report_docx.py` | MIT | DOCX export |
| `xhtml2pdf` | `reforge/report_export.py` | Apache-2.0 | PDF export; pulls `reportlab` (BSD) and `html5lib` |
| `pypdf` | `reforge/knowledge.py` | BSD-3-Clause | methodology PDF ingestion |
| **`PyMuPDF` (`fitz`)** | `reforge/knowledge.py` | **AGPL-3.0 or commercial (Artifex)** | ⚠️ see §3 |
| `pytest` | `tests/` | MIT | dev only |

## 3. Licence items that require a commercial decision

### ⚠️ PyMuPDF — AGPL-3.0
`reforge/knowledge.py` imports `fitz`. PyMuPDF is distributed under **AGPL-3.0**, with a paid
commercial licence from Artifex as the alternative. AGPL's network clause is triggered by exactly
the deployment ReTrace targets: a server that users interact with over a network. Shipping
PyMuPDF inside a proprietary on-premise product without the commercial licence would oblige
ReTrace to release its own source under AGPL.

**Decision required before any commercial shipment.** Options, in order of preference:
1. Drop `fitz` and use `pypdf` alone for methodology PDF ingestion (already imported in the same
   module — verify feature parity for the text extraction actually used).
2. Make PyMuPDF a user-installed optional extra that ReTrace never distributes, with the
   capability degrading cleanly when absent.
3. Buy the Artifex commercial licence.

Option 1 is the recommendation: the dependency serves one non-core feature.

### ⚠️ Frida — wxWindows Library Licence
`servers/frida_mcp.py`, declared in `requirements-optional.txt`. The wxWindows Library Licence is
LGPL-2.1 with a linking exception. Dynamic use as a separate process is generally unproblematic,
but confirm before bundling. Keep Frida as an **operator-installed** optional extra.

### angr — BSD-2-Clause (expected)
`servers/reach_mcp.py`, `requirements-angr.txt`. Permissive. The real issue is operational, not
legal: ~1 GB with tightly pinned transitive dependencies. The existing guidance (separate
virtualenv, point only the `reach` server at that interpreter) is correct and should become the
supported packaging model for every heavyweight analysis extra.

### External tools — not distributed, invoked
| Tool | Licence | Relationship |
|---|---|---|
| Ghidra (+ GhidraMCP bridge) | Apache-2.0 | separate install, HTTP bridge |
| x64dbg | GPL-3.0 | separate install, HTTP plugin — ReTrace talks to it over a socket and does not link or distribute it |
| Procmon (Sysinternals) | Microsoft EULA | ReTrace parses its XML export; the tool is never redistributed |
| Wireshark / tshark | GPL-2.0 | separate install, invoked as a subprocess |
| FLOSS | Apache-2.0 | invoked as a subprocess, not imported |

Invoking a GPL tool as a separate process does not impose GPL obligations on ReTrace. **Do not
bundle x64dbg or tshark binaries in the release artifact**, and document them as prerequisites.

## 4. What is missing

- No SBOM (CycloneDX for the *product*; the existing `sbom_sarif.py` produces an SBOM for the
  *analyzed target*, which is a different artifact).
- No lock file — builds are not reproducible.
- No automated licence scanning and no declared licence policy (which licences are acceptable,
  which require review, which are prohibited).
- No dependency vulnerability scanning in CI.
- No provenance or signature on release artifacts.

**Closing criterion:** every runtime import is declared with a pinned, locked version; a product
SBOM is generated per release; licence and vulnerability scanning run in CI against a declared
policy; the PyMuPDF decision is recorded in an ADR.

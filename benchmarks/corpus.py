"""The benchmark corpus: synthetic fixtures with ground truth derived from their specification.

Ground truth is written from what each fixture *is*, not from what ReTrace currently reports.
That distinction is the whole point. A corpus whose expectations are snapshots of today's output
measures "nothing changed"; a corpus whose expectations come from the input measures whether the
tool is right. Where the two disagree, the baseline records a real false positive or false
negative instead of hiding it.

`expected` is EXHAUSTIVE for every fixture: anything else reported counts against precision.

Nothing here is a real program, nothing is executed, and no third-party sample is redistributed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Set

from . import synth

# A fully hardened PE still legitimately reports these two: the fixture carries no LoadConfig
# security cookie and no Authenticode signature, so "absent" is a correct reading of the bytes.
PE_BASELINE: Set[str] = {"hardening/stack-canary-gs", "hardening/authenticode-signature"}
PE_NO_MITIGATIONS: Set[str] = PE_BASELINE | {
    "hardening/dep-nx", "hardening/aslr-dynamicbase",
    "hardening/control-flow-guard", "hardening/high-entropy-aslr-64-bit",
}
ELF_BASELINE: Set[str] = {"hardening/stack-canary", "hardening/fortify-source"}
ELF_NO_MITIGATIONS: Set[str] = ELF_BASELINE | {
    "hardening/nx-gnu-stack", "hardening/pie", "hardening/relro",
}

_TEXT = 0x40000040
_CODE = 0x60000020


@dataclass
class ChainExpectation:
    """What the source→sink engine may claim about a fixture (slice P1-S5/S6).

    `max_rows` bounds the noise: before the rewrite an ordinary import table produced one row per
    source x sink pairing. `max_tier` bounds the claim: without a call site nothing may be
    presented above `capability`, and `max_confidence` keeps a capability row out of the band that
    reads as a lead.
    """
    max_rows: int = 12
    max_tier: str = "capability"
    max_confidence: float = 0.20
    expect_mitigations: bool = False


@dataclass
class Fixture:
    name: str
    build: Callable[[], bytes]
    expected: Set[str]
    rationale: str
    pair: str = ""                      # vulnerable/patched partner, for delta reporting
    tags: List[str] = field(default_factory=list)
    chains: ChainExpectation = field(default_factory=ChainExpectation)

    def write(self, directory: Path) -> Path:
        path = directory / self.name
        path.write_bytes(self.build())
        return path


def _pe(dll_char: int, *, imports=None, rdata: bytes = b"", text: bytes = b"\x90" * 600,
        relocs_stripped: bool = False, extra=None) -> Callable[[], bytes]:
    sections = [synth.Section(".text", text, _CODE)]
    if rdata:
        sections.append(synth.Section(".rdata", rdata, _TEXT))
    if extra:
        sections.extend(extra)
    spec = synth.PESpec(dll_characteristics=dll_char, relocs_stripped=relocs_stripped,
                        imports=imports or {}, sections=sections)
    return lambda: synth.build_pe(spec)


def _elf(**kw) -> Callable[[], bytes]:
    spec = synth.ELFSpec(**kw)
    return lambda: synth.build_elf(spec)


def fixtures() -> List[Fixture]:
    return [
        # ---------------------------------------------------------------- PE mitigations
        Fixture(
            "pe_hardened_benign.exe",
            _pe(synth.FULLY_HARDENED,
                imports={"kernel32.dll": ["CreateFileW", "ReadFile"]},
                rdata=b"Settings saved successfully\x00Report generated\x00"),
            expected=set(PE_BASELINE),
            rationale="DEP, ASLR, CFG and high-entropy ASLR are all set, imports are benign and "
                      "the strings carry no component or crypto markers. Only the two mitigations "
                      "the fixture genuinely lacks may be reported.",
            tags=["negative", "mitigations"],
        ),
        Fixture(
            "pe_unhardened.exe",
            _pe(synth.UNHARDENED, relocs_stripped=True,
                imports={"kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile"]},
                rdata=b"Settings saved successfully\x00"),
            expected=set(PE_NO_MITIGATIONS),
            rationale="Every DllCharacteristics mitigation bit is clear and relocations are "
                      "stripped, so each mitigation gap is a true positive and nothing else is.",
            pair="pe_hardened_benign.exe",
            tags=["mitigations"],
        ),

        # ---------------------------------------------------------------- components and crypto
        Fixture(
            "pe_vulnerable_components.exe",
            _pe(synth.UNHARDENED, relocs_stripped=True,
                imports={"msvcrt.dll": ["strcpy", "sprintf"], "kernel32.dll": ["WinExec"]},
                rdata=b"OpenSSL 1.0.2k\x00MD5_Init\x00RC4_set_key\x00"),
            expected=PE_NO_MITIGATIONS | {
                "third-party-component/openssl-1-0-2k",
                "weak-crypto/md5", "weak-crypto/rc4",
            },
            rationale="An end-of-life OpenSSL banner plus MD5 and RC4 API symbols - not bare "
                      "words, actual API names - alongside no mitigations.",
            pair="pe_patched_components.exe",
            tags=["components", "crypto"],
        ),
        Fixture(
            "pe_patched_components.exe",
            _pe(synth.FULLY_HARDENED,
                imports={"msvcrt.dll": ["strncpy_s", "snprintf"], "kernel32.dll": ["CreateFileW"]},
                rdata=b"OpenSSL 3.0.13\x00EVP_sha256\x00EVP_aes_256_gcm\x00"),
            expected=PE_BASELINE | {"third-party-component/openssl-3-0-13"},
            rationale="The patched half of the pair: current OpenSSL, modern primitives, "
                      "mitigations on. The component is still inventoried (that is correct and "
                      "is LOW/HYPOTHESIS), but no weak-crypto finding may appear.",
            pair="pe_vulnerable_components.exe",
            tags=["components", "crypto", "negative"],
        ),

        # ---------------------------------------------------------------- anti-false-positive
        Fixture(
            "pe_crypto_word_in_prose.exe",
            _pe(synth.FULLY_HARDENED,
                imports={"kernel32.dll": ["CreateFileW"]},
                rdata=b"Supported checksum formats: MD5, SHA-1 and SHA-256.\x00"
                      b"This dialog explains why MD5 should not be used.\x00"),
            expected=set(PE_BASELINE),
            rationale="The classic false positive: the words MD5 and SHA-1 appear in user-facing "
                      "prose, with no crypto API symbol anywhere. Documentation about a weak hash "
                      "is not use of a weak hash.",
            tags=["negative", "anti-fp", "crypto"],
        ),
        Fixture(
            "pe_compressed_resources.exe",
            _pe(synth.FULLY_HARDENED,
                imports={"kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile",
                                          "CloseHandle", "GetLastError", "HeapAlloc",
                                          "HeapFree", "GetModuleHandleW", "LoadLibraryW"]},
                rdata=b"Application resources\x00",
                extra=[synth.Section(".rsrc", bytes(range(256)) * 24, _TEXT)]),
            expected=PE_BASELINE | {"packing/high-entropy-resource-section-informational"},
            rationale="A high-entropy .rsrc (compressed icons and media) with a normal import "
                      "table is an installer, not a packed binary. It must stay an INFO indicator "
                      "and must not become a MEDIUM packing finding - the documented anti-FP rule.",
            tags=["negative", "anti-fp", "packing"],
        ),
        Fixture(
            "pe_packed.exe",
            _pe(synth.UNHARDENED, relocs_stripped=True,
                imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
                text=bytes(range(256)) * 12,
                rdata=bytes(range(256)) * 12),
            expected=PE_NO_MITIGATIONS | {"packing/likely-packed-obfuscated"},
            rationale="Two corroborating signals as the rule requires: high-entropy code/data "
                      "sections AND a two-import table resolving everything dynamically.",
            pair="pe_compressed_resources.exe",
            tags=["packing"],
        ),

        # ---------------------------------------------------------------- source -> sink noise
        Fixture(
            "pe_ordinary_program.exe",
            _pe(synth.FULLY_HARDENED,
                imports={"kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
                                          "GetCommandLineW", "CreateProcessW", "LoadLibraryW"],
                         "msvcrt.dll": ["getenv", "memcpy", "strncpy", "sprintf", "malloc",
                                        "fopen"],
                         "ws2_32.dll": ["recv"]},
                rdata=b"Ready\x00"),
            expected=set(PE_BASELINE),
            rationale="A perfectly ordinary program: several untrusted input sources and several "
                      "dangerous sinks, with no evidence connecting any of them. The mitigation "
                      "findings are correct; anything source-to-sink is capability, not a lead. "
                      "This is the cartesian-explosion case - 4 sources x 8 sinks used to yield 32 "
                      "rows at confidence 0.40-0.55.",
            tags=["negative", "anti-fp", "source-to-sink"],
            chains=ChainExpectation(max_rows=12, max_tier="capability", max_confidence=0.20),
        ),
        Fixture(
            "pe_bounded_string_api.exe",
            _pe(synth.FULLY_HARDENED,
                imports={"kernel32.dll": ["GetCommandLineW", "CreateFileW"],
                         "msvcrt.dll": ["strcpy", "strcpy_s", "strncpy_s", "snprintf"]},
                rdata=b"Config loaded\x00"),
            expected=set(PE_BASELINE),
            rationale="The unsafe symbol is imported alongside its bounded counterparts, which is "
                      "what a codebase mid-migration looks like. The chain must still be reported "
                      "- strcpy is genuinely there - but the mitigating symbols must be recorded "
                      "against it rather than ignored.",
            tags=["negative", "anti-fp", "source-to-sink"],
            chains=ChainExpectation(max_rows=8, max_confidence=0.20, expect_mitigations=True),
        ),

        # ---------------------------------------------------------------- ELF
        Fixture(
            "elf_hardened",
            _elf(pie=True, nx=True, relro=True, bind_now=True,
                 strings=b"Configuration loaded\x00"),
            expected=set(ELF_BASELINE),
            rationale="PIE, NX via a non-executable GNU_STACK, and RELRO with BIND_NOW.",
            tags=["negative", "mitigations", "elf"],
        ),
        Fixture(
            "elf_unhardened",
            _elf(pie=False, nx=False, relro=False, bind_now=False,
                 strings=b"Configuration loaded\x00"),
            expected=set(ELF_NO_MITIGATIONS),
            rationale="ET_EXEC, an executable GNU_STACK and no GNU_RELRO segment.",
            pair="elf_hardened",
            tags=["mitigations", "elf"],
        ),

        # ---------------------------------------------------------------- robustness / negatives
        Fixture(
            "malformed_truncated_pe.exe",
            lambda: synth.build_pe(synth.PESpec(imports={"kernel32.dll": ["CreateFileW"]},
                                                sections=[synth.Section(".text", b"\x90" * 600,
                                                                        _CODE)]))[:96],
            expected=set(),
            rationale="An MZ header and nothing coherent after it. The analyzers must decline it "
                      "without crashing and without inventing findings from the wreckage.",
            tags=["malformed", "robustness"],
        ),
        Fixture(
            "malformed_header_only.bin",
            lambda: b"MZ" + bytes(range(256)) * 2,
            expected=set(),
            rationale="A magic number followed by noise. Same contract as above.",
            tags=["malformed", "robustness"],
        ),
        Fixture(
            "negative_plain_text.txt",
            lambda: (b"ReTrace benchmark corpus\n"
                     b"This file is plain text and contains no binary structure at all.\n") * 40,
            expected=set(),
            rationale="A non-binary file must produce nothing. Any finding here is pure noise.",
            tags=["negative", "robustness"],
        ),
        Fixture(
            "negative_empty.bin",
            lambda: b"",
            expected=set(),
            rationale="Zero bytes. The degenerate input every parser eventually meets.",
            tags=["negative", "robustness"],
        ),
    ]


def pairs() -> Dict[str, str]:
    """vulnerable -> patched, for the delta report."""
    out = {}
    for f in fixtures():
        if f.pair and "negative" not in f.tags:
            out[f.name] = f.pair
    return out

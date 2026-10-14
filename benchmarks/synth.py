"""Deterministic synthetic binary builders for the benchmark corpus.

Why synthesise instead of committing sample binaries or compiling fixtures:

* **No toolchain.** A corpus that needs gcc/MSVC runs on the author's machine and nowhere else.
  These builders run anywhere Python does, including a locked-down CI runner.
* **No committed binaries.** Opaque blobs in a repository are unreviewable, and the release
  artifact must provably contain no samples.
* **Exact ground truth.** The mitigations, imports, library version strings and crypto markers are
  *chosen*, so "the analyzer should find X here and nothing else" is a statement about a known
  input rather than a guess about a real one.
* **Byte-identical across runs.** No timestamps, no randomness: the same corpus hashes the same
  everywhere, which is what makes cross-release comparison meaningful.

These are not real programs. They have no executable code, and nothing in ReTrace executes them.
They are header-and-string fixtures shaped so the deterministic analyzers see what a real binary
would show them.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

# --- PE DllCharacteristics bits (the mitigations hardening.audit reads) ----------------------
HIGH_ENTROPY_VA = 0x0020
DYNAMIC_BASE = 0x0040        # ASLR
NX_COMPAT = 0x0100           # DEP
NO_SEH = 0x0400
GUARD_CF = 0x4000            # Control Flow Guard

FULLY_HARDENED = HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | GUARD_CF
UNHARDENED = 0x0000

_FILE_ALIGN = 0x200
_SECT_ALIGN = 0x1000
_IMAGE_FILE_RELOCS_STRIPPED = 0x0001
_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

_SCN_CODE = 0x60000020       # CODE | EXECUTE | READ
_SCN_DATA = 0xC0000040       # INITIALIZED_DATA | READ | WRITE
_SCN_RDATA = 0x40000040      # INITIALIZED_DATA | READ


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class Section:
    name: str
    data: bytes
    characteristics: int = _SCN_DATA


@dataclass
class PESpec:
    """What the fixture should look like to an analyzer."""
    dll_characteristics: int = FULLY_HARDENED
    relocs_stripped: bool = False
    imports: Dict[str, Sequence[str]] = field(default_factory=dict)
    sections: List[Section] = field(default_factory=list)
    machine: int = 0x8664            # x86_64
    subsystem: int = 3               # console


def build_pe(spec: PESpec) -> bytes:
    """A minimal but genuinely parseable PE32+ image.

    Deliberately complete enough for `pefile` to read the optional header, the section table and
    the import directory - those are what the analyzers actually consume - and no more.
    """
    sections = list(spec.sections)
    idata = _build_import_section(spec.imports) if spec.imports else None

    pe_off = 0x80
    n_sections = len(sections) + (1 if idata else 0)
    opt_size = 240                                           # PE32+ with 16 data directories
    headers_size = pe_off + 4 + 20 + opt_size + 40 * n_sections
    headers_size = _align(headers_size, _FILE_ALIGN)

    # Lay sections out: each gets the next aligned RVA and file offset.
    rva = _align(headers_size, _SECT_ALIGN)
    raw = headers_size
    placed: List[tuple] = []                                 # (Section, rva, raw)
    for sect in sections:
        placed.append((sect, rva, raw))
        rva = _align(rva + max(len(sect.data), 1), _SECT_ALIGN)
        raw += _align(max(len(sect.data), 1), _FILE_ALIGN)

    import_dir_rva = import_dir_size = 0
    if idata:
        body = idata.render(rva)                             # RVAs are only knowable now
        placed.append((Section(".idata", body, _SCN_RDATA), rva, raw))
        import_dir_rva, import_dir_size = rva, idata.descriptor_bytes
        rva = _align(rva + len(body), _SECT_ALIGN)
        raw += _align(len(body), _FILE_ALIGN)

    size_of_image = rva
    size_of_code = sum(len(s.data) for s, _, _ in placed if s.characteristics & 0x20)

    # ---- DOS header + stub
    dos = bytearray(b"\x00" * pe_off)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 0x3C - 0x3C + 0x3C, 0)       # placeholder, set below
    struct.pack_into("<I", dos, 0x3C, pe_off)
    dos[0x40:0x4E] = b"This is not a real program."[:14]

    # ---- COFF file header
    characteristics = _IMAGE_FILE_EXECUTABLE_IMAGE | _IMAGE_FILE_LARGE_ADDRESS_AWARE
    if spec.relocs_stripped:
        characteristics |= _IMAGE_FILE_RELOCS_STRIPPED
    coff = struct.pack("<HHIIIHH", spec.machine, n_sections, 0, 0, 0, opt_size, characteristics)

    # ---- Optional header (PE32+)
    opt = struct.pack(
        "<HBBIIIIIQ",
        0x20B,                       # magic PE32+
        14, 0,                       # linker version
        size_of_code, 0, 0,          # SizeOfCode, InitializedData, UninitializedData
        0x1000,                      # AddressOfEntryPoint
        0x1000,                      # BaseOfCode
        0x140000000,                 # ImageBase
    )
    opt += struct.pack(
        "<IIHHHHHHIIIIHH",
        _SECT_ALIGN, _FILE_ALIGN,
        6, 0, 0, 0, 6, 0,            # OS / image / subsystem versions
        0,                           # Win32VersionValue
        size_of_image, headers_size,
        0,                           # CheckSum
        spec.subsystem, spec.dll_characteristics,
    )
    opt += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    directories = [(0, 0)] * 16
    directories[1] = (import_dir_rva, import_dir_size)       # IMAGE_DIRECTORY_ENTRY_IMPORT
    for entry in directories:
        opt += struct.pack("<II", *entry)
    assert len(opt) == opt_size, f"optional header is {len(opt)} bytes, expected {opt_size}"

    # ---- Section table
    table = b""
    for sect, srva, sraw in placed:
        table += struct.pack(
            "<8sIIIIIIHHI",
            sect.name.encode("ascii")[:8].ljust(8, b"\x00"),
            max(len(sect.data), 1), srva,
            _align(max(len(sect.data), 1), _FILE_ALIGN), sraw,
            0, 0, 0, 0, sect.characteristics,
        )

    image = bytearray()
    image += dos
    image += b"PE\x00\x00" + coff + opt + table
    image += b"\x00" * (headers_size - len(image))
    for sect, _srva, sraw in placed:
        image += b"\x00" * (sraw - len(image))
        image += sect.data
        image += b"\x00" * (_align(max(len(sect.data), 1), _FILE_ALIGN) - max(len(sect.data), 1))
    return bytes(image)


class _ImportSection:
    """Builds the .idata blob. RVAs are patched in once the section's own RVA is known."""

    def __init__(self, imports: Dict[str, Sequence[str]]):
        self.imports = {dll: list(funcs) for dll, funcs in imports.items()}
        self.descriptor_bytes = 20 * (len(self.imports) + 1)

    def render(self, base_rva: int) -> bytes:
        descriptors = b""
        tail = bytearray()
        tail_off = self.descriptor_bytes

        for dll, funcs in self.imports.items():
            # IMAGE_IMPORT_BY_NAME entries
            name_rvas = []
            for func in funcs:
                name_rvas.append(base_rva + tail_off + len(tail))
                tail += struct.pack("<H", 0) + func.encode("ascii") + b"\x00"
                if len(tail) % 2:
                    tail += b"\x00"
            # Import lookup table (also used as the IAT), null-terminated
            ilt_rva = base_rva + tail_off + len(tail)
            for rva in name_rvas:
                tail += struct.pack("<Q", rva)
            tail += struct.pack("<Q", 0)
            # DLL name
            dll_rva = base_rva + tail_off + len(tail)
            tail += dll.encode("ascii") + b"\x00"
            if len(tail) % 2:
                tail += b"\x00"
            descriptors += struct.pack("<IIIII", ilt_rva, 0, 0, dll_rva, ilt_rva)

        descriptors += struct.pack("<IIIII", 0, 0, 0, 0, 0)   # terminator
        return descriptors + bytes(tail)


def _build_import_section(imports: Dict[str, Sequence[str]]) -> _ImportSection:
    return _ImportSection(imports)


# --------------------------------------------------------------------------- ELF
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PT_LOAD = 1


@dataclass
class ELFSpec:
    pie: bool = True
    nx: bool = True                  # GNU_STACK present and not executable
    relro: bool = True               # GNU_RELRO present
    bind_now: bool = True            # full RELRO
    strings: bytes = b""


def build_elf(spec: ELFSpec) -> bytes:
    """A minimal ELF64 carrying the program headers the hardening audit reads."""
    phdrs: List[bytes] = []

    def phdr(p_type: int, flags: int, offset: int = 0, vaddr: int = 0, filesz: int = 0) -> bytes:
        return struct.pack("<IIQQQQQQ", p_type, flags, offset, vaddr, vaddr, filesz, filesz, 8)

    phdrs.append(phdr(_PT_LOAD, 5, 0, 0x400000, 0x1000))
    if spec.nx:
        phdrs.append(phdr(_PT_GNU_STACK, 6))              # RW, not X
    else:
        phdrs.append(phdr(_PT_GNU_STACK, 7))              # RWX
    if spec.relro:
        phdrs.append(phdr(_PT_GNU_RELRO, 4, 0, 0x400000, 0x100))

    e_type = 3 if spec.pie else 2                         # ET_DYN (PIE) vs ET_EXEC
    ehsize, phentsize = 64, 56
    header = struct.pack(
        "<4sBBBBB7sHHIQQQIHHHHHH",
        b"\x7fELF", 2, 1, 1, 0, 0, b"\x00" * 7,
        e_type, 0x3E, 1,                                  # EM_X86_64
        0x401000, ehsize, 0,                              # entry, phoff, shoff
        0, ehsize, phentsize, len(phdrs), 64, 0, 0,
    )
    body = header + b"".join(phdrs)
    if spec.bind_now:
        body += b"\x00" * 16 + b"BIND_NOW\x00"
    return body + spec.strings

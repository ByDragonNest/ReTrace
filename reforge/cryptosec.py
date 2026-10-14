"""Weak-cryptography and hardcoded-secret detection for binary vulnerability auditing.

Signature-based scan over the binary's bytes/strings (+ imports) for:
  - weak/broken crypto algorithms (MD5/SHA1/DES/RC4/RC2/Blowfish/ECB)  -> CWE-327/328/326
  - insecure RNG (rand/srand for security)                              -> CWE-338/330
  - hardcoded secrets (private keys, cloud/API tokens, passwords)       -> CWE-798/321

Secrets are REDACTED in the output (only a short prefix + length), so the report never
dumps a usable credential. As always, presence is a strong lead, not proof of misuse.
"""
import re
from typing import Any, Dict, List, Optional

# (label, STRONG-regex, WEAK-regex, cwe, severity, note)
#   STRONG = an actual crypto API/constant reference (EVP_*, CALG_*, *_Init/_set_key): a real use
#            signal → keep at `severity`, still a HYPOTHESIS until confirmed it's used for security.
#   WEAK   = the bare algorithm name somewhere in the image. In a large binary (RTL, UI strings,
#            resource tables, protocol lists) the name alone is almost always a false positive, so a
#            weak-only match is demoted to a low-severity INDICATOR instead of a MEDIUM/HIGH finding.
_WEAK = [
    ("MD5",        re.compile(rb"MD5_Init|MD5_Update|EVP_md5|CALG_MD5"),
                   re.compile(rb"(?i)\bMD5\b"),                                 "CWE-328", "MEDIUM",
     "Cryptographically broken hash (collisions). Do not use for security signatures/integrity."),
    ("MD4/MD2",    re.compile(rb"EVP_md4|EVP_md2|CALG_MD4|CALG_MD2|MD4_Init"),
                   re.compile(rb"(?i)\bMD4\b|\bMD2\b"),                         "CWE-328", "MEDIUM",
     "Obsolete and broken hash."),
    ("SHA-1",      re.compile(rb"SHA1_Init|SHA1_Update|EVP_sha1|CALG_SHA1"),
                   re.compile(rb"(?i)\bSHA-?1\b"),                              "CWE-328", "MEDIUM",
     "SHA-1 is subject to collisions; deprecated for security uses."),
    ("RC4",        re.compile(rb"RC4_set_key|RC4\(|EVP_rc4|CALG_RC4"),
                   re.compile(rb"(?i)\bRC4\b|ARCFOUR"),                         "CWE-327", "HIGH",
     "Broken stream cipher; does not offer adequate confidentiality."),
    ("DES/3DES",   re.compile(rb"DES_set_key|DES_ecb|DES_cbc|EVP_des|CALG_3?DES"),
                   re.compile(rb"(?i)\b3DES\b|triple ?des|\bdes-(?:cbc|ecb)\b"), "CWE-327", "HIGH",
     "DES/3DES: key too weak, deprecated."),
    ("RC2",        re.compile(rb"CALG_RC2|EVP_rc2|RC2_set_key"),
                   re.compile(rb"(?i)\bRC2\b"),                                 "CWE-327", "MEDIUM",
     "Weak legacy cipher."),
    ("Blowfish",   re.compile(rb"EVP_bf_|BF_set_key"),
                   re.compile(rb"(?i)\bblowfish\b"),                            "CWE-327", "LOW",
     "Legacy cipher (64-bit block)."),
    ("ECB mode",   re.compile(rb"MODE_ECB|CRYPT_MODE_ECB|EVP_[a-z0-9_]*_ecb"),
                   re.compile(rb"(?i)\b-ecb\b|ECB mode"),                       "CWE-327", "HIGH",
     "ECB mode: does not hide plaintext patterns."),
]

_RNG_SYMS = {"rand", "srand", "random", "drand48", "lrand48"}

# (label, byte-regex, cwe, severity)
_SECRETS = [
    ("Private key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "CWE-321", "CRITICAL"),
    ("AWS Access Key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), "CWE-798", "HIGH"),
    ("Google API key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"), "CWE-798", "HIGH"),
    ("Slack token",    re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "CWE-798", "HIGH"),
    ("GitHub token",   re.compile(rb"\bghp_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}"),
     "CWE-798", "HIGH"),
    ("JWT",            re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
     "CWE-798", "MEDIUM"),
    ("Bearer token",   re.compile(rb"(?i)bearer [A-Za-z0-9._\-]{12,}"), "CWE-798", "MEDIUM"),
    ("Plaintext password", re.compile(rb"(?i)(?:password|passwd|pwd)\s*[=:]\s*[^\s'\";<>]{4,}"),
     "CWE-798", "MEDIUM"),
    ("API/secret key", re.compile(rb"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*[^\s'\";<>]{6,}"),
     "CWE-798", "MEDIUM"),
    ("Connection string", re.compile(rb"(?i)(?:data source|server|initial catalog)=[^;]{2,};.*?(?:pwd|password)=[^;]{2,}"),
     "CWE-798", "MEDIUM"),
]


def _redact(b: bytes) -> str:
    s = b.decode("ascii", "ignore")
    s = s.replace("\n", " ").strip()
    if len(s) <= 10:
        return s[:3] + "…"
    return s[:8] + "…" + f" ({len(s)} char)"


def _ref(offset: int) -> str:
    """A precise, verifiable file reference (hex offset) for an offline byte-scan hit."""
    return f"file offset 0x{offset:X} ({offset})"


def _context(data: bytes, offset: int, span: int = 40) -> str:
    """A short printable window around the match so the analyst can locate/verify it immediately."""
    lo = max(0, offset - span)
    hi = min(len(data), offset + span)
    window = data[lo:hi]
    printable = "".join(chr(b) if 32 <= b < 127 else "·" for b in window)
    return f"…{printable}…"


def scan(data: bytes, imports: Optional[List[str]] = None) -> Dict[str, Any]:
    weak: List[Dict[str, Any]] = []
    for label, strong_pat, weak_pat, cwe, sev, note in _WEAK:
        m = strong_pat.search(data)
        if m:
            weak.append({"algo": label, "cwe": cwe, "severity": sev, "note": note, "strong": True,
                         "offset": m.start(), "context": _context(data, m.start()),
                         "evidence": m.group(0).decode("ascii", "ignore")})
            continue
        m = weak_pat.search(data)
        if m:
            # bare-name only: recorded as context so the analyst can eyeball it, but it does NOT
            # become a finding — a lone "MD5"/"RC4" string in a large binary is almost always a
            # resource/UI/protocol-option string, i.e. a false positive as a vulnerability.
            weak.append({"algo": label, "cwe": cwe, "severity": "INFO", "note": note, "strong": False,
                         "offset": m.start(), "context": _context(data, m.start()),
                         "evidence": m.group(0).decode("ascii", "ignore")})
    rng = sorted({s for s in (imports or []) if s.lower() in _RNG_SYMS})
    secrets: List[Dict[str, Any]] = []
    seen = set()
    for label, pat, cwe, sev in _SECRETS:
        for m in pat.finditer(data):
            red = _redact(m.group(0))
            key = (label, red)
            if key in seen:
                continue
            seen.add(key)
            secrets.append({"type": label, "cwe": cwe, "severity": sev,
                            "strong": label in _STRONG_SECRETS, "offset": m.start(),
                            "context": _context(data, m.start()), "evidence": red})
            if sum(1 for s in secrets if s["type"] == label) >= 5:
                break

    findings: List[Dict[str, Any]] = []
    # Weak crypto: ONLY a real crypto-API/constant reference is a lead worth recording. Bare-name
    # matches are context, not findings (see above) — this is the biggest single false-positive
    # source on large real-world binaries.
    for w in [w for w in weak if w["strong"]]:
        findings.append({
            "title": f"Weak crypto: {w['algo']}", "severity": w["severity"],
            "status": "HYPOTHESIS", "vuln_type": "weak_crypto", "cwe": w["cwe"],
            "location": _ref(w["offset"]),
            "evidence_source": "crypto API symbol", "evidence_type": "crypto token",
            "evidence": f"Crypto API/constant reference '{w['evidence']}' at {_ref(w['offset'])}. "
                        f"Context: `{w['context']}`.",
            "missing_validation_steps": [
                "xref the symbol to confirm it is called for a security purpose "
                "(integrity/confidentiality) and not a non-security checksum or dead code",
                "trace what data is protected and whether a stronger primitive is also available",
            ],
            "plain": "The program references a protection method (encryption/signing) now considered "
                     "weak: if it is actually used for security, an attacker with modest means could "
                     "bypass it.",
            "description": w["note"] + " A crypto-API reference is a concrete lead, but it must still "
                           "be confirmed (by xref) that the algorithm is used for a security purpose "
                           "and is reachable — only then is it a confirmed vulnerability.",
            "impact": "If confirmed as a security use: bypassable cryptographic protection — low-cost "
                      "collisions/preimages or decryption → forged signatures/hashes, recovery of "
                      "encrypted data, authentication bypass.",
            "recommendation": "Replace with robust primitives (SHA-256+, HMAC, AES-GCM, "
                              "ChaCha20-Poly1305); for passwords use Argon2/bcrypt/PBKDF2 with a salt.",
        })
    if rng:
        # Import presence of rand/srand is NOT a vulnerability — these are ubiquitous in benign,
        # non-security code. It is only a lead: confirmed only if the output feeds a token/key/nonce.
        # So it stays as context (res["rng"], rendered in the text), never a standalone finding.
        pass
    for s in secrets:
        strong = s.get("strong", False)
        # High-precision matches (PEM key, AKIA…, ghp_…) are strong leads at their severity. The
        # loose "password=" / "api_key=" / connection-string matches are kept (a cleartext password
        # IS worth surfacing) but at a low severity and always with a precise, verifiable reference
        # so the analyst can confirm-or-dismiss it in seconds.
        sev = s["severity"] if strong else ("LOW" if s["severity"] in ("HIGH", "MEDIUM") else s["severity"])
        f = {
            "title": f"Hardcoded secret: {s['type']}", "severity": sev,
            "status": "HYPOTHESIS" if strong else "INDICATOR",
            "vuln_type": "hardcoded_secret", "cwe": s["cwe"], "location": _ref(s["offset"]),
            "evidence_source": "string scan", "evidence_type": "redacted match",
            "evidence": f"{s['type']} (redacted): {s['evidence']} at {_ref(s['offset'])}. "
                        f"Context: `{s['context']}`.",
            # §8: a byte-scan match is a lead, not a confirmed secret — confirmation needs an xref
            # to an auth/connection/decryption function, which this offline scan cannot establish.
            "missing_validation_steps": [
                "confirm a concrete value (not a label/placeholder/UI resource) at the offset above",
                "xref the value to an authentication/connection/decryption function",
            ],
            "assumptions": ["string assumed to be a live credential rather than a placeholder"],
            "plain": "A password or secret key may be written inside the program. Anyone with the "
                     "file could find it with trivial tools — verify at the offset above before "
                     "treating it as a real credential.",
            "description": f"Possible credential/secret embedded in the binary (redacted): "
                           f"{s['evidence']} at {_ref(s['offset'])}. If confirmed as a live value, "
                           "anyone who has the binary can extract it.",
            "impact": "If confirmed, exposure of credentials/keys to anyone who has the file → possible "
                      "unauthorized access; the exposed secret would need immediate rotation.",
            "recommendation": "If confirmed, remove the secrets from the binary; use a secret store / "
                              "external configuration and rotate the exposed credentials.",
        }
        if not strong:
            f["evidence_bundle"] = {"string_context": True}   # coherent context → HYPOTHESIS ceiling
        findings.append(f)
    res = {"weak_crypto": weak, "rng": rng, "secrets": secrets, "findings": findings}
    res["text"] = render(res)
    return res


# high-precision secret types whose severity is trusted as-is; everything else is a demoted lead.
_STRONG_SECRETS = {"Private key", "AWS Access Key", "Google API key", "Slack token",
                   "GitHub token", "JWT"}


def render(res: Dict[str, Any]) -> str:
    L = ["## Weak crypto & hardcoded secrets", ""]
    weak, rng, secrets = res["weak_crypto"], res["rng"], res["secrets"]
    if weak:
        L += ["**Weak algorithms:**", "", "| Algorithm | CWE | Severity | Note |", "|---|---|---|---|"]
        L += [f"| {w['algo']} | {w['cwe']} | {w['severity']} | {w['note']} |" for w in weak]
        L.append("")
    if rng:
        L += [f"**Insecure RNG:** {', '.join(rng)} (CWE-338).", ""]
    if secrets:
        L += ["**Hardcoded secrets (redacted):**", "", "| Type | CWE | Severity | Evidence |",
              "|---|---|---|---|"]
        L += [f"| {s['type']} | {s['cwe']} | {s['severity']} | `{s['evidence']}` |" for s in secrets]
        L.append("")
    if not (weak or rng or secrets):
        L += ["No indicator of weak crypto or hardcoded secrets detected.", ""]
    return "\n".join(L)

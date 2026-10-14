"""English-only interface, and accessibility (slice P2-S10, gap P3-17).

The product is English-only by decision. It had been accumulating a second language anyway: a
parallel Italian catalogue, language-keyed lookup tables, and a switch that silently ignored its
argument - so the Italian was simultaneously maintained and unreachable. A language a product
ships and does not want is a second set of strings to keep correct for nobody's benefit.

These tests hold the line: one language in the interface, one language in the backend, and a
machine-readable code beside any error so a client reacts to the code rather than to prose.

The accessibility half is unchanged: landmarks, labels, live regions, a skip link and a correct
document language are defects a structural check can find, and they are checked here.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "reforge" / "web"
HTML = (WEB / "index.html").read_text(encoding="utf-8")
APP = (WEB / "app.js").read_text(encoding="utf-8")


def _english_catalogue() -> set:
    start = APP.index("\n  en: {") + len("\n  en: {")
    return set(re.findall(r'"([a-zA-Z0-9_.\-]+)"\s*:', APP[start:APP.index("\n};", start)]))


# --------------------------------------------------------------------------- one language
def test_there_is_no_second_catalogue():
    assert "\n  it: {" not in APP, "an Italian catalogue reappeared"
    assert _english_catalogue(), "the English catalogue is empty"


def test_there_is_no_language_switch():
    """Not a switch set to English - no switch. The alternative is a second language that is
    maintained, unreachable, and wrong by the time anyone looks."""
    assert "let LANG" not in APP and "LANG =" not in APP
    assert 'LANG === "en"' not in APP


def test_language_keyed_lookups_resolve_to_english():
    """An `|| X.it` fallback would quietly reintroduce Italian for any key English happens to miss."""
    assert "[LANG]" not in APP
    assert not re.search(r"\|\|\s*[A-Za-z_$][\w$]*\.it\b", APP)


def test_the_document_language_is_english():
    assert re.search(r'<html lang="en"', HTML)
    assert 'setAttribute("lang", "en")' in APP


def test_the_settings_offer_no_second_language():
    from reforge.settings import Settings

    import pytest as _pytest

    assert Settings().ui_lang == "en"
    with _pytest.raises(Exception):
        Settings(ui_lang="it")


def test_every_data_i18n_key_exists():
    referenced = set(re.findall(r'data-i18n="([^"]+)"', HTML))
    missing = sorted(k for k in referenced if k not in _english_catalogue())
    assert not missing, f"markup references keys the catalogue does not have: {missing}"


def test_no_italian_literal_survives_a_tr_call():
    """`tr("it", "en")` call sites were collapsed to their English literal."""
    two_literals = re.findall(r'tr\(\s*"(?:[^"\\]|\\.)*"\s*,\s*"(?:[^"\\]|\\.)*"\s*\)', APP)
    assert not two_literals, f"{len(two_literals)} tr() calls still carry two literals"


# --------------------------------------------------------------------------- accessibility
def test_there_is_a_skip_link_and_it_can_be_focused():
    """display:none would remove it from the tab order, and a skip link you cannot focus is none."""
    assert 'class="skip-link"' in HTML
    assert 'href="#main"' in HTML
    css = (WEB / "styles.css").read_text(encoding="utf-8")
    assert ".skip-link:focus" in css
    block = css[css.index(".skip-link{"):css.index(".skip-link:focus")]
    assert "display:none" not in block.replace(" ", "")


def test_the_skip_target_exists_and_is_reachable():
    assert re.search(r'<main[^>]*id="main"[^>]*tabindex="-1"', HTML)


def test_the_agent_status_is_announced():
    """The most important dynamic region in the app; without this a screen reader never hears it."""
    status = re.search(r'<div id="status"[^>]*>', HTML).group(0)
    assert 'role="status"' in status
    assert 'aria-live="polite"' in status


def test_decorative_icons_are_hidden_from_assistive_technology():
    """An <svg> with no accessible meaning read aloud is noise between every real control."""
    pulse = re.search(r'<span class="pulse"[^>]*>', HTML).group(0)
    assert 'aria-hidden="true"' in pulse


def test_radio_groups_are_grouped_and_labelled():
    """Otherwise a screen reader announces four unrelated radios with no idea what they choose."""
    assert HTML.count('role="radiogroup"') >= 2
    for group in re.findall(r'<div class="seg" role="radiogroup" aria-labelledby="(\w+)"', HTML):
        assert f'id="{group}"' in HTML, f"aria-labelledby points at a missing id: {group}"


def test_every_icon_only_button_has_an_accessible_name():
    unnamed = []
    for match in re.finditer(r"<button\b[^>]*>(.*?)</button>", HTML, re.S):
        whole, inner = match.group(0), match.group(1)
        if re.sub(r"<[^>]+>", "", inner).strip():
            continue
        if "aria-label" not in whole and "title=" not in whole:
            unnamed.append(whole[:90])
    assert not unnamed, f"icon-only buttons a screen reader announces as just 'button': {unnamed}"


def test_the_page_declares_its_landmarks():
    for landmark in ("<main", "<nav"):
        assert landmark in HTML


# --------------------------------------------------------------------------- backend language
_ITALIAN = re.compile(
    r"\b(non ha|non è|non e|già |deve |nessun|impossibile|sconosciut|in attesa|"
    r"l'operatore|temporaneamente|ripristinat|caricat[oi]|richiest[oa])", re.IGNORECASE)


_BACKEND_MODULES = sorted(p.relative_to(ROOT / "reforge").as_posix()
                          for p in (ROOT / "reforge").rglob("*.py"))


@pytest.mark.parametrize("module", _BACKEND_MODULES)
def test_no_user_facing_italian_remains_in_the_backend(module):
    """The backend speaks one language and emits a stable code; the SPA does the localising.

    That way the backend does not have to know the operator's language, and adding a third one is
    not a backend release.

    **Every** module, discovered from the tree rather than listed. This used to name six files by
    hand, and the six were the ones someone remembered. Four modules outside that list were still
    emitting Italian into API responses - `jobs.py` raised "nessun target impostato per il
    progetto" as a ValueError that becomes an error body, `playbook.py` reported validation
    failures in Italian, `graph_diff.py` built the entire graph-diff highlight list in Italian and
    `server.py` returned it under `highlights`, and `xref_enrich.py` put "(nessuno: server Ghidra
    non disponibile)" in its result. A guard that only looks where you remembered to look is not a
    guard; it is a record of what you remembered.
    """
    source = (ROOT / "reforge" / module).read_text(encoding="utf-8")
    offenders = []
    for line in source.splitlines():
        code = line.split("#", 1)[0]          # a comment is not a user-facing string
        # Single-line literals only: a multi-line match spans into comments and docstrings, which
        # is how the first version of this test "found" Italian in a code comment.
        for literal in re.findall(r'"([^"\n]{4,})"', code):
            if _ITALIAN.search(literal):
                offenders.append(literal[:80])
    assert not offenders, f"{module} still emits Italian: {offenders}"


def test_machine_readable_codes_accompany_the_prose():
    """A client reacts to a code; prose is for a human and changes without notice."""
    host = (ROOT / "reforge" / "mcp_host.py").read_text(encoding="utf-8")
    assert '"code": "tool_timeout"' in host
    assert '"code": "server_breaker_open"' in host
    agent = (ROOT / "reforge" / "agent.py").read_text(encoding="utf-8")
    assert 'code="awaiting_approval"' in agent


def test_the_api_error_envelope_carries_a_code_not_only_a_message():
    from reforge.server import _CODE_FOR_STATUS

    assert _CODE_FOR_STATUS[404] == "not_found"
    for code in _CODE_FOR_STATUS.values():
        assert code.islower() and " " not in code


# --------------------------------------------------------------------------- end to end
def test_every_tr_call_supplies_both_languages():
    """`tr(it, en)` with one argument renders the same text whatever the language is set to.

    The catalogue parity test covers `data-i18n`; this covers the strings built in JavaScript,
    which the earlier slice listed as a known gap.
    """
    # tr( "..." , "..." ) with two string literals. A call with a non-literal argument is a
    # computed string and is out of scope for a static check - those are listed, not asserted on.
    one_arg = re.findall(r'\btr\(\s*"(?:[^"\\]|\\.)*"\s*\)', APP)
    assert not one_arg, f"tr() called with a single language: {one_arg[:5]}"


def test_tr_is_not_called_with_an_empty_alternative():
    empty = re.findall(r'\btr\(\s*""\s*,|\btr\([^)]{0,200}?,\s*""\s*\)', APP)
    assert not empty, f"tr() called with an empty string for one language: {empty[:5]}"


def test_reduced_motion_is_honoured():
    """An OS preference, not a nicety: continuous animation causes nausea for some people."""
    css = (WEB / "styles.css").read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in css
    block = css[css.index("prefers-reduced-motion"):]
    assert "animation-duration" in block and "transition-duration" in block


def test_the_tool_call_log_line_carries_the_correlation_id():
    """The one log entry that says what a request DID must be tied back to the request."""
    host = (ROOT / "reforge" / "mcp_host.py").read_text(encoding="utf-8")
    assert "cid=%s" in host
    assert "correlation_id" in host


def test_nothing_reads_an_italian_branch():
    """No lookup resolves through a language key, and no accessor picks a language by index."""
    assert "[LANG]" not in APP
    assert not re.search(r"\.it\s*\[", APP), "something indexes an Italian table"
    assert not re.search(r"\|\|\s*[A-Za-z_$][\w$]*\.it\b", APP), "an Italian fallback survives"
    assert not re.search(r"\?\.\s*it\b", APP), "an optional chain reaches an Italian branch"


def test_the_graph_vocabulary_is_one_string_per_entry():
    """`NODE_TYPE_LABELS` / `EDGE_TYPE_LABELS` were `["italiano","english"]` pairs read through a
    picker that always took index 1.

    Half of every entry was unreachable, and it still had to be kept in step with the half that
    rendered - while an entry added as a bare string would have rendered as the empty label the
    picker returns for a missing row. Unreachable data that can still break the thing that reads
    it is worse than dead code.
    """
    for table in ("NODE_TYPE_LABELS", "EDGE_TYPE_LABELS"):
        start = APP.index(f"const {table}={{")
        block = APP[start:APP.index("};", start)]
        pairs = re.findall(r'\["(?:[^"\\]|\\.)*","(?:[^"\\]|\\.)*"\]', block)
        assert not pairs, f"{table} carries {len(pairs)} two-language pairs again"
    assert "_pick(" not in APP, "the language-picking accessor is back"


def test_no_render_time_rewriting_survives():
    """`UI_PHRASE_PAIRS` mapped Italian literals to English as they hit the DOM, with a
    MutationObserver re-running it on every change. It was a patch over render paths that still
    emitted Italian. Those paths are rewritten; the patch, and the observer, are gone."""
    for name in ("UI_PHRASE_PAIRS", "translateDynamic", "startI18nObserver", "I18N.it", "function tr("):
        assert name not in APP, f"{name} is back"


# --------------------------------------------------------------------------- everything shipped
# Words that are Italian and not also English. Deliberately no "data", "state", "per", "come",
# "con": a guard that cries wolf gets ignored. Found with this list, then fixed, on 2026-10-13:
# the whole MCP-server tree (~300 literals), the SPA's playbook/strings/imports copy tables, the
# graph-diff highlights, five backend modules.
_IT_WORD = re.compile(
    r"\b(?:nessun[oa]?|errore|caricamento|progetto|binario|stringhe|stringa|funzione|funzioni|analisi|"
    r"evidenza|evidenze|sessione|utente|verifica|controlla|catena|catene|trovat[oaie]|disponibile|"
    r"aggiorna|avvia|imposta|scegli|clicca|carica|attendo|esegui|già|perché|oppure|senza|tramite|"
    r"sconosciut[oaie]|impossibile|fallit[oa]|valido|validi|elenco|chiamate|chiamata|registrat[oa]|"
    r"confermat[oa]|rilevat[oa]|percorso|cartella|avviso|attenzione|pericolos[oai]|riepilogo|dettagli|"
    r"annulla|applica|salva|chiudi|mostra|nascondi|riduci|attiva|disattiva|conferma|genera|analizza|"
    r"ricostruisce|identifica|classifica|collega|dinamico|statico|rumore|vicini|bloccata|sbloccata|"
    r"filtri|aperto|risolto|sospetto|respinto|ipotesi|confermato|stimati|totale|chiave|chiavi|dalla|"
    r"della|delle|degli|nella|nelle|negli|sulla|sulle|pronto|pronta|invio|attesa|elaborazione|"
    r"ragiona|concluso|interrotto|completato|completata|avviato|avviata|cerco|adatti|caccia|"
    r"invia|reinvia|messaggio|risposta|turno|"
    # Added 2026-10-14, when a wider scan found ~120 more literals across the MCP servers, two
    # package modules and the agent's phase block: words that are Italian and not also English.
    r"pacchetti|osservat[oi]|raggiungibil[ei]|chiamanti|decodifica|righe|colonne|percorsi|dimensione|"
    r"importati|simboli|mappatura|probabile|aggiornato|invece|problematica|negativa|prossimo|classi|"
    r"scrivibil[ei]|altri|altre|tutti|quindi|verdetto|parziale|entrambi|indiretti|diretti|semplice|"
    r"varietà|maggiore|richiesto|oggetti|troncato|candidati|totali|fuori|letture|scritture|sintesi|"
    r"eventi|configurazione|condivisa|rilevanti|privilegio|servizio|statico|eliminato|esecuzione|"
    r"corrispondenti|firmatario|scadenza|generato|dettaglio|vettore|registrato|mancano|esposti|"
    r"obbligatorio|confidenza|preceduto|seguito|minimizzazione|deduplica|distinti|minimo|scelta|"
    r"prerequisito|trascurato|classificazione|vuoto|mediana|rimossi|intervallo|scarica|stesso|"
    r"funzionano|coprono|vulnerabilit[aà]|severità|permessi|deboli|eseguibili|librerie|"
    r"sovrascrivibili|priorità|massima|analizzati|protetto|esporta|arricchisce|ritorna|costruisce|"
    r"proietta|persiste|valuta|confronta|esegue|ricarica|fase|nodo|tipo|argomento|genero|relazioni|aggiungi|suggerito)\b", re.I)

#: Sites that READ Italian a user or a model may type and never emit it. Each is named here so
#: adding one is a visible decision rather than a silent exemption.
_INPUT_TOLERANCE = {
    ("reforge/intent.py", "_PATTERNS"),            # intent keywords: `mostrami le stringhe` -> STRINGS_TRIAGE
    ("reforge/agent.py", "_STALL_SIGNALS"),         # the model asking the operator a question
    ("reforge/web/app.js", "localizeFindingText"),  # legacy `plain` text in projects saved before P2-S10
    ("servers/winsec_mcp.py", "UNTRUSTED"),         # localised principal names icacls prints on Italian Windows
}


def _shipped_sources():
    yield from (ROOT / "reforge").rglob("*.py")
    yield from (ROOT / "servers").glob("*.py")
    yield from WEB.glob("*.js")
    yield from WEB.glob("*.html")
    yield from (ROOT / "reforge" / "playbooks").glob("*.yaml")
    yield from (ROOT / "reforge" / "prompts").glob("*.md")
    yield ROOT / "reforge" / "mcp.servers.default.json"
    yield from (ROOT / "reforge" / "manifests").glob("*.json")


def _literals(path: Path):
    """String literals on code lines, with docstrings and comments left out."""
    in_doc = False
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        s = line.strip()
        if path.suffix == ".py":
            if s.count('"""') % 2 == 1 or s.count("'''") % 2 == 1:
                in_doc = not in_doc
                continue
            if in_doc or s.startswith("#"):
                continue
            code = line.split("#", 1)[0]
        elif path.suffix == ".js":
            if s.startswith(("//", "/*", "*")):
                continue
            code = line
        else:
            yield n, line
            continue
        for lit in re.findall(r'"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'|`((?:[^`\\\n]|\\.)*)`', code):
            yield n, next((x for x in lit if x), "")


def test_nothing_shipped_contains_italian():
    """One language, checked over everything that ships: the package, the MCP servers, the SPA,
    the playbooks and the prompts. Docstrings and comments are out of scope; a string literal,
    a YAML value or an HTML text node is in."""
    offenders = []
    for path in _shipped_sources():
        rel = path.relative_to(ROOT).as_posix()
        src = path.read_text(encoding="utf-8", errors="ignore")
        tolerated = [name for (f, name) in _INPUT_TOLERANCE if f == rel and name in src]
        for n, text in _literals(path):
            m = _IT_WORD.search(text)
            if not m:
                continue
            # an input-tolerance site is exempt only inside the named definition
            line_src = src.splitlines()[n - 1]
            if tolerated and _inside_named_block(src, n, tolerated):
                continue
            offenders.append(f"{rel}:{n}: [{m.group(0)}] {text[:90]}")
    assert not offenders, "Italian in shipped sources:\n" + "\n".join(offenders[:40])


def _inside_named_block(src: str, lineno: int, names) -> bool:
    """True when line `lineno` sits inside the top-level definition of one of `names`."""
    lines = src.splitlines()
    for name in names:
        start = next((i for i, l in enumerate(lines, 1)
                      if re.match(rf"^(?:const |function |async function |def |)\s*{re.escape(name)}\b", l)), None)
        if start is None or lineno < start:
            continue
        # the block ends at the next top-level statement
        end = next((i for i, l in enumerate(lines[start:], start + 1)
                    if l and not l[0].isspace() and not l.startswith(("}", "]", ")"))), len(lines))
        if start <= lineno <= end:
            return True
    return False


# --------------------------------------------------------------------------- model- and client-facing docstrings
def _defs_with_docstrings(path: Path):
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    yield "<module>", ast.get_docstring(tree) or ""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, ast.get_docstring(node) or ""


def test_mcp_tool_descriptions_are_english():
    """An MCP tool's docstring IS its description: the text the model reads to decide whether and
    how to call it. The literal scan treats docstrings as internal, so the servers get their own."""
    offenders = []
    for path in sorted((ROOT / "servers").glob("*.py")):
        for name, doc in _defs_with_docstrings(path):
            m = _IT_WORD.search(doc)
            if m:
                offenders.append(f"{path.name}:{name}: [{m.group(0)}]")
    assert not offenders, "Italian in MCP tool descriptions:\n" + "\n".join(offenders[:40])


def test_api_route_descriptions_are_english():
    """A route handler's docstring is published as the endpoint description in the OpenAPI
    document, so it is client-facing even though the literal scan treats docstrings as internal.
    The CycloneDX export route still described itself in Italian when this was written."""
    import ast

    offenders = []
    for node in ast.walk(ast.parse((ROOT / "reforge" / "server.py").read_text(encoding="utf-8"))):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        routed = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                     and isinstance(d.func.value, ast.Name) and d.func.value.id == "app"
                     for d in node.decorator_list)
        m = _IT_WORD.search(ast.get_docstring(node) or "") if routed else None
        if m:
            offenders.append(f"{node.name}: [{m.group(0)}]")
    assert not offenders, "Italian in API route descriptions:\n" + "\n".join(offenders)

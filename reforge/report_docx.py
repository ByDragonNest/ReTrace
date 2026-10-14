"""Professional Word (.docx) generator for ReTrace reports.

Renders a Markdown report (as produced by report_pt.py) into a clean, professionally formatted
.docx: a cover page with the ReTrace wordmark, violet table headers, severity cells colored by
band (Critical/High red, Medium amber, Low/Info muted), a running header with the document title
and a footer with page numbers.

Falls back gracefully if python-docx is missing.
"""
import io
import re
from typing import Tuple

# Palette matching the ReTrace "Neon Lab" brand (violet → magenta).
BLUE = "6D28D9"          # headers, titles, table header fill (deep violet)
BLUE_SUB = "9333EA"      # subtitle / H3 (violet)
PURPLE = "BE185D"        # accent (underlines, wordmark dot — magenta)
WHITE = "FFFFFF"
GREY = "595959"
SEV_FILL = {
    "critica": "E11D48", "alta": "E11D48", "media": "D97706",
    "bassa": "0891B2", "informativo": "64748B",
    "critical": "E11D48", "high": "E11D48", "medium": "D97706", "low": "0891B2", "info": "64748B",
}


def _sanitize_xml_text(s: str) -> str:
    """Drop characters that are illegal in OOXML (control chars except tab/newline, and other
    code points Word renders as garbage). Prevents 'corrupt character' artifacts (prompt §17)."""
    if not s:
        return ""
    import unicodedata
    s = unicodedata.normalize("NFC", s)
    out = []
    for ch in s:
        o = ord(ch)
        if ch in ("\t", "\n"):
            out.append(ch)
        elif o < 0x20 or o == 0x7f:            # C0 controls / DEL
            continue
        elif 0x80 <= o <= 0x9f:                # C1 controls
            continue
        elif o in (0xfffe, 0xffff):            # non-characters
            continue
        else:
            out.append(ch)
    return "".join(out)


def _plain(s: str) -> str:
    s = re.sub(r"\[([^\]]+)\]\((?:#|https?:)[^)]+\)", r"\1", s or "")  # links -> text
    s = re.sub(r"`([^`]+)`", r"\1", re.sub(r"\*\*([^*]+)\*\*", r"\1", s))
    return _sanitize_xml_text(s)


def to_docx(md: str, title: str = "ReTrace Report") -> Tuple[bytes, str]:
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor, Cm
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.enum.section import WD_SECTION
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
    except ImportError:
        return b"", "DOCX unavailable: pip install python-docx"

    doc = Document()
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor.from_string("222222")

    section = doc.sections[0]
    section.top_margin = Cm(2.4); section.bottom_margin = Cm(2.2)
    section.left_margin = Cm(2.3); section.right_margin = Cm(2.3)

    # ---- helpers ----
    def shade(cell, hexcolor):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), hexcolor)
        tcPr.append(shd)

    def cell_text(cell, text, bold=False, color=None, size=10):
        cell.text = ""
        p = cell.paragraphs[0]; p.paragraph_format.space_after = Pt(2); p.paragraph_format.space_before = Pt(2)
        run = p.add_run(_plain(text)); run.bold = bold; run.font.size = Pt(size)
        run.font.name = "Calibri"
        if color:
            run.font.color.rgb = RGBColor.from_string(color)

    def bottom_border(p, color, sz="8"):
        pPr = p._p.get_or_add_pPr()
        pbdr = OxmlElement("w:pBdr"); b = OxmlElement("w:bottom")
        b.set(qn("w:val"), "single"); b.set(qn("w:sz"), sz); b.set(qn("w:space"), "4"); b.set(qn("w:color"), color)
        pbdr.append(b); pPr.append(pbdr)

    # ---- running header & footer ----
    hdr = section.header.paragraphs[0]
    hdr.text = ""
    rh = hdr.add_run(title)
    rh.font.size = Pt(8); rh.font.color.rgb = RGBColor.from_string(BLUE); rh.font.name = "Calibri"
    # wordmark on the right of the header
    tab = hdr.add_run("\t\tReTrace")
    tab.font.size = Pt(11); tab.bold = True; tab.font.color.rgb = RGBColor.from_string(BLUE)
    bottom_border(hdr, PURPLE, "4")

    ftr = section.footer.paragraphs[0]; ftr.text = ""
    rf = ftr.add_run("ReTrace · Binary Vulnerability Research Report")
    rf.font.size = Pt(7); rf.font.color.rgb = RGBColor.from_string(GREY)
    # page number
    pnum = section.footer.add_paragraph(); pnum.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = pnum.add_run(); fld1 = OxmlElement("w:fldSimple"); fld1.set(qn("w:instr"), "PAGE")
    run._r.addnext(fld1); run.font.size = Pt(8)

    def heading(text, level):
        text = _plain(text)
        p = doc.add_paragraph(); pf = p.paragraph_format
        # Outline level so a native Word TOC field can pick these up (0-based).
        pPr = p._p.get_or_add_pPr()
        olvl = OxmlElement("w:outlineLvl"); olvl.set(qn("w:val"), str(min(max(level - 1, 0), 8)))
        pPr.append(olvl)
        if level == 1:                      # only the very first H1 = handled as cover, others rare
            pf.space_before = Pt(10); pf.space_after = Pt(6)
            r = p.add_run(text); r.bold = True; r.font.size = Pt(16); r.font.color.rgb = RGBColor.from_string(BLUE)
        elif level == 2:
            pf.space_before = Pt(14); pf.space_after = Pt(6)
            r = p.add_run(text); r.bold = True; r.font.size = Pt(14); r.font.color.rgb = RGBColor.from_string(BLUE)
            bottom_border(p, PURPLE, "6")
        elif level == 3:
            pf.space_before = Pt(10); pf.space_after = Pt(4)
            r = p.add_run(text); r.bold = True; r.font.size = Pt(12); r.font.color.rgb = RGBColor.from_string(BLUE_SUB)
        else:
            pf.space_before = Pt(8)
            r = p.add_run(text); r.bold = True; r.font.size = Pt(11); r.font.color.rgb = RGBColor.from_string(PURPLE)

    def _enable_update_fields_on_open():
        """Tell Word to refresh all fields when the document opens, so the TOC builds itself
        without the reader pressing F9 (prompt §17)."""
        try:
            settings = doc.settings.element
            if settings.find(qn("w:updateFields")) is None:
                el = OxmlElement("w:updateFields")
                el.set(qn("w:val"), "true")
                settings.append(el)
        except Exception:
            pass

    def insert_toc(title_text):
        """Native Word TOC field (levels 1-3), marked dirty so Word rebuilds it on open.

        Uses a fldChar begin/separate/end run with w:dirty="true" instead of a static
        "Update fields (F9)" placeholder — the reader never sees leftover placeholder text.
        """
        heading(title_text, 2)
        _enable_update_fields_on_open()
        p = doc.add_paragraph()
        run = p.add_run()
        begin = OxmlElement("w:fldChar")
        begin.set(qn("w:fldCharType"), "begin")
        begin.set(qn("w:dirty"), "true")
        instr = OxmlElement("w:instrText")
        instr.set(qn("xml:space"), "preserve")
        instr.text = r'TOC \o "1-3" \h \z \u'
        sep = OxmlElement("w:fldChar"); sep.set(qn("w:fldCharType"), "separate")
        # Neutral, non-instructional placeholder shown only until Word refreshes the field.
        holder_r = OxmlElement("w:r"); holder_t = OxmlElement("w:t")
        holder_t.set(qn("xml:space"), "preserve")
        holder_t.text = "Contents"
        holder_r.append(holder_t)
        end = OxmlElement("w:fldChar"); end.set(qn("w:fldCharType"), "end")
        for el in (begin, instr, sep, holder_r, end):
            run._r.append(el)

    def emit_para(text):
        p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(6)
        for part in re.split(r"(\*\*[^*]+\*\*)", text):
            if not part:
                continue
            if part.startswith("**") and part.endswith("**"):
                p.add_run(_sanitize_xml_text(part[2:-2])).bold = True
            else:
                p.add_run(_sanitize_xml_text(re.sub(r"`([^`]+)`", r"\1", part)))
        return p

    lines = (md or "").split("\n")

    # ============ COVER PAGE (from leading "# title" / "## subtitle") ============
    i = 0
    title_txt, subtitle_txt = None, None
    if i < len(lines) and lines[i].startswith("# "):
        title_txt = _plain(lines[i][2:]); i += 1
    if i < len(lines) and lines[i].startswith("## "):
        subtitle_txt = _plain(lines[i][3:]); i += 1

    # wordmark
    wm = doc.add_paragraph(); wm.paragraph_format.space_after = Pt(2)
    r1 = wm.add_run("Re"); r1.font.size = Pt(20); r1.font.color.rgb = RGBColor.from_string(BLUE); r1.bold = True
    r2 = wm.add_run("Trace"); r2.font.size = Pt(20); r2.bold = True; r2.font.color.rgb = RGBColor.from_string(PURPLE)
    r3 = wm.add_run("."); r3.font.size = Pt(20); r3.bold = True; r3.font.color.rgb = RGBColor.from_string(PURPLE)
    for _ in range(8):
        doc.add_paragraph()
    ct = doc.add_paragraph(); ct.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rt = ct.add_run((title_txt or title).upper()); rt.bold = True; rt.font.size = Pt(26)
    rt.font.color.rgb = RGBColor.from_string(BLUE)
    if subtitle_txt:
        cs = doc.add_paragraph(); cs.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rs = cs.add_run(subtitle_txt); rs.font.size = Pt(15); rs.font.color.rgb = RGBColor.from_string(BLUE_SUB)
    for _ in range(6):
        doc.add_paragraph()

    def render_table(head, rows, is_summary_first_col_blue=False):
        tbl = doc.add_table(rows=1, cols=len(head)); tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        try:
            tbl.style = "Table Grid"
        except Exception:
            pass
        for j, h in enumerate(head):
            c = tbl.rows[0].cells[j]; shade(c, BLUE); cell_text(c, h, bold=True, color=WHITE, size=10)
        sev_col = next((j for j, h in enumerate(head)
                        if _plain(h).strip().lower() in ("severity",)), None)
        # first column emphasis (label columns like in the template attribute tables)
        for r in rows:
            cells = tbl.add_row().cells
            for j, c in enumerate(r[:len(head)]):
                cell_text(cells[j], c)
                if sev_col is not None and j == sev_col:
                    fill = SEV_FILL.get(_plain(c).strip().lower())
                    if fill:
                        shade(cells[j], fill); cell_text(cells[j], c, bold=True, color=WHITE)
        return tbl

    # ============ BODY ============
    while i < len(lines):
        line = lines[i]; t = line.strip()

        mh = re.match(r"^(#{1,4})\s+(.*)$", line)
        if mh:
            htxt = _plain(mh.group(2))
            if len(mh.group(1)) == 2 and htxt.strip().lower() == "contents":
                insert_toc(htxt); i += 1
                # skip the markdown TOC anchor list that follows
                while i < len(lines) and (lines[i].strip() == "" or lines[i].lstrip().startswith("- [")):
                    i += 1
                continue
            heading(mh.group(2), len(mh.group(1))); i += 1; continue

        if t.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(re.sub(r"^\s*>\s?", "", lines[i])); i += 1
            p = doc.add_paragraph(); p.paragraph_format.left_indent = Cm(0.3)
            run = p.add_run(_plain(" ".join(buf))); run.italic = True; run.font.color.rgb = RGBColor.from_string(GREY)
            continue

        # caption line: "Table N: ..." or "*Figure ...*" (and the Italian forms in reports
        # generated before the product became English-only)
        if re.match(r"^\*?(Table|Figure|Tabella|Figura)\s", t):
            cap = doc.add_paragraph(); cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            rr = cap.add_run(_plain(t)); rr.italic = True; rr.font.size = Pt(8.5); rr.font.color.rgb = RGBColor.from_string(GREY)
            i += 1; continue

        if re.match(r"^\|.*\|$", t) and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            head = [c.strip() for c in t.strip("|").split("|")]
            i += 2; rows = []
            while i < len(lines) and re.match(r"^\|.*\|$", lines[i].strip()):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")]); i += 1
            render_table(head, rows)
            doc.add_paragraph()
            continue

        if re.match(r"^\s*[-*]\s+", line):
            txt = re.sub(r"^\s*[-*]\s+", "", line)
            p = doc.add_paragraph(style="List Bullet")
            for part in re.split(r"(\*\*[^*]+\*\*)", txt):
                if not part:
                    continue
                if part.startswith("**") and part.endswith("**"):
                    p.add_run(_sanitize_xml_text(part[2:-2])).bold = True
                else:
                    p.add_run(_sanitize_xml_text(re.sub(r"`([^`]+)`", r"\1", part)))
            i += 1; continue

        if t == "" or re.match(r"^\s*(---|___+)\s*$", line):
            i += 1; continue

        emit_para(line); i += 1

    out = io.BytesIO(); doc.save(out)
    return out.getvalue(), ""

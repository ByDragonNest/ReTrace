"""Export a Markdown report to HTML, PDF, or DOCX.

HTML is dependency-free. PDF uses xhtml2pdf (pip install xhtml2pdf), DOCX uses python-docx
(pip install python-docx); if a library is missing the caller gets a clear error instead of a
crash. The Markdown subset matches what report.py emits: # headings, **bold**, `code`, - lists,
| tables |, --- rules.
"""
import io
import html as _html
import re
from typing import List, Tuple

_PRINT_CSS = """
@page { size: A4; margin: 1.9cm; }
body { font-family: 'Helvetica','Arial',sans-serif; font-size: 10.5px; color: #1b1f27; line-height: 1.5; }
h1 { font-size: 20px; color: #2b2150; border-bottom: 3px solid #8B7DF7; padding-bottom: 6px; margin-bottom: 2px; }
h2 { font-size: 15px; color: #3a2f7a; margin-top: 20px; border-bottom: 1px solid #d8d4ee; padding-bottom: 3px; }
h3 { font-size: 12.5px; color: #4b3fb0; margin-top: 14px; }
h4 { font-size: 11.5px; color: #222; margin-top: 12px; margin-bottom: 3px; }
p { margin: 5px 0; }
em { color: #6b7180; font-style: italic; }
code { font-family: 'Courier New',monospace; background: #f0eff8; padding: 1px 4px; border-radius: 3px; font-size: 9.5px; }
pre { background: #f6f5fb; border: 1px solid #ddd; padding: 8px; border-radius: 4px; font-size: 9.5px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; }
th, td { border: 1px solid #cfcadf; padding: 4px 8px; text-align: left; font-size: 9.8px; vertical-align: top; }
th { background: #ece9fb; color: #2b2150; }
ul, ol { margin: 5px 0; padding-left: 20px; } li { margin: 2px 0; }
hr { border: 0; border-top: 1px solid #cfcadf; margin: 12px 0; }
blockquote.callout { margin: 9px 0; padding: 9px 13px; background: #f3f1fc; border-left: 4px solid #8B7DF7;
  border-radius: 0 5px 5px 0; }
blockquote.callout p { margin: 0; }
"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slugify(text: str) -> str:
    """GitHub-style heading slug. The one implementation; report_pt imports it for TOC links."""
    s = (text or "").strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"[\s_]+", "-", s).strip("-")


def md_to_html_fragment(src: str) -> str:
    src = src or ""
    blocks: List[str] = []

    def _stash(m: "re.Match[str]") -> str:
        blocks.append(f"<pre><code>{_esc(m.group(2).rstrip())}</code></pre>")
        return f"\x00{len(blocks) - 1}\x00"

    src = re.sub(r"```(\w+)?\n?([\s\S]*?)```", _stash, src)
    src = _esc(src)
    src = re.sub(r"`([^`]+)`", r"<code>\1</code>", src)
    src = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", src)
    src = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", src)
    src = re.sub(r"\[([^\]]+)\]\((https?:[^)]+)\)", r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>', src)
    lines = src.split("\n")
    html: List[str] = []
    para: List[str] = []
    i, in_list = 0, False

    def flush_p():
        if para:
            html.append("<p>" + "<br>".join(para) + "</p>")
            para.clear()

    def close_list():
        nonlocal in_list
        if in_list:
            html.append("</ul>"); in_list = False

    while i < len(lines):
        line = lines[i]; t = line.strip()
        m_ph = re.fullmatch(r"\x00(\d+)\x00", t)
        if m_ph:
            flush_p(); close_list(); html.append(blocks[int(m_ph.group(1))]); i += 1; continue
        if re.match(r"^\|.*\|$", t) and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            flush_p(); close_list()
            head = [c.strip() for c in t[1:-1].split("|")]
            i += 2; rows = []
            while i < len(lines) and re.match(r"^\|.*\|$", lines[i].strip()):
                rows.append([c.strip() for c in lines[i].strip()[1:-1].split("|")]); i += 1
            html.append("<table><thead><tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr></thead><tbody>"
                        + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</tbody></table>")
            continue
        mh = re.match(r"^(#{1,4})\s+(.*)$", line)
        if mh:
            flush_p(); close_list(); n = len(mh.group(1))
            # The id is what makes the report's table of contents work once it is HTML or PDF:
            # report_pt builds its links with the same slugify, so the two cannot drift apart.
            html.append(f'<h{n} id="{slugify(_html.unescape(mh.group(2)))}">{mh.group(2)}</h{n}>'); i += 1; continue
        if t.startswith("&gt;"):     # blockquote / callout (">" escaped to "&gt;")
            flush_p(); close_list()
            buf = []
            while i < len(lines) and lines[i].strip().startswith("&gt;"):
                buf.append(re.sub(r"^\s*&gt;\s?", "", lines[i])); i += 1
            html.append(f"<blockquote class='callout'>{'<br>'.join(buf)}</blockquote>")
            continue
        if re.match(r"^\s*[-*]\s+", line):
            flush_p()
            if not in_list:
                html.append("<ul>"); in_list = True
            html.append("<li>" + re.sub(r"^\s*[-*]\s+", "", line) + "</li>"); i += 1; continue
        if re.match(r"^\s*(---|___)\s*$", line):
            flush_p(); close_list(); html.append("<hr>"); i += 1; continue
        if t == "":
            flush_p(); close_list(); i += 1; continue
        close_list(); para.append(line); i += 1
    flush_p(); close_list()
    return "\n".join(html)


def to_html(md: str, title: str = "ReTrace Report") -> str:
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{_esc(title)}</title>"
            f"<style>{_PRINT_CSS}</style></head><body>{md_to_html_fragment(md)}</body></html>")


_EMOJI_PDF = {"✅": "Yes", "❌": "No", "⚠": "!", "🔬": "", "🎯": "", "⟳": "", "⏹": "", "📚": "", "🧩": "", "💬": "", "⚑": "", "📁": ""}


def _for_pdf(md: str) -> str:
    for k, v in _EMOJI_PDF.items():
        md = md.replace(k, v)
    return md


def to_pdf(md: str, title: str = "ReTrace Report") -> Tuple[bytes, str]:
    try:
        from xhtml2pdf import pisa
    except ImportError:
        return b"", "PDF export unavailable — install the optional dependency: pip install xhtml2pdf"
    out = io.BytesIO()
    pisa.CreatePDF(to_html(_for_pdf(md), title), dest=out, encoding="utf-8")
    return out.getvalue(), ""


def to_docx(md: str, title: str = "ReTrace Report") -> Tuple[bytes, str]:
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
    except ImportError:
        return b"", "DOCX export unavailable — install the optional dependency: pip install python-docx"
    doc = Document()
    lines = (md or "").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]; t = line.strip()
        mh = re.match(r"^(#{1,4})\s+(.*)$", line)
        if mh:
            doc.add_heading(_plain(mh.group(2)), level=min(int(len(mh.group(1))), 4)); i += 1; continue
        if t.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(re.sub(r"^\s*>\s?", "", lines[i])); i += 1
            try:
                p = doc.add_paragraph(style="Intense Quote")
            except Exception:
                p = doc.add_paragraph()
            _para_with_bold(p, " ".join(buf))
            continue
        if re.match(r"^\|.*\|$", t) and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            head = [c.strip() for c in t[1:-1].split("|")]
            i += 2; rows = []
            while i < len(lines) and re.match(r"^\|.*\|$", lines[i].strip()):
                rows.append([c.strip() for c in lines[i].strip()[1:-1].split("|")]); i += 1
            tbl = doc.add_table(rows=1, cols=len(head)); tbl.style = "Light Grid Accent 1"
            for j, h in enumerate(head):
                tbl.rows[0].cells[j].text = _plain(h)
            for r in rows:
                cells = tbl.add_row().cells
                for j, c in enumerate(r[:len(head)]):
                    cells[j].text = _plain(c)
            continue
        if re.match(r"^\s*[-*]\s+", line):
            doc.add_paragraph(_plain(re.sub(r"^\s*[-*]\s+", "", line)), style="List Bullet"); i += 1; continue
        if t == "" or re.match(r"^\s*(---|___)\s*$", line):
            i += 1; continue
        _para_with_bold(doc.add_paragraph(), line)
        i += 1
    out = io.BytesIO(); doc.save(out)
    return out.getvalue(), ""


def _plain(s: str) -> str:
    return re.sub(r"`([^`]+)`", r"\1", re.sub(r"\*\*([^*]+)\*\*", r"\1", s))


def _para_with_bold(paragraph, text: str) -> None:
    for part in re.split(r"(\*\*[^*]+\*\*)", text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            paragraph.add_run(part[2:-2]).bold = True
        else:
            paragraph.add_run(re.sub(r"`([^`]+)`", r"\1", part))

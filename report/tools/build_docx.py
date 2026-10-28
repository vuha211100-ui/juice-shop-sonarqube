"""Dựng bản Word (.docx) sửa được từ report/report_concise.md — song song với build_pdf.py.

Cần: Python + python-docx (`pip install python-docx`). Không cần Word/Office.
Chạy:  python report/tools/build_docx.py
Ra:    report/BaoCao_DevSecOps_JuiceShop_gon.docx
Mục lục là field TOC của Word — mở file, bấm Ctrl+A rồi F9 để cập nhật số trang.
"""
import pathlib
import re
import sys

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH as ALIGN
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

sys.stdout.reconfigure(encoding='utf-8')

ROOT = pathlib.Path(__file__).resolve().parents[2]
REPORT = ROOT / 'report'
SRC = REPORT / 'report_concise.md'
SHOTS = REPORT / 'screenshots'
OUT = REPORT / 'BaoCao_DevSecOps_JuiceShop_gon.docx'

NAVY = RGBColor(0x0B, 0x2A, 0x4A)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
BODY_FONT = 'Times New Roman'
MONO = 'Consolas'

TITLE = ['Đánh giá an toàn và bảo vệ dữ liệu người dùng',
         'ứng dụng OWASP Juice Shop v20.2.0']
COURSE = 'Học phần: DevOps và DevSecOps (SEC4349)'
SCHOOL = 'Học viện Công nghệ Bưu chính Viễn thông — Khoa An toàn thông tin'
MEMBERS = [
    ('Nguyễn Toàn Thắng', 'B26CHAT039', 'F01 — SQL injection đăng nhập'),
    ('Phạm Thị Minh Thúy', 'B26CHAT042', 'F02 — SQL injection tìm kiếm'),
    ('Đỗ Đức Quốc Anh', 'B26CHAT001', 'F03 — lộ endpoint /metrics'),
    ('Hồ Anh Vũ', 'B26CHAT048', 'F04 — cấu hình an toàn container'),
]
DATE = 'Năm học 2026'

FIG_MAP = {}


def expand_includes(md):
    """!include[relpath] -> nội dung file bọc trong khối mã (giữ phụ lục luôn đồng bộ với file thật)."""
    def repl(m):
        p = ROOT / m.group(1).strip()
        return '```\n' + p.read_text(encoding='utf-8').rstrip('\n') + '\n```'
    return re.sub(r'^!include\[([^\]]+)\]\s*$', repl, md, flags=re.M)


INLINE_RE = re.compile(r'(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*|\[[^\]]+\]\(https?://[^)]+\)|https?://[^\s)]+)')


def shade(el, fill):
    tcPr = el.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill)
    tcPr.append(shd)


def add_hyperlink(p, url, text):
    part = p.part
    r_id = part.relate_to(url, 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink',
                          is_external=True)
    link = OxmlElement('w:hyperlink')
    link.set(qn('r:id'), r_id)
    run = OxmlElement('w:r')
    rPr = OxmlElement('w:rPr')
    col = OxmlElement('w:color'); col.set(qn('w:val'), '0B4EA2'); rPr.append(col)
    u = OxmlElement('w:u'); u.set(qn('w:val'), 'single'); rPr.append(u)
    run.append(rPr)
    t = OxmlElement('w:t'); t.text = text; run.append(t)
    link.append(run)
    p._p.append(link)


def add_inline(p, text):
    text = re.sub(r'@fig\(([^)]+)\)', lambda m: 'Hình ' + str(FIG_MAP.get(m.group(1), '?')), text)
    pos = 0
    for m in INLINE_RE.finditer(text):
        if m.start() > pos:
            p.add_run(text[pos:m.start()])
        tok = m.group(0)
        if tok.startswith('**'):
            p.add_run(tok[2:-2]).bold = True
        elif tok.startswith('`'):
            r = p.add_run(tok[1:-1]); r.font.name = MONO; r.font.size = Pt(10)
        elif tok.startswith('*'):
            p.add_run(tok[1:-1]).italic = True
        elif tok.startswith('['):
            mm = re.match(r'\[([^\]]+)\]\((https?://[^)]+)\)', tok)
            add_hyperlink(p, mm.group(2), mm.group(1))
        else:
            add_hyperlink(p, tok, tok)
        pos = m.end()
    if pos < len(text):
        p.add_run(text[pos:])


def add_caption(doc, text):
    p = doc.add_paragraph()
    p.alignment = ALIGN.CENTER
    r = p.add_run(text)
    r.italic = True
    r.font.size = Pt(11)
    return p


def add_table(doc, rows, caption, n):
    cells = [[c.strip() for c in r.strip().strip('|').split('|')] for r in rows]
    cells = [r for r in cells if not all(set(c) <= set('-: ') for c in r)]
    if caption:
        add_caption(doc, f'Bảng {n}. {caption}')
    head, body = cells[0], cells[1:]
    t = doc.add_table(rows=len(cells), cols=len(head))
    t.style = 'Table Grid'
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(head):
        cell = t.cell(0, j)
        shade(cell._tc, '0B2A4A')
        run = cell.paragraphs[0].add_run(h)
        run.bold = True
        run.font.color.rgb = WHITE
    for i, row in enumerate(body, 1):
        for j, val in enumerate(row):
            if j < len(head):
                add_inline(t.cell(i, j).paragraphs[0], val)
    doc.add_paragraph()


def add_code(doc, code):
    t = doc.add_table(rows=1, cols=1)
    t.style = 'Table Grid'
    cell = t.cell(0, 0)
    shade(cell._tc, 'F6F8FA')
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    lines = code.split('\n')
    for k, ln in enumerate(lines):
        r = p.add_run(ln)
        r.font.name = MONO
        r.font.size = Pt(8.5)
        if k < len(lines) - 1:
            p.add_run().add_break()
    doc.add_paragraph()


def add_fig(doc, name, caption, width_cm, n):
    p = doc.add_paragraph()
    p.alignment = ALIGN.CENTER
    p.add_run().add_picture(str(SHOTS / name), width=Cm(min(width_cm, 16)))
    cap = doc.add_paragraph()
    cap.alignment = ALIGN.CENTER
    r = cap.add_run(f'Hình {n}. ')
    r.italic = True
    r.font.size = Pt(11)
    add_inline(cap, caption)
    for run in cap.runs:
        run.italic = True
        run.font.size = Pt(11)


def field(p, instr, placeholder=''):
    r = p.add_run()._r
    for ft, txt in (('begin', None), (None, instr), ('separate', None), ('text', placeholder), ('end', None)):
        if ft in ('begin', 'separate', 'end'):
            fc = OxmlElement('w:fldChar'); fc.set(qn('w:fldCharType'), ft); r.append(fc)
        elif ft == 'text':
            t = OxmlElement('w:t'); t.text = txt; r.append(t)
        else:
            it = OxmlElement('w:instrText'); it.set(qn('xml:space'), 'preserve'); it.text = txt; r.append(it)


def build():
    global FIG_MAP
    md = expand_includes(SRC.read_text(encoding='utf-8'))
    FIG_MAP = {pathlib.Path(m.group(1)).stem: i
               for i, m in enumerate(re.finditer(r'!fig\[([^\]]+)\]', md), 1)}

    doc = Document()
    # cho Word tự cập nhật mục lục khi mở (không cần hướng dẫn Ctrl+A/F9 thủ công)
    upd = OxmlElement('w:updateFields'); upd.set(qn('w:val'), 'true')
    doc.settings.element.append(upd)
    normal = doc.styles['Normal']
    normal.font.name = BODY_FONT
    normal.font.size = Pt(13)
    for sec in doc.sections:
        sec.page_width, sec.page_height = Cm(21), Cm(29.7)
        sec.top_margin = sec.bottom_margin = Cm(2.2)
        sec.left_margin = sec.right_margin = Cm(2)
        # số trang ở footer
        fp = sec.footer.paragraphs[0]
        fp.alignment = ALIGN.CENTER
        field(fp, 'PAGE', '')

    # ----- bìa -----
    for _ in range(4):
        doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = ALIGN.CENTER
    r = p.add_run(SCHOOL); r.bold = True; r.font.size = Pt(13)
    doc.add_paragraph()
    for line in TITLE:
        p = doc.add_paragraph(); p.alignment = ALIGN.CENTER
        r = p.add_run(line); r.bold = True; r.font.size = Pt(20); r.font.color.rgb = NAVY
    doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = ALIGN.CENTER
    p.add_run(COURSE).font.size = Pt(14)
    doc.add_paragraph()
    t = doc.add_table(rows=1, cols=3); t.style = 'Table Grid'; t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(('Thành viên', 'MSSV', 'Lỗi phụ trách')):
        shade(t.cell(0, j)._tc, '0B2A4A')
        rr = t.cell(0, j).paragraphs[0].add_run(h); rr.bold = True; rr.font.color.rgb = WHITE
    for name, code, job in MEMBERS:
        row = t.add_row().cells
        row[0].paragraphs[0].add_run(name)
        row[1].paragraphs[0].add_run(code)
        row[2].paragraphs[0].add_run(job)
    doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = ALIGN.CENTER
    p.add_run(DATE).font.size = Pt(13)
    doc.add_page_break()

    # ----- mục lục -----
    h = doc.add_paragraph(); r = h.add_run('Mục lục'); r.bold = True; r.font.size = Pt(16); r.font.color.rgb = NAVY
    field(doc.add_paragraph(), 'TOC \\o "1-2" \\h \\z \\u', 'Mục lục tự cập nhật khi mở tài liệu.')
    doc.add_page_break()

    # ----- thân -----
    lines = md.split('\n')
    i = fig_no = tbl_no = 0
    pending = None
    while i < len(lines):
        ln = lines[i]
        if ln.startswith('```'):
            i += 1; buf = []
            while i < len(lines) and not lines[i].startswith('```'):
                buf.append(lines[i]); i += 1
            i += 1
            add_code(doc, '\n'.join(buf)); continue
        m = re.match(r'^!fig\[([^\]]+)\]\((.*)\)\{width=([\d.]+)\}\s*$', ln)
        if m:
            fig_no += 1
            add_fig(doc, m.group(1), m.group(2), float(m.group(3)), fig_no)
            i += 1; continue
        if ln.startswith('Table:'):
            pending = ln[len('Table:'):].strip(); i += 1; continue
        if ln.startswith('|'):
            buf = []
            while i < len(lines) and lines[i].startswith('|'):
                buf.append(lines[i]); i += 1
            tbl_no += 1
            add_table(doc, buf, pending, tbl_no); pending = None; continue
        m = re.match(r'^(#{1,4})\s+(.*)$', ln)
        if m:
            lvl, txt = len(m.group(1)), m.group(2).strip()
            if txt.startswith('Phụ lục'):
                doc.add_page_break()
            doc.add_heading(txt, level=lvl)
            i += 1; continue
        if ln.lstrip().startswith('- '):
            while i < len(lines) and lines[i].lstrip().startswith('- '):
                p = doc.add_paragraph(style='List Bullet')
                add_inline(p, lines[i].lstrip()[2:]); i += 1
            continue
        if ln.strip() == '':
            i += 1; continue
        buf = []
        while i < len(lines) and lines[i].strip() and not lines[i].startswith(('```', '|', 'Table:')) \
                and not re.match(r'^#{1,4}\s', lines[i]) and not lines[i].lstrip().startswith('- ') \
                and not lines[i].startswith('!fig['):
            buf.append(lines[i]); i += 1
        p = doc.add_paragraph()
        p.alignment = ALIGN.JUSTIFY
        add_inline(p, ' '.join(buf))

    doc.save(str(OUT))
    print('đã dựng', OUT, f'({OUT.stat().st_size // 1024} KB)')


if __name__ == '__main__':
    build()

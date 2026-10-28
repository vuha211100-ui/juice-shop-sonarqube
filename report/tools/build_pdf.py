"""Dựng PDF báo cáo từ report/report_concise.md.

Thay cho bộ build cũ (đã mất): markdown -> HTML (nhúng ảnh base64) -> Edge/Chrome headless -> PDF.
Không cần cài gì ngoài Edge hoặc Chrome (mọi máy Windows 11 có sẵn Edge) và Python.

Chạy:  python report/tools/build_pdf.py
Ra:    report/BaoCao_DevSecOps_JuiceShop_gon.pdf
"""
import base64
import html
import os
import pathlib
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8')

ROOT = pathlib.Path(__file__).resolve().parents[2]   # report/tools -> report -> gốc repo
REPORT = ROOT / 'report'
SRC = REPORT / 'report_concise.md'
SHOTS = REPORT / 'screenshots'
OUT_PDF = REPORT / 'BaoCao_DevSecOps_JuiceShop_gon.pdf'

TITLE = 'Đánh giá an toàn và bảo vệ dữ liệu người dùng\nứng dụng OWASP Juice Shop v20.2.0'
COURSE = 'Học phần: DevOps và DevSecOps (SEC4349)'
SCHOOL = 'Học viện Công nghệ Bưu chính Viễn thông — Khoa An toàn thông tin'
MEMBERS = [
    ('Nguyễn Toàn Thắng', 'B26CHAT039', 'F01 — SQL injection đăng nhập'),
    ('Phạm Thị Minh Thúy', 'B26CHAT042', 'F02 — SQL injection tìm kiếm'),
    ('Đỗ Đức Quốc Anh', 'B26CHAT001', 'F03 — lộ endpoint /metrics'),
    ('Hồ Anh Vũ', 'B26CHAT048', 'F04 — cấu hình an toàn container'),
]
DATE = 'Năm học 2026'

FIG_MAP = {}   # tên hình (không .png) -> số thứ tự, dùng để phân giải @fig(...)

CHROMES = [
    os.environ.get('CHROME', ''),
    r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
]


def find_chrome():
    for p in CHROMES:
        if p and pathlib.Path(p).exists():
            return p
    sys.exit('Không tìm thấy Chrome/Edge. Đặt biến môi trường CHROME trỏ tới chrome.exe/msedge.exe.')


def img_data_uri(name):
    p = SHOTS / name
    if not p.exists():
        sys.exit(f'Thiếu ảnh: {p}')
    ext = p.suffix.lstrip('.').lower()
    mime = 'jpeg' if ext in ('jpg', 'jpeg') else ext
    return f'data:image/{mime};base64,' + base64.b64encode(p.read_bytes()).decode()


def expand_includes(md):
    """!include[relpath] -> nội dung file bọc trong khối mã (giữ phụ lục luôn đồng bộ với file thật)."""
    def repl(m):
        p = ROOT / m.group(1).strip()
        return '```\n' + p.read_text(encoding='utf-8').rstrip('\n') + '\n```'
    return re.sub(r'^!include\[([^\]]+)\]\s*$', repl, md, flags=re.M)


def slug(t, i):
    s = re.sub(r'[^a-z0-9]+', '-', t.lower()).strip('-')
    return f's{i}-{s}'[:60]


def inline(t):
    codes = []

    def stash(m):
        codes.append(m.group(1))
        return f'\x00{len(codes) - 1}\x00'

    t = re.sub(r'`([^`]+)`', stash, t)
    t = html.escape(t)
    t = re.sub(r'@fig\(([^)]+)\)', lambda m: 'Hình ' + str(FIG_MAP.get(m.group(1), '?')), t)
    t = re.sub(r'\[([^\]]+)\]\((https?://[^)]+)\)', r'<a href="\2">\1</a>', t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'<em>\1</em>', t)
    t = re.sub(r'(?<![">\w])(https?://[^\s<)]+)', r'<a href="\1">\1</a>', t)
    t = re.sub('\x00(\\d+)\x00', lambda m: '<code>' + html.escape(codes[int(m.group(1))]) + '</code>', t)
    return t


def render_table(rows, caption, tbl_no):
    cells = [[c.strip() for c in r.strip().strip('|').split('|')] for r in rows]
    cells = [r for r in cells if not all(set(c) <= set('-: ') for c in r)]  # bỏ hàng ---
    head, body = cells[0], cells[1:]
    out = ['<figure class="tbl">']
    if caption:
        out.append(f'<figcaption>Bảng {tbl_no}. {inline(caption)}</figcaption>')
    out.append('<table><thead><tr>' + ''.join(f'<th>{inline(c)}</th>' for c in head) + '</tr></thead><tbody>')
    for r in body:
        out.append('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>')
    out.append('</tbody></table></figure>')
    return '\n'.join(out)


def convert(md):
    lines = md.split('\n')
    i, parts, toc = 0, [], []
    fig_no = tbl_no = 0
    pending_cap = None
    while i < len(lines):
        ln = lines[i]
        if ln.startswith('```'):
            i += 1
            buf = []
            while i < len(lines) and not lines[i].startswith('```'):
                buf.append(lines[i])
                i += 1
            i += 1
            parts.append('<pre class="code"><code>' + html.escape('\n'.join(buf)) + '</code></pre>')
            continue
        m = re.match(r'^!fig\[([^\]]+)\]\((.*)\)\{width=([\d.]+)\}\s*$', ln)
        if m:
            fig_no += 1
            name, cap, w = m.group(1), m.group(2), float(m.group(3))
            wcm = min(w, 16.5)
            parts.append(f'<figure class="fig"><img src="{img_data_uri(name)}" '
                         f'style="width:{wcm}cm;max-width:100%"/>'
                         f'<figcaption>Hình {fig_no}. {inline(cap)}</figcaption></figure>')
            i += 1
            continue
        if ln.startswith('Table:'):
            pending_cap = ln[len('Table:'):].strip()
            i += 1
            continue
        if ln.startswith('|'):
            buf = []
            while i < len(lines) and lines[i].startswith('|'):
                buf.append(lines[i])
                i += 1
            tbl_no += 1
            parts.append(render_table(buf, pending_cap, tbl_no))
            pending_cap = None
            continue
        m = re.match(r'^(#{1,4})\s+(.*)$', ln)
        if m:
            lvl, txt = len(m.group(1)), m.group(2).strip()
            anc = slug(txt, i)
            if lvl <= 2:
                toc.append((lvl, txt, anc))
            cls = ' class="appendix"' if txt.startswith('Phụ lục') else ''
            parts.append(f'<h{lvl} id="{anc}"{cls}>{inline(txt)}</h{lvl}>')
            i += 1
            continue
        if ln.lstrip().startswith('- '):
            items = []
            while i < len(lines) and lines[i].lstrip().startswith('- '):
                items.append(lines[i].lstrip()[2:])
                i += 1
            parts.append('<ul>' + ''.join(f'<li>{inline(x)}</li>' for x in items) + '</ul>')
            continue
        if ln.strip() == '':
            i += 1
            continue
        # đoạn văn
        buf = []
        stop = ('```', '|', 'Table:')
        while i < len(lines) and lines[i].strip() and not lines[i].startswith(stop) \
                and not re.match(r'^#{1,4}\s', lines[i]) and not lines[i].lstrip().startswith('- ') \
                and not lines[i].startswith('!fig['):
            buf.append(lines[i])
            i += 1
        parts.append('<p>' + inline(' '.join(buf)) + '</p>')
    return '\n'.join(parts), toc


def build():
    md = expand_includes(SRC.read_text(encoding='utf-8'))
    global FIG_MAP
    FIG_MAP = {pathlib.Path(m.group(1)).stem: i
               for i, m in enumerate(re.finditer(r'!fig\[([^\]]+)\]', md), 1)}
    body, toc = convert(md)
    toc_html = ['<nav class="toc"><h1>Mục lục</h1>']
    for lvl, txt, anc in toc:
        toc_html.append(f'<div class="toc{lvl}"><a href="#{anc}">{inline(txt)}</a></div>')
    toc_html.append('</nav>')

    members = ''.join(f'<tr><td>{n}</td><td>{code}</td><td>{job}</td></tr>' for n, code, job in MEMBERS)
    title_html = TITLE.replace('\n', '<br/>')

    css = """
    @page { size: A4; margin: 2.2cm 2cm; }
    * { box-sizing: border-box; }
    body { font-family: "Times New Roman", serif; font-size: 13pt; line-height: 1.5; color: #111; }
    h1,h2,h3,h4 { font-family: "Times New Roman", serif; color: #0b2a4a; line-height: 1.25; }
    h1 { font-size: 17pt; margin: 18pt 0 8pt; border-bottom: 2px solid #0b2a4a; padding-bottom: 3pt; }
    h2 { font-size: 14.5pt; margin: 14pt 0 6pt; }
    h3 { font-size: 12.5pt; margin: 10pt 0 4pt; }
    h4 { font-size: 12pt; margin: 8pt 0 3pt; font-style: italic; }
    h1.appendix { page-break-before: always; }
    h1,h2,h3,h4 { break-after: avoid; page-break-after: avoid; }
    p { margin: 5pt 0; text-align: justify; }
    ul { margin: 5pt 0 5pt 0; padding-left: 20pt; }
    li { margin: 2pt 0; text-align: justify; }
    code { font-family: Consolas, "Courier New", monospace; font-size: 10.5pt; background: #f3f5f7; padding: 0 2px; border-radius: 3px; }
    pre.code { background: #f6f8fa; border: 1px solid #d8dee4; border-radius: 5px; padding: 7px 10px; font-family: Consolas, "Courier New", monospace; font-size: 8.5pt; line-height: 1.3; white-space: pre-wrap; word-break: break-word; margin: 6pt 0; }
    pre.code code { background: none; font-size: 8.5pt; padding: 0; }
    figure { margin: 10pt 0; text-align: center; page-break-inside: avoid; }
    figure.fig img { border: 1px solid #d8dee4; border-radius: 4px; }
    figcaption { font-size: 10.5pt; color: #333; font-style: italic; margin-top: 4pt; }
    figure.tbl figcaption { margin: 0 0 4pt; font-style: italic; }
    table { border-collapse: collapse; width: 100%; font-size: 11pt; }
    th, td { border: 1px solid #b9c2cc; padding: 4px 7px; text-align: left; vertical-align: top; }
    thead th { background: #0b2a4a; color: #fff; font-weight: bold; }
    tbody tr:nth-child(even) { background: #f3f6f9; }
    a { color: #0b4ea2; text-decoration: none; }
    .cover { text-align: center; height: 24.5cm; display: flex; flex-direction: column; justify-content: center; page-break-after: always; }
    .cover .school { font-size: 13pt; text-transform: uppercase; letter-spacing: .3px; }
    .cover .big { font-size: 22pt; font-weight: bold; color: #0b2a4a; margin: 26pt 20pt; line-height: 1.3; }
    .cover .course { font-size: 14pt; margin-top: 6pt; }
    .cover table { width: auto; margin: 26pt auto 0; font-size: 12.5pt; }
    .cover .date { margin-top: 26pt; font-size: 12.5pt; }
    nav.toc { page-break-after: always; }
    nav.toc h1 { border: none; }
    .toc1 { font-weight: bold; margin: 6pt 0 2pt; }
    .toc2 { margin: 1pt 0 1pt 18pt; }
    .toc1 a, .toc2 a { color: #111; }
    """

    doc = f"""<!doctype html><html lang="vi"><head><meta charset="utf-8"><style>{css}</style></head><body>
    <section class="cover">
      <div class="school">{SCHOOL}</div>
      <div class="big">{title_html}</div>
      <div class="course">{COURSE}</div>
      <table><thead><tr><th>Thành viên</th><th>MSSV</th><th>Lỗi phụ trách</th></tr></thead>
      <tbody>{members}</tbody></table>
      <div class="date">{DATE}</div>
    </section>
    {''.join(toc_html)}
    {body}
    </body></html>"""

    html_path = REPORT / '.build_report.html'
    html_path.write_text(doc, encoding='utf-8')
    chrome = find_chrome()
    url = 'file:///' + str(html_path).replace('\\', '/')
    if OUT_PDF.exists():
        OUT_PDF.unlink()
    subprocess.run([chrome, '--headless', '--disable-gpu', '--no-sandbox',
                    f'--print-to-pdf={OUT_PDF}', '--no-pdf-header-footer', url],
                   check=True, capture_output=True)
    html_path.unlink(missing_ok=True)
    if not OUT_PDF.exists():
        sys.exit('Không tạo được PDF.')
    add_page_numbers(OUT_PDF)
    print('đã dựng', OUT_PDF, f'({OUT_PDF.stat().st_size // 1024} KB)')


def add_page_numbers(pdf):
    """Đánh số trang ở giữa đáy mỗi trang (bỏ bìa). Cần pymupdf; thiếu thì bỏ qua."""
    try:
        import fitz
    except ImportError:
        print('(bỏ qua đánh số trang: cần `pip install pymupdf`)')
        return
    doc = fitz.open(pdf)
    for i, page in enumerate(doc):
        if i == 0:                       # bỏ trang bìa
            continue
        r = page.rect
        page.insert_textbox(fitz.Rect(0, r.height - 32, r.width, r.height - 14),
                            str(i + 1), fontsize=10, align=1, color=(0.3, 0.3, 0.3))
    tmp = pdf.with_suffix('.np.pdf')
    doc.save(str(tmp))
    doc.close()
    pdf.unlink()
    tmp.replace(pdf)


if __name__ == '__main__':
    build()

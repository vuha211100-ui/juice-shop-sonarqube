"""Sinh hình quy trình DevSecOps cho báo cáo (report/screenshots/devsecops-pipeline.png).

Pipeline 8 pha; ghim 4 lỗi F01-F04 vào đúng pha và cổng kiểm soát/công cụ dưới mỗi pha.
Tô màu theo paradigm: Security as Code = xanh dương (F01/F02), Policy as Code = xanh lá (F03/F04).
Chạy: python report/figures/devsecops_pipeline.py   (cần Pillow; dùng font Arial của Windows)
"""
import pathlib
import sys
from PIL import Image, ImageDraw, ImageFont

sys.stdout.reconfigure(encoding='utf-8')

OUT = pathlib.Path(__file__).resolve().parents[1] / 'screenshots' / 'devsecops-pipeline.png'

# ----- màu -----
INK = (30, 41, 59)          # slate-800
MUTE = (100, 116, 139)      # slate-500
BOXF = (241, 245, 249)      # slate-100
BOXB = (51, 65, 85)         # slate-700
SAC = (37, 99, 235)         # blue-600  (Security as Code)
SACF = (219, 234, 254)      # blue-100
PAC = (5, 150, 105)         # emerald-600 (Policy as Code)
PACF = (209, 250, 229)      # emerald-100
WHITE = (255, 255, 255)

W, H = 2200, 1000
img = Image.new('RGB', (W, H), WHITE)
d = ImageDraw.Draw(img)


def font(sz, bold=False):
    for name in ((['arialbd.ttf', 'Arialbd.ttf'] if bold else ['arial.ttf', 'Arial.ttf'])):
        for base in ('C:/Windows/Fonts/', ''):
            try:
                return ImageFont.truetype(base + name, sz)
            except OSError:
                continue
    return ImageFont.load_default()


F_TITLE = font(42, True)
F_SUB = font(24)
F_PHASE = font(30, True)
F_FIND = font(23, True)
F_GATE = font(20)
F_LEG = font(23)
F_SMALL = font(19)


def center(draw, cx, y, text, fnt, fill):
    w = draw.textlength(text, font=fnt)
    draw.text((cx - w / 2, y), text, font=fnt, fill=fill)


def pill(draw, x0, y0, x1, y1, fill, border, radius=14, width=3):
    draw.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=fill, outline=border, width=width)


def arrow(draw, x0, y0, x1, y1, color, width=5, head=16):
    draw.line([x0, y0, x1, y1], fill=color, width=width)
    import math
    ang = math.atan2(y1 - y0, x1 - x0)
    # vẽ đầu mũi tên tam giác
    p1 = (x1, y1)
    p2 = (x1 - head * math.cos(ang - 0.5), y1 - head * math.sin(ang - 0.5))
    p3 = (x1 - head * math.cos(ang + 0.5), y1 - head * math.sin(ang + 0.5))
    draw.polygon([p1, p2, p3], fill=color)


# ----- tiêu đề -----
center(d, W / 2, 28, 'Quy trình DevSecOps — ánh xạ 4 lỗi và cổng kiểm soát theo từng pha', F_TITLE, INK)
center(d, W / 2, 82, 'Security as Code (xanh dương): F01, F02   ·   Policy as Code (xanh lá): F03, F04', F_SUB, MUTE)

# ----- các pha -----
phases = ['Plan', 'Code', 'Build', 'Test', 'Release', 'Deploy', 'Operate', 'Monitor']
gates = [
    [],
    ['Semgrep (SAST)', 'Gitleaks'],
    ['Conftest · Dockerfile'],
    ['node:test (đỏ->xanh)'],
    ['Conftest · compose'],
    ['Nginx reverse proxy'],
    ['docker inspect', '+ Conftest runtime'],
    [],
]

n = len(phases)
BOX_W, GAP, BOX_H = 230, 22, 104
total = n * BOX_W + (n - 1) * GAP
left = (W - total) / 2
BOX_TOP = 360


def box_left(i):
    return left + i * (BOX_W + GAP)


def box_cx(i):
    return box_left(i) + BOX_W / 2


# mũi tên nối các pha
for i in range(n - 1):
    arrow(d, box_left(i) + BOX_W, BOX_TOP + BOX_H / 2, box_left(i + 1) - 2, BOX_TOP + BOX_H / 2, MUTE, 5, 15)

# hộp pha
for i, name in enumerate(phases):
    x0 = box_left(i)
    pill(d, x0, BOX_TOP, x0 + BOX_W, BOX_TOP + BOX_H, BOXF, BOXB, radius=16, width=4)
    center(d, box_cx(i), BOX_TOP + BOX_H / 2 - 18, name, F_PHASE, INK)

# ----- thanh lỗi (phía trên) -----
# (nhãn, pha bắt đầu, pha kết thúc, màu viền, màu nền, hàng)
findings = [
    ('F02  IDOR giỏ hàng', 0, 3, SAC, SACF, 0),
    ('F01  SQLi đăng nhập', 1, 3, SAC, SACF, 1),
    ('F03  lộ /metrics', 5, 6, PAC, PACF, 1),
    ('F04  cấu hình container', 2, 4, PAC, PACF, 2),
]
ROW_H, ROW_TOP = 52, 120
for label, a, b, bd, bg, row in findings:
    y0 = ROW_TOP + row * (ROW_H + 10)
    x0, x1 = box_left(a), box_left(b) + BOX_W
    pill(d, x0, y0, x1, y0 + ROW_H, bg, bd, radius=16, width=4)
    center(d, (x0 + x1) / 2, y0 + ROW_H / 2 - 13, label, F_FIND, bd)
    # chân nối xuống hàng pha
    d.line([(x0 + x1) / 2, y0 + ROW_H, (x0 + x1) / 2, BOX_TOP], fill=bd, width=2)

# ----- cổng kiểm soát (phía dưới) -----
GATE_TOP = BOX_TOP + BOX_H + 26
for i, gs in enumerate(gates):
    if not gs:
        continue
    # màu theo paradigm: Code/Test = SaC; Build/Release/Deploy/Operate = PaC
    col = SAC if i in (1, 3) else PAC
    colf = SACF if i in (1, 3) else PACF
    y = GATE_TOP
    for g in gs:
        tw = d.textlength(g, font=F_GATE)
        x0 = box_cx(i) - tw / 2 - 16
        x1 = box_cx(i) + tw / 2 + 16
        pill(d, x0, y, x1, y + 40, colf, col, radius=12, width=3)
        center(d, box_cx(i), y + 8, g, F_GATE, col)
        # nối lên hộp pha
        d.line([box_cx(i), BOX_TOP + BOX_H, box_cx(i), y], fill=col, width=2)
        y += 52

# ----- mũi tên vòng phản hồi liên tục -----
loop_y = 760
arrow(d, box_cx(n - 1), loop_y, box_cx(0), loop_y, MUTE, 4, 16)
d.line([box_cx(n - 1), BOX_TOP + BOX_H, box_cx(n - 1), loop_y], fill=MUTE, width=3)
d.line([box_cx(0), loop_y, box_cx(0), BOX_TOP + BOX_H], fill=MUTE, width=3)
center(d, W / 2, loop_y - 34, 'phản hồi liên tục — mỗi cổng trả PASS/WARN/FAIL; chỉ FAIL (luật deny) mới chặn phát hành', F_SMALL, MUTE)

# ----- chú giải -----
ly = 850
d.text((left, ly), 'Chú giải:', font=F_LEG, fill=INK)
lx = left + d.textlength('Chú giải:  ', font=F_LEG)
for txt, bd, bg in [('Security as Code (SAST, quét secret, kiểm thử bảo mật)', SAC, SACF),
                    ('Policy as Code (luật Rego cho Dockerfile & compose)', PAC, PACF)]:
    pill(d, lx, ly - 4, lx + 34, ly + 28, bg, bd, radius=8, width=3)
    d.text((lx + 46, ly), txt, font=F_LEG, fill=INK)
    lx += 46 + d.textlength(txt, font=F_LEG) + 60

img.save(OUT)
print('đã ghi', OUT, img.size)

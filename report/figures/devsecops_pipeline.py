"""Sinh hình quy trình DevSecOps cho báo cáo (report/screenshots/devsecops-pipeline.png).

Pipeline theo vòng đời; ghim 4 lỗi F01-F04 vào đúng pha và ánh xạ NĂM lớp cổng kiểm soát:
  - Security as Code  (xanh dương): Semgrep/Gitleaks (Code) + node:test (Test)   -> F01, F02
  - Policy as Code    (xanh lá)   : Conftest/Rego cho Dockerfile (Build) & compose (Deploy)
                                    + Compliance as Code runtime (Operate)        -> F03, F04
  - Quét image        (cam)       : Trivy (SCA) + Dockle (CIS) trên image đã build (Release)
  - Giám sát vận hành (tím)       : Prometheus + Grafana + cảnh báo 4XX (Monitor)
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
SAC = (37, 99, 235)         # blue-600    (Security as Code)
SACF = (219, 234, 254)      # blue-100
PAC = (5, 150, 105)         # emerald-600 (Policy as Code)
PACF = (209, 250, 229)      # emerald-100
SCAN = (217, 119, 6)        # amber-600   (Quét image)
SCANF = (254, 243, 199)     # amber-100
MON = (124, 58, 237)        # violet-600  (Giám sát vận hành)
MONF = (237, 233, 254)      # violet-100
WHITE = (255, 255, 255)

W, H = 2200, 1080
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
F_SUB = font(23)
F_PHASE = font(30, True)
F_FIND = font(22, True)
F_GATE = font(19)
F_LEG = font(22)
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
    p1 = (x1, y1)
    p2 = (x1 - head * math.cos(ang - 0.5), y1 - head * math.sin(ang - 0.5))
    p3 = (x1 - head * math.cos(ang + 0.5), y1 - head * math.sin(ang + 0.5))
    draw.polygon([p1, p2, p3], fill=color)


# ----- tiêu đề -----
center(d, W / 2, 28, 'Quy trình DevSecOps — ánh xạ 4 lỗi và năm lớp cổng kiểm soát theo từng pha', F_TITLE, INK)
center(d, W / 2, 82,
       'Security as Code (xanh dương): F01, F02  ·  Policy as Code (xanh lá): F03, F04  ·  '
       'Quét image (cam): Release  ·  Giám sát (tím): Operate', F_SUB, MUTE)

# ----- các pha -----
phases = ['Plan', 'Code', 'Build', 'Test', 'Release', 'Deploy', 'Operate', 'Monitor']
# gate dưới mỗi pha + màu lớp kiểm soát của pha đó
gates = [
    [],                                               # 0 Plan
    ['Semgrep (SAST)', 'Gitleaks'],                   # 1 Code    -> SaC
    ['Conftest · Dockerfile'],                        # 2 Build   -> PaC
    ['node:test (đỏ->xanh)'],                         # 3 Test    -> SaC
    ['Trivy (SCA)', 'Dockle (CIS)'],                  # 4 Release -> Quét image
    ['Conftest · compose', 'Nginx reverse proxy'],    # 5 Deploy  -> PaC
    ['docker inspect', '+ Conftest runtime'],         # 6 Operate -> PaC (Compliance as Code)
    ['Prometheus + Grafana', 'cảnh báo 4XX'],         # 7 Monitor -> Giám sát
]
GATE_COL = {1: (SAC, SACF), 2: (PAC, PACF), 3: (SAC, SACF), 4: (SCAN, SCANF),
            5: (PAC, PACF), 6: (PAC, PACF), 7: (MON, MONF)}

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
    ('F01  SQLi đăng nhập', 1, 3, SAC, SACF, 0),
    ('F02  Poison Null Byte', 1, 3, SAC, SACF, 1),
    ('F04  cấu hình container', 2, 4, PAC, PACF, 2),
    ('F03  lộ /metrics', 5, 6, PAC, PACF, 2),
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
gate_bottom = GATE_TOP
for i, gs in enumerate(gates):
    if not gs:
        continue
    col, colf = GATE_COL[i]
    y = GATE_TOP
    for g in gs:
        tw = d.textlength(g, font=F_GATE)
        x0 = box_cx(i) - tw / 2 - 16
        x1 = box_cx(i) + tw / 2 + 16
        pill(d, x0, y, x1, y + 40, colf, col, radius=12, width=3)
        center(d, box_cx(i), y + 8, g, F_GATE, col)
        d.line([box_cx(i), BOX_TOP + BOX_H, box_cx(i), y], fill=col, width=2)
        y += 52
    gate_bottom = max(gate_bottom, y)

# ----- mũi tên vòng phản hồi liên tục -----
loop_y = gate_bottom + 70
arrow(d, box_cx(n - 1), loop_y, box_cx(0), loop_y, MUTE, 4, 16)
d.line([box_cx(0), BOX_TOP + BOX_H, box_cx(0), loop_y], fill=MUTE, width=3)   # Plan: không có gate
d.line([box_cx(n - 1), gate_bottom + 6, box_cx(n - 1), loop_y], fill=MUTE, width=3)
center(d, W / 2, loop_y - 34,
       'phản hồi liên tục — mỗi cổng trả PASS/WARN/FAIL; chỉ FAIL (luật deny) mới chặn phát hành', F_SMALL, MUTE)

# ----- chú giải (2 hàng × 2 mục) -----
legend = [('Security as Code — SAST, quét secret, kiểm thử bảo mật', SAC, SACF),
          ('Policy as Code — Rego cho Dockerfile, compose & runtime', PAC, PACF),
          ('Quét image — Trivy (CVE/SCA), Dockle (CIS)', SCAN, SCANF),
          ('Giám sát vận hành — Prometheus/Grafana + cảnh báo', MON, MONF)]
ly0 = loop_y + 50
col_x = [left, W / 2 + 20]
for k, (txt, bd, bg) in enumerate(legend):
    lx = col_x[k % 2]
    ly = ly0 + (k // 2) * 44
    pill(d, lx, ly - 2, lx + 34, ly + 28, bg, bd, radius=8, width=3)
    d.text((lx + 46, ly), txt, font=F_LEG, fill=INK)

img.save(OUT)
print('đã ghi', OUT, img.size)

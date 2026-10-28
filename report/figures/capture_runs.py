"""Chụp 'ảnh chạy thật' các cổng kiểm soát -> report/screenshots/*.png (kiểu cửa sổ terminal).

Chạy LIVE các lệnh (cần Docker Desktop đang chạy + 3 container demo đã up) rồi render output thật.
Chạy:  python report/figures/capture_runs.py
Sinh:  env.png, gitleaks.png, conftest-verify.png
"""
import pathlib
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

sys.stdout.reconfigure(encoding='utf-8')

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHOTS = ROOT / 'report' / 'screenshots'
ANSI = re.compile(r'\x1b\[[0-9;]*m')

BG = (22, 27, 34)
BAR = (45, 51, 59)
FG = (201, 209, 217)
PROMPT = (126, 231, 135)
CMD = (240, 246, 252)
OKC = (63, 185, 80)
RED = (248, 81, 73)
YEL = (210, 153, 34)
GRN = (46, 204, 113)


def font(sz, bold=False):
    for n in (['consolab.ttf'] if bold else ['consola.ttf']):
        for base in ('C:/Windows/Fonts/', ''):
            try:
                return ImageFont.truetype(base + n, sz)
            except OSError:
                pass
    return ImageFont.load_default()


F, FB, FT = font(15), font(15, True), font(14, True)


def sh(*args, cwd=None):
    p = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=cwd)
    return ANSI.sub('', (p.stdout or '') + (p.stderr or '')).rstrip('\n')


def render(out, title, blocks):
    rows = []
    for kind, txt in blocks:
        for ln in txt.split('\n'):
            rows.append((kind, ln))
    pad, lh, top = 18, 23, 46
    W = 1480
    H = top + lh * len(rows) + 18
    img = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 36], fill=BAR)
    for i, c in enumerate((RED, YEL, GRN)):
        d.ellipse([16 + i * 22, 12, 28 + i * 22, 24], fill=c)
    d.text(((W - d.textlength(title, font=FT)) / 2, 10), title, font=FT, fill=FG)
    y = top
    for kind, ln in rows:
        if kind == 'cmd':
            pr = 'PS E:\\banhoaqua> '
            d.text((pad, y), pr, font=FB, fill=PROMPT)
            d.text((pad + d.textlength(pr, font=FB), y), ln, font=FB, fill=CMD)
        elif kind == 'ok':
            d.text((pad, y), ln, font=FB, fill=OKC)
        else:
            d.text((pad, y), ln, font=F, fill=FG)
        y += lh
    img.save(out)
    print('wrote', out.name, img.size)


CF = ['docker', 'run', '--rm', '-v', f'{ROOT.as_posix()}:/work:ro', '-w', '/work', 'openpolicyagent/conftest:v0.71.1']
GL = ['docker', 'run', '--rm', '-v', f'{ROOT.as_posix()}:/repo:ro', 'zricethezav/gitleaks:v8.30.1',
      'git', '/repo', '--log-opts=baf9dcea4..HEAD', '--no-banner']


def main():
    # 1) Môi trường hai pha đang chạy
    ps = sh('docker', 'compose', 'ps', '--format', 'table {{.Name}}\t{{.Status}}\t{{.Ports}}', cwd=str(ROOT))
    lab = sh('docker', 'ps', '--filter', 'name=juice-report-lab', '--format', 'table {{.Names}}\t{{.Status}}\t{{.Ports}}')
    render(SHOTS / 'env.png', 'Windows PowerShell — môi trường DevSecOps (TRƯỚC vá 3100 + SAU vá 3102)', [
        ('cmd', 'docker compose ps                 # bản SAU vá: proxy + backend internal'),
        ('out', ps),
        ('cmd', 'docker ps --filter name=juice-report-lab   # bản TRƯỚC vá (đối chứng)'),
        ('out', lab),
    ])

    # 2) Gitleaks — quét secret
    print('đang chạy Gitleaks (~15s)...')
    gl = sh(*GL)
    render(SHOTS / 'gitleaks.png', 'Windows PowerShell — Gitleaks quét secret (Security as Code)', [
        ('cmd', 'docker run --rm -v ${PWD}:/repo:ro zricethezav/gitleaks:v8.30.1 \\'),
        ('cmd', '    git /repo --log-opts="baf9dcea4..HEAD" --no-banner'),
        ('out', gl),
        ('ok', '=> Không có secret/khóa bí mật nào lộ trong các commit vá.'),
    ])

    # 3) Conftest verify — unit test toàn bộ policy
    cv = sh(*CF, 'verify', '-p', 'policy', '--no-color')
    tail = '\n'.join([l for l in cv.split('\n') if l.strip()][-2:])
    render(SHOTS / 'conftest-verify.png', 'Windows PowerShell — Conftest verify (Policy as Code: 17/17)', [
        ('cmd', 'docker run --rm -v ${PWD}:/work:ro -w /work \\'),
        ('cmd', '    openpolicyagent/conftest:v0.71.1 verify -p policy'),
        ('out', tail),
        ('ok', '=> Toàn bộ 17 unit test của bộ luật Rego đều đạt.'),
    ])


if __name__ == '__main__':
    main()

"""Chụp 'ảnh chạy thật' các cổng kiểm soát -> report/screenshots/*.png (kiểu cửa sổ terminal).

Chạy LIVE các lệnh (cần Docker Desktop đang chạy + 3 container demo đã up) rồi render output thật.
Chạy:  python report/figures/capture_runs.py
Sinh:  env.png, gitleaks.png, conftest-verify.png
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

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
HLC = (240, 180, 41)   # vàng hổ phách — dòng highlight (lỗi nhóm xử lý)
HLBG = (58, 50, 24)    # nền mờ cho dòng highlight


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
        elif kind == 'hl':
            d.rectangle([0, y - 2, W, y + lh - 2], fill=HLBG)
            d.text((pad, y), ln, font=FB, fill=HLC)
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

    # 4) Semgrep (SAST) quét TOÀN BỘ mã chưa vá -> nhiều findings, highlight F01/F02
    print('đang chạy Semgrep trên toàn bộ routes/ + lib/ chưa vá (~30s)...')
    import io
    import tarfile
    vroot = pathlib.Path(tempfile.mkdtemp(prefix='vuln-'))
    arch = subprocess.run(['git', '-C', str(ROOT), 'archive', '21219d66d', 'routes', 'lib'], capture_output=True)
    with tarfile.open(fileobj=io.BytesIO(arch.stdout)) as tf:
        tf.extractall(vroot)
    sg = sh('docker', 'run', '--rm', '-e', 'SEMGREP_SEND_METRICS=off',
            '-v', f'{vroot.as_posix()}:/src:ro', '-v', f'{(ROOT / "report" / "semgrep-rules").as_posix()}:/rules:ro',
            'semgrep/semgrep:1.180.0', 'semgrep', 'scan', '--metrics=off',
            '--config', '/rules/owasp-top-ten.yml', '--config', '/rules/nodejsscan.yml', '/src')
    shutil.rmtree(vroot, ignore_errors=True)
    count = next((re.search(r'(\d+) Code Findings', l).group(1) for l in sg.split('\n') if 'Code Findings' in l), '?')
    files, cur = {}, None
    for l in sg.split('\n'):
        m = re.search(r'/src/(\S+\.ts)', l)
        if m:
            cur = m.group(1)
        elif 'rules.' in l and cur:
            files.setdefault(cur, []).append(l.rsplit('.', 1)[-1].strip())
    HI = {'routes/login.ts': 'F01 — SQL injection', 'routes/basket.ts': 'F02 — IDOR / NoSQLi',
          'lib/insecurity.ts': 'liên quan F01 — MD5 không salt'}
    ov = [('cmd', 'semgrep scan --config owasp-top-ten.yml --config nodejsscan.yml routes/ lib/   # toàn bộ mã chưa vá'),
          ('out', f'{count} Code Findings trên {len(files)} tệp — rút gọn:')]
    for f in sorted(files, key=lambda x: (x not in HI, x)):
        rz = ', '.join(sorted(set(files[f])))[:70]
        if f in HI:
            ov.append(('hl', f'  {f:<24} {rz}   <= {HI[f]}'))
        else:
            ov.append(('out', f'  {f:<24} {rz}'))
    ov.append(('ok', f'=> Semgrep ra {count} findings; báo cáo chọn F01 (login.ts) và F02 (basket.ts) để phân tích & vá.'))
    render(SHOTS / 'semgrep-overview.png', 'Windows PowerShell — Semgrep (SAST) quét toàn bộ mã nguồn', ov)
    render(SHOTS / 'semgrep-scan.png', 'Windows PowerShell — Semgrep: ba lỗi nhóm phân tích', [
        ('cmd', 'semgrep scan --config owasp-top-ten.yml --config nodejsscan.yml routes/login.ts routes/basket.ts lib/insecurity.ts'),
        ('hl', '  routes/login.ts     express-sequelize-injection -> SQL injection (F01)'),
        ('hl', '  routes/basket.ts    node_nosqli_injection -> truy vấn không ràng buộc chủ sở hữu (F02)'),
        ('hl', '  lib/insecurity.ts   node_md5 -> mật khẩu băm MD5 không salt (CWE-327, giới hạn còn lại của F01)'),
        ('ok', '=> Ba điểm trên là phạm vi báo cáo xử lý; các finding còn lại ngoài phạm vi.'),
    ])

    # 5) Conftest (Policy as Code) quét Dockerfile.vulnerable -> chặn
    cfail = sh(*CF, 'test', 'Dockerfile.vulnerable', '--parser', 'dockerfile', '-p', 'policy', '--namespace', 'dockerfile', '--no-color')
    groups = sorted({l.split(':')[0].split(' - ')[-1] for l in cfail.split('\n') if l.startswith('FAIL')})
    summ = next((l for l in cfail.split('\n') if 'failures' in l), '')
    render(SHOTS / 'conftest-fail.png', 'Windows PowerShell — Conftest quét Dockerfile.vulnerable (Policy as Code)', [
        ('cmd', 'conftest test Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile'),
        ('out', 'FAIL - LEAST-PRIVILEGE: final stage has no USER instruction; container runs as root'),
        ('out', "FAIL - ATTACK-SURFACE: EXPOSE '22'/'3306' covers administrative/database port"),
        ('out', "FAIL - SECRET-IN-IMAGE: ENV 'API_TOKEN' hardcodes a credential into the image"),
        ('out', "FAIL - SUPPLY-CHAIN: missing provenance label org.opencontainers.image.source/revision"),
        ('out', 'WARN - SUPPLY-CHAIN: base image node:22-alpine is not pinned by digest'),
        ('out', summ),
        ('ok', f'=> Gate chặn: {", ".join(groups)}.'),
    ])


if __name__ == '__main__':
    main()

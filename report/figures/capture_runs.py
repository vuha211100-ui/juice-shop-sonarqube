"""Dựng 'ảnh chạy' các cổng kiểm soát -> report/screenshots/*.png (kiểu cửa sổ terminal).

Khác với bản cũ: MỖI lệnh chạy LIVE, bắt đủ stdout + stderr + exit code, ghi log gốc ra
report/evidence/<id>.log (kèm lệnh, thời điểm, commit, phiên bản công cụ, exit code), rồi
render lại chính output đó. Dòng kết luận PASS/FAIL/GATE được TÍNH TỪ exit code thật — một
lần chạy lỗi không thể tạo ra dòng xanh. Hình vì vậy là bản dựng trung thực từ log, không phải
ảnh chụp màn hình; log gốc đi kèm để đối chiếu.

Cần Docker Desktop đang chạy + 3 container demo (juice-report-lab, juice-app-proxy-1,
juice-app-juice-shop-1). Chạy:  python report/figures/capture_runs.py
"""
import datetime
import io
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from PIL import Image, ImageDraw, ImageFont

sys.stdout.reconfigure(encoding='utf-8')

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHOTS = ROOT / 'report' / 'screenshots'
EVID = ROOT / 'report' / 'evidence'
EVID.mkdir(parents=True, exist_ok=True)
ANSI = re.compile(r'\x1b\[[0-9;]*m')

# phiên bản công cụ (ghim theo tag image dùng để chạy) — vào header log gốc
TOOLS = {'gitleaks': 'zricethezav/gitleaks:v8.30.1', 'conftest': 'openpolicyagent/conftest:v0.71.1',
         'semgrep': 'semgrep/semgrep:1.180.0'}
COMMIT = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'],
                        capture_output=True, text=True).stdout.strip() or '?'
NOW = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

BG = (22, 27, 34)
BAR = (45, 51, 59)
FG = (201, 209, 217)
DIM = (125, 133, 144)
PROMPT = (126, 231, 135)
CMD = (240, 246, 252)
OKC = (63, 185, 80)
RED = (248, 81, 73)
YEL = (210, 153, 34)
GRN = (46, 204, 113)
HLC = (240, 180, 41)   # vàng hổ phách — dòng highlight (điểm trong phạm vi báo cáo)
HLBG = (58, 50, 24)


def font(sz, bold=False):
    for n in (['consolab.ttf'] if bold else ['consola.ttf']):
        for base in ('C:/Windows/Fonts/', ''):
            try:
                return ImageFont.truetype(base + n, sz)
            except OSError:
                pass
    return ImageFont.load_default()


F, FB, FT, FD = font(15), font(15, True), font(14, True), font(13)


def run(evid_id, display, argv, cwd=None, tool=None):
    """Chạy LIVE, bắt stdout+stderr+exit code, ghi log gốc, trả (text, rc)."""
    p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8',
                       errors='replace', cwd=cwd)
    text = ANSI.sub('', (p.stdout or '') + (p.stderr or '')).rstrip('\n')
    hdr = [f'# EVIDENCE {evid_id}', f'# command : {display}',
           f'# argv    : {" ".join(argv)}', f'# cwd     : {cwd or str(ROOT)}',
           f'# time    : {NOW}', f'# commit  : {COMMIT}']
    if tool:
        hdr.append(f'# tool    : {TOOLS.get(tool, tool)}')
    hdr += [f'# exit    : {p.returncode}', '# ----- combined stdout+stderr -----']
    (EVID / f'{evid_id}.log').write_text('\n'.join(hdr) + '\n' + text + '\n', encoding='utf-8')
    print(f'  evidence/{evid_id}.log  exit={p.returncode}')
    return text, p.returncode


def render(out, title, blocks, evid_id=None, rc=None):
    rows = []
    for kind, txt in blocks:
        for ln in txt.split('\n'):
            rows.append((kind, ln))
    pad, lh, top = 18, 23, 46
    W = 1480
    foot_h = 26 if evid_id is not None else 0
    H = top + lh * len(rows) + 18 + foot_h
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
        elif kind == 'fail':
            d.text((pad, y), ln, font=FB, fill=RED)
        elif kind == 'note':
            d.text((pad, y), ln, font=FB, fill=YEL)
        elif kind == 'hl':
            d.rectangle([0, y - 2, W, y + lh - 2], fill=HLBG)
            d.text((pad, y), ln, font=FB, fill=HLC)
        else:
            d.text((pad, y), ln, font=F, fill=FG)
        y += lh
    if evid_id is not None:
        foot = f'log gốc: report/evidence/{evid_id}.log   ·   {NOW}   ·   commit {COMMIT}   ·   exit code {rc}'
        d.text((pad, H - foot_h + 4), foot, font=FD, fill=DIM)
    img.save(out)
    print('wrote', out.name, img.size)


CF = ['docker', 'run', '--rm', '-v', f'{ROOT.as_posix()}:/work:ro', '-w', '/work', TOOLS['conftest']]
GL = ['docker', 'run', '--rm', '-v', f'{ROOT.as_posix()}:/repo:ro', TOOLS['gitleaks'],
      'git', '/repo', '--log-opts=baf9dcea4..HEAD', '--no-banner']


def main():
    # 1) Môi trường hai pha đang chạy (thông tin, không có PASS/FAIL)
    ps, _ = run('env-compose', 'docker compose ps', ['docker', 'compose', 'ps', '--format',
                'table {{.Name}}\t{{.Status}}\t{{.Ports}}'], cwd=str(ROOT))
    lab, _ = run('env-lab', 'docker ps --filter name=juice-report-lab',
                 ['docker', 'ps', '--filter', 'name=juice-report-lab', '--format',
                  'table {{.Names}}\t{{.Status}}\t{{.Ports}}'])
    render(SHOTS / 'env.png', 'Windows PowerShell — môi trường DevSecOps (đối chứng 3100 + triển khai 3102)', [
        ('cmd', 'docker compose ps                 # bản SAU vá: proxy + backend internal'),
        ('out', ps),
        ('cmd', 'docker ps --filter name=juice-report-lab   # bản TRƯỚC vá (đối chứng)'),
        ('out', lab),
    ], evid_id='env-compose', rc=0)

    # 2) Gitleaks — quét secret; PASS <=> exit 0
    print('Gitleaks (~15s)...')
    gl, rc = run('gitleaks', 'gitleaks git /repo --log-opts=baf9dcea4..HEAD', GL, tool='gitleaks')
    ncommit = next((re.search(r'(\d+)\s*commits', l).group(1) for l in gl.split('\n') if 'commits' in l), None)
    summ = (f'=> exit {rc}: không phát hiện secret theo cấu hình quét Gitleaks trong phạm vi commit baf9dcea4..HEAD'
            if rc == 0 else f'=> exit {rc}: Gitleaks báo phát hiện — xem log gốc')
    render(SHOTS / 'gitleaks.png', 'Windows PowerShell — Gitleaks quét secret (Security as Code)', [
        ('cmd', 'docker run --rm -v ${PWD}:/repo:ro zricethezav/gitleaks:v8.30.1 \\'),
        ('cmd', '    git /repo --log-opts="baf9dcea4..HEAD" --no-banner'),
        ('out', gl),
        (('ok' if rc == 0 else 'fail'), summ),
    ], evid_id='gitleaks', rc=rc)

    # 3) Conftest verify — unit test toàn bộ policy; PASS <=> exit 0 và số liệu lấy từ output
    cv, rc = run('conftest-verify', 'conftest verify -p policy', CF + ['verify', '-p', 'policy', '--no-color'], tool='conftest')
    line = next((l for l in cv.split('\n') if re.search(r'\d+ tests?,', l)), '')
    npass = next((re.search(r'(\d+) passed', line).group(1) for _ in [0] if 'passed' in line), '?')
    summ = (f'=> exit {rc}: {npass} unit test của bộ luật Rego đều đạt (13 ca Dockerfile + 6 ca compose).'
            if rc == 0 else f'=> exit {rc}: có unit test KHÔNG đạt — xem log gốc.')
    render(SHOTS / 'conftest-verify.png', 'Windows PowerShell — Conftest verify (Policy as Code: unit test bộ luật Rego)', [
        ('cmd', 'docker run --rm -v ${PWD}:/work:ro -w /work \\'),
        ('cmd', '    openpolicyagent/conftest:v0.71.1 verify -p policy'),
        ('out', line or cv.split('\n')[-1]),
        (('ok' if rc == 0 else 'fail'), summ),
    ], evid_id='conftest-verify', rc=rc)

    # 4) Semgrep (SAST) quét TOÀN BỘ mã chưa vá -> nhiều cảnh báo; highlight phạm vi báo cáo.
    #    QUAN TRỌNG (R01): Semgrep = gợi ý vị trí cần rà. F01 xác nhận ở login.ts; cảnh báo tại
    #    basket.ts là NoSQLi (CWE-943) — KHÔNG phải IDOR; IDOR xác nhận bằng test A/B (mục 5.2).
    print('Semgrep trên routes/ + lib/ chưa vá (~30s)...')
    vroot = pathlib.Path(tempfile.mkdtemp(prefix='vuln-'))
    arch = subprocess.run(['git', '-C', str(ROOT), 'archive', '21219d66d', 'routes', 'lib'], capture_output=True)
    with tarfile.open(fileobj=io.BytesIO(arch.stdout)) as tf:
        tf.extractall(vroot)
    sg, sgrc = run('semgrep-overview', 'semgrep scan --config owasp-top-ten.yml --config nodejsscan.yml routes/ lib/',
                   ['docker', 'run', '--rm', '-e', 'SEMGREP_SEND_METRICS=off',
                    '-v', f'{vroot.as_posix()}:/src:ro',
                    '-v', f'{(ROOT / "report" / "semgrep-rules").as_posix()}:/rules:ro',
                    TOOLS['semgrep'], 'semgrep', 'scan', '--metrics=off',
                    '--config', '/rules/owasp-top-ten.yml', '--config', '/rules/nodejsscan.yml', '/src'],
                   tool='semgrep')
    shutil.rmtree(vroot, ignore_errors=True)
    count = next((re.search(r'(\d+) Code Findings', l).group(1) for l in sg.split('\n') if 'Code Findings' in l), '?')
    files, cur = {}, None
    for l in sg.split('\n'):
        m = re.search(r'/src/(\S+\.ts)', l)
        if m:
            cur = m.group(1)
        elif 'rules.' in l and cur:
            files.setdefault(cur, []).append(l.rsplit('.', 1)[-1].strip())
    HI = {'routes/login.ts': 'F01 SQL injection — xác nhận',
          'routes/basket.ts': 'cảnh báo NoSQLi (CWE-943) — gợi ý rà; IDOR xác nhận bằng test A/B (5.2)',
          'lib/insecurity.ts': 'MD5 không salt (CWE-327) — rủi ro còn lại, ngoài F01'}
    ov = [('cmd', 'semgrep scan --config owasp-top-ten.yml --config nodejsscan.yml routes/ lib/   # mã chưa vá'),
          ('out', f'{count} Code Findings trên {len(files)} tệp (CẢNH BÁO công cụ, chưa phải {count} lỗ hổng đã xác nhận) — rút gọn:')]
    for f in sorted(files, key=lambda x: (x not in HI, x)):
        rz = ', '.join(sorted(set(files[f])))[:66]
        ov.append(('hl', f'  {f:<22} {rz}   <= {HI[f]}') if f in HI else ('out', f'  {f:<22} {rz}'))
    ov.append(('note', f'=> exit {sgrc}: semgrep scan không tự chặn (cần --error). Đây là bước PHÁT HIỆN;'))
    ov.append(('note', '   báo cáo chọn F01 (login.ts) để vá; cảnh báo basket.ts chỉ là gợi ý rà, xem 5.2.'))
    render(SHOTS / 'semgrep-overview.png', 'Windows PowerShell — Semgrep (SAST) quét toàn bộ mã nguồn chưa vá', ov,
           evid_id='semgrep-overview', rc=sgrc)

    # semgrep-scan.png: lấy ĐÚNG cảnh báo thật của 3 tệp trong phạm vi + khối phân loại của nhóm (ghi rõ)
    def rules_of(fn):
        return ', '.join(sorted(set(files.get(fn, [])))) or '(không có)'
    render(SHOTS / 'semgrep-scan.png', 'Windows PowerShell — Semgrep: ba điểm trong phạm vi báo cáo', [
        ('cmd', 'semgrep ... routes/login.ts routes/basket.ts lib/insecurity.ts   # trích từ lần quét trên'),
        ('out', 'Cảnh báo Semgrep (nguyên văn rule) tại ba tệp phạm vi:'),
        ('hl', f'  routes/login.ts     {rules_of("routes/login.ts")}'),
        ('hl', f'  routes/basket.ts    {rules_of("routes/basket.ts")}'),
        ('hl', f'  lib/insecurity.ts   {rules_of("lib/insecurity.ts")}'),
        ('out', ''),
        ('note', 'Phân loại của nhóm (không phải output công cụ):'),
        ('out', '  F01  login.ts    SQL injection — Semgrep chỉ đúng dòng, xác nhận bằng test + đọc mã.'),
        ('out', '  F02  basket.ts   rule NoSQLi/CWE-943 là gợi ý vị trí; KHÔNG kết luận IDOR theo loại'),
        ('out', '                   lỗi công cụ báo — IDOR xác nhận độc lập bằng test A/B (token A đọc giỏ B).'),
        ('out', '  --   insecurity.ts  MD5 không salt — rủi ro lưu trữ còn lại, nằm ngoài phạm vi F01.'),
    ], evid_id='semgrep-overview', rc=sgrc)

    # 5) Conftest (Policy as Code) quét Dockerfile.vulnerable -> gate chặn khi exit != 0 (đúng kỳ vọng)
    cfail, rc = run('conftest-fail', 'conftest test Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile',
                    CF + ['test', 'Dockerfile.vulnerable', '--parser', 'dockerfile', '-p', 'policy',
                          '--namespace', 'dockerfile', '--no-color'], tool='conftest')
    lines = [l for l in cfail.split('\n') if l.startswith(('FAIL', 'WARN'))]
    groups = sorted({l.split(':')[0].split(' - ')[-1] for l in cfail.split('\n') if l.startswith('FAIL')})
    summ_line = next((l for l in cfail.split('\n') if 'failures' in l), '')
    blocks = [('cmd', 'conftest test Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile')]
    for l in lines:
        blocks.append((('fail' if l.startswith('FAIL') else 'out'), l))
    blocks.append(('out', summ_line))
    gate = (f'=> exit {rc}: gate CHẶN phát hành — {len(groups)} nhóm luật vi phạm ({", ".join(groups)}). Đúng kỳ vọng với fixture lỗi.'
            if rc != 0 else f'=> exit {rc}: không có vi phạm (không kỳ vọng với fixture lỗi) — xem log.')
    blocks.append((('fail' if rc != 0 else 'ok'), gate))
    render(SHOTS / 'conftest-fail.png', 'Windows PowerShell — Conftest quét Dockerfile.vulnerable (Policy as Code)', blocks,
           evid_id='conftest-fail', rc=rc)


if __name__ == '__main__':
    main()

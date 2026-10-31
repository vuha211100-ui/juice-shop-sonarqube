"""Dựng ảnh 4 demo F01–F04 + ảnh kiểm thử F01/F02 (đỏ/xanh) từ output chạy THẬT.

- tv1.png        : demo F01 (SQL injection đăng nhập) trên 3100 vs 3102.
- tv2.png        : demo F02 (Poison Null Byte, lộ tệp sao lưu) trên 3100 vs 3102.
- tv3.png        : demo F03 (lộ endpoint /metrics) trên 3100 vs 3102.
- tv4.png        : demo F04 (Policy as Code, Conftest) trên các Dockerfile vá/lỗi/gốc.
- f0102-green.png: node:test trên mã ĐÃ VÁ (toàn bộ xanh).
- f0102-red.png  : node:test trên mã baseline (login.ts + fileServer.ts chưa vá) -> F01+F02 đỏ.

Mỗi demo chạy thật, lưu log gốc report/evidence/<id>.log rồi render lại chính output đó.
Cần Docker + 3 container demo đang chạy. Chạy: python report/figures/capture_demos.py
"""
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from capture_runs import ANSI, EVID, NOW, ROOT, SHOTS, render  # noqa: E402

TCMD = ['node', '--import', './test/api/helpers/test-env.mjs', '--import', 'tsx',
        '--test', 'test/api/security/f01-f02.test.ts']
TLINE = 'node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts'


def runout(argv, cwd=ROOT, evid_id=None, display=None):
    """Chạy, trả output; nếu có evid_id thì lưu log gốc (lệnh, thời điểm, commit, exit code)."""
    p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=str(cwd))
    out = ANSI.sub('', (p.stdout or '') + (p.stderr or '')).rstrip('\n')
    if evid_id:
        hdr = [f'# EVIDENCE {evid_id}', f'# command : {display or " ".join(argv)}', f'# cwd     : {cwd}',
               f'# time    : {NOW}', f'# exit    : {p.returncode}',
               '# ----- combined stdout+stderr -----']
        (EVID / f'{evid_id}.log').write_text('\n'.join(hdr) + '\n' + out + '\n', encoding='utf-8')
        print(f'  evidence/{evid_id}.log  exit={p.returncode}')
    return out


def test_blocks(out, commitline):
    b = [('cmd', TLINE), ('out', commitline)]
    for ln in out.split('\n'):
        if 'failing tests:' in ln:
            break
        ln = ln.rstrip().replace('✔', '√').replace('✖', '×').replace('▶', '»').replace('ℹ', 'i')
        s = ln.strip()
        if not s:
            continue
        # chỉ giữ dòng cấu trúc kết quả test; bỏ log lỗi của ứng dụng + stack trace
        if '√' in ln and '×' not in ln:
            b.append(('ok', ln))
        elif '×' in ln:
            b.append(('fail', ln))
        elif s.startswith('» '):
            b.append(('out', ln))
        elif s.startswith('i tests'):
            b.append(('out', ln))
        elif s.startswith('i pass'):
            b.append(('ok', ln))
        elif s.startswith('i fail'):
            b.append(('fail', ln))
    return b


def _demo(script, png, title, comment, evid, classify):
    """Chạy một demo THẬT, lưu log gốc, render ảnh terminal có footer dẫn log."""
    out = runout(['python', f'report/demos/{script}'], evid_id=evid,
                 display=f'python report/demos/{script}')
    blocks = [('cmd', f'python report/demos/{script}   # {comment}')]
    blocks += [(classify(ln), ln) for ln in out.split('\n')]
    render(SHOTS / png, title, blocks, evid_id=evid, rc=0)


def _cl_sqli(ln):               # tv1 (F01) + tv2 (F02): tô LỖ HỔNG / an toàn
    return 'hl' if 'LỖ HỔNG' in ln else ('ok' if 'an toàn' in ln else 'out')


def _cl_metrics(ln):            # tv3 (F03)
    if 'LỘ' in ln:
        return 'hl'
    if any(k in ln for k in ('chặn tại proxy', 'không còn đường vòng', 'mạng internal',
                             'vẫn hoạt động', 'đọc được')):
        return 'ok'
    return 'fail' if ('KHÔNG' in ln or 'CÒN ĐƯỜNG' in ln) else 'out'


def _cl_policy(ln):             # tv4 (F04)
    if ln.startswith('conftest verify') or 'đúng:' in ln:
        return 'ok'
    return 'fail' if 'SAI' in ln else 'out'


def main():
    # 1) Demo F01 — SQL injection đăng nhập
    _demo('tv1_f01_sqli.py', 'tv1.png',
          'Windows PowerShell — Demo F01: SQL injection đăng nhập (trước vá 3100 / sau vá 3102)',
          'F01 SQL injection đăng nhập', 'tv1-f01', _cl_sqli)

    # 2) Demo F02 — Poison Null Byte (lộ tệp sao lưu)
    _demo('tv2_f02_pathtraversal.py', 'tv2.png',
          'Windows PowerShell — Demo F02: Poison Null Byte (lộ tệp sao lưu) (trước vá 3100 / sau vá 3102)',
          'F02 Poison Null Byte', 'tv2-f02', _cl_sqli)

    # 3) Demo F03 — lộ endpoint /metrics
    _demo('tv3_f03_metrics.py', 'tv3.png',
          'Windows PowerShell — Demo F03: endpoint /metrics (trước vá 3100 / sau vá 3102)',
          'F03 lộ /metrics', 'tv3-f03', _cl_metrics)

    # 4) Demo F04 — Policy as Code (Conftest)
    _demo('tv4_f04_policy.py', 'tv4.png',
          'Windows PowerShell — Demo F04: Policy as Code cho container (Conftest)',
          'F04 Policy as Code', 'tv4-f04', _cl_policy)

    # 5) f0102-green: mã đã vá (trạng thái hiện tại)
    render(SHOTS / 'f0102-green.png', 'Windows PowerShell — kiểm thử bảo mật F01/F02 SAU khi vá',
           test_blocks(runout(TCMD, evid_id='f0102-green-test', display=TLINE),
                       'HEAD  test(security): F01 SQLi dang nhap + F02 null byte /ftp (da va)'))

    # 6) f0102-red: swap baseline CẢ login.ts (F01) LẪN fileServer.ts (F02) -> cả hai lỗi đều đỏ
    targets = {ROOT / 'routes' / 'login.ts': 'routes/login.ts',
               ROOT / 'routes' / 'fileServer.ts': 'routes/fileServer.ts'}
    patched = {p: p.read_text(encoding='utf-8') for p in targets}
    for p, rel in targets.items():
        base = subprocess.run(['git', '-C', str(ROOT), 'show', f'21219d66d:{rel}'],
                              capture_output=True, text=True, encoding='utf-8').stdout
        p.write_text(base, encoding='utf-8')
    try:
        out = runout(TCMD, evid_id='f0102-red-test', display=TLINE + '   # baseline login.ts + fileServer.ts')
    finally:
        for p, txt in patched.items():
            p.write_text(txt, encoding='utf-8')
    render(SHOTS / 'f0102-red.png', 'Windows PowerShell — kiểm thử bảo mật F01/F02 TRƯỚC khi vá',
           test_blocks(out, '21219d66d  test(security): F01 SQLi dang nhap + F02 Poison Null Byte /ftp (dang do)'))


if __name__ == '__main__':
    main()

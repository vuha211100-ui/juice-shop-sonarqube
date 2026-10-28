"""Dựng ảnh demo F02 + ảnh kiểm thử F01/F02 (đỏ/xanh) từ output chạy THẬT.

- tv2.png        : chạy demo F02 (SQL injection ở tìm kiếm) trên 3100 vs 3102.
- f0102-green.png: node:test trên mã ĐÃ VÁ (toàn bộ xanh).
- f0102-red.png  : node:test trên mã baseline (search.ts chưa vá) -> các ca F02 đỏ.

Cần Docker + 3 container demo đang chạy. Chạy: python report/figures/capture_demos.py
"""
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from capture_runs import ANSI, ROOT, SHOTS, render  # noqa: E402

TCMD = ['node', '--import', './test/api/helpers/test-env.mjs', '--import', 'tsx',
        '--test', 'test/api/security/f01-f02.test.ts']
TLINE = 'node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts'


def runout(argv, cwd=ROOT):
    p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=str(cwd))
    return ANSI.sub('', (p.stdout or '') + (p.stderr or '')).rstrip('\n')


def test_blocks(out, commitline):
    b = [('cmd', TLINE), ('out', commitline)]
    for ln in out.split('\n'):
        if 'failing tests:' in ln:
            break
        ln = ln.rstrip().replace('✔', '√').replace('✖', '×').replace('▶', '»').replace('ℹ', 'i')
        s = ln.strip()
        if not s:
            continue
        if s.startswith(('i cancelled', 'i skipped', 'i todo', 'i suites', 'i duration')):
            continue
        if '√' in ln and '×' not in ln:
            b.append(('ok', ln))
        elif '×' in ln:
            b.append(('fail', ln))
        elif s.startswith('i fail'):
            b.append(('fail', ln))
        elif s.startswith('i pass'):
            b.append(('ok', ln))
        else:
            b.append(('out', ln))
    return b


def main():
    # 1) Demo F02 — SQL injection ở tìm kiếm
    out = runout(['python', 'report/demos/tv2_f02_sqli.py'])
    blocks = [('cmd', 'python report/demos/tv2_f02_sqli.py   # F02 SQL injection o tim kiem san pham')]
    for ln in out.split('\n'):
        if 'LỖ HỔNG' in ln:
            blocks.append(('hl', ln))
        elif 'an toàn' in ln:
            blocks.append(('ok', ln))
        else:
            blocks.append(('out', ln))
    render(SHOTS / 'tv2.png', 'Windows PowerShell — Demo F02: SQL injection ở tìm kiếm (trước vá 3100 / sau vá 3102)', blocks)

    # 2) f0102-green: mã đã vá (trạng thái hiện tại)
    render(SHOTS / 'f0102-green.png', 'Windows PowerShell — kiểm thử bảo mật F01/F02 SAU khi vá',
           test_blocks(runout(TCMD), 'HEAD  test(security): F01 SQLi dang nhap + F02 SQLi tim kiem (da va)'))

    # 3) f0102-red: swap baseline search.ts (lưu lại bản vá), chạy, rồi khôi phục
    search = ROOT / 'routes' / 'search.ts'
    patched = search.read_text(encoding='utf-8')
    base = subprocess.run(['git', '-C', str(ROOT), 'show', '21219d66d:routes/search.ts'],
                          capture_output=True, text=True, encoding='utf-8').stdout
    search.write_text(base, encoding='utf-8')
    try:
        out = runout(TCMD)
    finally:
        search.write_text(patched, encoding='utf-8')
    render(SHOTS / 'f0102-red.png', 'Windows PowerShell — kiểm thử bảo mật F01/F02 TRƯỚC khi vá',
           test_blocks(out, '21219d66d  test(security): F01 SQLi dang nhap + F02 SQLi tim kiem (dang do)'))


if __name__ == '__main__':
    main()

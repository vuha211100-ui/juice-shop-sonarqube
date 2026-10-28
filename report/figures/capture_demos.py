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
from capture_runs import ANSI, COMMIT, EVID, NOW, ROOT, SHOTS, render  # noqa: E402

TCMD = ['node', '--import', './test/api/helpers/test-env.mjs', '--import', 'tsx',
        '--test', 'test/api/security/f01-f02.test.ts']
TLINE = 'node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts'


def runout(argv, cwd=ROOT, evid_id=None, display=None):
    """Chạy, trả output; nếu có evid_id thì lưu log gốc (lệnh, thời điểm, commit, exit code)."""
    p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=str(cwd))
    out = ANSI.sub('', (p.stdout or '') + (p.stderr or '')).rstrip('\n')
    if evid_id:
        hdr = [f'# EVIDENCE {evid_id}', f'# command : {display or " ".join(argv)}', f'# cwd     : {cwd}',
               f'# time    : {NOW}', f'# commit  : {COMMIT}', f'# exit    : {p.returncode}',
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


def main():
    # 1) Demo F02 — poison null byte
    out = runout(['python', 'report/demos/tv2_f02_pathtraversal.py'],
                 evid_id='tv2-f02', display='python report/demos/tv2_f02_pathtraversal.py')
    blocks = [('cmd', 'python report/demos/tv2_f02_pathtraversal.py   # F02 Poison Null Byte')]
    for ln in out.split('\n'):
        if 'LỖ HỔNG' in ln:
            blocks.append(('hl', ln))
        elif 'an toàn' in ln:
            blocks.append(('ok', ln))
        else:
            blocks.append(('out', ln))
    render(SHOTS / 'tv2.png', 'Windows PowerShell — Demo F02: Poison Null Byte (doc tep sao luu) (trước vá 3100 / sau vá 3102)', blocks)

    # 2) f0102-green: mã đã vá (trạng thái hiện tại)
    render(SHOTS / 'f0102-green.png', 'Windows PowerShell — kiểm thử bảo mật F01/F02 SAU khi vá',
           test_blocks(runout(TCMD, evid_id='f0102-green-test', display=TLINE),
                       'HEAD  test(security): F01 SQLi dang nhap + F02 null byte /ftp (da va)'))

    # 3) f0102-red: swap baseline fileServer.ts (lưu lại bản vá), chạy, rồi khôi phục
    fsrv = ROOT / 'routes' / 'fileServer.ts'
    patched = fsrv.read_text(encoding='utf-8')
    base = subprocess.run(['git', '-C', str(ROOT), 'show', '21219d66d:routes/fileServer.ts'],
                          capture_output=True, text=True, encoding='utf-8').stdout
    fsrv.write_text(base, encoding='utf-8')
    try:
        out = runout(TCMD, evid_id='f0102-red-test', display=TLINE + '   # baseline fileServer.ts')
    finally:
        fsrv.write_text(patched, encoding='utf-8')
    render(SHOTS / 'f0102-red.png', 'Windows PowerShell — kiểm thử bảo mật F01/F02 TRƯỚC khi vá',
           test_blocks(out, '21219d66d  test(security): F01 SQLi dang nhap + F02 Poison Null Byte /ftp (dang do)'))


if __name__ == '__main__':
    main()

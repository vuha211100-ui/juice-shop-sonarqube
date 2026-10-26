"""TV1 — F01 SQL injection tại POST /rest/user/login.

Phát hiện: gửi email chứa payload SQL kèm mật khẩu SAI. Nếu máy chủ vẫn cấp token thì dữ liệu nhập
đã làm thay đổi câu SQL (lỗ hổng còn). Sau vá, payload chỉ là một chuỗi email không tồn tại -> 401.
"""
from common import AFTER, BEFORE, call, table

PAYLOADS = ["' OR 1=1--", "admin@juice-sh.op'--", "' UNION SELECT * FROM Users--"]
rows = [('Môi trường', 'Email gửi lên', 'HTTP', 'Cấp token?', 'Kết luận')]
for label, base in (BEFORE, AFTER):
    status, _ = call(base, 'POST', '/rest/user/login', {'email': 'jim@juice-sh.op', 'password': 'ncc-1701'})
    rows.append((label, 'jim@juice-sh.op (đúng mật khẩu)', status, status == 200, 'đối chứng: đăng nhập hợp lệ'))
    for p in PAYLOADS:
        status, body = call(base, 'POST', '/rest/user/login', {'email': p, 'password': 'wrong-password'})
        token = isinstance(body, dict) and bool(body.get('authentication', {}).get('token'))
        rows.append((label, p, status, token, 'LỖ HỔNG: vượt xác thực' if token else 'an toàn: bị từ chối'))
table(rows)

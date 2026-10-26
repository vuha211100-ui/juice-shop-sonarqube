"""TV2 — F02 IDOR tại GET /rest/basket/:id.

Phát hiện: tạo hai tài khoản A, B; dùng token của A đọc giỏ của B. Nếu nhận được giỏ của B thì
route chỉ kiểm tra "có token" mà không kiểm tra "giỏ có thuộc người gọi không". Sau vá: 404.
"""
import time
from common import AFTER, BEFORE, call, table

rows = [('Môi trường', 'Yêu cầu', 'HTTP', 'Dữ liệu trả về', 'Kết luận')]
for label, base in (BEFORE, AFTER):
    acc = []
    for who in 'ab':
        email, pw = f'demo-{who}-{time.time_ns()}@example.invalid', 'Lab-Only-9!xQ2'
        call(base, 'POST', '/api/Users', {'email': email, 'password': pw, 'passwordRepeat': pw})
        acc.append(call(base, 'POST', '/rest/user/login', {'email': email, 'password': pw})[1]['authentication'])
    a, b = acc
    s, body = call(base, 'GET', f"/rest/basket/{a['bid']}", token=a['token'])
    rows.append((label, f"A đọc giỏ của A (id {a['bid']})", s, f"giỏ {body['data']['id']}" if s == 200 else '-', 'hợp lệ'))
    s, body = call(base, 'GET', f"/rest/basket/{b['bid']}", token=a['token'])
    leaked = s == 200 and body.get('data', {}).get('id') == b['bid']
    rows.append((label, f"A đọc giỏ của B (id {b['bid']})", s, f"giỏ {b['bid']} của B" if leaked else '-',
                 'LỖ HỔNG: lộ giỏ người khác' if leaked else 'an toàn: từ chối'))
    s, _ = call(base, 'GET', f"/rest/basket/{b['bid']}")
    rows.append((label, 'không có token', s, '-', 'yêu cầu đăng nhập'))
table(rows)

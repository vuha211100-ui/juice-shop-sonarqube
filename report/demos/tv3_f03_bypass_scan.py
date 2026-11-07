"""TV3b — F03: quét biến thể đường dẫn để tìm đường VƯỢT proxy (kiểm thử động).

Bối cảnh: nginx chặn /metrics và giới hạn tốc độ /rest/user/login bằng `location = ...` (PHÂN BIỆT hoa thường),
còn Express ở backend định tuyến KHÔNG phân biệt hoa thường. Đường dẫn khác dạng (chữ hoa, mã hóa %4D...) có thể
lọt khỏi luật của proxy nhưng vẫn tới đúng route ở backend.

Quét 2 thứ trên một proxy (mặc định 127.0.0.1:3102, truyền URL khác làm đối số):
  1. Biến thể của /metrics: trả nội dung metrics (có dòng '# HELP') = LỘ.
  2. Biến thể của /rest/user/login: gửi 8 lần đăng nhập sai, không gặp 429 = KHÔNG GIỚI HẠN.
Mã thoát: 0 = không tìm thấy đường vượt, 1 = có đường vượt (dùng được như một cổng trong pipeline).
"""
import json
import sys
import urllib.error
import urllib.request

from common import table

BASE = (sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:3102').rstrip('/')

METRICS_VARIANTS = ['/metrics', '/metrics/', '/Metrics', '/METRICS', '/mEtRiCs', '/%4Detrics', '/metrics?x=1', '//metrics', '/./metrics']
LOGIN_VARIANTS = ['/REST/USER/LOGIN', '/Rest/User/Login', '/rest/user/login/']
LOGIN_CONTROL = '/rest/user/login'
TRIES = 8   # nginx: rate=5r/m, burst=5 -> từ lần thứ 7 phải là 429


def get(path):
    try:
        with urllib.request.urlopen(urllib.request.Request(BASE + path), timeout=10) as r:
            return r.status, r.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, ''
    except OSError as e:
        return 'refused', str(e)


def post_login(path):
    req = urllib.request.Request(BASE + path, method='POST', headers={'Content-Type': 'application/json'},
                                 data=json.dumps({'email': 'scan@example.test', 'password': 'wrong'}).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return 'refused'


found = 0
print(f'Quét đường vượt proxy trên {BASE}')
print()
rows = [('Đường dẫn', 'HTTP', 'Nội dung', 'Kết luận')]
for p in METRICS_VARIANTS:
    status, body = get(p)
    leaked = status == 200 and '# HELP' in body
    found += leaked
    rows.append((p, status, f'metrics {len(body.splitlines())} dòng' if leaked else '-', 'LỘ: vượt proxy' if leaked else 'chặn'))
table(rows)

print()
rows = [('Đăng nhập sai x%d' % TRIES, 'Mã trả về', 'Kết luận')]
for p in LOGIN_VARIANTS + [LOGIN_CONTROL]:   # biến thể trước, đường chuẩn cuối để đối chứng
    codes = [post_login(p) for _ in range(TRIES)]
    limited = 429 in codes
    if p != LOGIN_CONTROL:
        found += not limited
    summary = ', '.join(f'{c} x{codes.count(c)}' for c in dict.fromkeys(codes))
    verdict = ('đối chứng: có giới hạn' if limited else 'đối chứng: KHÔNG giới hạn') if p == LOGIN_CONTROL else \
              ('có giới hạn' if limited else 'KHÔNG GIỚI HẠN: vượt rate-limit')
    rows.append((p, summary, verdict))
table(rows)

print()
print(f'Kết quả: {found} đường vượt proxy' if found else 'Kết quả: không tìm thấy đường vượt proxy')
sys.exit(1 if found else 0)

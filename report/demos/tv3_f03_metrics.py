"""TV3 — F03 endpoint /metrics bị truy cập được không qua xác thực (lỗi triển khai).

Phát hiện: gọi /metrics từ host. Trước vá: container publish thẳng cổng ứng dụng -> 200, lộ số liệu vận hành.
Sau vá: chỉ proxy có cổng host; proxy trả 404 cho /metrics; backend không còn cổng host (không vòng qua được),
nhưng hệ thống giám sát nội bộ vẫn đọc được /metrics qua mạng internal.
Ngăn tái diễn: policy/compose.rego (NET-02) chặn mọi cấu hình cho backend publish cổng.
"""
import json
from common import AFTER, BEFORE, call, sh, table

rows = [('Môi trường', 'Truy cập', 'Kết quả', 'Kết luận')]
s, body = call(BEFORE[1], 'GET', '/metrics')
rows.append((BEFORE[0], 'GET 127.0.0.1:3100/metrics', s, f'LỘ: {len(str(body).splitlines())} dòng metrics' if s == 200 else '-'))
s, _ = call(AFTER[1], 'GET', '/metrics')
rows.append((AFTER[0], 'GET 127.0.0.1:3102/metrics (qua proxy)', s, 'chặn tại proxy' if s == 404 else 'KHÔNG CHẶN'))
s, _ = call(AFTER[1], 'GET', '/')
rows.append((AFTER[0], 'GET 127.0.0.1:3102/ (trang chủ)', s, 'ứng dụng vẫn hoạt động'))
s, _ = call('http://127.0.0.1:3101', 'GET', '/metrics')
rows.append((AFTER[0], 'GET 127.0.0.1:3101/metrics (cổng backend cũ)', s, 'không còn đường vòng' if s == 'refused' else 'CÒN ĐƯỜNG VÒNG'))
ports = json.loads(sh('docker', 'inspect', 'juice-app-juice-shop-1', '--format', '{{json .HostConfig.PortBindings}}').stdout or '{}')
rows.append((AFTER[0], 'docker inspect cổng host của backend', ports or 'không có', 'backend chỉ ở mạng internal'))
internal = sh('docker', 'exec', 'juice-app-proxy-1', 'wget', '-qO-', 'http://juice-shop:3000/metrics').stdout
rows.append((AFTER[0], 'giám sát nội bộ: proxy -> juice-shop:3000/metrics', 'đọc được' if internal.strip() else 'không đọc được',
             f'{len(internal.splitlines())} dòng, chỉ trong mạng internal'))
table(rows)

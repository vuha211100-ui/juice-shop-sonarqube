"""TV3 — F03 endpoint /metrics bị truy cập được không qua xác thực (lỗi triển khai).

Phát hiện: gọi /metrics từ host. Trước vá: container publish thẳng cổng ứng dụng -> 200, lộ số liệu vận hành.
Sau vá: chỉ proxy có cổng host; proxy trả 404 cho /metrics; backend không còn cổng host (không vòng qua được),
nhưng hệ thống giám sát nội bộ vẫn đọc được /metrics qua mạng internal.
Ngăn tái diễn: chạy Conftest với policy/compose.rego (NET-02) trên cấu hình compose:
  - report/fixtures/compose.before-f03.yml (backend publish 127.0.0.1:3101) -> phải FAIL
  - docker-compose.yml (bản vá, chỉ proxy publish)                           -> phải PASS
"""
import json
import pathlib
from common import AFTER, BEFORE, call, sh, table

# Gốc repo chứa docker-compose.yml + policy/compose.rego: report/demos/ -> gốc repo,
# hoặc thư mục juice-shop cạnh bản sao báo cáo BaoCao-DevSecOps/demos/.
_here = pathlib.Path(__file__).resolve()
ROOT = next((r for r in (_here.parents[2], _here.parents[2] / 'juice-shop')
             if (r / 'policy' / 'compose.rego').is_file()), _here.parents[2])
CF = ['docker', 'run', '--rm', '-v', f'{ROOT.as_posix()}:/work:ro', '-w', '/work', 'openpolicyagent/conftest:v0.71.1']

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

# Policy as Code: mỗi file chạy riêng để exit code phản ánh đúng file đó.
print()
rows = [('Cấu hình compose', 'Exit', 'Luật bị chặn (FAIL)', 'Kết luận')]
for target, desc, bad in [('report/fixtures/compose.before-f03.yml', 'compose.before-f03.yml (trước vá)', True),
                          ('docker-compose.yml', 'docker-compose.yml (sau vá)', False)]:
    p = sh(*CF, 'test', target, '-p', 'policy', '--namespace', 'compose', '--no-color')
    fails = [l.split(' - ')[-1] for l in p.stdout.splitlines() if l.startswith('FAIL')]
    rules = ', '.join(sorted({f.split(']')[0].lstrip('[') + ' ' + f.split("'")[1] for f in fails if "'" in f})) or '-'
    if p.returncode not in (0, 1):
        verdict = 'LỖI CHẠY CONFTEST'
    elif bad:
        verdict = 'đúng: gate chặn' if p.returncode else 'SAI: lọt gate'
    else:
        verdict = 'đúng: đạt chính sách' if p.returncode == 0 else 'SAI: chặn nhầm'
    rows.append((desc, p.returncode, rules, verdict))
table(rows)

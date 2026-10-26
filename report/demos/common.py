"""Hàm dùng chung cho 4 demo F01–F04. Chỉ gọi tới các cổng loopback của lab."""
import json, subprocess, sys, urllib.error, urllib.request

sys.stdout.reconfigure(encoding='utf-8')
BEFORE = ('trước vá', 'http://127.0.0.1:3100')   # container đối chứng: image gốc, truy cập thẳng, chưa vá
AFTER = ('sau vá', 'http://127.0.0.1:3102')      # bản triển khai trong repo: proxy + hotfix image


def call(base, method, path, body=None, token=None):
    """Gửi một request JSON, trả (status, body). Lỗi HTTP vẫn trả về status để so sánh."""
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.startswith(('{', '[')) else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw.startswith(('{', '[')) else raw)
    except OSError as e:                       # cổng không mở: không có dịch vụ lắng nghe
        return 'refused', str(e.reason if hasattr(e, 'reason') else e)


def table(rows):
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    for k, r in enumerate(rows):
        print('  '.join(str(x).ljust(w[i]) for i, x in enumerate(r)).rstrip())
        if k == 0:
            print('  '.join('-' * x for x in w))


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace')

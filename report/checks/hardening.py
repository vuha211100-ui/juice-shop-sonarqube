"""In bảng cấu hình an toàn của các container đang chạy (từ docker inspect) và trạng thái các mạng Compose.
Chỉ xét các container/mạng của mô hình demo sau khi đã dọn hạ tầng phụ. Bỏ qua thứ không tồn tại."""
import json, subprocess, sys
sys.stdout.reconfigure(encoding='utf-8')

# juice-app-*: bản SAU vá (proxy + backend internal); juice-report-lab: container đối chứng TRƯỚC vá.
CONTAINERS = ['juice-app-proxy-1', 'juice-app-juice-shop-1', 'juice-report-lab']
NETWORKS = ['juice-app_edge', 'juice-app_backend']


def inspect(kind, name):
    p = subprocess.run(['docker', kind, 'inspect', name], capture_output=True, text=True, encoding='utf-8')
    if p.returncode != 0:
        return None
    return json.loads(p.stdout)[0]


def short(c):
    return (c.replace('juice-app-', 'app/').replace('juice-report-lab', 'control/lab').removesuffix('-1'))


rows = [('CONTAINER', 'USER', 'READ-ONLY', 'CAP_DROP', 'NO-NEW-PRIV', 'CỔNG HOST')]
for c in CONTAINERS:
    d = inspect('container', c)
    if d is None:
        continue
    hc = d['HostConfig']
    ports = ','.join(f"{b['HostIp']}:{b['HostPort']}" for v in (hc.get('PortBindings') or {}).values() for b in v) or '-'
    rows.append((short(c), d['Config']['User'] or '(image)', str(hc['ReadonlyRootfs']).lower(),
                 ','.join(hc.get('CapDrop') or []) or '-',
                 str('no-new-privileges:true' in (hc.get('SecurityOpt') or [])).lower(), ports))

w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
for r in rows:
    print('  '.join(x.ljust(w[i]) for i, x in enumerate(r)).rstrip())
print()
for n in NETWORKS:
    d = inspect('network', n)
    if d is None:
        continue
    print(f"network {n:20} internal={str(d['Internal']).lower():5}  containers={len(d['Containers'])}")

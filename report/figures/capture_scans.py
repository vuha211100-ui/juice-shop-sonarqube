"""Ảnh quét bổ sung -> report/screenshots/*.png (đồng bộ style capture_runs).

- trivy.png     : Trivy quét CVE dependency của image (SCA, pha Release).
- dockle.png    : Dockle quét cấu hình image theo CIS — bắt secret bake vào layer (pha Release).
- monitoring.png: Prometheus scrape /metrics + cảnh báo khi bị tấn công (pha Operate).

Yêu cầu: stack juice-app + juice-monitoring đang chạy, Docker Desktop bật.
Chạy:  python report/figures/capture_scans.py
"""
import json
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from capture_runs import EVID, NOW, ROOT, SHOTS, render  # noqa: E402

SOCK = '/var/run/docker.sock'
TRIVY = ['docker', 'run', '--rm', '-v', f'{SOCK}:{SOCK}',
         '-v', 'trivy-cache:/root/.cache/trivy', 'aquasec/trivy:latest']
DOCKLE = ['docker', 'run', '--rm', '-v', f'{SOCK}:{SOCK}', 'goodwithtech/dockle:latest', '--no-color']
IMG = 'juice-shop:hotfix-f01-f02'


def sh(argv):
    p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace')
    return ((p.stdout or '') + (p.stderr or '')).rstrip('\n'), p.returncode


def save_log(evid_id, display, argv, text, rc, tool=None):
    hdr = [f'# EVIDENCE {evid_id}', f'# command : {display}', f'# argv    : {" ".join(argv)}',
           f'# time    : {NOW}']
    if tool:
        hdr.append(f'# tool    : {tool}')
    hdr += [f'# exit    : {rc}', '# ----- combined stdout+stderr -----']
    (EVID / f'{evid_id}.log').write_text('\n'.join(hdr) + '\n' + text + '\n', encoding='utf-8')
    print(f'  evidence/{evid_id}.log exit={rc}')


def trivy_fig():
    argv = TRIVY + ['image', '-q', '--no-progress', '--scanners', 'vuln', '-f', 'json', IMG]
    out, rc = sh(argv)
    jtext = out[out.find('{'):]
    data = json.loads(jtext)
    sev = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    ids = set()                      # VulnerabilityID duy nhất (một CVE có thể lặp trên nhiều gói)
    cves, seen = [], set()
    for res in data.get('Results', []) or []:
        for v in res.get('Vulnerabilities', []) or []:
            s = v.get('Severity', 'UNKNOWN')
            sev[s] = sev.get(s, 0) + 1
            ids.add(v.get('VulnerabilityID'))
            if s in ('CRITICAL', 'HIGH') and v.get('VulnerabilityID') not in seen:
                seen.add(v['VulnerabilityID'])
                cves.append((s, v['VulnerabilityID'], v.get('PkgName', ''), v.get('InstalledVersion', '')))
    total = sum(sev.values())
    distinct = len(ids)
    digest, _ = sh(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMG])
    verout, _ = sh(TRIVY + ['--version'])
    ver = next((l.strip() for l in verout.split('\n') if 'Version' in l), 'trivy')
    # lưu JSON gốc (đúng dữ liệu dùng để đếm) làm bằng chứng kiểm toán được
    (EVID / 'trivy-image.json').write_text(jtext, encoding='utf-8')
    save_log('trivy-image', f'trivy image -f json {IMG}', argv,
             jtext[:1500] + '\n...(JSON đầy đủ: report/evidence/trivy-image.json)', rc, tool=ver)
    blocks = [('cmd', f'trivy image {IMG}      # SCA - lỗ hổng dependency'),
              ('out', f'image {digest.strip()[:26]}…   ({ver})'),
              ('out', f'Quét {len(data.get("Results", []))} target (OS Debian + package.json / node_modules)'),
              ('note', f'{total} bản ghi phát hiện ({distinct} CVE duy nhất)   '
                       f'CRITICAL {sev["CRITICAL"]}  HIGH {sev["HIGH"]}  MEDIUM {sev["MEDIUM"]}  LOW {sev["LOW"]}'),
              ('out', 'Một số CVE CRITICAL/HIGH trong dependency:')]
    for s, cid, pkg, ver2 in cves[:8]:
        tag = '[CRIT]' if s == 'CRITICAL' else '[HIGH]'
        blocks.append(('fail' if s == 'CRITICAL' else 'out', f'   {tag} {cid:<18} {pkg} {ver2}'))
    blocks.append(('out', '→ Lớp SCA mà Semgrep (quét mã) và Conftest (quét cấu hình) không phủ.'))
    render(SHOTS / 'trivy.png', 'Windows PowerShell — Trivy quét CVE image (SCA · pha Release)',
           blocks, evid_id='trivy-image', rc=rc)


def dockle_fig():
    demo = ROOT / '_dockle_demo'
    demo.mkdir(exist_ok=True)
    (demo / 'id_rsa').write_text('-----BEGIN RSA PRIVATE KEY-----\nMIIEoFAKEdemoKeyNotReal000\n'
                                 '-----END RSA PRIVATE KEY-----\n', encoding='utf-8')
    # image JUICE SHOP bị đóng gói SAI: lấy chính image triển khai của nhóm rồi chồng các lỗi
    # đóng gói (secret trong TỆP + trong ENV, chạy root) -> vẫn là một image Juice Shop thật,
    # không phải image demo rời. Dockle vì thế quét ngay trên image Juice Shop.
    (demo / 'Dockerfile').write_text(
        f'FROM {IMG}\n'
        'USER root\n'
        'COPY id_rsa /juice-shop/id_rsa\n'
        'ENV API_TOKEN=supersecret123\n', encoding='utf-8')
    bad_img = 'juice-shop:dockle-misconfig'
    sh(['docker', 'build', '-q', '-t', bad_img, str(demo)])
    bad, rcb = sh(DOCKLE + [bad_img])
    good, rcg = sh(DOCKLE + [IMG])
    save_log('dockle-bad', f'dockle {bad_img}', DOCKLE + [bad_img],
             bad, rcb, tool='goodwithtech/dockle')
    save_log('dockle-good', f'dockle {IMG}', DOCKLE + [IMG], good, rcg, tool='goodwithtech/dockle')

    def classify(text):
        rows = []
        for ln in text.split('\n'):
            disp = ln.replace('\t', '  ').rstrip()
            s = disp.strip()
            if not s:
                continue
            if s.startswith('FATAL'):
                rows.append(('fail', disp))
            elif s.startswith('WARN'):
                rows.append(('note', disp))
            else:
                rows.append(('out', disp))
        return rows

    blocks = [('cmd', f'dockle {bad_img}     # image JUICE SHOP đóng gói SAI')]
    blocks += classify(bad)
    blocks.append(('out', ''))
    blocks.append(('cmd', f'dockle {IMG}     # image JUICE SHOP triển khai của nhóm'))
    blocks += classify(good)
    blocks.append(('ok', '→ Cả hai đều là image JUICE SHOP. Dockle đọc IMAGE thành phẩm: bắt secret nằm trong'))
    blocks.append(('ok', '  TỆP bị COPY (id_rsa - dữ liệu giả lập), secret trong ENV và user hiệu lực (root).'))
    blocks.append(('ok', '  Secret-ENV và chạy root thì CẢ Conftest lẫn Dockle đều bắt - bổ sung nhau, có phần giao.'))
    render(SHOTS / 'dockle.png', 'Windows PowerShell — Dockle quét cấu hình image theo CIS (pha Release)',
           blocks, evid_id='dockle-bad', rc=rcb)


def _api(path):
    with urllib.request.urlopen('http://127.0.0.1:9090' + path, timeout=5) as r:
        return json.load(r)


def trigger_attack(n=60):
    cmd = (f'for i in $(seq 1 {n}); do curl -s -o /dev/null -X POST '
           'http://juice-app-juice-shop-1:3000/rest/user/login '
           "-H 'Content-Type: application/json' "
           "-d '{\"email\":\"attacker@x.op\",\"password\":\"wrong\"}'; done")
    subprocess.run(['docker', 'run', '--rm', '--network', 'juice-app_backend',
                    'curlimages/curl:latest', 'sh', '-c', cmd], capture_output=True)


def mon_fig():
    trigger_attack()
    al = []
    for _ in range(12):            # poll tối đa ~60s tới khi cảnh báo chuyển firing
        time.sleep(5)
        al = _api('/api/v1/alerts')['data']['alerts']
        if any(a['state'] == 'firing' for a in al):
            break
    tg = _api('/api/v1/targets')['data']['activeTargets']
    q = _api('/api/v1/query?query=juiceshop_users_registered_total')['data']['result']
    users = q[0]['value'][1] if q else '?'
    blocks = [('cmd', 'curl http://127.0.0.1:9090/api/v1/targets      # Prometheus scrape /metrics nội bộ')]
    for t in tg:
        h = t['health']
        blocks.append(('ok' if h == 'up' else 'fail',
                       f'   {t["scrapeUrl"]}   health={h}   job={t["labels"].get("job")}'))
    blocks.append(('cmd', 'curl .../api/v1/query?query=juiceshop_users_registered_total'))
    blocks.append(('out', f'   juiceshop_users_registered_total = {users}   (số liệu vận hành thật)'))
    blocks.append(('cmd', 'mô phỏng tấn công: 60x POST /rest/user/login (sai) -> 401'))
    blocks.append(('cmd', 'curl .../api/v1/alerts                         # phát hiện bất thường'))
    if al:
        for a in al:
            st = a['state']
            blocks.append(('fail' if st == 'firing' else 'note',
                           f'   {a["labels"].get("alertname")}   state={st.upper()}   '
                           f'— {a["annotations"].get("summary", "")}'))
    else:
        blocks.append(('out', '   (chưa có cảnh báo)'))
    save_log('monitoring', 'Prometheus API: targets / query / alerts',
             ['curl', 'http://127.0.0.1:9090/api/v1/{targets,query,alerts}'],
             json.dumps({'targets': [(t['scrapeUrl'], t['health']) for t in tg], 'users': users,
                         'alerts': [(a['labels'].get('alertname'), a['state']) for a in al]},
                        ensure_ascii=False, indent=2), 0)
    render(SHOTS / 'monitoring.png',
           'Windows PowerShell — Giám sát vận hành: Prometheus scrape + cảnh báo (pha Operate)',
           blocks, evid_id='monitoring', rc=0)


def main():
    trivy_fig()
    dockle_fig()
    mon_fig()


if __name__ == '__main__':
    main()

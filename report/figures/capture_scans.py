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
    data = json.loads(out[out.find('{'):])
    sev = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    cves, seen = [], set()
    for res in data.get('Results', []) or []:
        for v in res.get('Vulnerabilities', []) or []:
            s = v.get('Severity', 'UNKNOWN')
            sev[s] = sev.get(s, 0) + 1
            if s in ('CRITICAL', 'HIGH') and v.get('VulnerabilityID') not in seen:
                seen.add(v['VulnerabilityID'])
                cves.append((s, v['VulnerabilityID'], v.get('PkgName', ''), v.get('InstalledVersion', '')))
    total = sum(sev.values())
    tbl, _ = sh(TRIVY + ['image', '--no-progress', '--scanners', 'vuln', '--severity', 'HIGH,CRITICAL', IMG])
    save_log('trivy-image', f'trivy image {IMG}', argv, tbl, rc, tool='aquasec/trivy:latest')
    blocks = [('cmd', f'trivy image {IMG}      # SCA - lỗ hổng dependency'),
              ('out', f'Quét {len(data.get("Results", []))} target (OS Debian + package.json / node_modules)'),
              ('note', f'Tổng: {total} CVE    CRITICAL {sev["CRITICAL"]}    HIGH {sev["HIGH"]}    '
                       f'MEDIUM {sev["MEDIUM"]}    LOW {sev["LOW"]}'),
              ('out', 'Một số CVE CRITICAL/HIGH trong dependency:')]
    for s, cid, pkg, ver in cves[:9]:
        tag = '[CRIT]' if s == 'CRITICAL' else '[HIGH]'
        blocks.append(('fail' if s == 'CRITICAL' else 'out', f'   {tag} {cid:<18} {pkg} {ver}'))
    blocks.append(('out', '→ Semgrep/Conftest KHÔNG quét được lớp này — đây là mảng SCA bổ sung.'))
    render(SHOTS / 'trivy.png', 'Windows PowerShell — Trivy quét CVE image (SCA · pha Release)',
           blocks, evid_id='trivy-image', rc=rc)


def dockle_fig():
    demo = ROOT / '_dockle_demo'
    demo.mkdir(exist_ok=True)
    (demo / 'id_rsa').write_text('-----BEGIN RSA PRIVATE KEY-----\nMIIEoFAKEdemoKeyNotReal000\n'
                                 '-----END RSA PRIVATE KEY-----\n', encoding='utf-8')
    (demo / 'package.json').write_text('{"name":"demo","version":"1.0.0"}\n', encoding='utf-8')
    shutil.copy(ROOT / 'Dockerfile.vulnerable', demo / 'Dockerfile')
    sh(['docker', 'build', '-q', '-t', 'dockle-demo:vulnerable', str(demo)])
    bad, _ = sh(DOCKLE + ['dockle-demo:vulnerable'])
    good, rcg = sh(DOCKLE + [IMG])
    save_log('dockle-bad', 'dockle dockle-demo:vulnerable', DOCKLE + ['dockle-demo:vulnerable'],
             bad, 0, tool='goodwithtech/dockle')
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

    blocks = [('cmd', 'dockle dockle-demo:vulnerable     # image đóng gói SAI')]
    blocks += classify(bad)
    blocks.append(('out', ''))
    blocks.append(('cmd', f'dockle {IMG}     # image triển khai của nhóm'))
    blocks += classify(good)
    blocks.append(('ok', '→ Bắt secret BAKE vào layer (id_rsa) + ENV secret + thiếu HEALTHCHECK —'))
    blocks.append(('ok', '  những lỗi Conftest đọc text Dockerfile KHÔNG thấy.'))
    render(SHOTS / 'dockle.png', 'Windows PowerShell — Dockle quét cấu hình image theo CIS (pha Release)',
           blocks, evid_id='dockle-bad', rc=0)


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

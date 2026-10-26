"""TV4 — F04: Policy as Code cho container Juice Shop (bám theo lab "Policy as Code with Conftest").

Vấn đề: image/triển khai của Juice Shop phải tuân thủ chính sách an toàn tối thiểu của tổ chức.
Các "original check" ngây thơ (USER bất kỳ, EXPOSE, LABEL mfa="true"...) dễ bị qua mặt; bộ policy
docker_security.rego đặt luật tại điểm thực thi đúng. Demo chạy Conftest trên:
  - Dockerfile.vulnerable (4 vi phạm cố ý) -> phải FAIL
  - Dockerfile.remediated (bản vá của lab)  -> phải PASS
  - Dockerfile gốc Juice Shop (distroless)  -> đạt toàn bộ chính sách an toàn
"""
import pathlib
from common import sh, table

# Gốc repo = hai cấp trên thư mục script (report/demos/ -> report/ -> gốc repo).
ROOT = pathlib.Path(__file__).resolve().parents[2]
CF = ['docker', 'run', '--rm', '-v', f'{ROOT.as_posix()}:/work:ro', '-w', '/work', 'openpolicyagent/conftest:v0.71.1']


def conftest(target):
    p = sh(*CF, 'test', target, '--parser', 'dockerfile', '-p', 'policy', '--namespace', 'dockerfile', '--no-color')
    cats = sorted({l.split(' - ')[-1].split(':')[0] for l in p.stdout.splitlines() if l.startswith('FAIL')})
    return p.returncode, ', '.join(cats) or '-'


verify = sh(*CF, 'verify', '-p', 'policy', '--no-color')
print('conftest verify -p policy  ->  ' + next((l.strip() for l in verify.stdout.splitlines() if 'tests,' in l), '?'))
print()
rows = [('Dockerfile', 'Exit', 'Nhóm luật bị chặn', 'Kết luận')]
for target, desc, bad in [('Dockerfile.vulnerable', 'Dockerfile.vulnerable (4 vi phạm)', True),
                          ('report/fixtures/Dockerfile.remediated', 'Dockerfile.remediated (bản vá)', False),
                          ('Dockerfile', 'Dockerfile gốc Juice Shop (distroless)', False),
                          ('deploy/Dockerfile.hotfix', 'hotfix image F01/F02', False)]:
    rc, cats = conftest(target)
    if bad is True:
        verdict = 'đúng: gate chặn' if rc else 'SAI: lọt gate'
    else:
        verdict = 'đúng: đạt chính sách' if rc == 0 else 'SAI: chặn nhầm'
    rows.append((desc, rc, cats, verdict))
table(rows)

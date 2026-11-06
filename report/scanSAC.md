

**Chuẩn bị — dựng stack:**
```powershell
cd E:\banhoaqua\juice-shop
$ROOT = "E:/banhoaqua/juice-shop"       # dùng cho các lệnh docker bên dưới
```

### Pha Code — Phát hiện lỗ hổng
**Semgrep (SAST)** — quét tĩnh **toàn bộ `routes/` + `lib/`** trên mã **CHƯA vá** (như báo cáo): ra **38 cảnh báo / 25 tệp**, trong đó khoanh đúng **F01** (`login.ts` — SQL injection) và **F02** (`fileServer.ts` — Poison Null Byte).
```powershell
git checkout 21219d66d -- routes        # lấy route CHƯA vá (login.ts + fileServer.ts)
docker run --rm -e SEMGREP_SEND_METRICS=off -v "${ROOT}:/src:ro" -v "${ROOT}/report/semgrep-rules:/rules:ro" `
  semgrep/semgrep:1.180.0 semgrep scan --metrics=off --quiet `
  --config /rules/owasp-top-ten.yml --config /rules/nodejsscan.yml `
  /src/routes /src/lib                  # quét hết routes + lib -> 38 cảnh báo / 25 tệp
git checkout HEAD -- routes             # trả lại bản vá
```


**Gitleaks (quét secret)** — quét commit vá của nhóm:
```powershell
docker run --rm -v "${ROOT}:/repo:ro" zricethezav/gitleaks:v8.30.1 `
  git /repo --log-opts="baf9dcea4..HEAD" --no-banner      # kỳ vọng: no leaks found (exit 0)
```

**Conftest · `docker_security.rego`** (F04):
```powershell
$CF = @("run","--rm","-v","${ROOT}:/work:ro","-w","/work","openpolicyagent/conftest:v0.71.1")
docker @CF verify -p policy --no-color                                                                                 # tự kiểm luật: 19/19
docker @CF test report/fixtures/Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile --no-color  # fixture: exit 1 (4 nhóm)
docker @CF test Dockerfile --parser dockerfile -p policy --namespace dockerfile --no-color                             # gốc distroless: exit 0
docker @CF test deploy/Dockerfile.hotfix --parser dockerfile -p policy --namespace dockerfile --no-color               # image đã vá: exit 0
```

```powershell
git checkout 21219d66d -- routes        # lấy tạm route CHƯA vá -> một số ca đỏ
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
git checkout HEAD -- routes             # trả lại bản vá -> toàn bộ ca xanh (11/11)
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
```



**Trivy (SCA)** — CVE dependency. *Lọc theo mức cho dễ nhìn* (đầu ra có bảng **Report Summary** đếm theo mức ở trên cùng):
```powershell
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.76.1 `
  image --scanners vuln --severity CRITICAL,HIGH juice-shop:hotfix-f01-f02
#  gọn nhất cho demo: chỉ 12 lỗ hổng CRITICAL -> đổi thành  --severity CRITICAL
#  bỏ --severity để xem đủ 173 CVE như báo cáo
```
**Dockle (CIS image)** — lint image thành phẩm:
```powershell
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock goodwithtech/dockle:v0.4.15 `
  juice-shop:hotfix-f01-f02                                 # image của nhóm: không FATAL/WARN
```

### Pha Deploy — Policy as Code (compose)
**Conftest · `compose.rego`** (F03):
```powershell
docker @CF test docker-compose.yml -p policy --namespace compose --no-color   # exit 0 (backend không mở cổng host)
```

### Pha Operate — Compliance as Code & Giám sát
**docker inspect** — kiểm container đang chạy:
```powershell
docker inspect juice-app-juice-shop-1 --format '{{json .HostConfig.PortBindings}}'                       # cổng host: trống (backend không lộ)
docker inspect juice-app-juice-shop-1 --format 'User={{.Config.User}} CapDrop={{.HostConfig.CapDrop}} Sec={{.HostConfig.SecurityOpt}}'   # non-root · cap_drop · no-new-privileges
```



### Integration — 4 lỗi F01–F04 đi qua quy trình DevSecOps

#### Chuẩn bị
```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$GB = "C:\Program Files\Git\bin\bash.exe"
docker compose up -d
docker compose -f docker-compose.monitoring.yml up -d
git switch main
git status -s routes deploy docker-compose.yml
git config core.hooksPath
```

#### F01 — SQL injection quay lại `login.ts`: bị chặn ở Code (Semgrep) và Test
```powershell
git restore --source 5658473cf -- routes/login.ts
git add routes/login.ts
git commit -m "demo F01"                  # -> Semgrep FAIL, commit bị hủy
& $GB devsecops/pipeline.sh test          # -> Test FAIL (payload SQLi được 200)
git restore --staged --worktree routes/login.ts
```

#### Lộ khóa bí mật trong mã: bị chặn ở Code (Gitleaks)
```powershell
Add-Content routes/login.ts 'export const awsKey = "AKIAZ7Q4M2K9LX3VBN8P"'
git add routes/login.ts
git commit -m "demo secret"               # -> Gitleaks FAIL, commit bị hủy
git restore --staged --worktree routes/login.ts
```

#### F02 — Poison Null Byte quay lại `fileServer.ts`: Semgrep không thấy, Test chặn
```powershell
git restore --source 5658473cf -- routes/fileServer.ts
git add routes/fileServer.ts
& $GB devsecops/pipeline.sh --staged --quick code   # -> Code PASS
& $GB devsecops/pipeline.sh test                    # -> Test FAIL (đọc được .bak)
git restore --staged --worktree routes/fileServer.ts
```

#### F03 — Backend mở cổng ra host: bị chặn ở Deploy (Policy as Code `compose.rego`)
```powershell
$p = (Resolve-Path docker-compose.yml).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace 'labels: \{lab\.exposure: internal\}.*', 'ports: ["0.0.0.0:3000:3000"]'))
git add docker-compose.yml
git commit -m "demo F03"                  # -> F03 NET-02 + NET-01 FAIL, commit bị hủy
git restore --staged --worktree docker-compose.yml
```

#### F03 — Proxy hết chặn `/metrics` khi đang chạy: bị chặn ở Operate
```powershell
$p = (Resolve-Path deploy\nginx.conf).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace '(?m)^.*location = /metrics \{ return 404; \}\r?\n', ''))
docker compose restart proxy
& $GB devsecops/pipeline.sh operate       # -> FAIL: GET /metrics → 200
git restore deploy/nginx.conf
docker compose restart proxy
& $GB devsecops/pipeline.sh operate       # -> 5 PASS
```

#### F04 — Dockerfile bỏ `USER` (chạy root): bị chặn ở Build (Policy as Code `docker_security.rego`)
```powershell
$p = (Resolve-Path deploy\Dockerfile.hotfix).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace '(?m)^USER 65532\r?$', ''))
git add deploy/Dockerfile.hotfix
git commit -m "demo F04"                  # -> LEAST-PRIVILEGE FAIL, commit bị hủy
git restore --staged --worktree deploy/Dockerfile.hotfix
```

#### F04 — Container chạy root, không cap_drop, không giới hạn: bị chặn ở Operate (Compliance as Code `runtime.rego`)
```powershell
docker run -d --name f04-root --user 0 juice-shop:hotfix-f01-f02
docker inspect --format '{{json .}}' f04-root | docker run --rm -i -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test --parser json -p report/policy --namespace runtime -   # -> 5 FAIL
docker rm -f f04-root
```

#### Bản đã vá đi qua đủ 7 pha
```powershell
& $GB devsecops/pipeline.sh               # -> 20 PASS · 1 WARN · 0 FAIL
```

#### Bỏ qua hook (`--no-verify`): GitHub Actions vẫn chặn
```powershell
git switch -c fix/demo-ci main
git restore --source 5658473cf -- routes/login.ts
git add routes/login.ts
git commit -m "demo: bypass hook" --no-verify
git push github fix/demo-ci --no-verify
git switch main                           # -> Actions đỏ ở step Code
```

#### Dọn và tự kiểm bản vá còn nguyên
```powershell
& $GB devsecops/demo-cleanup.sh
git status -s routes deploy docker-compose.yml
node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit test/api/security/f01-f02.test.ts   # -> pass 11
```

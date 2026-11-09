

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
Trong pipeline, cổng Semgrep không chặn cả 38 cảnh báo này: `devsecops/semgrep-diff.mjs` so với bản gốc của cùng tệp và chỉ FAIL khi có cảnh báo **mới**.


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
#  cổng Release của pipeline thêm: --severity CRITICAL --ignorefile devsecops/.trivyignore --exit-code 1
#  -> bỏ qua 11 CVE CRITICAL có sẵn của image gốc, chỉ chặn CRITICAL mới
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

**Prometheus + Grafana** — giám sát nội bộ:
```powershell
docker compose -f docker-compose.monitoring.yml up -d
(Invoke-RestMethod http://127.0.0.1:9090/api/v1/targets).data.activeTargets | % { "$($_.labels.job) $($_.health)" }   # juice-shop up
Start-Process http://127.0.0.1:3103          # Grafana: dashboard "Juice Shop — Giám sát vận hành"
```



### Integration — 4 lỗi F01–F04 đi qua quy trình DevSecOps (chỉ dùng `git commit` / `git push`)

#### Chuẩn bị
```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
docker compose up -d
git switch main
git config core.hooksPath                 # -> .githooks
git switch -c fix/demo-ci main
```

#### F01 — SQL injection quay lại `login.ts`: commit bị chặn (Code · Semgrep)
```powershell
git restore --source 5658473cf -- routes/login.ts
git add routes/login.ts
git commit -m "demo F01"                  # -> Semgrep FAIL (express-sequelize-injection), commit bị hủy
git restore --staged --worktree routes/login.ts
```

#### Lộ khóa bí mật trong mã: commit bị chặn (Code · Gitleaks)
```powershell
Add-Content routes/login.ts 'export const awsKey = "AKIAZ7Q4M2K9LX3VBN8P"'
git add routes/login.ts
git commit -m "demo secret"               # -> Gitleaks FAIL (leaks found: 1), commit bị hủy
git restore --staged --worktree routes/login.ts
```

#### F01 — bỏ qua pre-commit (`--no-verify`): push bị chặn (Code · Semgrep)
```powershell
git restore --source 5658473cf -- routes/login.ts
git add routes/login.ts
git commit -m "demo F01" --no-verify
git push github fix/demo-ci               # -> pre-push: Semgrep FAIL, các pha sau SKIP, push bị hủy
git reset --soft HEAD~1
git restore --staged --worktree routes/login.ts
```

#### F02 — Poison Null Byte quay lại `fileServer.ts`: commit qua, push bị chặn (Test · node:test + Supertest)
```powershell
git restore --source 5658473cf -- routes/fileServer.ts
git add routes/fileServer.ts
git commit -m "demo F02"                  # -> PASS: Semgrep không thấy lỗi này
git push github fix/demo-ci               # -> pre-push: Code, Build PASS; Test FAIL (đọc được .bak: 200 thay vì 403), push bị hủy
git reset --soft HEAD~1
git restore --staged --worktree routes/fileServer.ts
```

#### F04 — Dockerfile bỏ `USER` (chạy root): commit bị chặn (Build · `docker_security.rego`)
```powershell
$p = (Resolve-Path deploy\Dockerfile.hotfix).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace '(?m)^USER 65532\r?$', ''))
git add deploy/Dockerfile.hotfix
git commit -m "demo F04"                  # -> LEAST-PRIVILEGE FAIL, commit bị hủy
git restore --staged --worktree deploy/Dockerfile.hotfix
```

#### F03 — Backend mở cổng ra host: commit bị chặn (Deploy · `compose.rego`)
```powershell
$p = (Resolve-Path docker-compose.yml).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace 'labels: \{lab\.exposure: internal\}.*', 'ports: ["0.0.0.0:3000:3000"]'))
git add docker-compose.yml
git commit -m "demo F03"                  # -> F03 NET-02 + NET-01 FAIL, commit bị hủy
git restore --staged --worktree docker-compose.yml
```

#### F03 — Proxy bỏ chặn `/metrics`: commit qua, push bị chặn (Operate · kiểm tra sau triển khai)
```powershell
$p = (Resolve-Path deploy\nginx.conf).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace '(?m)^.*location = /metrics \{ return 404; \}\r?\n', ''))
git add deploy/nginx.conf
git commit -m "demo F03 proxy"            # -> PASS: không luật tĩnh nào đọc nginx.conf
git push github fix/demo-ci               # -> pre-push: triển khai lên 3102, Operate FAIL (GET /metrics → 200), push bị hủy
git reset --soft HEAD~1
git restore --staged --worktree deploy/nginx.conf
docker compose restart proxy              # trả proxy về cấu hình đúng (/metrics → 404)
```

#### F04 — Container chạy root, bỏ `cap_drop`: commit qua, push bị chặn (Operate · `runtime.rego`)
```powershell
$p = (Resolve-Path docker-compose.yml).Path; [IO.File]::WriteAllText($p, ([IO.File]::ReadAllText($p) -replace 'user: "65532:0"\r?\n\s*cap_drop: \[ALL\]', 'user: "0:0"'))
git add docker-compose.yml
git commit -m "demo F04 root"             # -> PASS: compose.rego không chặn user/cap_drop
git push github fix/demo-ci               # -> pre-push: triển khai lên 3102, Operate FAIL (PRIV-02 root, PRIV-03 cap_drop), push bị hủy
git reset --soft HEAD~1
git restore --staged --worktree docker-compose.yml
docker compose up -d --wait               # trả container về 65532 + cap_drop ALL
```

#### Bản đã vá: push đi qua đủ 7 pha, GitHub Actions chạy tiếp
```powershell
Add-Content routes/fileServer.ts '// demo: thay doi vo hai'
git add routes/fileServer.ts
git commit -m "demo: sua vo hai"          # -> PASS
git push github fix/demo-ci               # -> pre-push: 21 PASS · 0 FAIL (tự bật Prometheus), push thành công -> Actions chạy nhánh fix/demo-ci
```

#### Bỏ qua cả hai hook (`--no-verify`): GitHub Actions vẫn chặn
```powershell
git restore --source 5658473cf -- routes/login.ts
git add routes/login.ts
git commit -m "demo: bypass hook" --no-verify
git push github fix/demo-ci --no-verify   # -> Actions đỏ ở step Code
```

#### Dọn và tự kiểm bản vá còn nguyên
```powershell
& "C:\Program Files\Git\bin\bash.exe" devsecops/demo-cleanup.sh -y   # về main, xóa fix/demo-ci (local + GitHub + Actions), triển khai lại 3102
node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit test/api/security/f01-f02.test.ts   # -> pass 11
```

# scanSAC — chạy tay các use-case F01–F04

PowerShell, tại gốc repo. `127.0.0.1:3100` = trước vá · `127.0.0.1:3102` = sau vá.

```powershell
cd E:\banhoaqua\juice-shop        # gốc repo (đổi nếu clone nơi khác)
docker start juice-report-lab
docker compose up -d --build
```

## F01 — SQL injection đăng nhập
```powershell
curl.exe -s -i -X POST http://127.0.0.1:3100/rest/user/login -H "Content-Type: application/json" --data-raw '{"email":"'' OR 1=1--","password":"wrong-password"}'   # trước vá: 200 + token
curl.exe -s -i -X POST http://127.0.0.1:3102/rest/user/login -H "Content-Type: application/json" --data-raw '{"email":"'' OR 1=1--","password":"wrong-password"}'   # sau vá: 401
curl.exe -s -i -X POST http://127.0.0.1:3102/rest/user/login -H "Content-Type: application/json" --data-raw '{"email":"jim@juice-sh.op","password":"ncc-1701"}'   # đối chứng: 200
```

## F02 — Poison Null Byte
```powershell
curl.exe -s -i "http://127.0.0.1:3100/ftp/package.json.bak%2500.md"      # trước vá: 200 + nội dung
curl.exe -s -i "http://127.0.0.1:3100/ftp/coupons_2013.md.bak%2500.md"   # trước vá: 200 + nội dung
curl.exe -s -i "http://127.0.0.1:3102/ftp/package.json.bak%2500.md"      # sau vá: 403
curl.exe -s -i "http://127.0.0.1:3102/ftp/legal.md"                      # đối chứng: 200
```

## F03 — lộ /metrics
```powershell
curl.exe -s http://127.0.0.1:3100/metrics | Select-Object -First 20                               # trước vá: 200, lộ
curl.exe -s -i http://127.0.0.1:3102/metrics                                                      # sau vá: 404
curl.exe -s -i http://127.0.0.1:3101/metrics                                                      # cổng backend cũ: refused
docker inspect juice-app-juice-shop-1 --format '{{json .HostConfig.PortBindings}}'                # backend không map cổng host
docker exec juice-app-proxy-1 wget -qO- http://juice-shop:3000/metrics | Select-Object -First 5   # giám sát nội bộ vẫn đọc được
```

## F04 — Policy as Code (Conftest, từng Dockerfile)
```powershell
$ROOT = "E:/banhoaqua/juice-shop"   # gốc repo (đổi nếu clone nơi khác)
$CF = @("run","--rm","-v","${ROOT}:/work:ro","-w","/work","openpolicyagent/conftest:v0.71.1")
docker @CF verify -p policy --no-color                                                                                 # 19/19
docker @CF test report/fixtures/Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile --no-color   # exit 1, chặn 4 nhóm
docker @CF test report/fixtures/Dockerfile.remediated --parser dockerfile -p policy --namespace dockerfile --no-color  # exit 0
docker @CF test Dockerfile --parser dockerfile -p policy --namespace dockerfile --no-color                             # exit 0, gốc distroless
docker @CF test deploy/Dockerfile.hotfix --parser dockerfile -p policy --namespace dockerfile --no-color               # exit 0
docker @CF test docker-compose.yml -p policy --namespace compose --no-color                                           # exit 0, F03
```

## Cổng quét (tùy chọn)
```powershell
$ROOT = "E:/banhoaqua/juice-shop"   # gốc repo (đổi nếu clone nơi khác)
docker run --rm -e SEMGREP_SEND_METRICS=off -v "${ROOT}:/src:ro" -v "${ROOT}/report/semgrep-rules:/rules:ro" semgrep/semgrep:1.180.0 semgrep scan --metrics=off --quiet --config /rules/owasp-top-ten.yml --config /rules/nodejsscan.yml /src/routes/login.ts /src/routes/fileServer.ts
docker run --rm -v "${ROOT}:/repo:ro" zricethezav/gitleaks:v8.30.1 git /repo --log-opts="baf9dcea4..HEAD" --no-banner
trivy image --scanners vuln juice-shop:hotfix-f01-f02
dockle juice-shop:hotfix-f01-f02
```

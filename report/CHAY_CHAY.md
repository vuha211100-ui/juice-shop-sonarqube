# Chạy chay — demo F01–F04 bằng lệnh thô (không qua script `.py`)

Dùng khi bảo vệ: **gõ từng lệnh rồi giải thích**, thay vì chạy `report/demos/tv*.py`.
Riêng **F04 chạy Conftest từng Dockerfile một** (không gộp "chạy thẳng hết policy" như `tv4_f04_policy.py`).

- Shell: **PowerShell**, đứng ở **thư mục gốc repo**. `curl.exe` có sẵn trên Windows 11.
- `127.0.0.1:3100` = **trước vá** (image gốc, container `juice-report-lab`).
- `127.0.0.1:3102` = **sau vá** (reverse proxy, project `juice-app`; backend ở mạng internal).
- Trong chuỗi single-quote của PowerShell, `''` nghĩa là **một** dấu nháy đơn.

## 0. Khởi động hai môi trường
```powershell
docker start juice-report-lab        # trước vá (3100) — lần đầu dựng container: xem report/DEMO.md mục 1
docker compose up -d --build         # sau vá (3102) — project 'juice-app'
docker compose ps
$ROOT = (Get-Location).Path -replace '\\','/'   # đường dẫn posix để mount vào container
```

## 1. F01 — SQL injection đăng nhập (`POST /rest/user/login`)
Payload SQL + mật khẩu **sai**. Trước vá vẫn được cấp `token` (lỗ hổng); sau vá `401`.
```powershell
# TRƯỚC VÁ (3100): payload -> 200 và body có "token"  => LỖ HỔNG (vượt xác thực)
curl.exe -s -i -X POST http://127.0.0.1:3100/rest/user/login -H "Content-Type: application/json" --data-raw '{"email":"'' OR 1=1--","password":"wrong-password"}'

# SAU VÁ (3102): cùng payload -> 401
curl.exe -s -i -X POST http://127.0.0.1:3102/rest/user/login -H "Content-Type: application/json" --data-raw '{"email":"'' OR 1=1--","password":"wrong-password"}'

# ĐỐI CHỨNG: đăng nhập ĐÚNG vẫn 200 (vá không làm hỏng chức năng)
curl.exe -s -i -X POST http://127.0.0.1:3102/rest/user/login -H "Content-Type: application/json" --data-raw '{"email":"jim@juice-sh.op","password":"ncc-1701"}'
```
Payload khác để thử: `admin@juice-sh.op''--` · `'' UNION SELECT * FROM Users--`.
**Nói:** email bị ghép thẳng vào câu SQL ở `routes/login.ts`; vá = **truy vấn tham số** (`$email`/`$password`).

## 2. F02 — Poison Null Byte (`GET /ftp/:file`)
`%2500` = `%00` mã-hai-lần; nó cắt tên tệp **sau khi** đã qua kiểm tra đuôi `.md`.
```powershell
# TRƯỚC VÁ (3100): đọc được tệp sao lưu (200 + nội dung)  => LỖ HỔNG
curl.exe -s -i "http://127.0.0.1:3100/ftp/package.json.bak%2500.md"
curl.exe -s -i "http://127.0.0.1:3100/ftp/coupons_2013.md.bak%2500.md"

# SAU VÁ (3102): bị chặn -> 403
curl.exe -s -i "http://127.0.0.1:3102/ftp/package.json.bak%2500.md"

# ĐỐI CHỨNG: tệp .md hợp lệ vẫn tải bình thường (200)
curl.exe -s -i "http://127.0.0.1:3102/ftp/legal.md"
```
**Nói:** lỗi ở **thứ tự xử lý** tại `routes/fileServer.ts` (kiểm một tên, phục vụ tên khác); vá = **từ chối null byte trước** khi kiểm tra/phục vụ.

## 3. F03 — lộ endpoint `/metrics`
```powershell
# TRƯỚC VÁ (3100): 200, hàng trăm dòng số liệu  => LỘ
curl.exe -s http://127.0.0.1:3100/metrics | Select-Object -First 20

# SAU VÁ (3102): proxy trả 404
curl.exe -s -i http://127.0.0.1:3102/metrics

# Trang chủ vẫn hoạt động (200)
curl.exe -s -i http://127.0.0.1:3102/

# Cổng backend cũ 3101: không kết nối được (hết đường vòng)
curl.exe -s -i http://127.0.0.1:3101/metrics

# Backend KHÔNG map cổng host (kết quả rỗng/null):
docker inspect juice-app-juice-shop-1 --format '{{json .HostConfig.PortBindings}}'

# Giám sát NỘI BỘ vẫn đọc được /metrics qua mạng internal (đúng mục đích):
docker exec juice-app-proxy-1 wget -qO- http://juice-shop:3000/metrics | Select-Object -First 5
```
**Nói:** `/metrics` **không bị xóa**, chỉ chặn lối vào từ ngoài; policy `compose.rego` (NET-02) chặn mọi cấu hình để backend publish cổng host.

## 4. F04 — Policy as Code: chạy Conftest **từng Dockerfile một**
Đây là phần "không chạy thẳng hết policy": định nghĩa prefix một lần, rồi chạy **riêng từng file** để đọc exit code từng cái.
```powershell
$CF = @("run","--rm","-v","${ROOT}:/work:ro","-w","/work","openpolicyagent/conftest:v0.71.1")

# (a) Unit test TOÀN BỘ bộ luật Rego -> "19 tests, 19 passed"
docker @CF verify -p policy --no-color

# (b) fixture cố ý lỗi -> FAIL, chặn bởi 4 nhóm luật
docker @CF test Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile --no-color
$LASTEXITCODE        # kỳ vọng = 1 (gate chặn)

# (c) bản vá -> PASS
docker @CF test report/fixtures/Dockerfile.remediated --parser dockerfile -p policy --namespace dockerfile --no-color
$LASTEXITCODE        # kỳ vọng = 0

# (d) Dockerfile GỐC Juice Shop (distroless) -> PASS (luật KHÔNG báo nhầm)
docker @CF test Dockerfile --parser dockerfile -p policy --namespace dockerfile --no-color
$LASTEXITCODE        # kỳ vọng = 0

# (e) image hotfix F01/F02 -> PASS
docker @CF test deploy/Dockerfile.hotfix --parser dockerfile -p policy --namespace dockerfile --no-color
$LASTEXITCODE        # kỳ vọng = 0

# (f) policy cho docker-compose (F03) -> PASS
docker @CF test docker-compose.yml -p policy --namespace compose --no-color
$LASTEXITCODE        # kỳ vọng = 0
```
**Nói:** fixture xấu bị chặn **4 nhóm** (LEAST-PRIVILEGE / ATTACK-SURFACE / SUPPLY-CHAIN / SECRET-IN-IMAGE); **bản vá và Dockerfile gốc đều đạt** → luật đúng, không báo nhầm.

## 5. (tùy chọn) Các cổng quét — chạy riêng
```powershell
# SAST (Semgrep) -> chỉ đúng dòng F01 (login.ts) và F02 (fileServer.ts)
docker run --rm -e SEMGREP_SEND_METRICS=off -v "${ROOT}:/src:ro" -v "${ROOT}/report/semgrep-rules:/rules:ro" `
  semgrep/semgrep:1.180.0 semgrep scan --metrics=off --quiet `
  --config /rules/owasp-top-ten.yml --config /rules/nodejsscan.yml /src/routes/login.ts /src/routes/fileServer.ts

# Quét secret (Gitleaks) trên các commit vá -> không có secret
docker run --rm -v "${ROOT}:/repo:ro" zricethezav/gitleaks:v8.30.1 git /repo --log-opts="baf9dcea4..HEAD" --no-banner

# CVE/SCA (Trivy) và CIS image (Dockle) — yêu cầu tool trên PATH:
trivy image --scanners vuln juice-shop:hotfix-f01-f02
dockle juice-shop:hotfix-f01-f02

# (Operate) Compliance as Code: docker inspect -> đưa JSON vào Conftest runtime
docker inspect juice-app-juice-shop-1

# (Operate) Giám sát: Prometheus target scrape /metrics (UP) + trạng thái cảnh báo
curl.exe -s http://127.0.0.1:9090/api/v1/targets
curl.exe -s http://127.0.0.1:9090/api/v1/alerts
```

> Bản tự động tương ứng: `report/demos/tv1_f01_sqli.py` … `tv4_f04_policy.py` (xem `report/HUONG_DAN_DEMO.md`). File này chỉ để **chạy tay** khi bảo vệ.

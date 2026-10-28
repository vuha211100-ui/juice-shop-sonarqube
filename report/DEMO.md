# DEMO — Khởi động và chạy toàn bộ demo (F01–F04)

Runbook cho báo cáo `report/BaoCao_DevSecOps_JuiceShop_gon.pdf`.
Mỗi demo chạy **cùng một kịch bản trên hai môi trường** và in bảng *trước vá → sau vá*.

- **Trước vá** — container đối chứng `juice-report-lab`, image gốc, truy cập thẳng: `http://127.0.0.1:3100`
- **Sau vá** — bản triển khai trong repo: reverse proxy Nginx → backend hotfix (mạng internal): `http://127.0.0.1:3102`

> Clone repo này (nhánh mặc định `main` đã là bản báo cáo lần này — không cần checkout gì), rồi chạy **mọi lệnh tại thư mục gốc của repo** (PowerShell, Docker Desktop đang chạy). Thư mục gốc repo chính là mã nguồn Juice Shop; báo cáo + demo nằm trong `report/`.

---

## 0. Yêu cầu

> **Máy mới hoàn toàn?** Cài Git / Docker Desktop (WSL2) / Node ≥20 / Python ≥3.12 từ số 0 theo
> **`README.md` mục 2** trước, rồi quay lại đây.

| Thành phần | Dùng để |
|---|---|
| Docker Desktop (WSL2) | chạy container, Conftest, Semgrep, Gitleaks |
| Python 3.12+ | chạy 4 script demo (`report/demos`) |
| Node.js 20+ | build image hotfix và chạy kiểm thử bảo mật |

Image lấy từ Docker Hub (demo tự pull): `bkimminich/juice-shop:v20.2.0`, `nginx:1.28-alpine`,
`openpolicyagent/conftest:v0.71.1`, `semgrep/semgrep:1.180.0`, `zricethezav/gitleaks:v8.30.1`.

---

## 1. Khởi động môi trường

```powershell
# Nhánh mặc định 'main' đã là báo cáo lần này (clone xong là ở main).

# Lần đầu: build server để dựng image hotfix, tạo volume log
npm ci
npm run build:server
docker volume create juice-report-accesslogs

# Môi trường TRƯỚC vá (container đối chứng, 127.0.0.1:3100)
docker run -d --name juice-report-lab -p 127.0.0.1:3100:3000 `
  --cap-drop ALL --security-opt no-new-privileges:true bkimminich/juice-shop:v20.2.0
#   các lần sau chỉ cần:  docker start juice-report-lab

# Môi trường SAU vá (proxy 127.0.0.1:3102 + backend internal); project name cố định 'juice-app'
docker compose up -d --build

# Kiểm tra
docker compose ps
docker ps --filter name=juice-report-lab --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

> `docker-compose.yml` đặt `name: juice-app` nên container luôn là `juice-app-proxy-1` và
> `juice-app-juice-shop-1` — các script demo dựa vào đúng hai tên này.

---

## 2. Chạy TẤT CẢ demo (một lệnh)

```powershell
foreach ($d in 'tv1_f01_sqli','tv2_f02_sqli','tv3_f03_metrics','tv4_f04_policy') {
  Write-Host "`n===== $d =====" -ForegroundColor Cyan
  python report/demos/$d.py
}
```

Hoặc chạy từng demo theo bảng dưới.

---

## 3. Bốn demo (đúng các lệnh trong ảnh báo cáo)

| Lỗi (thành viên) | Lệnh demo | Kết quả mong đợi | Nơi vá |
|---|---|---|---|
| **F01 — SQL injection** (Nguyễn Toàn Thắng) | `python report/demos/tv1_f01_sqli.py` | trước vá: payload được cấp token; sau vá: 401 | `routes/login.ts` |
| **F02 — SQL injection ở tìm kiếm** (Phạm Thị Minh Thúy) | `python report/demos/tv2_f02_sqli.py` | trước vá: payload UNION lộ email+hash toàn bộ Users; sau vá: 0 dòng dữ liệu người dùng | `routes/search.ts` |
| **F03 — endpoint /metrics** (Đỗ Đức Quốc Anh) | `python report/demos/tv3_f03_metrics.py` | 3100/metrics lộ; 3102/metrics → 404; cổng 3101 refused; giám sát nội bộ vẫn đọc được | `docker-compose.yml`, `deploy/nginx.conf` |
| **F04 — sai cấu hình container / Policy as Code** (Hồ Anh Vũ) | `python report/demos/tv4_f04_policy.py` | Dockerfile.vulnerable bị chặn 4 nhóm luật; bản vá, hotfix và **Dockerfile gốc đều đạt chính sách** | `policy/docker_security.rego` |

---

## 4. Các cổng kiểm soát (Security as Code & Policy as Code)

### 4.1. SAST — Semgrep (phát hiện F01/F02)

```powershell
docker run --rm -e SEMGREP_SEND_METRICS=off `
  -v "${PWD}:/src:ro" -v "${PWD}/report/semgrep-rules:/rules:ro" `
  semgrep/semgrep:1.180.0 semgrep scan --metrics=off --quiet `
  --config /rules/owasp-top-ten.yml --config /rules/nodejsscan.yml `
  /src/routes/login.ts /src/routes/basket.ts
```

### 4.2. Kiểm thử bảo mật — node:test (đỏ trước vá → xanh sau vá)

```powershell
# Lấy tạm route CHƯA vá -> kỳ vọng một số ca ĐỎ
git checkout 21219d66d -- routes
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts

# Trả lại bản vá (routes của nhánh hiện tại) -> kỳ vọng toàn bộ XANH
git checkout HEAD -- routes
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
```

### 4.3. Quét secret — Gitleaks

```powershell
docker run --rm -v "${PWD}:/repo:ro" `
  zricethezav/gitleaks:v8.30.1 git /repo --log-opts="baf9dcea4..HEAD" --no-banner
```

> `baf9dcea4` là commit gốc trước khi nhóm vá (14 commit F01–F04 nằm sau nó). Dùng khoảng cố định
> này thay cho `main..fix/f01-f04` vì sau khi gộp báo cáo, `main` và `fix/f01-f04` trỏ cùng một commit
> nên khoảng đó rỗng — Gitleaks sẽ không quét commit nào.

### 4.4. Policy as Code — Conftest/OPA (build time)

```powershell
$CF = 'docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1'

# Unit test toàn bộ policy (Dockerfile F04 + compose F03) -> 17/17
Invoke-Expression "$CF verify -p policy --no-color"

# F04 — chính sách Dockerfile: bản lỗi bị chặn, bản vá và Dockerfile gốc đạt
Invoke-Expression "$CF test Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile --no-color"
Invoke-Expression "$CF test report/fixtures/Dockerfile.remediated --parser dockerfile -p policy --namespace dockerfile --no-color"
Invoke-Expression "$CF test Dockerfile --parser dockerfile -p policy --namespace dockerfile --no-color"

# F03 — chính sách compose: chỉ dịch vụ 'edge' được publish cổng
Invoke-Expression "$CF test report/fixtures/compose.before-f03.yml docker-compose.yml -p policy --namespace compose --no-color"
```

### 4.5. Policy as Code — kiểm tra container ĐANG CHẠY (runtime)

```powershell
$CF = 'docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1'
New-Item -ItemType Directory -Force report/evidence | Out-Null
docker inspect juice-app-juice-shop-1 > report/evidence/inspect-after.json
docker inspect juice-report-lab       > report/evidence/inspect-before.json
Invoke-Expression "$CF test report/evidence/inspect-after.json  -p report/policy --namespace runtime --no-color"
Invoke-Expression "$CF test report/evidence/inspect-before.json -p report/policy --namespace runtime --no-color"

# Bảng hardening tổng hợp (ảnh hardening.png trong báo cáo)
python report/checks/hardening.py
```

---

## 5. Dừng / dọn môi trường

```powershell
docker compose down               # dừng bản sau vá (giữ volume log)
docker stop juice-report-lab      # dừng container đối chứng
```

> Báo cáo PDF đã kèm sẵn (`report/BaoCao_DevSecOps_JuiceShop_gon.pdf`); nguồn Markdown ở
> `report/report_concise.md`. Ảnh minh chứng ở `report/screenshots/`.

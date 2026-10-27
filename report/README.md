# Báo cáo DevSecOps — OWASP Juice Shop (nhóm)

Học phần **DevOps và DevSecOps (SEC4349)** — Học viện Công nghệ Bưu chính Viễn thông, Khoa An toàn thông tin.
Đánh giá an toàn / bảo vệ dữ liệu người dùng trên **OWASP Juice Shop v20.2.0**, xử lý **4 lỗi** theo mạch *trước khi sửa → sau khi sửa*.

> **Đọc file này trước.** Toàn bộ mã vá nằm ở **gốc repo** (nhánh mặc định `main`); báo cáo + script demo nằm trong thư mục `report/`.
> Mỗi demo chạy cùng một kịch bản trên **hai môi trường** và in bảng *trước vá → sau vá*.

---

## 1. Thành viên & phân công

| Thành viên | Lỗi phụ trách | Vá / kiểm tra tại |
|---|---|---|
| Nguyễn Toàn Thắng — B26CHAT039 | **F01** SQL injection khi đăng nhập | `routes/login.ts` |
| Phạm Thị Minh Thúy — B26CHAT042 | **F02** IDOR khi đọc giỏ hàng | `routes/basket.ts` |
| Đỗ Đức Quốc Anh — B26CHAT001 | **F03** lộ endpoint `/metrics` không xác thực | `docker-compose.yml`, `deploy/nginx.conf`, `policy/compose.rego` |
| Hồ Anh Vũ — B26CHAT048 | **F04** sai cấu hình container (Policy as Code) | `policy/docker_security.rego` |

---

## 2. Chuẩn bị (cài một lần)

| Công cụ | Dùng để | Ghi chú |
|---|---|---|
| **Docker Desktop** (WSL2) | chạy container + Conftest/Semgrep/Gitleaks | phải đang chạy trước khi demo |
| **Python 3.12+** | chạy 4 script demo | `python --version` để kiểm tra |
| **Node.js 20+** | build image hotfix + chạy kiểm thử bảo mật | |

Các image Docker sẽ **tự tải** khi chạy: `bkimminich/juice-shop:v20.2.0`, `nginx:1.28-alpine`,
`openpolicyagent/conftest:v0.71.1`, `semgrep/semgrep:1.180.0`, `zricethezav/gitleaks:v8.30.1`.

---

## 3. Cách chạy (từng bước)

Mở **PowerShell**, Docker Desktop đang chạy. Chạy mọi lệnh tại **thư mục gốc repo**.

### 3.1. Lấy mã nguồn

```powershell
git clone https://github.com/vuha211100-ui/juice-shop-sonarqube
cd juice-shop-sonarqube
# Nhánh mặc định 'main' đã là báo cáo lần này — clone xong là chạy được, không cần checkout gì thêm.
```

### 3.2. Lần đầu: build server + tạo volume log

```powershell
npm ci
npm run build:server
docker volume create juice-report-accesslogs
```

### 3.3. Khởi động hai môi trường

```powershell
# TRƯỚC vá — container đối chứng, image gốc (127.0.0.1:3100)
docker run -d --name juice-report-lab -p 127.0.0.1:3100:3000 `
  --cap-drop ALL --security-opt no-new-privileges:true bkimminich/juice-shop:v20.2.0
#   các lần sau chỉ cần:  docker start juice-report-lab

# SAU vá — reverse proxy + backend internal (127.0.0.1:3102); project cố định 'juice-app'
docker compose up -d --build

docker compose ps        # kiểm tra proxy + juice-shop đã chạy
```

### 3.4. Chạy cả 4 demo (một lệnh)

```powershell
foreach ($d in 'tv1_f01_sqli','tv2_f02_idor','tv3_f03_metrics','tv4_f04_policy') {
  Write-Host "`n===== $d =====" -ForegroundColor Cyan
  python report/demos/$d.py
}
```

Hoặc chạy từng cái: `python report/demos/tv1_f01_sqli.py` …

### 3.5. Kết quả mong đợi

| Demo | Trước vá | Sau vá |
|---|---|---|
| **tv1 — F01 SQLi** | payload `' OR 1=1--` được cấp token quản trị | mọi payload bị **401** |
| **tv2 — F02 IDOR** | tài khoản A đọc được giỏ của B | A đọc giỏ B nhận **404**, giỏ mình vẫn 200 |
| **tv3 — F03 /metrics** | `3100/metrics` → **200**, lộ số liệu | `3102/metrics` → **404**, cổng `3101` **refused**; giám sát nội bộ vẫn đọc được |
| **tv4 — F04 policy** | `Dockerfile.vulnerable` bị chặn **4 nhóm luật** | bản vá, hotfix và **Dockerfile gốc đều đạt chính sách**; `conftest verify` = **17/17** |

---

## 4. Các cổng kiểm soát (Security as Code / Policy as Code)

Lệnh chi tiết cho từng cổng (Semgrep SAST, Gitleaks, node:test đỏ→xanh, Conftest build-time & runtime) ở **`report/DEMO.md` mục 4**. Tóm tắt:

- **SAST (Semgrep)** chỉ ra dòng lỗi F01/F02.
- **node:test** chạy app thật: đỏ trước vá → xanh sau vá.
- **Policy as Code (Conftest/OPA)**: luật Rego chặn Dockerfile/compose sai cấu hình (`conftest verify -p policy` → 17/17).
- **Chặn phát hành** chỉ ở luật `deny` (mức FAIL); luật `warn` chỉ cảnh báo.

---

## 5. Tài liệu & bản đồ thư mục `report/`

| Đường dẫn | Mô tả |
|---|---|
| `README.md` | **File này** — tổng quan + cách chạy |
| `DEMO.md` | Runbook đầy đủ: khởi động + chạy mọi demo + từng cổng kiểm soát |
| `HUONG_DAN_DEMO.md` | Bản tóm tắt nhanh theo từng lỗi |
| `PHAN_NOI.md` | Kịch bản thuyết trình + 12 câu hỏi phản biện |
| `BaoCao_...gon.pdf` / `report_concise.md` | Báo cáo (PDF, 18 trang) và nguồn Markdown |
| `demos/` | 4 script demo `tv1`–`tv4` + `common.py` |
| `checks/hardening.py` | Bảng cấu hình an toàn container đang chạy (ảnh `hardening.png`) |
| `policy/` | Luật Rego kiểm tra container **runtime** (`docker inspect`) |
| `semgrep-rules/` | Luật Semgrep cho SAST (F01/F02) |
| `fixtures/` | Dockerfile/compose mẫu để đối chứng policy |
| `screenshots/` | Ảnh minh chứng trong báo cáo |

> Chính sách **build-time** (Dockerfile F04 + compose F03) ở `policy/` tại **gốc repo**; `report/policy/` chỉ chứa luật **runtime**.

---

## 6. Dừng / dọn môi trường

```powershell
docker compose down               # dừng bản sau vá (giữ volume log)
docker stop juice-report-lab      # dừng container đối chứng
```

---

## 7. Khắc phục sự cố

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| Lệnh docker báo *"daemon … not running"* | Mở **Docker Desktop**, đợi biểu tượng xanh rồi chạy lại. |
| Demo báo không thấy container | Tên phải là `juice-app-proxy-1` / `juice-app-juice-shop-1` — do `docker-compose.yml` đặt `name: juice-app`. Đừng đổi tên project. |
| `tv1/tv2/tv3` không có cột *trước vá* | Chưa chạy container đối chứng — xem **3.3** (`docker run --name juice-report-lab …`). |
| Cổng `3101` báo **refused** | **Đúng thiết kế** (F03): backend không mở cổng host, chỉ tới được qua proxy. |
| `docker compose up` lỗi thiếu `build/` | Chưa `npm run build:server` — xem **3.2**. |
| `python` không chạy | Cài Python 3.12+ và thêm vào PATH. |

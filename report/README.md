# Báo cáo DevSecOps — OWASP Juice Shop (nhóm)

Học phần **DevOps và DevSecOps (SEC4349)** — Học viện Công nghệ Bưu chính Viễn thông, Khoa An toàn thông tin.
Đánh giá an toàn / bảo vệ dữ liệu người dùng trên **OWASP Juice Shop v20.2.0**, xử lý **4 lỗi** theo mạch *trước khi sửa → sau khi sửa*.

> **Đọc file này trước.** Hướng dẫn chạy **từ số 0 trên một máy Windows 11 hoàn toàn mới**.
> Mã vá nằm ở **gốc repo** (nhánh mặc định `main`); báo cáo + script demo nằm trong thư mục `report/`.
> Mỗi demo chạy cùng một kịch bản trên **hai môi trường** và in bảng *trước vá → sau vá*.

---

## ⚡ Khởi động nhanh (máy đã cài sẵn & đã có repo)

Đã từng cài Docker/Node/Python và chạy `npm ci` + `npm run build:server` **một lần** rồi →
**bỏ qua mục 2–4**. Tại **gốc repo**, Docker Desktop đang xanh:

```powershell
# 1) TRƯỚC vá (127.0.0.1:3100) — tạo container đối chứng
docker run -d --name juice-report-lab -p 127.0.0.1:3100:3000 `
  --cap-drop ALL --security-opt no-new-privileges:true bkimminich/juice-shop:v20.2.0
#    Nếu container đã tồn tại (chỉ bị dừng): docker start juice-report-lab

# 2) SAU vá (127.0.0.1:3102) — proxy + backend internal
docker compose up -d --build

# 3) Kiểm tra (đợi backend 'healthy' ~30–60s rồi mới chạy tv2/tv3)
docker compose ps
```

Rồi chạy 4 demo:

```powershell
foreach ($d in 'tv1_f01_sqli','tv2_f02_pathtraversal','tv3_f03_metrics','tv4_f04_policy') {
  Write-Host "`n===== $d =====" -ForegroundColor Cyan
  python report/demos/$d.py
}
```

Dừng khi xong: `docker compose down` và `docker stop juice-report-lab`.

> **Máy mới hoàn toàn** (chưa cài Docker/Node/Python) → đọc tiếp từ **mục 2**.
> Quên đã cài `build/` chưa? Chạy `docker compose up -d --build`, nếu báo thiếu `build/` thì làm **mục 4** một lần.

---

## 1. Thành viên & phân công

| Thành viên | Lỗi phụ trách | Phần việc chính (công cụ) |
|---|---|---|
| Nguyễn Toàn Thắng — B26CHAT039 | **F01** SQL injection khi đăng nhập | Vá `routes/login.ts`; SAST **Semgrep**; kiểm thử bảo mật **node:test + Supertest**; cổng Semgrep chỉ chặn cảnh báo mới |
| Phạm Thị Minh Thúy — B26CHAT042 | **F02** Poison Null Byte (lộ tệp sao lưu) | Vá `routes/fileServer.ts`; quét secret **Gitleaks**; SCA **Trivy** + `devsecops/.trivyignore` |
| Đỗ Đức Quốc Anh — B26CHAT001 | **F03** lộ endpoint `/metrics` không xác thực | **Docker Compose**, **Nginx**, `compose.rego`, `hardening.py` (**docker inspect**), **Prometheus + Grafana**, **GitHub Actions** |
| Hồ Anh Vũ — B26CHAT048 | **F04** sai cấu hình container (Policy as Code) | **Conftest** `docker_security.rego`, `Dockerfile.hotfix`, **Dockle**, `runtime.rego`, `pipeline.sh` + **Git hook**, dựng báo cáo |

Phân công chi tiết từng tệp: `report/TONG_KET_PHAN_CONG.md` mục 3–4.

---

## 2. Cài đặt trên máy mới hoàn toàn (Windows 11)

Cần **4 phần mềm**: Git, Docker Desktop (nền WSL2), Node.js ≥20, Python ≥3.12.
Windows 11 có sẵn `winget`. Mở **PowerShell quyền Administrator** (Start → gõ *PowerShell* → **Run as administrator**).

### 2.1. Bật ảo hoá + WSL2 (Docker cần)

```powershell
wsl --install
```

- Cài WSL2 + Ubuntu. **Khởi động lại máy** sau khi xong rồi làm tiếp.
- Nếu báo lỗi ảo hoá: vào **BIOS/UEFI** bật **Virtualization (Intel VT‑x / AMD‑V)**.

### 2.2. Cài 4 công cụ

```powershell
winget install -e --id Git.Git
winget install -e --id Docker.DockerDesktop
winget install -e --id OpenJS.NodeJS.LTS      # Node LTS (≥20)
winget install -e --id Python.Python.3.12
```

> Không có `winget`? Cập nhật **App Installer** trong Microsoft Store, hoặc tải tay:
> Git — git-scm.com · Docker — docker.com/products/docker-desktop ·
> Node — nodejs.org (bản **LTS**) · Python — python.org (**≥3.12**, nhớ tick *Add python.exe to PATH*).

### 2.3. Khởi động Docker Desktop

- Mở **Docker Desktop**, chấp nhận điều khoản, đợi biểu tượng cá voi chuyển **xanh** (*Engine running*).
- Settings → General: bật **Use the WSL 2 based engine**.

### 2.4. Kiểm tra (mở một cửa sổ PowerShell **MỚI** để PATH cập nhật)

```powershell
git --version          # hiện bất kỳ phiên bản
docker version         # phải thấy phần "Server" -> Docker đang chạy
docker run --rm hello-world
node --version         # v20 trở lên
npm --version
python --version       # 3.12 trở lên
```

Chạy trơn cả 6 lệnh là xong phần cài đặt.

> **macOS / Linux** cũng chạy được: cần Docker, Node ≥20, Python ≥3.12; thay PowerShell bằng terminal tương ứng
> và đổi ký tự nối dòng `` ` `` thành `\`.

---

## 3. Lấy mã nguồn

```powershell
cd $HOME\Desktop                 # hoặc thư mục bất kỳ
git clone https://github.com/vuha211100-ui/juice-shop-sonarqube
cd juice-shop-sonarqube
# Nhánh mặc định 'main' đã là báo cáo lần này — clone xong là chạy được, không cần checkout gì thêm.
```

**Từ đây chạy mọi lệnh tại thư mục gốc repo** (`juice-shop-sonarqube`), Docker Desktop đang xanh.

---

## 4. Lần đầu: build server + tạo volume log

```powershell
npm ci                 # cài phụ thuộc (vài phút, tải vài trăm MB)
npm run build:server   # biên dịch server -> build/ (dùng để dựng image hotfix F01/F02)
docker volume create juice-report-accesslogs
docker run --rm --user 0 --entrypoint chown -v juice-report-accesslogs:/logs nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236 101:101 /logs   # proxy chạy UID 101 phải ghi được log
```

---

## 5. Khởi động hai môi trường

```powershell
# TRƯỚC vá — container đối chứng, image gốc (127.0.0.1:3100)
docker run -d --name juice-report-lab -p 127.0.0.1:3100:3000 `
  --cap-drop ALL --security-opt no-new-privileges:true bkimminich/juice-shop:v20.2.0
#   các lần sau chỉ cần:  docker start juice-report-lab

# SAU vá — reverse proxy + backend internal (127.0.0.1:3102); project cố định 'juice-app'
docker compose up -d --build

docker compose ps        # kiểm tra proxy + juice-shop đã chạy
```

Lần đầu Docker **tự tải** các image: `bkimminich/juice-shop:v20.2.0`, `nginx` (ghim digest),
`openpolicyagent/conftest:v0.71.1`, `semgrep/semgrep:1.180.0`, `zricethezav/gitleaks:v8.30.1` (mất vài phút).
Khi chạy tới các bước sau, Docker tải thêm `aquasec/trivy:0.76.1`, `goodwithtech/dockle:v0.4.15`, `prom/prometheus`, `grafana/grafana`.

---

## 6. Chạy cả 4 demo (một lệnh)

```powershell
foreach ($d in 'tv1_f01_sqli','tv2_f02_pathtraversal','tv3_f03_metrics','tv4_f04_policy') {
  Write-Host "`n===== $d =====" -ForegroundColor Cyan
  python report/demos/$d.py
}
```

Hoặc chạy từng cái: `python report/demos/tv1_f01_sqli.py` …

---

## 7. Kết quả mong đợi

| Demo | Trước vá | Sau vá |
|---|---|---|
| **tv1 — F01 SQLi** | payload `' OR 1=1--` được cấp token quản trị | mọi payload bị **401** |
| **tv2 — F02 Poison Null Byte** | đọc được `package.json.bak`, `coupons_2013.md.bak` | payload null byte nhận **403**, tệp `.md` hợp lệ vẫn tải |
| **tv3 — F03 /metrics** | `3100/metrics` → **200**, lộ số liệu | `3102/metrics` → **404**, cổng `3101` **refused**; giám sát nội bộ vẫn đọc được; Conftest `compose.rego`: compose trước vá **exit 1** (`F03 NET-02`), `docker-compose.yml` **exit 0** |
| **tv4 — F04 policy** | `Dockerfile.vulnerable` bị chặn **4 nhóm luật** (6 vi phạm) | bản vá, hotfix và **Dockerfile gốc đều đạt chính sách**; `conftest verify` = **19/19** |

---

## 8. Các cổng kiểm soát (Security as Code / Policy as Code)

Lệnh chạy riêng từng công cụ ở **`report/scanSAC.md`** (theo pha) và `report/DEMO.md` mục 4. Tóm tắt các cổng:

| Pha | Công cụ | Kiểm gì |
|---|---|---|
| Code | **Gitleaks** v8.30.1 | Secret trong dòng được thêm |
| Code | **Semgrep** 1.180.0 | SAST — chỉ ra dòng lỗi F01/F02; trong pipeline chỉ chặn cảnh báo **mới** (`devsecops/semgrep-diff.mjs`) |
| Build | **Conftest** v0.71.1 + `docker_security.rego` | Dockerfile sai cấu hình (F04); `conftest verify -p policy -p report/policy` → **26/26** |
| Test | **node:test + Supertest** | Chạy app thật: đỏ trước vá → xanh sau vá (11 ca) |
| Release | **Trivy** 0.76.1 | CVE dependency của image; chỉ chặn CRITICAL không có trong `devsecops/.trivyignore` |
| Release | **Dockle** 0.4.15 | Image thành phẩm theo CIS (secret trong layer, chạy root) |
| Deploy | **Conftest** + `compose.rego` | Compose sai: backend mở cổng host (F03), privileged, `docker.sock`… |
| Operate | **Conftest** + `report/policy/runtime.rego`, `checks/hardening.py` | Container **đang chạy** (`docker inspect`): non-root, `cap_drop`, giới hạn CPU/PID, cổng host |
| Monitor | **Prometheus** + **Grafana** | Scrape `/metrics` nội bộ, cảnh báo `HighClientErrorRate`; dashboard `http://127.0.0.1:3103` |

**Chặn phát hành** chỉ ở luật `deny` (mức FAIL); luật `warn` chỉ cảnh báo.

**Chạy tự động theo Git** (cần Git Bash, một lần sau khi clone):

```powershell
& "C:\Program Files\Git\bin\bash.exe" devsecops/install-hooks.sh   # bật hook: core.hooksPath = .githooks
```

- `git commit` → hook **pre-commit**: Gitleaks, Semgrep, Conftest Dockerfile + compose (vài giây).
- `git push` → hook **pre-push**: đủ 7 pha của `devsecops/pipeline.sh`, triển khai lên 3102 rồi kiểm Operate/Monitor (khoảng 2 phút).
- Push lên GitHub / pull request vào `main` → **GitHub Actions** `.github/workflows/devsecops.yml` chạy lại đủ 7 pha.
- Kịch bản thử 4 lỗi qua `git commit`/`git push`: `report/scanSAC.md` mục *Integration*; chi tiết pipeline: `devsecops/README.md`.

---

## 9. Tài liệu & bản đồ thư mục `report/`

| Đường dẫn | Mô tả |
|---|---|
| `README.md` | **File này** — cài máy mới + cách chạy |
| `DEMO.md` | Runbook đầy đủ: khởi động + chạy mọi demo + từng cổng kiểm soát |
| `HUONG_DAN_DEMO.md` | Bản tóm tắt nhanh theo từng lỗi |
| `PHAN_THUYET_TRINH.md` | Kịch bản thuyết trình phần chung + 4 lỗi, câu hỏi phản biện |
| `TONG_KET_PHAN_CONG.md` | So với Juice Shop gốc, phân công từng tệp, cách chạy, giới hạn còn lại |
| `scanSAC.md` | Lệnh từng công cụ theo pha + kịch bản kiểm thử tích hợp qua `git commit`/`git push` |
| `F04_THUYET_TRINH.md` | Tài liệu sâu về bộ luật Rego, mapping luật → chuẩn |
| `slide/` | Slide riêng của 4 thành viên (`TV1`–`TV4`) + script dựng (`slide/build/`) |
| `evidence/` | Log gốc của từng lần chạy, kèm lệnh, thời điểm, phiên bản, mã thoát |
| `BaoCao_...gon.pdf` / `.docx` / `report_concise.md` | Báo cáo bản nộp (PDF 35 trang **+ Word sửa được**) và nguồn Markdown |
| `SLIDE_BaoCao_JuiceShop.pptx` | Slide trình bày của nhóm |
| `demos/` | 4 script demo `tv1`–`tv4` + `common.py` |
| `checks/hardening.py` | Bảng cấu hình an toàn container đang chạy (ảnh `hardening.png`) |
| `policy/` | Luật Rego kiểm tra container **runtime** (`docker inspect`) |
| `semgrep-rules/` | Luật Semgrep cho SAST (F01/F02) |
| `fixtures/` | Dockerfile/compose mẫu để đối chứng policy |
| `screenshots/` | Ảnh minh chứng trong báo cáo |
| `figures/` | Script sinh hình minh hoạ (vd `devsecops_pipeline.py`) |
| `tools/build_pdf.py` | **Dựng lại PDF** từ `report_concise.md` (Edge/Chrome) |
| `tools/build_docx.py` | **Dựng lại Word (.docx)** từ `report_concise.md` (python-docx) |

> **Dựng lại báo cáo** (sửa nội dung trong `report_concise.md` rồi chạy lại):
> - PDF: `python report/tools/build_pdf.py` — cần Python + Edge/Chrome (Win11 có sẵn Edge).
> - Word: `python report/tools/build_docx.py` — cần `pip install python-docx`. Mở file, bấm **Ctrl+A → F9** để cập nhật mục lục.

> Chính sách **build-time** (Dockerfile F04 + compose F03) ở `policy/` tại **gốc repo**; `report/policy/` chỉ chứa luật **runtime**.

---

## 10. Dừng / dọn môi trường

```powershell
docker compose -f docker-compose.monitoring.yml down   # dừng Prometheus + Grafana
docker compose down               # dừng bản sau vá (giữ volume log)
docker stop juice-report-lab      # dừng container đối chứng
```

---

## 11. Khắc phục sự cố

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| `winget` *không nhận lệnh* | Mở Microsoft Store, cập nhật **App Installer**; hoặc tải cài tay theo mục 2.2. |
| `wsl --install` lỗi, hoặc Docker không khởi động được | Chưa bật ảo hoá — vào **BIOS/UEFI** bật **Virtualization (VT‑x/AMD‑V)**, rồi khởi động lại. |
| Lệnh docker báo *"daemon … not running"* | Mở **Docker Desktop**, đợi biểu tượng **xanh** rồi chạy lại. |
| `git` / `node` / `python` *không nhận lệnh* | Mở **cửa sổ PowerShell mới** (PATH mới cập nhật). Cài Python nhớ tick *Add to PATH*. |
| `npm ci` lỗi về phiên bản Node | Dùng **Node 20 LTS** (Juice Shop 20.2.0). Có thể cài qua `nvm-windows` rồi `nvm use 20`. |
| `docker compose up` lỗi thiếu `build/` | Chưa `npm run build:server` — xem **mục 4**. |
| Demo báo không thấy container | Tên phải là `juice-app-proxy-1` / `juice-app-juice-shop-1` (do `docker-compose.yml` đặt `name: juice-app`). Đừng đổi tên project. |
| `tv1/tv2/tv3` không có cột *trước vá* | Chưa chạy container đối chứng — xem **mục 5** (`docker run --name juice-report-lab …`). |
| Cổng `3101` báo **refused** | **Đúng thiết kế** (F03): backend không mở cổng host, chỉ tới được qua proxy. |
| Cổng `3100`/`3102` báo *đang bận* | Có container cũ giữ cổng — `docker ps` rồi `docker stop <tên>`, hoặc `docker compose down`. |
| Lần đầu chạy rất chậm | Docker đang tải image (vài trăm MB) — đợi mạng xong là nhanh ở các lần sau. |

# Tổng kết dự án & phân công — Security as Code cho OWASP Juice Shop

> Môn **DevOps và DevSecOps (SEC4349)** · Ứng dụng nền: **OWASP Juice Shop v20.2.0** (tag gốc `v20.2.0`, repo `juice-shop/juice-shop`).
> Kho của nhóm: `github.com/vuha211100-ui/juice-shop-sonarqube` (nhánh `main` = `fix/f01-f04`).
> Slide: `report/SLIDE_BaoCao_JuiceShop.pptx` (26 slide; dữ liệu cần bảo vệ & cơ sở chính sách ở **slide 8**; phần việc từng thành viên ở **slide 22–25**).

---

## 1. Đề bài → nhóm đã đáp ứng thế nào

| Yêu cầu (requirements.txt) | Đáp ứng |
|---|---|
| Đánh giá an toàn ứng dụng theo yêu cầu bảo vệ dữ liệu người dùng | Juice Shop: tài khoản, giỏ hàng/đơn hàng, thẻ thanh toán, tệp tài liệu; đối chiếu GDPR + NĐ 13/2023 |
| Mô tả ứng dụng + ≥ 2 quy trình/nghiệp vụ | Luồng đăng nhập (JWT), luồng mua hàng (Basket → Order), phục vụ tệp `/ftp`, endpoint giám sát `/metrics` |
| Mô tả môi trường triển khai (yêu cầu an toàn tối thiểu) | 2 môi trường đối chứng: **3100** (image gốc) và **3102** (proxy + backend internal, đã gia cố) |
| Mỗi thành viên 1 vấn đề: phát hiện · xử lý · chính sách vi phạm · pha DevSecOps | F01–F04, mỗi người một lỗi (mục 4) |
| Thể hiện Policy as Code / Security as Code | Rego (`docker_security.rego`, `compose.rego`, `runtime.rego`), SAST, TDS, SCA, giám sát + cảnh báo |
| ≥ 1 lỗi về code + ≥ 1 lỗi về triển khai/vận hành | Code: **F01, F02** · Triển khai/vận hành: **F03, F04** |
| Mỗi thành viên demo đoạn mã phát hiện / khắc phục / cảnh báo | `report/demos/tv1…tv4_*.py` |

---

## 2. Đánh giá: so với Juice Shop gốc, nhóm đã làm thêm gì

### 2.1 Bản gốc v20.2.0 có sẵn
- **Image:** `Dockerfile` 2 stage → distroless, `USER 65532`, nhãn OCI, sinh SBOM (CycloneDX).
- **CI/CD:** 16 workflow GitHub Actions (lint, test, e2e, smoke, build/push image, CodeQL, ZAP hằng tuần, deploy Heroku).
- **Triển khai:** chỉ có `docker run`. Thư mục `infrastructure/` và `terraform/` **cố tình viết lỗi** để làm challenge (README ghi "NOT the IaC you are looking for").
- **Giám sát:** `/metrics` (prom-client) có sẵn trong app, **không xác thực**, cùng 1 file dashboard Grafana JSON. Không có Prometheus, không có luật cảnh báo.

→ Bản gốc **mạnh ở chất lượng ứng dụng**, nhưng **bỏ trống kiến trúc triển khai an toàn và các kiểm soát cấu hình/vận hành**. Đóng góp chính của nhóm nằm ở phần này.

### 2.2 Nhóm làm thêm, theo từng lớp

| Lớp | Bản gốc | Nhóm làm thêm |
|---|---|---|
| **Mã ứng dụng** | Có F01 (SQLi đăng nhập), F02 (Poison Null Byte) | Vá `routes/login.ts` (tham số bind) và `routes/fileServer.ts` (chặn null byte → 403) |
| **Image (Build)** | Distroless, non-root | `deploy/Dockerfile.hotfix`: ghim **digest** image gốc, chỉ chép 2 route đã vá, `USER 65532`, nhãn OCI trỏ repo nhóm, `HEALTHCHECK` |
| **Mạng / triển khai (Deploy)** | Không có | `docker-compose.yml`: 2 mạng `edge` + `backend` (`internal: true`); chỉ proxy mở `127.0.0.1:3102`; backend không mở cổng host |
| **Reverse proxy** | Không có (bản trong `infrastructure/` là bản cố tình lỗi) | `deploy/nginx.conf`: `/metrics` → 404; đăng nhập 5 lần/phút → 429; header bảo mật; `server_tokens off`; log JSON chỉ ghi route đã chuẩn hoá (không lộ dữ liệu cá nhân); `proxy-start.sh` xoay vòng log |
| **Gia cố container** | Chỉ có non-root | `cap_drop: ALL`, `no-new-privileges`, giới hạn CPU/PID, `tmpfs noexec`, proxy `read_only`, ghim digest nginx, `depends_on: service_healthy` |
| **Vận hành / giám sát (Operate)** | `/metrics` mở cho tất cả | Prometheus scrape qua mạng nội bộ, luật `HighClientErrorRate` (4XX > 20 / 2 phút → FIRING), Grafana + dashboard mới |
| **Security as Code** | CodeQL, SBOM | Semgrep (2 bộ luật), Gitleaks + `.gitleaks.toml`, node:test + Supertest (TDS), Conftest/Rego (3 bộ luật, 26 ca kiểm thử), Trivy, Dockle, `hardening.py` |
| **Quy trình Git / CI** | 16 workflow GitHub của dự án gốc (test, CodeQL, release…), không gắn với F01–F04 | `devsecops/pipeline.sh` chạy các cổng theo đúng sơ đồ 7 pha. Kích hoạt bằng Git hook (`.githooks/pre-commit`, `pre-push`) và workflow `.github/workflows/devsecops.yml`. Semgrep/Gitleaks chỉ chặn phát hiện **mới**; image chỉ được gắn tag triển khai khi qua Test + Release (§5.7) |
| **Tài liệu / bằng chứng** | — | Báo cáo DOCX/PDF + công cụ build, slide, kịch bản, runbook (`README.md`, `DEMO.md`, `scanSAC.md`), log bằng chứng có mã thoát (`report/evidence/`) |

### 2.3 Con số chính (từ `report/evidence/`)
| Hạng mục | Kết quả |
|---|---|
| Semgrep (mã chưa vá, `routes/` + `lib/`) | 38 cảnh báo / 25 tệp; khoanh đúng F01, F02 |
| Kiểm thử bảo mật `f01-f02.test.ts` | Trước vá 4/11 đạt (7 đỏ) → sau vá **11/11** |
| Gitleaks (`baf9dcea4..HEAD`) | 42 commit, **no leaks** |
| Conftest `verify -p policy` | **19/19** (13 Dockerfile + 6 compose); `runtime.rego` 7/7 |
| Conftest trên `Dockerfile.vulnerable` | exit 1, 6 vi phạm / 4 nhóm luật |
| Trivy (image đã vá) | 189 bản ghi, 173 CVE duy nhất (12 CRITICAL, 56 HIGH) — rủi ro dependency đã biết |
| Dockle (image đã vá) | 0 FATAL / 0 WARN |
| `/metrics` | 3100: 200 (393 dòng) → 3102: 404; giám sát nội bộ vẫn đọc được |

### 2.4 Điểm còn thiếu / chưa nhất quán (kiểm thật ngày 2026-11-06)
| # | Vấn đề | Mức |
|---|---|---|
| 1 | ~~Chưa có pipeline CI thật~~ → **đã có** pipeline gắn Git (§5.7). Còn lại 2 việc: (a) GitHub Actions trên fork đang **tắt**, cần bật rồi đặt branch protection cho `main` bắt buộc job *DevSecOps pipeline*; (b) khi bật, workflow gốc `ci.yml` cũng chạy và sẽ đỏ vì #6, nên tắt các workflow gốc không dùng | Trung bình |
| 2 | Stack giám sát **fail chính `compose.rego`** của nhóm (2 FAIL: Prometheus/Grafana mở cổng nhưng không phải edge; 4 WARN) và fail `runtime.rego` (Prometheus 6/8, Grafana 5/8) | Cao |
| 3 | Prometheus vừa nằm trong mạng `backend` vừa mở `127.0.0.1:9090` → vẫn đọc được số liệu `/metrics` qua Prometheus (chỉ trên loopback) | Trung bình |
| 4 | Grafana ẩn danh quyền **Admin** + cho phép nhúng; Prometheus/Grafana dùng `:latest`, không ghim digest | Trung bình |
| 5 | Code sót từ commit đầu `baf9dcea4` (`lib/cardMasking.ts`, `models/card.ts`, `data/datacreator.ts`, `routes/dataErasure.ts`, error handler trong `server.ts`): có trong mã nguồn nhưng **không được triển khai** (image chỉ chép 2 route) và báo cáo không nhắc | Trung bình |
| 6 | `test/api/basket.test.ts` vẫn viết theo F02 cũ (IDOR giỏ hàng) → **7/22 ca fail** (3 do kỳ vọng cũ, 4 do error handler che mất message) | Trung bình |
| 7 | Con số `conftest verify` 19/19 chưa tính 7 ca của `runtime.rego`; proxy chưa có TLS (chấp nhận được vì chỉ mở loopback, nên ghi vào phần Giới hạn) | Thấp |

---

## 3. Công cụ trong báo cáo → người phụ trách

Bám theo **Bảng "Bảy pha thực hành"** của báo cáo (§4). Mỗi công cụ có đúng một người phụ trách; riêng node:test và TypeScript/Express dùng chung cho F01, F02.

| Pha (báo cáo) | Công cụ (phiên bản) | Tình huống | Người phụ trách | Kết quả / bằng chứng |
|---|---|---|---|---|
| 1. Thiết lập môi trường | Docker Compose, Node.js | — | **Quốc Anh** | 3100 (gốc) / 3102 (proxy) · `env-*.log` |
| 2. Policy as Code | Conftest/OPA v0.71.1 — `compose.rego` | F03 | **Quốc Anh** | 6/6 ca · compose sau vá exit 0 |
| 2. Policy as Code | Conftest/OPA v0.71.1 — `docker_security.rego` | F04 | **Vũ** | 13/13 ca · fixture exit 1 (6 vi phạm / 4 nhóm) |
| 3. Phát hiện lỗ hổng (SAST) | Semgrep 1.180.0 | F01, F02 | **Thắng** | 38 cảnh báo / 25 tệp · `semgrep-overview.log` |
| 3. Phát hiện lỗ hổng (SCA) | Trivy 0.76.1 | F02 (lộ phiên bản thư viện) | **Thúy** | 189 bản ghi, 173 CVE (12 CRITICAL) · `trivy-image.json` |
| 4. Test-Driven Security | node:test + Supertest | F01, F02 | **Thắng** (khung + F01), **Thúy** (ca F02) | đỏ 7/11 → xanh 11/11 · `f0102-*-test.log` |
| 5. Vá ứng dụng | TypeScript / Express | F01, F02 | **Thắng** (`login.ts`), **Thúy** (`fileServer.ts`) | tv1, tv2 |
| 6. Compliance as Code | `docker inspect` (`hardening.py`) | F03 | **Quốc Anh** | backend 0 cổng host · `hardening.log` |
| 6. Compliance as Code | Dockle 0.4.15 | F04 | **Vũ** | image sai: FATAL CIS-DI-0010 · image đã vá: 0 FATAL/WARN |
| 6. Compliance as Code | Conftest — `runtime.rego` | F03, F04 | **Vũ** | 7/7 ca · app + proxy đạt 8/8 luật |
| 7. Kiểm chứng & bàn giao | Gitleaks v8.30.1 | — | **Thúy** | 42 commit, no leaks · `gitleaks.log` |
| 7. Kiểm chứng & bàn giao | Conftest verify | — | **Vũ** | 19/19 · `conftest-verify.log` |
| 7. Giám sát vận hành | Prometheus 3.15.1 · Grafana 13.3.0 | F03 | **Quốc Anh** | target UP · cảnh báo FIRING · `monitoring.log` |

**Tóm tắt theo người:** Thắng: pha 3, 4, 5 · Thúy: pha 3, 4, 5, 7 · Quốc Anh: pha 1, 2, 6, 7 · Vũ: pha 2, 6, 7.

---

## 4. Phân công chi tiết

### 4.1 Nguyễn Toàn Thắng — B26CHAT039 · slide 22
**Vai trò:** lớp mã nguồn — xác thực, SAST và kiểm thử bảo mật · **Lỗi:** F01 SQL injection đăng nhập (CWE-89, OWASP A03; GDPR Đ.32(1)(b)) · **Pha (báo cáo):** 3 → 4 → 5

**Công cụ:** Semgrep 1.180.0 (pha 3, SAST) · node:test + Supertest (pha 4, TDS) · TypeScript/Express (pha 5, vá)

| Việc đã làm | Tệp |
|---|---|
| Vá F01: truy vấn đăng nhập dùng tham số bind `$email/$password`, ép kiểu đầu vào về string | `routes/login.ts` |
| Dựng bước SAST: Semgrep với bộ luật `owasp-top-ten` + `nodejsscan`, quét `routes/` + `lib/`, phân loại kết quả | `report/semgrep-rules/` |
| Dựng khung Test-Driven Security (node:test + Supertest): đỏ trên mã chưa vá → xanh sau vá | `test/api/security/f01-f02.test.ts` |
| Cập nhật 2 ca SQLi trong bộ test gốc sang kỳ vọng 401 | `test/api/login.test.ts` |
| Demo trước/sau vá | `report/demos/tv1_f01_sqli.py` |

**Cách chạy:** §5.2 pha 3 (Semgrep), pha 4 (node:test), pha 5 (vá + dựng lại image); demo §5.4.

**Kết quả:** 38 cảnh báo Semgrep / 25 tệp · 11/11 ca xanh sau vá (trước 7 đỏ) · payload `' OR 1=1--`: 3100 cấp token quản trị → 3102 trả 401; đăng nhập hợp lệ vẫn 200.

### 4.2 Phạm Thị Minh Thúy — B26CHAT042 · slide 23
**Vai trò:** lớp mã nguồn tệp và chuỗi cung ứng (secret, dependency) · **Lỗi:** F02 Poison Null Byte (CWE-158/180, OWASP A01; GDPR Đ.5(1)(f), 32) · **Pha (báo cáo):** 3 → 4 → 5 → 7

**Công cụ:** Trivy 0.76.1 (pha 3, SCA) · node:test + Supertest (pha 4, ca F02) · TypeScript/Express (pha 5, vá) · Gitleaks v8.30.1 (pha 7, quét secret)

| Việc đã làm | Tệp |
|---|---|
| Vá F02: từ chối tên tệp chứa `%00`/NUL (403) **trước** bước kiểm đuôi `.md/.pdf` | `routes/fileServer.ts` |
| Viết các ca kiểm thử F02 (payload `%2500.md` → 403; `.md` hợp lệ vẫn tải được) | `test/api/security/f01-f02.test.ts` |
| Quét secret bằng Gitleaks trên các commit của nhóm; allowlist cho khóa RSA giả của demo | `.gitleaks.toml` |
| Quét CVE dependency của image triển khai bằng Trivy (SCA). Lý do gắn với F02: tệp `package.json.bak` bị lộ chứa phiên bản thư viện, Trivy chỉ ra thư viện nào có CVE | `report/evidence/trivy-image.json` |
| Demo trước/sau vá | `report/demos/tv2_f02_pathtraversal.py` |

**Cách chạy:** §5.2 pha 3 (Trivy), pha 4 (ca F02), pha 5 (vá), pha 7 (Gitleaks); demo §5.4.

**Kết quả:** `/ftp/package.json.bak%2500.md`: trước 200 (lộ `.bak`) → sau 403 · Gitleaks 0 leak / 42 commit · Trivy 173 CVE duy nhất (189 bản ghi, 12 CRITICAL).

### 4.3 Đỗ Đức Quốc Anh — B26CHAT001 · slide 24
**Vai trò:** hạ tầng triển khai và vận hành — mạng, proxy, giám sát · **Lỗi:** F03 `/metrics` không xác thực (OWASP A05; GDPR Đ.25(2), 32) · **Pha (báo cáo):** 1 → 2 → 6 → 7

**Công cụ:** Docker Compose + Node.js (pha 1) · Conftest/OPA `compose.rego` (pha 2) · `docker inspect` (pha 6) · Prometheus 3.15.1 + Grafana 13.3.0 (pha 7)

| Việc đã làm | Tệp |
|---|---|
| Dựng 2 môi trường đối chứng (3100 image gốc / 3102 đã vá); topology mạng `edge` (chỉ proxy) + `backend` internal, chỉ mở `127.0.0.1:3102` | `docker-compose.yml` |
| nginx: `/metrics` → 404, đăng nhập 5 lần/phút → 429, header bảo mật, log JSON không chứa dữ liệu cá nhân, xoay vòng log | `deploy/nginx.conf`, `deploy/proxy-start.sh` |
| Gia cố container: non-root, `cap_drop ALL`, `no-new-privileges`, read-only, giới hạn CPU/PID, `tmpfs noexec` | `docker-compose.yml` |
| Policy as Code chống tái diễn F03 (6 ca kiểm thử) | `policy/compose.rego`, `policy/compose_test.rego` |
| Kiểm container đang chạy bằng `docker inspect`: backend 0 cổng host, non-root, `cap_drop ALL` | `report/checks/hardening.py` |
| Giám sát: Prometheus scrape nội bộ, luật `HighClientErrorRate`, Grafana + dashboard | `docker-compose.monitoring.yml`, `deploy/monitoring/*` |
| Demo trước/sau vá | `report/demos/tv3_f03_metrics.py` |

**Cách chạy:** §5.1 (2 môi trường + bảng kiểm hạ tầng), §5.2 pha 2 (`compose.rego`), pha 6 (`hardening.py`), §5.3 (Prometheus/Grafana + kích FIRING); demo §5.4.

**Kết quả:** `/metrics`: 3100 trả 200 (393 dòng) → 3102 trả 404 · backend không có cổng host · rate-limit 429 · `compose.rego` 6/6 · cảnh báo FIRING khi 4XX tăng đột biến.

### 4.4 Hồ Anh Vũ — B26CHAT048 · slide 25
**Vai trò:** Build & Release container — Policy / Compliance as Code · **Lỗi:** F04 sai cấu hình container (CIS Docker, NIST SP 800-190, PCI-DSS 2.2/8.2.1; GDPR Đ.25(1), 32(1)(d)) · **Pha (báo cáo):** 2 → 6 → 7

**Công cụ:** Conftest/OPA `docker_security.rego` (pha 2) · Dockle 0.4.15 + Conftest `runtime.rego` (pha 6) · `conftest verify` (pha 7)

| Việc đã làm | Tệp |
|---|---|
| Bộ luật 4 nhóm (LEAST-PRIVILEGE, ATTACK-SURFACE, SUPPLY-CHAIN, SECRET-IN-IMAGE) + 13 ca kiểm thử | `policy/docker_security.rego`, `policy/docker_security_test.rego` |
| Dựng Dockerfile có lỗi để kiểm năng lực phát hiện của bộ luật | `report/fixtures/Dockerfile.vulnerable` |
| Đóng gói image đã vá: ghim digest, chép 2 route đã vá, `USER 65532`, nhãn OCI, `HEALTHCHECK` | `deploy/Dockerfile.hotfix` |
| Dockle kiểm CIS image thành phẩm (image đóng gói sai → FATAL; image đã vá → 0 FATAL/WARN) | `report/evidence/dockle-*.log` |
| Luật runtime đối chiếu kết quả `docker inspect` của container đang chạy (7 ca kiểm thử) | `report/policy/runtime.rego` |
| Chạy lại toàn bộ luật trước bàn giao (`conftest verify`) | `report/evidence/conftest-verify.log` |
| Demo trước/sau vá | `report/demos/tv4_f04_policy.py` |

**Cách chạy:** §5.2 pha 2 (`docker_security.rego`), pha 6 (Dockle + `runtime.rego`), pha 7 (`conftest verify`); demo §5.4.

**Kết quả:** `conftest verify` 19/19 · fixture lỗi exit 1 (6 vi phạm / 4 nhóm) · Dockerfile gốc và image đã vá exit 0 · Dockle 0 FATAL/WARN.

---

## 5. Cách chạy — từng hạ tầng, công cụ, tài liệu

> **PowerShell, chạy tại gốc repo** (`juice-shop/`), Docker Desktop đang chạy. Các lệnh dưới đã được chạy thử ngày 2026-11-06.
> Máy mới hoàn toàn (chưa có Git/Docker/Node/Python): cài theo `report/README.md` mục 2 trước.

```powershell
$ROOT = (Get-Location).Path -replace '\\','/'      # đường dẫn gốc repo cho các lệnh docker -v
$CF   = @("run","--rm","-v","${ROOT}:/work:ro","-w","/work","openpolicyagent/conftest:v0.71.1")
```

### 5.0 Chuẩn bị (một lần)
```powershell
npm ci                                         # cài dependency của Juice Shop
npm run build:server                           # biên dịch server -> build/ (nguồn của image đã vá)
docker volume create juice-report-accesslogs   # volume lưu log truy cập của proxy
```

### 5.1 Hạ tầng triển khai (pha 1 — Quốc Anh)

**Hai môi trường đối chứng:**
```powershell
# TRƯỚC vá: image gốc, chỉ mở loopback 3100
docker run -d --name juice-report-lab -p 127.0.0.1:3100:3000 `
  --cap-drop ALL --security-opt no-new-privileges:true bkimminich/juice-shop:v20.2.0
#   lần sau chỉ cần:  docker start juice-report-lab

# SAU vá: build image đã vá (deploy/Dockerfile.hotfix) + proxy nginx + backend internal
docker compose up -d --build
docker compose ps                              # chờ juice-shop 'healthy' (~30–60 s)
```

**Kiểm từng lớp hạ tầng đã dựng:**

| Hạng mục | Lệnh | Kết quả mong đợi |
|---|---|---|
| Mạng `backend` internal | `docker network inspect juice-app_backend --format "internal={{.Internal}}"` | `internal=true` |
| Backend không cổng host | `docker inspect juice-app-juice-shop-1 --format "{{json .HostConfig.PortBindings}}"` | `{}` (rỗng) |
| Chỉ proxy mở cổng | `docker ps --format "{{.Names}}  {{.Ports}}"` | proxy: `127.0.0.1:3102->8080`; juice-shop: chỉ `3000/tcp` |
| Gia cố container | `docker inspect juice-app-juice-shop-1 --format "User={{.Config.User}} CapDrop={{.HostConfig.CapDrop}} Sec={{.HostConfig.SecurityOpt}}"` | `User=65532:0 CapDrop=[ALL] Sec=[no-new-privileges:true]` |
| Healthcheck | `docker inspect juice-app-juice-shop-1 --format "{{.State.Health.Status}}"` | `healthy` |
| nginx chặn `/metrics` | `curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:3102/metrics` | `404` (3100 thì `200`) |
| Rate-limit đăng nhập | `1..12 \| % { curl.exe -s -o NUL -w "%{http_code} " -X POST http://127.0.0.1:3102/rest/user/login }` | 6 lần `401` rồi `429` |
| Header bảo mật | `curl.exe -s -I http://127.0.0.1:3102/` | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Server: nginx` (không lộ phiên bản) |
| Log JSON không chứa dữ liệu cá nhân | `docker exec juice-app-proxy-1 tail -n 3 /logs/access.log` | `request_uri` chỉ là route chuẩn hoá (`/rest/user/login`, `other`), không có query string |

### 5.2 Công cụ theo pha (bám Bảng 7 pha của báo cáo)

**Pha 2 · Policy as Code — Conftest/OPA** (Quốc Anh: `compose.rego` · Vũ: `docker_security.rego`)
```powershell
docker @CF verify -p policy --no-color                                                                        # tự kiểm luật: 19/19
docker @CF test report/fixtures/Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile --no-color   # F04 fixture lỗi: exit 1, 6 vi phạm / 4 nhóm
docker @CF test report/fixtures/Dockerfile.remediated --parser dockerfile -p policy --namespace dockerfile --no-color  # bản vá của fixture: exit 0 (1 warn)
docker @CF test Dockerfile --parser dockerfile -p policy --namespace dockerfile --no-color                    # Dockerfile gốc: exit 0
docker @CF test deploy/Dockerfile.hotfix --parser dockerfile -p policy --namespace dockerfile --no-color      # image đã vá: exit 0
docker @CF test report/fixtures/compose.before-f03.yml -p policy --namespace compose --no-color              # F03 trước vá: exit 1, đúng 1 FAIL F03 NET-02 (juice-shop mở 3101)
docker @CF test docker-compose.yml -p policy --namespace compose --no-color                                  # F03 sau vá: exit 0
```

**Pha 3 · SAST — Semgrep 1.180.0** (Thắng) — quét mã **chưa vá** như trong báo cáo:
```powershell
git checkout 21219d66d -- routes                                   # lấy tạm route chưa vá
docker run --rm -e SEMGREP_SEND_METRICS=off -v "${ROOT}:/src:ro" -v "${ROOT}/report/semgrep-rules:/rules:ro" `
  semgrep/semgrep:1.180.0 semgrep scan --metrics=off --quiet `
  --config /rules/owasp-top-ten.yml --config /rules/nodejsscan.yml /src/routes /src/lib
git checkout HEAD -- routes                                        # trả lại bản vá
```
Kỳ vọng: 38 cảnh báo / 25 tệp. F01 ở `login.ts` (`express-sequelize-injection`), F02 ở `fileServer.ts` (`express-res-sendfile`). Sau vá, F01 hết báo; F02 vẫn còn mẫu `res.sendFile`, vì SAST cảnh báo theo mẫu code còn chạy thật thì đã bị chặn 403.

**Pha 3 · SCA — Trivy 0.76.1** (Thúy):
```powershell
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.76.1 `
  image --scanners vuln --severity CRITICAL,HIGH juice-shop:hotfix-f01-f02
#  bỏ --severity để xem đủ: 189 bản ghi, 173 CVE (12 CRITICAL, 56 HIGH); bảng "Report Summary" ở đầu output
```

**Pha 4 · Test-Driven Security — node:test + Supertest** (Thắng: khung + F01 · Thúy: ca F02):
```powershell
git checkout 21219d66d -- routes                                   # mã chưa vá -> 7/11 ca ĐỎ
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
git checkout HEAD -- routes                                        # bản vá -> 11/11 ca XANH
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
```

**Pha 5 · Vá ứng dụng — TypeScript/Express** (Thắng: `routes/login.ts` · Thúy: `routes/fileServer.ts`). Sau khi sửa mã, phải dựng lại image thì môi trường 3102 mới nhận bản vá:
```powershell
git diff v20.2.0 HEAD -- routes/login.ts routes/fileServer.ts     # xem đúng phần đã vá so với bản gốc
npm run build:server; docker compose up -d --build                 # dựng lại image đã vá
```

**Pha 6 · Compliance as Code** (Quốc Anh: `docker inspect` · Vũ: Dockle + `runtime.rego`):
```powershell
# docker inspect — bảng hardening của các container đang chạy
python report/checks/hardening.py

# Conftest runtime — đối chiếu docker inspect với report/policy/runtime.rego
docker @CF verify -p report/policy --no-color                                                # 7/7
docker inspect juice-app-juice-shop-1 > report/evidence/inspect-after.json
docker inspect juice-report-lab       > report/evidence/inspect-before.json
docker @CF test report/evidence/inspect-after.json  -p report/policy --namespace runtime --no-color   # đạt
docker @CF test report/evidence/inspect-before.json -p report/policy --namespace runtime --no-color   # có vi phạm

# Dockle 0.4.15 — image đã vá: không có FATAL/WARN
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock goodwithtech/dockle:v0.4.15 juice-shop:hotfix-f01-f02
# Dockle — image Juice Shop đóng gói SAI (đối chứng): chạy root + COPY khóa RSA GIẢ + secret trong ENV
New-Item -ItemType Directory -Force _dockle_demo | Out-Null      # thư mục đã có trong .gitignore
Set-Content -Encoding ascii _dockle_demo/id_rsa "-----BEGIN RSA PRIVATE KEY-----`nMIIEoFAKEdemoKeyNotReal000`n-----END RSA PRIVATE KEY-----"
Set-Content -Encoding ascii _dockle_demo/Dockerfile "FROM juice-shop:hotfix-f01-f02`nUSER root`nCOPY id_rsa /juice-shop/id_rsa`nENV API_TOKEN=supersecret123"
docker build -q -t juice-shop:dockle-misconfig _dockle_demo
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock goodwithtech/dockle:v0.4.15 juice-shop:dockle-misconfig
#  -> FATAL CIS-DI-0010 (secret trong tệp/ENV) + WARN CIS-DI-0001 (chạy root)
```

**Pha 7 · Kiểm chứng & bàn giao** (Thúy: Gitleaks · Vũ: `conftest verify`):
```powershell
docker run --rm -v "${ROOT}:/repo:ro" zricethezav/gitleaks:v8.30.1 `
  git /repo --log-opts="baf9dcea4..HEAD" --no-banner                # "no leaks found", exit 0
docker @CF verify -p policy --no-color                              # chạy lại toàn bộ luật: 19/19
```

### 5.3 Giám sát vận hành — Prometheus + Grafana (pha 7 — Quốc Anh)
```powershell
docker compose -f docker-compose.monitoring.yml up -d     # cần stack ứng dụng đang chạy (gắn vào mạng juice-app_backend)
```
| Kiểm | Cách làm | Kết quả mong đợi |
|---|---|---|
| Scrape | Mở `http://127.0.0.1:9090` → **Status ▸ Targets** | `juice-shop` = **UP** (`http://juice-app-juice-shop-1:3000/metrics`) |
| Truy vấn | Tab **Graph**, gõ `http_requests_count` hoặc `juiceshop_users_registered` → **Execute** | Có số liệu theo `status_code` / loại người dùng |
| Cảnh báo | Tab **Alerts** | `HighClientErrorRate` = Inactive |
| Dashboard | Mở `http://127.0.0.1:3103` | Dashboard "Juice Shop — Giám sát vận hành" (ẩn danh, chỉ mở loopback) |

**Kích cảnh báo FIRING** (mô phỏng dò đăng nhập). Lưu ý: script `tv3_f03_metrics.py` **không** kích được cảnh báo này. Phải bắn thẳng vào backend qua mạng nội bộ, vì đi qua proxy thì bị rate-limit trả 429 trước khi tới app.
```powershell
docker run --rm --network juice-app_backend curlimages/curl:latest sh -c 'for i in $(seq 1 30); do curl -s -o /dev/null -X POST http://juice-app-juice-shop-1:3000/rest/user/login; done; echo sent'
#  chờ ~30 s rồi xem tab Alerts, hoặc:
(Invoke-RestMethod http://127.0.0.1:9090/api/v1/alerts).data.alerts | % { "$($_.labels.alertname) $($_.state)" }   # HighClientErrorRate firing
```
> Nếu backend **vừa khởi động lại** và chưa từng trả 4XX, đợt bắn đầu chỉ tạo chuỗi số liệu `4XX` mới (Prometheus tính `increase` = 0). Chạy lệnh bắn **thêm một lần** là FIRING. Đã kiểm ngày 2026-11-06: đợt 1 cho 0, đợt 2 cho 33.6 > 20 → firing.

### 5.4 Demo của 4 thành viên
```powershell
python report/demos/tv1_f01_sqli.py            # Thắng   — 3100 cấp token · 3102 401
python report/demos/tv2_f02_pathtraversal.py   # Thúy    — trước 200 + .bak · sau 403
python report/demos/tv3_f03_metrics.py         # Quốc Anh — 3100/metrics 200 · 3102 404 · 3101 refused · compose trước vá exit 1 · sau vá exit 0
python report/demos/tv4_f04_policy.py          # Vũ      — verify 19/19 · fixture exit 1 · gốc/đã vá exit 0
```

### 5.5 Tài liệu — dựng lại báo cáo
```powershell
python report/tools/build_docx.py      # report_concise.md -> BaoCao_DevSecOps_JuiceShop_gon.docx (cần python-docx; mở Word: Ctrl+A → F9 cập nhật mục lục)
python report/tools/build_pdf.py       # report_concise.md -> BaoCao_DevSecOps_JuiceShop_gon.pdf (cần Edge/Chrome)
```
| Tài liệu | Nội dung |
|---|---|
| `report/report_concise.md` | Nguồn báo cáo (sửa ở đây rồi build lại DOCX/PDF) |
| `report/README.md` | Cài máy mới + chạy từ đầu + khắc phục sự cố |
| `report/DEMO.md` · `HUONG_DAN_DEMO.md` | Runbook đầy đủ / bản tóm tắt theo lỗi |
| `report/scanSAC.md` | Lệnh từng công cụ theo pha |
| `devsecops/README.md` | Quy trình Git DevSecOps: hook, pipeline, workflow CI, bảng cổng theo pha (§5.7) |
| `report/PHAN_THUYET_TRINH.md` | Kịch bản thuyết trình theo slide |
| `report/PHAN_NOI.md` | Kịch bản nói theo thành viên + câu hỏi phản biện |
| `report/GHI_CHU_NOI_KHI_BAO_CAO.md` | Ghi chú nội bộ khi bảo vệ (không thuộc báo cáo) |
| `report/GIOI_HAN_VA_HUONG_MO_RONG.md` | Giới hạn phạm vi + hướng mở rộng |
| `report/TONG_KET_PHAN_CONG.md` | File này |
| `report/evidence/` | Log gốc kèm lệnh, thời điểm, phiên bản, mã thoát |
| `report/SLIDE_BaoCao_JuiceShop.pptx` | Slide (26 trang). Script sinh slide (`build_deck.js`, pptxgenjs) hiện **chưa nằm trong repo** |

### 5.6 Sinh lại hình và log bằng chứng
Các script chạy **lệnh thật**, ghi log gốc vào `report/evidence/<id>.log` (kèm lệnh, thời điểm, phiên bản, mã thoát) rồi vẽ ảnh vào `report/screenshots/`. Cần Docker + 3 container (`juice-report-lab`, `juice-app-proxy-1`, `juice-app-juice-shop-1`).

| Lệnh | Sinh ra | Yêu cầu thêm |
|---|---|---|
| `python report/figures/capture_demos.py` | `tv1–tv4.png`, `f0102-red/green.png` + log | Tạm thay `login.ts`/`fileServer.ts` bằng bản chưa vá để chạy ca đỏ, rồi tự trả lại |
| `python report/figures/capture_runs.py` | ảnh Semgrep, Conftest, Gitleaks, môi trường + log | Quét bản chưa vá qua `git archive` vào thư mục tạm, không đụng mã đang làm |
| `python report/figures/capture_scans.py` | `trivy.png`, `dockle.png`, `monitoring.png` + log | Cần thêm stack giám sát (§5.3). Script tự bắn 60 lần đăng nhập sai để kích FIRING |
| `python report/figures/devsecops_pipeline.py` | `devsecops-pipeline.png` (sơ đồ quy trình) | Pillow + font Arial của Windows |

Sau khi sinh lại hình, chạy §5.5 để dựng lại DOCX/PDF.

### 5.7 Quy trình Git DevSecOps — khi sửa lỗi / đổi mã nguồn
Chi tiết ở `devsecops/README.md`. Mọi cổng ở §5.2–5.3 được gói vào `devsecops/pipeline.sh` và chạy theo thứ tự sơ đồ: **Code → Build → Test → Release → Deploy → Operate → Monitor**.

| Kích hoạt | Pha chạy |
|---|---|
| `git commit` → `.githooks/pre-commit` | Code (Gitleaks trên phần đã `git add`, Semgrep chặn cảnh báo **mới**) + Conftest Dockerfile/compose |
| `git push` → `.githooks/pre-push` | Code → Build (tsc, image ứng viên `juice-shop:ci-<sha>`) → Test → Release (Trivy CVE CRITICAL mới, Dockle; đạt thì gắn tag `hotfix-f01-f02`) → Deploy (chỉ chính sách) |
| GitHub Actions `devsecops.yml` (push `main`/`fix/**`/`tv-*`, PR vào `main`) | Cả 7 pha, triển khai thật trên runner rồi chạy Operate + Monitor |

```bash
# Git Bash, một lần sau khi clone
npm install
bash devsecops/install-hooks.sh                      # core.hooksPath = .githooks

# chạy tay
bash devsecops/pipeline.sh                           # cả 7 pha (so với v20.2.0), triển khai lên 3102
bash devsecops/pipeline.sh deploy operate monitor    # chỉ triển khai + kiểm tra vận hành
```

**Đã chạy thử ngày 2026-11-06:**
- Chạy đủ 7 pha trên mã hiện tại: **20 PASS · 1 WARN · 0 FAIL**, khoảng 2 phút. WARN đúng là lỗ hổng #5: 5 tệp sửa ngoài 2 route không có trong image.
- Các tình huống lỗi, thử trong git worktree tạm:

| Tình huống | Kết quả |
|---|---|
| Commit đưa lại `login.ts` chưa vá kèm AWS key giả | Bị chặn: Gitleaks **2 leaks**, Semgrep **2 cảnh báo mới** (`express-sequelize-injection`, `node_secret`) |
| Bỏ qua bằng `--no-verify` rồi push | pre-push chặn ở Semgrep. Chạy riêng pha Test thì **5 ca SQLi đỏ** (200 thay vì 401) |
| Bỏ `USER 65532` và mở `0.0.0.0:3000` cho backend | Bị chặn: `LEAST-PRIVILEGE` (F04), `F03 NET-02` và `NET-01` (F03), báo cùng một lần |
| Sửa vô hại trong `fileServer.ts` | Đạt. Cảnh báo `res.sendFile` có sẵn không bị tính là mới |

### 5.8 Dừng môi trường
```powershell
docker compose -f docker-compose.monitoring.yml down
docker compose down                    # giữ volume log
docker stop juice-report-lab
```

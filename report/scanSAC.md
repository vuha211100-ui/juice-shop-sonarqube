# scanSAC — Lệnh chạy các công cụ (slide A7 · ánh xạ công cụ ↔ pha)

> PowerShell, chạy tại gốc repo. Phiên bản công cụ: Semgrep 1.180.0 · Gitleaks v8.30.1 · Conftest/OPA v0.71.1 · Trivy 0.76.1 · Dockle 0.4.15 · Prometheus/Grafana (latest). `3100` = trước vá · `3102` = sau vá.

**Chuẩn bị — dựng stack:**
```powershell
cd E:\banhoaqua\juice-shop
$ROOT = "E:/banhoaqua/juice-shop"       # dùng cho các lệnh docker bên dưới
docker start juice-report-lab           # container đối chứng (3100)
docker compose up -d --build            # stack ứng dụng: backend + proxy (3102)
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
*Lưu ý (SAST cảnh báo theo mẫu code):* phần lớn 38 cảnh báo nằm ở `lib/` (JWT RS256 cố định, băm yếu…) — **ngoài phạm vi 4 lỗi, nhóm không xử lý**. Sau vá: **F01 hết báo** (dòng lỗi được viết lại), nhưng **F02 vẫn còn** mẫu `res.sendFile` (chạy thật đã chặn 403 — là residual, không phải lỗ hổng còn sống). Quét trên mã đã vá (bỏ 2 dòng `git checkout`) ra **~37**.

**Gitleaks (quét secret)** — quét commit vá của nhóm:
```powershell
docker run --rm -v "${ROOT}:/repo:ro" zricethezav/gitleaks:v8.30.1 `
  git /repo --log-opts="baf9dcea4..HEAD" --no-banner      # kỳ vọng: no leaks found (exit 0)
```

### Pha Build — Policy as Code (Dockerfile)
**Conftest · `docker_security.rego`** (F04):
```powershell
$CF = @("run","--rm","-v","${ROOT}:/work:ro","-w","/work","openpolicyagent/conftest:v0.71.1")
docker @CF verify -p policy --no-color                                                                                 # tự kiểm luật: 19/19
docker @CF test report/fixtures/Dockerfile.vulnerable --parser dockerfile -p policy --namespace dockerfile --no-color  # fixture: exit 1 (4 nhóm)
docker @CF test Dockerfile --parser dockerfile -p policy --namespace dockerfile --no-color                             # gốc distroless: exit 0
docker @CF test deploy/Dockerfile.hotfix --parser dockerfile -p policy --namespace dockerfile --no-color               # image đã vá: exit 0
```

### Pha Test — Kiểm thử bảo mật (TDS)
**node:test + Supertest** — đỏ trước vá → xanh sau vá:
```powershell
git checkout 21219d66d -- routes        # lấy tạm route CHƯA vá -> một số ca đỏ
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
git checkout HEAD -- routes             # trả lại bản vá -> toàn bộ ca xanh (11/11)
node --import ./test/api/helpers/test-env.mjs --import tsx --test test/api/security/f01-f02.test.ts
```

### Pha Release — Quét image đã build
> Nếu máy **chưa cài** `trivy`/`dockle` (báo `command not found`), chạy qua **Docker** như dưới (không cần cài). Nếu đã cài sẵn thì dùng thẳng `trivy …` / `dockle …`.

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
**Prometheus + Grafana** — giám sát + cảnh báo:
```powershell
docker compose -f docker-compose.monitoring.yml up -d       # cần stack ứng dụng đã chạy (gắn mạng backend)
# Prometheus  http://127.0.0.1:9090   (Status ▸ Targets: juice-shop UP; Alerts: HighClientErrorRate)
# Grafana     http://127.0.0.1:3103   (dashboard số liệu thật; anonymous)
# Mô phỏng cảnh báo FIRING (dò đăng nhập → 4XX tăng): chạy  python report/demos/tv3_f03_metrics.py
```
> **Dễ bị hỏi — Grafana không cần đăng nhập:** cấu hình bật `anonymous` role **Admin** để demo cho gọn → nguyên tắc là rủi ro (ai vào cũng quyền admin). Giảm nhẹ vì Grafana **chỉ bind loopback `127.0.0.1`** (không ra mạng/host), là portal của người vận hành — khác F03 (`/metrics` phơi ra host cho mọi client). Trả lời: *"biết là rủi ro, bật để demo; thực tế để `Viewer` hoặc bắt đăng nhập; đã nêu ở Giới hạn §4.3"*. Siết nhanh: đổi `GF_AUTH_ANONYMOUS_ORG_ROLE` → `Viewer` (ẩn danh chỉ xem).

### Prometheus — mục đích & cách dùng (hiện đang đọc gì)
- **Mục đích:** hệ **thu thập số liệu vận hành theo thời gian + cảnh báo**, mô hình **PULL** (Prometheus *tự đi lấy*, không phải app đẩy). Không dùng để vẽ (đó là Grafana) — Prometheus là "bộ não".
- **Hiện đang đọc gì** (`deploy/monitoring/prometheus.yml`): job `juice-shop`, **mỗi 10 giây** gọi `GET /metrics` tại `juice-app-juice-shop-1:3000` **qua mạng nội bộ `backend`** (không ra host → vẫn đúng F03). Metric gồm: số người dùng đăng ký, đơn hàng, số dư ví, thời gian xử lý HTTP, `http_requests_count` theo `status_code`, RAM tiến trình.
- **Luật cảnh báo** (`deploy/monitoring/alerts.yml`): `HighClientErrorRate` = `sum(increase(http_requests_count{status_code="4XX"}[2m])) > 20` → **FIRING** khi 4XX vượt 20 trong 2 phút (dấu hiệu dò đăng nhập / null-byte / bị rate-limit chặn).
- **Cách dùng** (`http://127.0.0.1:9090`):
  1. **Status ▸ Targets** → `juice-shop` = **UP** (scrape OK; DOWN = không tới được endpoint).
  2. **Graph** → gõ metric (vd `http_requests_count`) rồi **Execute** → xem **Table** (giá trị) / **Graph** (đồ thị). Ngôn ngữ = **PromQL**.
  3. **Alerts** → trạng thái luật (Inactive → Pending → **Firing**).
- **Demo FIRING:** `python report/demos/tv3_f03_metrics.py` (đẩy 4XX vượt ngưỡng).
- **Prometheus vs Grafana:** Prometheus = lấy + lưu + cảnh báo (bộ não); Grafana = đọc từ Prometheus để **vẽ dashboard** (màn hình). Có thể demo chỉ bằng Prometheus (Targets UP + Alerts FIRING).
- **Câu "mục đích chính" gọn:** *"Prometheus định kỳ tự lấy số liệu từ /metrics, lưu theo thời gian và tự bắn cảnh báo khi bất thường — lớp phát hiện lúc chạy ở pha Operate; chính vì lấy qua mạng nội bộ nên F03 chặn /metrics từ host mà giám sát vẫn chạy."*

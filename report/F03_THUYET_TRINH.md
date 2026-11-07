# F03 — Tài liệu thuyết trình & demo: Lộ endpoint /metrics không xác thực (Đỗ Đức Quốc Anh)

> Dựa trên `report/SLIDE_BaoCao_JuiceShop.pptx` (slide 12 bộ luật, **slide 18 F03**, **slide 25 phần việc thành viên 3/4**) và báo cáo `report/BaoCao_DevSecOps_JuiceShop_gon.docx` mục 5.3 (Bảng 9), Phụ lục B.
> Mọi output là **kết quả chạy thật** trên lab (ngày 06–07/11/2026), chạy lại được bằng lệnh kèm theo.

> ⚠️ **ĐỌC MỤC 9 TRƯỚC KHI THUYẾT TRÌNH.** Khi chuẩn bị tài liệu này đã phát hiện proxy sau vá **bị vượt bằng chữ hoa**: `GET 127.0.0.1:3102/METRICS` trả **200, đủ 393 dòng số liệu**; `POST /REST/USER/LOGIN` **không bị giới hạn tốc độ**. Có bản sửa nginx đã kiểm chứng (mục 9.1). Nên áp dụng trước buổi thuyết trình, hoặc ít nhất chuẩn bị câu trả lời trung thực.

Mục lục: 1. Thông điệp chính · 2. Kịch bản nói slide 18 · 3. Demo từng bước · 4. Kịch bản nói slide 25 · 5. Cấu hình đã sửa (compose + nginx) · 6. Giải thích mã `compose.rego`, `compose_test.rego`, `runtime.rego` · 7. Hậu quả an ninh · 8. Vì sao F03 cần `.rego` · 9. Giới hạn đã kiểm chứng + bản sửa · 10. Hướng mở rộng · 11. Câu hỏi phản biện · 12. Chất liệu "chém gió" · 13. Checklist trước giờ G

---

## 1. Thông điệp chính (học thuộc)

1. **F03 là lỗi CẤU HÌNH triển khai, không phải lỗi mã.** `/metrics` không cần đăng nhập là thiết kế bình thường của Prometheus; lỗi là file compose **mở thẳng cổng backend ra host**, ai tới được host cũng đọc được.
2. **Sửa bằng kiến trúc mạng:** backend vào mạng `internal`, không còn cổng host; chỉ reverse proxy nginx là lối vào, nginx trả 404 cho `/metrics`; giám sát nội bộ vẫn đọc được.
3. **Chống tái diễn bằng Policy as Code:** luật **NET-02** trong `compose.rego` chặn ở pha **Deploy** (trước `docker compose up`), và cùng ý đó trong `runtime.rego` kiểm lại **container đang chạy** ở pha **Operate**.

**Câu mở màn 30 giây:** "Lỗi của em không nằm trong một dòng code nào — mã ứng dụng không đổi. Nó nằm ở một dòng cấu hình: `ports: 3000:3000`. Chỉ một dòng đó là đủ để số người dùng, số đơn hàng, tổng số dư ví của cửa hàng mở cho bất kỳ ai. Em sửa bằng kiến trúc mạng, và viết luật để dòng đó không bao giờ quay lại."

---

## 2. Kịch bản nói — Slide 18 (F03), ~3–4 phút + demo

**[Mở đầu — chỉ ô F03 và các nhãn]**
"Em là Đỗ Đức Quốc Anh, phụ trách F03 — lộ endpoint /metrics không xác thực. Thuộc nhóm OWASP A05 *Sai cấu hình bảo mật*; đối chiếu GDPR Điều 25(2) — theo mặc định không mở dữ liệu cho người không xác định — và Điều 32; nằm ở pha Deploy → Operate."

**[Lỗi — chỉ ô LỖI, rồi khung "Trước khi sửa"]**
"Juice Shop dùng thư viện `prom-client` mở sẵn đường `/metrics` để hệ thống giám sát Prometheus lấy số liệu. Đường này không yêu cầu đăng nhập — điều đó bình thường nếu chỉ hệ thống giám sát nội bộ gọi được. Vấn đề là dòng `ports: ["3000:3000"]` trong docker-compose: nó mở thẳng cổng của container ra máy chủ, nên mọi chủ thể tới được host đều đọc được. Đây là lỗi khâu triển khai, không phải lỗi mã nguồn."

**[Impact]**
"Hậu quả: lộ số liệu vận hành — số người dùng, số đơn hàng, tổng số dư ví, bộ nhớ, thời gian chạy. Kẻ tấn công dùng để trinh sát hệ thống và suy ra quy mô kinh doanh. Nghiêm trọng hơn: khi backend có cổng riêng thì mọi kiểm soát đặt ở proxy, như giới hạn số lần đăng nhập, đều bị vòng qua."

**[Phát hiện — 2 lớp]**
"Em phát hiện ở hai lớp. Lớp vận hành: gọi `/metrics` từ host thấy trả 200 với hàng trăm dòng — nhưng cách này chỉ thấy lỗi *sau khi* đã triển khai. Nên lớp thứ hai là lớp cấu hình: luật `compose.rego`, luật NET-02, đọc chính file compose và chặn mọi service không phải dịch vụ biên mà lại mở cổng ra host — chạy ở cổng pha Deploy, trước khi triển khai. Giống F04 dùng Rego cho Dockerfile, F03 dùng Rego cho file compose."

**[Cách sửa — chỉ khung "Sau khi sửa"]**
"Em đưa backend vào mạng `internal`, bỏ cổng host; chỉ nginx là lối vào và trả 404 cho `/metrics`. Prometheus vẫn đọc `/metrics` qua mạng nội bộ. Luật `compose.rego` gác để lỗi không quay lại."

**[Demo]** → mục 3 (Demo A rồi Demo B).

**[Chốt + chuyển]** "Cùng một luật NET-02 gác ở hai thời điểm: trên file compose trước khi triển khai, và trên container thật khi đang chạy. Em xin chuyển lời cho bạn Vũ trình bày F04."

---

## 3. Demo từng bước

### 3.0 Chuẩn bị (TRƯỚC buổi, không làm trên sân khấu)
PowerShell, thư mục gốc repo `E:\banhoaqua\juice-shop`:
```powershell
docker start juice-report-lab        # TRƯỚC vá: image gốc, 127.0.0.1:3100
docker compose up -d                 # SAU vá: proxy 127.0.0.1:3102, backend chỉ trong mạng internal
docker compose ps                    # juice-shop "healthy", proxy "running"
docker compose -f docker-compose.monitoring.yml up -d   # Prometheus 127.0.0.1:9090, Grafana 127.0.0.1:3103 (cho phần cảnh báo)
docker pull openpolicyagent/conftest:v0.71.1             # kéo sẵn để demo không phải chờ tải
```
Chạy thử cả Demo A và Demo B một lần. Phóng to chữ terminal.

> Lưu ý: bản `report/demos/tv3_f03_metrics.py` có bảng Conftest hiện ở thư mục `main` (chưa commit) — chạy demo từ `E:\banhoaqua\juice-shop`.

### 3.1 Demo A — chứng minh lỗi và bản vá: `python report/demos/tv3_f03_metrics.py`

Output thật:
```
Môi trường  Truy cập                                           Kết quả   Kết luận
----------  -------------------------------------------------  --------  ---------------------------------
trước vá    GET 127.0.0.1:3100/metrics                         200       LỘ: 393 dòng metrics
sau vá      GET 127.0.0.1:3102/metrics (qua proxy)             404       chặn tại proxy
sau vá      GET 127.0.0.1:3102/ (trang chủ)                    200       ứng dụng vẫn hoạt động
sau vá      GET 127.0.0.1:3101/metrics (cổng backend cũ)       refused   không còn đường vòng
sau vá      docker inspect cổng host của backend               không có  backend chỉ ở mạng internal
sau vá      giám sát nội bộ: proxy -> juice-shop:3000/metrics  đọc được  393 dòng, chỉ trong mạng internal

Cấu hình compose                   Exit  Luật bị chặn (FAIL)    Kết luận
---------------------------------  ----  ---------------------  --------------------
compose.before-f03.yml (trước vá)  1     F03 NET-02 juice-shop  đúng: gate chặn
docker-compose.yml (sau vá)        0     -                      đúng: đạt chính sách
```

Nói theo từng dòng (script làm gì bên trong → ý nghĩa):
| Dòng | Script làm gì | Nói |
|---|---|---|
| 3100/metrics → 200, 393 dòng | HTTP GET bằng `urllib` tới bản gốc, đếm dòng | "Bản gốc: không đăng nhập vẫn đọc 393 dòng số liệu — đây là lỗi." |
| 3102/metrics → 404 | GET qua nginx | "Bản vá: proxy chặn." |
| 3102/ → 200 | GET trang chủ | "Chức năng vẫn chạy — vá không làm hỏng ứng dụng." |
| 3101 → refused | GET thẳng cổng backend cũ | "Không còn đường vòng qua proxy." |
| docker inspect → không có | `docker inspect juice-app-juice-shop-1 --format {{json .HostConfig.PortBindings}}` | "Chính Docker xác nhận backend không publish cổng nào." |
| proxy → juice-shop:3000/metrics → đọc được | `docker exec juice-app-proxy-1 wget -qO- http://juice-shop:3000/metrics` | "Giám sát nội bộ vẫn hoạt động — chặn từ ngoài chứ không khóa tuyệt đối." |
| Bảng 2 | `conftest test <file> -p policy --namespace compose` cho từng file | "Luật bắt đúng file cũ, cho qua file mới." |

### 3.2 Demo B — cho thấy CÔNG CỤ QUÉT tự tìm ra F03

**B1. Quét file cấu hình trước vá** (bắt trước khi triển khai):
```powershell
docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test report/fixtures/compose.before-f03.yml -p policy --namespace compose --no-color
```
Output thật — **exit 1**:
```
WARN - ... - [CIS Docker 5.12] service 'juice-shop' has a writable root filesystem
FAIL - ... - [F03 NET-02] service 'juice-shop' publishes ports but is not an edge service (label lab.exposure=edge); backend must only be reachable through the proxy
7 tests, 5 passed, 1 warning, 1 failure, 0 exceptions
```
Nói: "File cũ: backend mở `127.0.0.1:3101`. Luật NET-02 chặn, exit 1. Dòng WARN chỉ là khuyến nghị (root filesystem ghi được), không chặn."

**B2. Quét file sau vá** (không chặn nhầm):
```powershell
docker run --rm -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test docker-compose.yml -p policy --namespace compose --no-color
```
Output thật — **exit 0**: `7 tests, 6 passed, 1 warning, 0 failures`.

**B3. Quét CONTAINER ĐANG CHẠY** (đẩy `docker inspect` thẳng vào Conftest):
```powershell
docker inspect --format '{{json .}}' juice-report-lab | docker run --rm -i -v "${PWD}:/work:ro" -w /work openpolicyagent/conftest:v0.71.1 test - --parser json -p report/policy --namespace runtime --no-color
```
Output thật trên **bản gốc 3100** — **exit 1**:
```
FAIL - - runtime - F03 NET-02: non-edge container publishes 3000/tcp to the host
FAIL - - runtime - RES-02: CPU quota must be bounded
FAIL - - runtime - RES-03: PID count must be bounded
8 tests, 5 passed, 0 warnings, 3 failures, 0 exceptions
```
Đổi `juice-report-lab` → `juice-app-juice-shop-1` (backend sau vá): `8 tests, 8 passed` — **exit 0**. (Proxy `juice-app-proxy-1` cũng 8/8: có cổng nhưng mang nhãn `edge`.)
Nói: "Không đọc file nữa mà hỏi thẳng Docker container đang chạy được cấu hình thế nào. Bản gốc publish 3000 ra 3100 và không có nhãn edge → NET-02 báo đúng F03. RES-02/RES-03 là phát hiện phụ: bản gốc chạy `docker run` mặc định, không giới hạn CPU và số tiến trình — không thuộc F03."

**B4 (tùy chọn, hiệu ứng mạnh nhưng sửa file thật):** thêm `ports: ["127.0.0.1:3101:3000"]` vào service `juice-shop` trong `docker-compose.yml`, chạy (Git Bash) `bash devsecops/pipeline.sh --full --no-apply deploy` → cổng "Conftest — docker-compose.yml" FAIL; **trả lại ngay**: `git checkout -- docker-compose.yml`. *(Chưa chạy thử bước này — tập trước nếu dùng; B1 cho kết quả tương đương mà an toàn.)*

### 3.3 Demo C (tùy chọn) — cảnh báo Grafana "FIRING"

Luật thật trong `deploy/monitoring/alerts.yml`:
```yaml
- alert: HighClientErrorRate
  expr: sum(increase(http_requests_count{status_code="4XX"}[2m])) > 20
  for: 0m
```
- Nghĩa: trong 2 phút gần nhất, **ứng dụng** trả hơn 20 phản hồi 4XX → cảnh báo kích hoạt ngay.
- **Bẫy:** mã 429 do **nginx** trả, ứng dụng không đếm. Đăng nhập sai qua proxy bị giới hạn 5 lần/phút nên khó vượt 20 trong 2 phút. Cách chắc ăn: gọi một API cần đăng nhập mà không gửi token, ứng dụng trả 401:
```powershell
1..25 | ForEach-Object { try { Invoke-WebRequest http://127.0.0.1:3102/api/Users -UseBasicParsing } catch {} } | Out-Null
```
- Đã chạy thử: 25 lần đều 401. Cảnh báo ở trạng thái `firing` (trạng thái này còn do các lần thử trước đó). Muốn thấy chuyển trạng thái: để yên **hơn 2 phút** không có lỗi cho cảnh báo về `inactive`, rồi chạy lệnh trên, mở `http://127.0.0.1:9090/alerts` hoặc Grafana `http://127.0.0.1:3103`.
- Nói: "Lớp cuối cùng: khi có người dò quét làm lỗi 4XX tăng vọt, cảnh báo bật — mã nguồn không tự biết điều này."

### 3.4 Dự phòng khi demo hỏng
- Mở ảnh `report/screenshots/tv3.png` (đúng output Demo A) và log `report/evidence/tv3-f03.log`.
- Nếu container không chạy: chỉ chạy Demo B1/B2 (không cần container, chỉ cần Docker).

---

## 4. Kịch bản nói — Slide 25 (phần việc thành viên 3/4), ~1,5 phút

"Em là Đỗ Đức Quốc Anh, B26CHAT001, phụ trách hạ tầng triển khai và vận hành — pha 1, 2, 6, 7.
- **Pha 1**, Docker Compose: em viết `docker-compose.yml` và `deploy/nginx.conf`, chia mạng `edge` (phía ngoài) và `backend` (phía trong, `internal: true`); dựng 2 môi trường đối chứng 3100 (gốc) và 3102 (proxy + backend không cổng host).
- **Pha 2**, Conftest + `compose.rego`: chặn dịch vụ không phải edge mà mở cổng host — 6 ca kiểm thử.
- **Pha 6**, `docker inspect` qua `checks/hardening.py` và `runtime.rego`: kiểm container đang chạy — cổng host, user, cap_drop.
- **Pha 7**, Prometheus + Grafana: lấy `/metrics` qua mạng nội bộ, dashboard, cảnh báo `HighClientErrorRate`.
Nginx: `/metrics` → 404, đăng nhập 5 lần/phút → 429, header `nosniff` và `no-referrer`, log JSON tối giản. Gia cố container: non-root, `cap_drop: ALL`, `no-new-privileges`, giới hạn CPU/PID.
Kết quả: `/metrics` qua proxy 404 (trước 200, 393 dòng); 0 cổng host của backend; 6/6 ca compose.rego và cảnh báo đã FIRING thật."

---

## 5. Cấu hình đã sửa — giải thích

### 5.1 `docker-compose.yml` (phần liên quan F03)
```yaml
services:
  proxy:
    read_only: true
    ports: ["127.0.0.1:3102:8080"]
    labels: {lab.exposure: edge}          # dịch vụ duy nhất được phép publish cổng (policy/compose.rego)
    networks: [edge, backend]
  juice-shop:
    labels: {lab.exposure: internal}      # không có khóa ports: không truy cập trực tiếp từ host
    networks: [backend]
networks:
  edge: {}
  backend: {internal: true}               # không có đường ra ngoài và không publish cổng
```
- `ports: ["127.0.0.1:3102:8080"]`: chỉ proxy mở cổng, và chỉ gắn vào `127.0.0.1` (loopback) — máy khác trong mạng không vào được.
- `labels: {lab.exposure: edge}`: nhãn nhóm tự đặt, đánh dấu "dịch vụ biên"; luật NET-02 dựa vào nhãn này.
- Backend **không có khóa `ports`** và chỉ ở mạng `backend`.
- `internal: true`: mạng Docker không có đường ra Internet và không publish được cổng — container chỉ nói chuyện với nhau.
- Proxy ở **cả hai** mạng: nhận yêu cầu ở `edge`, chuyển vào backend qua `backend`.

### 5.2 `deploy/nginx.conf` (dòng liên quan)
| Dòng | Nghĩa |
|---|---|
| `location = /metrics { return 404; }` | So khớp **chính xác** `/metrics` → trả 404 |
| `location ^~ /metrics/ { return 404; }` | Mọi đường bắt đầu bằng `/metrics/` → 404 (`^~`: ưu tiên, không xét regex) |
| `location = /rest/user/login { limit_req zone=login burst=5 nodelay; limit_req_status 429; ... }` | Đăng nhập: tối đa 5 yêu cầu/phút/IP (`limit_req_zone ... rate=5r/m`), cho dồn 5 yêu cầu (`burst=5 nodelay`), vượt → **429** |
| `location / { proxy_pass http://juice-shop:3000; }` | Mọi đường khác chuyển vào backend |
| `add_header X-Content-Type-Options nosniff` / `Referrer-Policy no-referrer` | Header bảo mật: trình duyệt không đoán kiểu tệp; không gửi URL nguồn sang trang khác |
| `server_tokens off` | Không lộ phiên bản nginx |
| `log_format security ...` + `map $uri $safe_route` | Log JSON chỉ ghi thời điểm, mã yêu cầu, IP, phương thức, route đã chuẩn hóa, mã trạng thái, thời gian; không ghi thân yêu cầu |

> Xem **mục 9.1**: hai `location = ...` phân biệt hoa thường → bị vượt bằng `/METRICS`, `/REST/USER/LOGIN`.

---

## 6. Giải thích mã Rego

### 6.1 `policy/compose.rego` — luật cho file compose (chạy ở pha Deploy)
Conftest tự đọc YAML thành JSON: `input.services` là một **đối tượng** `{tên_service: cấu_hình}`.

```rego
package compose
import rego.v1
```
Gói `compose` (gọi bằng `--namespace compose`), cú pháp Rego v1.

```rego
host_ip(p) := split(p, ":")[0] if { is_string(p); count(split(p, ":")) == 3 }
host_ip(p) := "" if { is_string(p); count(split(p, ":")) < 3 }
host_ip(p) := "" if is_number(p)
host_ip(p) := object.get(p, "host_ip", "") if is_object(p)
```
Hàm lấy IP gắn cổng, xử lý **cả 3 cú pháp `ports` của Compose**:
- `"127.0.0.1:3102:8080"` (3 phần) → `"127.0.0.1"`;
- `"3102:8080"` (2 phần) → `""` (nghĩa là mọi giao diện mạng);
- số `3000` → `""`;
- dạng đối tượng `{target, published, host_ip}` → lấy trường `host_ip`, thiếu thì `""`.
Bốn định nghĩa cùng tên = bốn trường hợp; điều kiện sau `if` quyết định trường hợp nào áp dụng.

```rego
ports(svc) := object.get(svc, "ports", [])
edge(svc) if object.get(object.get(svc, "labels", {}), "lab.exposure", "") == "edge"
```
- `ports(svc)`: danh sách cổng, không có thì mảng rỗng (`object.get` tránh lỗi khi thiếu trường).
- `edge(svc)`: đúng khi service có nhãn `lab.exposure: edge`.

```rego
# F03 / NET-02
deny contains msg if {
	some name, svc in input.services
	count(ports(svc)) > 0
	not edge(svc)
	msg := sprintf("[F03 NET-02] service '%s' publishes ports but is not an edge service ...", [name])
}
```
**Luật cốt lõi của F03.** Với mỗi service (`some name, svc in` duyệt cả tên và cấu hình): có cổng **VÀ** không phải edge → 1 FAIL. Kiểu **mặc định từ chối**: không cần liệt kê "backend nào bị cấm", mọi thứ không tự khai là biên đều bị cấm mở cổng. Lưu ý: **không quan tâm IP** — `127.0.0.1:3101` vẫn bị chặn, vì vấn đề là *vòng qua proxy*.

```rego
# NET-01
deny contains msg if {
	some name, svc in input.services
	some p in ports(svc)
	host_ip(p) != "127.0.0.1"
	msg := sprintf("[GDPR Art.32 NET-01] service '%s' publishes %v on all interfaces", [name, p])
}
```
Cổng nào được mở (kể cả của proxy) phải gắn `127.0.0.1`. `"3102:8080"` → IP rỗng → FAIL.

```rego
deny contains msg if { some name, svc in input.services; svc.privileged == true; msg := ... "[CIS Docker 5.4] ... runs privileged" }
deny contains msg if { some name, svc in input.services; some v in object.get(svc, "volumes", []); contains(sprintf("%v", [v]), "docker.sock"); msg := ... "[CIS Docker 5.31] ... mounts the Docker socket" }
```
- Cấm `privileged: true` (container gần như toàn quyền host).
- Cấm mount `docker.sock`: `sprintf("%v", [v])` biến volume (chuỗi hoặc đối tượng) thành chuỗi để tìm "docker.sock".

```rego
env(svc) := [e | some e in svc.environment] if is_array(svc.environment)
env(svc) := [sprintf("%s=%v", [k, v]) | some k, v in svc.environment] if is_object(svc.environment)
env(svc) := [] if not svc.environment

deny contains msg if {
	some name, svc in input.services
	some e in env(svc)
	regex.match(`(?i)^[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY)=.+`, e)
	msg := ... "[PCI-DSS 8.2.1 / GDPR Art.32] ... inline secret in environment: %s"
}
```
- `env(svc)` chuẩn hóa 2 cú pháp `environment` (danh sách `KEY=value` hoặc map `{KEY: value}`) thành danh sách chuỗi `KEY=value`.
- Regex: tên biến **kết thúc** bằng PASSWORD/SECRET/TOKEN/API_KEY, ngay sau là `=` và có giá trị → FAIL. Vì tên phải kết thúc đúng như vậy rồi tới `=`, biến `POSTGRES_PASSWORD_FILE` **không khớp** → được phép (trỏ tới tệp secret).

```rego
warn contains msg if { ... not drops_all_caps(svc) ... "[CIS Docker 5.3] ... does not drop capabilities" }
warn contains msg if { ... not svc.read_only ... "[CIS Docker 5.12] ... writable root filesystem" }
```
Hai **cảnh báo** (không chặn): nên `cap_drop: [ALL]` và `read_only: true`. Backend Juice Shop cần ghi tệp (SQLite, upload) nên còn WARN 5.12 — đó là dòng WARN trong demo.

### 6.2 `policy/compose_test.rego` — 6 ca kiểm thử cho chính bộ luật
Mẫu: `backend` (không cổng, `cap_drop: ALL`, `read_only`) và `proxy` = backend + cổng `127.0.0.1:3102:8080` + nhãn edge.

| Ca | Đầu vào | Kỳ vọng | Ý nghĩa |
|---|---|---|---|
| `test_backend_publishing_port_denied` | backend có `127.0.0.1:3101:3000` | có "F03 NET-02" | Kịch bản F03, chặn dù đã loopback |
| `test_only_proxy_publishes_passes` | proxy có cổng, backend không | `count(deny) == 0` | Không chặn nhầm cấu hình sau vá |
| `test_edge_on_all_interfaces_denied` | proxy `"3102:8080"` | có "NET-01" | Mở ra mọi giao diện |
| `test_long_syntax_port_checked` | `{target: 8080, published: 3102}` | có "NET-01" | Cú pháp đối tượng không lách được |
| `test_inline_secret_in_env_map_denied` | `POSTGRES_PASSWORD: "x"` | có "inline secret" | Mật khẩu viết thẳng |
| `test_secret_file_reference_allowed` | `POSTGRES_PASSWORD_FILE: /run/secrets/db` | `count(deny) == 0` | `*_FILE` được phép |

Chạy: `conftest verify -p policy` → 19/19 (13 Dockerfile + 6 compose). Ý nghĩa: **kiểm thử cả công cụ kiểm thử** — mỗi lần sửa luật, verify chạy lại.

### 6.3 `report/policy/runtime.rego` — phần NET-02 lúc chạy (pha Operate)
```rego
labels := object.get(object.get(input, "Config", {}), "Labels", {})
exposure := object.get(labels, "lab.exposure", "") if is_object(labels)
exposure := "" if not is_object(labels)

deny contains msg if {
    exposure != "edge"
    some port, binds in object.get(input.HostConfig, "PortBindings", {})
    count(binds) > 0
    msg := sprintf("F03 NET-02: non-edge container publishes %s to the host", [port])
}
```
- Đầu vào là JSON của `docker inspect`: nhãn nằm ở `Config.Labels`, cổng publish ở `HostConfig.PortBindings` (ví dụ `{"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3100"}]}`).
- `Labels` có thể `null` → `is_object` để luôn có giá trị.
- Container không phải edge mà có cổng bind → FAIL. Đây là lý do bản gốc `juice-report-lab` bị báo F03 trong Demo B3.
- Các luật khác trong file (RES-02 CPU, RES-03 PID, PRIV-01..04, NET-01) kiểm gia cố container; có 7 ca trong `runtime_test.rego`.

---

## 7. Hậu quả an ninh — và vì sao

| Vấn đề | Hậu quả | Vì sao |
|---|---|---|
| `/metrics` lộ ra ngoài (F03) | Lộ số người dùng, số đơn hàng, tổng số dư ví, bộ nhớ, uptime | Trinh sát: biết quy mô kinh doanh, biết lúc nào hệ thống tải cao để tấn công; số liệu nghiệp vụ không nên công khai (GDPR 25(2): mặc định không mở cho người không xác định) |
| Backend có cổng host (vòng qua proxy) | **Mọi** kiểm soát ở proxy mất tác dụng: chặn `/metrics`, giới hạn đăng nhập, header bảo mật, log | Proxy chỉ bảo vệ được những gì đi qua nó; có cửa phụ thì cửa chính vô nghĩa |
| Không giới hạn tốc độ đăng nhập | Dò mật khẩu tự động (brute-force, credential stuffing) không giới hạn | Kết hợp F01 trước vá thì còn tệ hơn |
| Cổng mở ra mọi giao diện (NET-01) | Máy khác trong mạng (Wi-Fi quán, mạng công ty) truy cập được dịch vụ lab | `0.0.0.0` lắng nghe trên mọi card mạng |
| `privileged` / mount `docker.sock` | Chiếm container = chiếm máy chủ | `docker.sock` là API điều khiển Docker: tạo container mới mount `/` của host |
| Mật khẩu viết thẳng trong compose | Lộ qua repo Git, qua `docker inspect` | File compose thường được commit |

---

## 8. Vì sao F03 cần `.rego` (câu hỏi chắc chắn bị hỏi)

- **Semgrep (SAST) không thấy F03:** Semgrep đọc mã nguồn; F03 nằm trong cấu hình triển khai.
- **Gọi HTTP `/metrics` (kiểm thử động) chỉ thấy *triệu chứng* sau khi đã triển khai** — dữ liệu đã lộ rồi mới biết.
- **`compose.rego` thấy *nguyên nhân* ngay trong file**, trước `docker compose up` → shift-left. Pipeline: `conftest test docker-compose.yml -p policy --namespace compose` (`devsecops/pipeline.sh:228`); FAIL thì không chạy `deploy_apply` (`pipeline.sh:231`).
- **`runtime.rego` bắt container chạy ngoài pipeline** (ví dụ ai đó `docker run -p ...` tay) — chính là trường hợp `juice-report-lab` trong Demo B3.
- **Vì sao NET-01 không đủ:** `127.0.0.1:3101` vẫn là loopback nên NET-01 cho qua, nhưng nó vẫn vòng qua proxy → cần NET-02.

---

## 9. Giới hạn ĐÃ KIỂM CHỨNG — và bản sửa

### 9.1 ⚠️ Proxy bị vượt bằng chữ hoa (phát hiện 07/11/2026)

**Thử thật trên proxy 3102:**
```
GET /metrics      -> 404        GET /Metrics  -> 200, 393 dòng (METRICS LỘ)
GET /metrics/     -> 404        GET /METRICS  -> 200, 393 dòng (METRICS LỘ)
GET /metrics?x=1  -> 404        GET //metrics -> 404      GET /api/../metrics -> 404

POST /REST/USER/LOGIN x12 -> [401 x12]                 (KHÔNG bao giờ 429)
POST /rest/user/login x12 -> [401 x6, 429 x6]          (giới hạn hoạt động)
```
**Nguyên nhân:** nginx `location = /metrics` và `location = /rest/user/login` **phân biệt hoa thường**; còn Express (backend) mặc định định tuyến **không phân biệt hoa thường**. `/METRICS` không khớp `location = /metrics` → rơi vào `location /` → chuyển vào backend → Express coi như `/metrics` → trả số liệu. Bài học tổng quát: **proxy và backend phải chuẩn hóa đường dẫn giống nhau** (lỗi kiểu "path normalization mismatch").

**Bản sửa (đã kiểm chứng trên một nginx thử nghiệm cùng image, cùng mạng backend, cổng 3199 — proxy thật không bị đụng):**
```nginx
    map $uri $safe_route {
        default "other";
        ~*^/rest/user/login/?$ "/rest/user/login";
        ~*^/metrics(/|$) "/metrics";
        ~^/rest/basket/[0-9]+/checkout$ "/rest/basket/:id/checkout";
    }
    ...
        # Express định tuyến KHÔNG phân biệt hoa thường và chấp nhận '/' cuối -> so khớp bằng regex ~* cho cùng phạm vi
        location ~* ^/metrics(/|$) { return 404; }
        location ~* ^/rest/user/login/?$ {
            limit_req zone=login burst=5 nodelay;
            limit_req_status 429;
            proxy_pass http://juice-shop:3000;
        }
        location / { proxy_pass http://juice-shop:3000; }
```
(`~*` = regex không phân biệt hoa thường. Regex location được nginx xét trước `location /` thường, nên thắng.)

Kết quả thật với bản sửa: `nginx -t` hợp lệ; `/metrics`, `/metrics/`, `/Metrics`, `/METRICS`, `/mEtRiCs/` → **404**; `/` và `/rest/products/search?q=apple` → **200**; `POST /REST/USER/LOGIN` x8 → `[401 x6, 429, 429]`.

**Áp dụng (khi nhóm đồng ý):** thay 2 `location` + 2 dòng `map` trong `deploy/nginx.conf`, rồi `docker compose restart proxy`; kiểm lại: `curl -s -o NUL -w "%{http_code}" http://127.0.0.1:3102/METRICS` phải ra `404`. Nên thêm kiểm `/METRICS` vào `check_metrics` của `pipeline.sh` (hiện chỉ kiểm `/metrics` chữ thường) và thêm 1 dòng vào demo tv3.

**Nếu CHƯA sửa kịp mà bị hỏi:** nói thẳng — "Nhóm đã tự kiểm và phát hiện nginx so khớp phân biệt hoa thường trong khi Express không phân biệt, nên `/METRICS` vượt được proxy. Bản sửa dùng regex không phân biệt hoa thường đã kiểm chứng; đây là bài học về chuẩn hóa đường dẫn giữa proxy và backend." Đừng phủ nhận — hội đồng có thể thử ngay.

> Lưu ý: điểm mấu chốt của F03 (backend **không có cổng host**) vẫn đứng vững — lỗ này nằm ở lớp lọc đường dẫn của proxy, không phải ở kiến trúc mạng. Cổng 3101 vẫn `refused`.

### 9.2 Luật `compose.rego` chưa bắt được (đã chạy thử)
| Cấu hình thử | Kết quả | Hậu quả | Hướng vá luật |
|---|---|---|---|
| Backend `network_mode: host` (không khóa `ports`) | **exit 0** | Backend dùng chung mạng máy chủ → **mọi cổng** của nó mở trên host, vòng qua proxy hoàn toàn | Thêm luật: service không phải edge thì cấm `network_mode: host` |
| Backend **tự gắn** `labels: {lab.exposure: edge}` + `ports` | **exit 0** | Nhãn là tự khai → ai cũng "tự phong" là biên | Chỉ cho phép nhãn edge với danh sách service/image cố định (ví dụ image nginx đã ghim digest) |
| Cổng thêm trong `docker-compose.override.yml` | Pipeline chỉ quét `docker-compose.yml` | Compose tự gộp file override khi chạy → cổng lọt | Quét cấu hình **sau khi gộp**: `docker compose config` rồi đưa kết quả vào Conftest |
| `runtime.rego` với `network_mode: host` | `PortBindings` rỗng → NET-02 lúc chạy cũng không thấy *(suy luận từ mã luật, chưa dựng container thử)* | Như trên | Kiểm thêm `HostConfig.NetworkMode == "host"` |

---

## 10. Hướng mở rộng

**Ngắn hạn**
- Áp bản sửa nginx (9.1); thêm vào pipeline/demo kiểm các biến thể đường dẫn (`/METRICS`, `/metrics/`, `/REST/USER/LOGIN`).
- Vá 4 điểm của 9.2, mỗi điểm thêm 1 ca vào `compose_test.rego` (tìm lỗ → ca đỏ → sửa luật → xanh).
- Thêm ca kiểm thử cho các luật hiện chưa có ca: `CIS 5.4` privileged, `CIS 5.31` docker.sock, 2 luật warn.
- Đổi chiến lược ở proxy từ **chặn danh sách đen** (`/metrics` → 404) sang **danh sách trắng**: chỉ chuyển vào backend các tiền tố hợp lệ (`/`, `/api/`, `/rest/`, `/assets/`...) — đường lạ mặc định 404.

**Trung hạn**
- Bảo vệ `/metrics` thêm một lớp: Prometheus scrape bằng **bearer token** hoặc **mTLS**; hoặc cấu hình ứng dụng phục vụ metrics trên **cổng riêng** chỉ mở trong mạng nội bộ.
- Kiểm thử động tự động (**DAST**: OWASP ZAP baseline) trong pipeline để bắt kiểu lỗi như 9.1 mà kiểm thử tĩnh không thấy.
- Giới hạn tốc độ theo tài khoản (không chỉ theo IP) để chống credential stuffing qua nhiều IP.
- Cảnh báo theo **route**: dò đăng nhập (401 ở `/rest/user/login`) tách khỏi 4XX chung.

**Dài hạn**
- Lên Kubernetes: **NetworkPolicy** mặc định từ chối (chỉ Ingress → backend, chỉ Prometheus → `/metrics`); cùng ý NET-02 viết bằng Rego trong **OPA Gatekeeper** để cụm từ chối Service kiểu `NodePort/LoadBalancer` cho backend.
- Service mesh (mTLS giữa mọi dịch vụ, chính sách truy cập theo danh tính).

---

## 11. Câu hỏi phản biện — trả lời mẫu

1. **Sao không đặt mật khẩu cho `/metrics`?** — Làm được (Prometheus hỗ trợ basic auth/bearer token), nhưng tách mạng thì `/metrics` không tới được từ ngoài ngay từ đầu, đơn giản và chắc hơn. Hai cách kết hợp được (mục 10).
2. **Bind 127.0.0.1 rồi đâu có lộ?** — Vẫn lộ với mọi tiến trình/người trên máy chủ, và quan trọng hơn là vòng qua proxy → mất mọi kiểm soát ở proxy. Vì vậy cần NET-02, NET-01 không đủ.
3. **Số liệu `/metrics` có phải dữ liệu cá nhân không?** — Là số liệu tổng hợp, chưa định danh từng người; nhưng là thông tin nghiệp vụ không nên công khai. Báo cáo ghi rõ điều này.
4. **Sao chặn bằng 404 mà không 403?** — 404 không xác nhận đường đó tồn tại, giảm thông tin cho kẻ dò quét.
5. **Proxy có bị vượt không?** — Có, nhóm đã tự kiểm và tìm ra `/METRICS` (mục 9.1) cùng bản sửa. Trả lời thẳng, không phủ nhận.
6. **`lab.exposure: edge` ai cũng gắn được, có ý nghĩa gì?** — Đúng, nhãn tự khai; luật hiện tin nhãn. Hướng mở rộng: chỉ cho phép nhãn edge với image/service cố định, hoặc review bắt buộc khi đổi nhãn (CODEOWNERS).
7. **Sao không dùng firewall của máy chủ?** — Docker tự chèn luật iptables khi publish cổng, thường vượt qua firewall kiểu ufw; kiểm soát ở tầng compose/Docker network trực tiếp và kiểm được bằng mã.
8. **Prometheus đọc `/metrics` bằng cách nào khi backend không có cổng?** — Prometheus nằm trong mạng `backend`, gọi `juice-shop:3000/metrics` qua DNS nội bộ của Docker (Demo A dòng cuối: proxy đọc được).
9. **Nếu ai đó `docker run -p` tay ngoài pipeline?** — `runtime.rego` ở pha Operate kiểm `docker inspect` mọi container — Demo B3 chính là trường hợp này.
10. **Giới hạn 5 lần/phút có làm phiền người dùng thật?** — Hiếm ai đăng nhập quá 5 lần/phút; vượt chỉ phải chờ; đổi lại chặn dò mật khẩu tự động.
11. **Sao backend vẫn WARN CIS 5.12?** — Juice Shop cần ghi SQLite và tệp tải lên nên không bật `read_only` được; để mức cảnh báo, không chặn. Proxy thì đã `read_only`.
12. **Cảnh báo HighClientErrorRate có đếm 429 không?** — Không: 429 do nginx trả, số liệu lấy từ ứng dụng. Cảnh báo đếm 4XX ứng dụng trả (401, 403, 404...).

---

## 12. Chất liệu "chém gió"

- "Lỗi của em không có dòng code nào sai — nó nằm ở một dòng YAML. DevSecOps không chỉ là quét code, mà là quét cả **cách triển khai**."
- "Một cửa chính có bảo vệ mà còn cửa sau mở thì bảo vệ vô nghĩa. NET-02 là luật **khóa cửa sau**: mặc định không ai được mở cổng, trừ dịch vụ biên tự khai."
- "Chặn ở **hai thời điểm**: trên giấy (file compose) trước khi triển khai, và trên thực tế (container) khi đang chạy."
- "Kiểm thử động thấy triệu chứng, Policy as Code thấy nguyên nhân."
- "Chúng em tự tấn công bản vá của mình và tìm ra `/METRICS` — đây là lý do bảo mật phải nhiều lớp và phải tự kiểm liên tục." *(chỉ dùng câu này nếu đã áp bản sửa hoặc sẵn sàng nói về nó)*
- Câu chuyện thật nên biết (nói ngắn, không thêm chi tiết): nhiều sự cố lộ **dashboard/endpoint quản trị không xác thực** ra Internet — ví dụ năm 2018 cụm Kubernetes của Tesla bị dùng để đào tiền ảo vì bảng điều khiển Kubernetes không có mật khẩu (theo báo cáo của RedLock).

---

## 13. Checklist trước giờ G

- [ ] Quyết định với nhóm: **áp bản sửa nginx (mục 9.1)** hay chuẩn bị câu trả lời. Nếu áp: `docker compose restart proxy`, kiểm `/METRICS` → 404.
- [ ] Bật đủ: `juice-report-lab` (3100), `docker compose up -d` (3102), stack giám sát (9090/3103).
- [ ] Kéo sẵn `openpolicyagent/conftest:v0.71.1`; chạy thử Demo A, B1, B2, B3.
- [ ] Nếu dùng Demo C: để yên > 2 phút trước khi demo để cảnh báo về `inactive`.
- [ ] Mở sẵn tab: `docker-compose.yml`, `deploy/nginx.conf`, `policy/compose.rego`, `report/fixtures/compose.before-f03.yml`.
- [ ] Thuộc số: **393 dòng, 404, refused, 0 cổng host, NET-02, 6/6 ca, 19/19, 5 lần/phút → 429, >20 lỗi 4XX/2 phút**.
- [ ] Dự phòng: `report/screenshots/tv3.png`, `report/evidence/tv3-f03.log`.

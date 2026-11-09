# Kịch bản thuyết trình — OWASP Juice Shop (SEC4349)

Ý kĩ thuật. **Phần A** cả nhóm nói từ đầu (hạ tầng → mô hình → triển khai → luồng → DevSecOps). **Phần B** mỗi thành viên nói lỗi của mình.

---

## A. PHẦN CHUNG (cả nhóm, từ đầu)

### A1. Hạ tầng (infrastructure)
- **Docker + docker-compose** trên Windows/WSL2.
- Các container:
  - `juice-report-lab` — **image Juice Shop gốc**, publish `127.0.0.1:3100` (đối chứng, **trước vá**).
  - Stack `juice-app`: container **backend** (`juice-shop`, image hotfix, **không** mở cổng host) + container **proxy** (nginx, publish `127.0.0.1:3102`).
  - Stack giám sát: **Prometheus** (`127.0.0.1:9090`) + **Grafana** (`127.0.0.1:3103`).
- Mạng: backend ở **network `internal`** (không ra host); chỉ **reverse proxy** mở **loopback**.
- Nginx (reverse proxy): chặn `/metrics` (trả 404), **giới hạn tốc độ đăng nhập** (rate-limit).

### A2. Mô hình (kiến trúc)
- Single Page Application: **Angular** (frontend) → **REST API** → **Node.js/Express** (backend).
- Dữ liệu: **ORM Sequelize** trên **SQLite** (Users, Baskets, Cards…).
- Xác thực phiên: **JWT (RS256)**.
- Giám sát: **prom-client** → endpoint `/metrics`.
- Đóng gói: **Docker image distroless**, chạy **non-root (UID 65532)**.
- Mô hình thực nghiệm: **trước vá (3100)** ↔ **sau vá (3102)**, cố định các biến, chỉ thay đúng phần cần kiểm chứng.

### A3. Triển khai những gì
- **Trước vá:** container image Juice Shop gốc (3100).
- **Sau vá:**
  - **Hotfix image** = image gốc (ghim digest) + **2 route đã vá** (`login.js` F01, `fileServer.js` F02) COPY đè, thêm `USER 65532` + nhãn provenance OCI + HEALTHCHECK.
  - **Reverse proxy nginx**: chặn `/metrics`, rate-limit; backend đưa vào **mạng internal** → vá **F03**.
  - **Bộ luật Policy as Code** (Conftest/Rego) cho Dockerfile + `docker-compose` → **F04/F03**.
  - **Giám sát** Prometheus/Grafana + luật cảnh báo.
- **Vì sao triển khai thế — lợi ích:**
  - *Hotfix (COPY đè route thay vì build lại):* image gốc distroless không có toolchain, build lại cả app rất nặng → vá **nhanh, gọn**, giữ nguyên phần còn lại.
  - *Reverse proxy + backend mạng internal:* proxy là **điểm vào duy nhất** → tập trung chặn `/metrics`, rate-limit đăng nhập; backend **không lộ trực tiếp** ra host → **giảm bề mặt tấn công**.
  - *Non-root 65532 + cap_drop + no-new-privileges:* **phòng thủ chiều sâu** — nếu về sau có RCE, **khoanh vùng thiệt hại**, khó leo thang/thoát container.
  - *Hai môi trường 3100/3102:* **đối chứng công bằng** trước/sau vá — chứng minh vá có tác dụng mà **không hỏng chức năng**.

### A4. Luồng Juice Shop
- **Khách hàng làm gì (app bán nước ép):** vào trang → **duyệt / tìm sản phẩm nước ép**, xem chi tiết & đánh giá → **đăng ký / đăng nhập** → **thêm vào giỏ hàng**, chỉnh số lượng → **áp mã giảm giá (coupon)** → **đặt đơn & thanh toán** (địa chỉ giao + thẻ/ví) → **theo dõi đơn hàng**, sửa hồ sơ, gửi đánh giá/khiếu nại. Mỗi bước sinh/đụng tới **dữ liệu cần bảo vệ**: email/mật khẩu (đăng nhập), JWT (phiên), giỏ hàng, thẻ thanh toán, hồ sơ — đúng các dữ liệu mà 4 lỗi đe dọa.
- **Vòng đời request:** trình duyệt → Angular gọi REST → Express nhận (với tài nguyên cần quyền thì **lớp trung gian kiểm JWT**) → Sequelize/SQLite → trả JSON.
- **Nghiệp vụ chính:**
  - Đăng ký/đăng nhập: `POST /api/Users`, `POST /rest/user/login` → `login.ts` cấp JWT. *(gốc F01)*
  - Mua hàng: thêm **giỏ hàng** (Basket) → **đặt đơn/thanh toán** (Card/Order), mỗi request kèm JWT ràng buộc chủ sở hữu.
  - Tải tệp tĩnh: `GET /ftp/:file` → `fileServer.ts`, lọc đuôi `.md/.pdf`. *(gốc F02)*
  - Giám sát: `/metrics` (prom-client) xuất số liệu vận hành. *(gốc F03)*
- **Dữ liệu cần bảo vệ & cơ sở chính sách** (slide riêng, theo bảng ở mục 2 báo cáo + Phụ lục C):
  - *Bảng:* email/hồ sơ và giỏ hàng → chỉ chủ sở hữu truy cập (GDPR Đ.5(1)(f), 25(2)); mật khẩu, JWT → không vượt xác thực, chỉ cấp khi đúng (Đ.32(1)(b)); thẻ → không lộ số thẻ, PAN lưu ở dạng không đọc được (PCI-DSS 3.4); tệp cấu hình/sao lưu → không tải được qua endpoint tệp tĩnh (Đ.32(1)(b), F02).
  - *Đ.5(1)(f) — toàn vẹn & bảo mật:* xử lý dữ liệu ở mức an toàn thích hợp, chống truy cập/xử lý trái phép và mất mát, hư hỏng. → F02.
  - *Đ.25 — từ thiết kế & theo mặc định:* (1) đưa bảo vệ vào ngay khi thiết kế → F04; (2) mặc định không mở dữ liệu cho số người không xác định → F03 (`/metrics` mở sẵn cho mọi client).
  - *Đ.32 — an toàn khi xử lý:* (1)(b) bảo đảm bí mật, toàn vẹn, sẵn sàng → F01, F02; (1)(d) kiểm thử, đánh giá định kỳ hiệu quả biện pháp → pipeline tự kiểm mỗi lần build (F04).
  - *PCI-DSS 3.4:* số thẻ không đọc được ở mọi nơi lưu (băm một chiều, cắt bớt, token hóa, mã hóa mạnh). Không viện dẫn cho F02 vì tệp bị lộ là cấu hình, không phải dữ liệu thẻ.

### A5. DevSecOps gồm gì (Security as Code)
- **Security as Code (SaC) — khung tổng:** viết **mọi kiểm soát an toàn thành mã** (luật, kịch bản quét, ca kiểm thử, kiểm tuân thủ) đặt trong kho mã, chạy **tự động như các cổng** trong pipeline, **chặn phát hành** khi vi phạm (shift-left). Nhờ là mã nên **review qua pull request, version-control, lặp lại và truy vết** được — thay cho rà soát thủ công một lần. SaC là *cái ô* chứa các kỹ thuật con bên dưới.
- **Policy as Code (PaC) — một kỹ thuật con của SaC:** viết **chính sách an toàn của tổ chức thành luật** (ngôn ngữ **Rego**), chạy bằng **Conftest/OPA**. Kiểm **văn bản cấu hình** (Dockerfile, `docker-compose`) **trước khi triển khai**, trả PASS/FAIL + mã thoát → **cổng chặn** nếu vi phạm. Thứ tự: **viết luật → `verify` (unit test cho luật) → `test` (soi file thật)**. Khác SAST: SAST tìm *bug trong mã nguồn*, còn PaC *thực thi chính sách cấu hình* do tổ chức tự định nghĩa. Trong báo cáo: `compose.rego` (F03) + `docker_security.rego` (F04).
- **Pha vòng đời:** Plan → Code → Build → Test → Release → Deploy → Operate → Monitor.
- **Kỹ thuật con — công cụ — pha:**
  - **Phát hiện lỗ hổng (SAST/SCA):** Semgrep (SAST, pha Code), **Trivy** (SCA/CVE image, pha Release), Gitleaks (secret).
  - **Kiểm thử bảo mật (TDS):** node:test + Supertest (pha Test), đỏ trước vá → xanh sau vá.
  - **Policy as Code:** Conftest/Rego kiểm **văn bản** Dockerfile + compose **trước khi triển khai** (Build/Deploy).
  - **Compliance as Code:** **Dockle** kiểm **image thành phẩm** (Release) + `runtime.rego` trên `docker inspect` kiểm **container đang chạy** (Operate).
  - **Giám sát vận hành:** Prometheus/Grafana + cảnh báo (Monitor).
    - **Vai trò (chốt khi bị hỏi):**
      - `/metrics` — app Juice Shop *tự phơi* số liệu (qua `prom-client`, **có sẵn** trong Juice Shop; chỉ là trang text định dạng Prometheus, **không phải server**). Chính endpoint này là bề mặt của **F03**.
      - **Prometheus** (*nhóm dựng*) — **lấy** `/metrics` mỗi 10s, **lưu theo thời gian** (tạo lịch sử), **truy vấn** (PromQL: tốc độ/mức tăng) và **tự cảnh báo** khi bất thường. Đây là phần làm được việc mà 1 ảnh chụp `/metrics` không làm được.
      - **Grafana** (*nhóm dựng*) — chỉ **đọc từ Prometheus và vẽ dashboard** cho dễ nhìn.
      - Tóm: Juice Shop **phát** số liệu · Prometheus **thu thập + phát hiện** · Grafana **hiển thị**. Prometheus scrape **thẳng backend qua mạng nội bộ** (không qua proxy 3102 vì proxy chặn `/metrics`) → đúng F03: bịt lối ngoài, giám sát trong vẫn chạy.
- **Phân biệt hay bị hỏi:** PaC = kiểm *văn bản cấu hình trước build*; CaC = kiểm *thực thể đang chạy sau build*. Semgrep/Trivy/Gitleaks dùng **luật/CSDL có sẵn**; chỉ **Conftest + kiểm thử** là nhóm **tự viết**.
- **[Cue]** Chiếu **Hình quy trình DevSecOps** (ánh xạ F01–F04 lên pha).
- 4 tình huống: F01/F02 (code) · F03 (vận hành) · F04 (cấu hình container).

### A6. Pipeline tích hợp Git — chạy thế nào, output ra sao
- **Một câu:** mọi cổng trên sơ đồ gói trong **một script** `devsecops/pipeline.sh`; **Git tự gọi** nó mỗi khi sửa lỗi/đổi mã, nên máy thành viên và GitHub chạy **đúng cùng một bộ cổng**.
- **Ai kích hoạt (3 điểm, cùng một script):**
  - `git commit` → hook **pre-commit** (`.githooks/pre-commit`): chỉ **cổng tĩnh** trên phần đã `git add` — vài giây đến ~1 phút.
  - `git push` → hook **pre-push** (`.githooks/pre-push`): đủ **7 pha** trên các commit sắp đẩy, **triển khai thật lên 3102** trên máy rồi kiểm Operate/Monitor — ~2 phút, cần Docker đang chạy.
  - push nhánh `main` / `fix/**` / `tv-*`, pull request vào `main` → **GitHub Actions** `devsecops.yml`: đủ **7 pha**, mỗi pha một step, triển khai trên máy ảo của GitHub.
  - Hook được bật bằng `git config core.hooksPath .githooks` (`devsecops/install-hooks.sh`, mỗi máy một lần).
  - **Cơ chế chặn:** Git chạy hook **trước** khi commit/push; script trả **exit 1** → Git **hủy** thao tác. Trên GitHub, step exit 1 → **đỏ ❌**, các step sau không chạy.
- **Cổng nào chạy ở đâu:**

  | Pha | Cổng | Bắt gì | commit | push | GitHub Actions |
  |---|---|---|:-:|:-:|:-:|
  | Code | Gitleaks | Secret trong dòng **được thêm** | ✅ | ✅ | ✅ |
  | Code | Semgrep | Cảnh báo SAST **mới** so với bản gốc (F01) | ✅ | ✅ | ✅ |
  | Build | `conftest verify` | 26 ca unit test cho chính các luật Rego | ✅ | ✅ | ✅ |
  | Build | Conftest `docker_security.rego` | Dockerfile sai (F04: thiếu `USER`, cổng 22/3306, secret…) | ✅ | ✅ | ✅ |
  | Build | `tsc` + `docker build` | Lỗi biên dịch; tạo image **ứng viên** `ci-<sha>` | — | ✅ | ✅ |
  | Test | node:test + Supertest | 11 ca F01/F02 (gửi payload thật, đỏ nếu khai thác được) | — | ✅ | ✅ |
  | Release | Trivy | CVE **CRITICAL mới** (ngoài 11 CVE đã chấp nhận) | — | ✅ | ✅ |
  | Release | Dockle | Image vi phạm CIS (WARN/FATAL) | — | ✅ | ✅ |
  | Release | Gắn tag `hotfix-f01-f02` | Chỉ khi Test + Trivy + Dockle đều đạt | — | ✅ | ✅ |
  | Deploy | Conftest `compose.rego` | Compose sai (F03: backend mở cổng host, `0.0.0.0`, `privileged`, `docker.sock`…) | ✅ | ✅ | ✅ |
  | Deploy | `docker compose up --wait` | Container không lên / không healthy | — | ✅ 3102 | ✅ máy ảo |
  | Operate | `runtime.rego` trên `docker inspect` | Container **đang chạy** là root, thiếu `cap_drop`/`no-new-privileges`, không giới hạn CPU/PID (F04) | — | ✅ | ✅ |
  | Operate | Gọi HTTP qua proxy | `/`→200, `/metrics`→**404** (F03), header `nosniff`/`no-referrer`, đăng nhập dồn dập → **429** | — | ✅ | ✅ |
  | Monitor | Prometheus | Target `juice-shop` UP + luật `HighClientErrorRate` đã nạp (stack giám sát chưa chạy thì tự bật) | — | ✅ | ✅ |
  | | **Bỏ qua được bằng `--no-verify`?** | | có | có | **không** |

- **Vì sao commit chỉ chạy cổng tĩnh — không phải bypass:** commit còn nằm trên máy, chưa ảnh hưởng ai; các cổng chậm (build image, test, Trivy, triển khai) **dời sang push và CI**, không bị bỏ. Bắt mỗi commit chờ vài phút thì người ta quen gõ `--no-verify` — mất luôn cả Gitleaks/Semgrep. Cái phải chặn ngay ở commit là **secret** (đã vào lịch sử Git là coi như lộ).
- **Operate trong luồng push nghĩa là gì:** không phải giám sát production, mà là **kiểm tra ngay sau triển khai** trên 3102 (đóng vai staging) trước khi cho code lên GitHub. Cần vì có lỗi **chỉ lộ khi đã chạy**:
  - `nginx.conf` bỏ dòng chặn `/metrics` → không luật Rego nào đọc được file nginx, commit/Build/Deploy đều PASS; chỉ Operate gọi `GET /metrics` thấy **200** → chặn.
  - compose cho chạy root + bỏ `cap_drop` → `compose.rego` chỉ cảnh báo; `runtime.rego` trên container đang chạy **FAIL** (PRIV-02, PRIV-03) → chặn.
  - Phần "vận hành liên tục" đúng nghĩa là **Monitor** (Prometheus + cảnh báo chạy suốt).
- **Bên trong script (5 bước):**
  1. **Xác định phần thay đổi** — pre-commit: so phần đã `git add` với HEAD; pre-push: so với commit đang có trên GitHub; CI: so với commit trước/nhánh `main`; chạy tay: so với bản gốc v20.2.0.
  2. **Lọc** — Gitleaks luôn chạy; Semgrep chỉ khi đổi mã server; Test chỉ khi đổi mã ứng dụng; Build/Release/Deploy khi đổi mã **hoặc** hạ tầng (Dockerfile, compose, `deploy/`, policy, `devsecops/`). Chỉ sửa tài liệu → chỉ Gitleaks, Deploy không triển khai nên Operate/Monitor cũng SKIP. `--full` (hoặc chạy Actions tay với `full=true`) bỏ lọc.
  3. **Chạy các pha theo đúng sơ đồ** (bảng trên), mỗi cổng là một công cụ chạy trong Docker, ghim phiên bản như báo cáo.
  4. **In bảng kết quả** — mỗi cổng một dòng `Pha · Cổng · Trạng thái`; FAIL thì in kèm 20 dòng log ngay bên dưới.
  5. **Trả mã thoát** — 0 = đạt (WARN không chặn), 1 = có FAIL. Pha nào FAIL thì các pha sau **SKIP** (không build/deploy bản lỗi); riêng pre-commit chạy hết cổng tĩnh để thấy mọi lỗi một lần. pre-push đạt thì ghi dấu theo SHA → đẩy cùng commit lên nhánh thứ hai không chạy lại.
- **Output khi đạt** (chạy thật trên mã hiện tại):
  ```
  ══ DevSecOps pipeline · main@838b2531b ══
    Code     Semgrep — SAST, chặn cảnh báo mới               PASS
    Build    docker build — juice-shop:ci-838b2531b          PASS
    Test     node:test — test/api/security                   PASS
    Release  Gắn tag phát hành juice-shop:hotfix-f01-f02     PASS
    Operate  F03 — /metrics bị chặn (404)                    PASS
    …
  ══ Tổng: 20 PASS · 1 WARN · 0 FAIL · 0 SKIP — log: .devsecops/ ══
  ✓ Pipeline đạt.
  ```
- **Output khi bị chặn** (commit đưa lại lỗi F01 + khóa giả):
  ```
    Code     Gitleaks — quét secret                          FAIL  → .devsecops/01-Code.log
             │ WRN leaks found: 1   RuleID: generic-api-key
    Code     Semgrep — SAST, chặn cảnh báo mới               FAIL  → .devsecops/02-Code.log
             │ NEW  routes/login.ts:34  [express-sequelize-injection] …
  ✗ Pipeline FAIL — sửa lỗi ở cổng FAIL rồi chạy lại.        ← commit bị hủy
  ```
- **Đọc trạng thái:** **PASS** đạt · **WARN** cần biết nhưng **không chặn** (vd 5 tệp sửa ngoài 2 route không vào image hotfix — nói thẳng, đó là giới hạn) · **FAIL** vi phạm, **chặn** · **SKIP** không liên quan thay đổi hoặc pha trước đã FAIL.
- **Output lưu ở đâu:** log từng cổng `.devsecops/NN-<Pha>.log`; bảng tổng `.devsecops/summary.md`; trên GitHub: mỗi pha một step ✅/❌, bảng ở trang *Summary*, log tải ở *Artifacts*.
- **Chốt khi bị hỏi:**
  - *"Juice Shop đầy lỗ hổng cố ý, sao commit được?"* — cổng **chỉ chặn cái mới**: Semgrep so với bản gốc của cùng tệp (`devsecops/semgrep-diff.mjs`, nhận diện theo luật + nội dung dòng), Gitleaks chỉ quét dòng được thêm, Trivy bỏ qua danh sách rủi ro đã chấp nhận (`devsecops/.trivyignore`).
  - *"Trivy cứ ra CVE là chặn?"* — không: chỉ chặn CVE **CRITICAL** và **không nằm trong** `.trivyignore` (11 CVE có sẵn của image gốc). Image còn 173 CVE vẫn qua; chỉ đỏ khi thay đổi kéo thêm dependency có lỗi CRITICAL. Giới hạn: không chặn HIGH; danh sách chấp nhận chưa có người duyệt bắt buộc (CODEOWNERS).
  - *"Bản lỗi có lên 3102 được không?"* — không: Build chỉ tạo tag **ứng viên**; compose triển khai tag `hotfix-f01-f02`, chỉ được gắn khi **Test + Trivy + Dockle đều đạt**. Riêng lỗi cấu hình chỉ lộ khi chạy (nginx, root) thì có lên 3102, Operate phát hiện và **hủy push** — phải trả cấu hình lại.
  - *"Sao cần cả hook lẫn CI?"* — hook cho phản hồi **sớm** trên máy (shift-left) nhưng bỏ qua được bằng `--no-verify`; **GitHub Actions** là cổng không bỏ qua được. Muốn CI thật sự bắt buộc thì phải bật branch protection cho `main` (chưa bật).
  - *"Có tự triển khai lên môi trường thật không?"* — **chưa có CD**: pre-push triển khai lên 3102 trên máy thành viên, Actions triển khai lên máy ảo tạm; chưa có môi trường production.
- **[Cue] Demo** theo `report/scanSAC.md` mục *Integration* (PowerShell, chỉ dùng `git commit` / `git push`): F01 + secret bị chặn ở commit → F01 `--no-verify` bị chặn ở push → F02 qua commit, chặn ở Test → F03/F04 cấu hình sai bị chặn ở commit → nginx bỏ chặn `/metrics` và container root bị chặn ở Operate → bản vá push đạt 21 PASS → bỏ qua cả hai hook thì Actions đỏ. Dọn: `& "C:\Program Files\Git\bin\bash.exe" devsecops/demo-cleanup.sh -y`.

---

## B. BỐN LỖI (mỗi thành viên)

**F01 — SQL injection đăng nhập — *Nguyễn Toàn Thắng***
- **Lỗi:** `login.ts` ghép thẳng email vào câu SQL; `' OR 1=1--` → cấp token tài khoản đầu tiên (admin) không cần mật khẩu. **CWE-89 / A03**.
- **Impact:** **vượt xác thực, chiếm tài khoản quản trị** → truy cập **toàn bộ dữ liệu người dùng** (email, đơn, giỏ) — mức nghiêm trọng. Chuẩn: **GDPR Đ.32**.
- **Phát hiện (quét kiểu gì):** **SAST Semgrep** quét `routes/` chỉ đúng dòng lỗi; **kiểm thử** gửi payload + mật khẩu sai, yêu cầu 401 → **đỏ** trên mã chưa vá.
- **Xử lý (sửa kiểu gì):** đổi sang **truy vấn tham số** (bind `$email`/`$password`) → ký tự SQL chỉ còn là dữ liệu. Kiểm chứng: test **xanh**, demo 401 (payload) / 200 (hợp lệ).
- Pha **Code → Test**.
- **Demo (vừa chạy vừa nói):** `python report/demos/tv1_f01_sqli.py`. Chỉ hàng **trước vá (3100)**: cùng payload `' OR 1=1--`, cột *Cấp token?* = **True** → "còn lỗ hổng". Chỉ hàng **sau vá (3102)**: **401** → "đã chặn". Chỉ dòng đối chứng `jim`: **200** → "đăng nhập thật vẫn vào bình thường".

**F02 — Poison Null Byte — *Phạm Thị Minh Thúy***
- **Lỗi:** `fileServer.ts` lọc đuôi `.md/.pdf` nhưng **kiểm một tên, phục vụ tên khác**; `...bak%2500.md` lọt lọc → cắt null byte → đọc tệp sao lưu. **CWE-158/180 / A01**.
- **Impact:** **lộ tệp sao lưu nhạy cảm** — `package.json.bak` lộ **phiên bản dependency** (→ dò CVE), `coupons_2013.md.bak` lộ **mã giảm giá** (lạm dụng nghiệp vụ). **Giới hạn trong `ftp/`**, không ra `/etc/passwd` (chặn `/` + neo `ftp/`). Chuẩn: **GDPR Đ.5(1)(f), 32**.
- **Phát hiện (quét kiểu gì):** **Semgrep** (rule `express-res-sendfile`) chỉ ra `res.sendFile` nhận tên từ người dùng; phân tích luồng + **kiểm thử HTTP** yêu cầu 403.
- **Xử lý (sửa kiểu gì):** **từ chối null byte** (`%00`/NUL) **trước** bước kiểm tra → 403; tệp `.md` hợp lệ vẫn tải.
- Pha **Code → Test**.
- **Demo (vừa chạy vừa nói):** `python report/demos/tv2_f02_pathtraversal.py`. Trước vá: `...bak%2500.md` → **200 + nội dung** tệp sao lưu (chỉ vào nội dung bị lộ). Sau vá: **403**; tệp `legal.md` hợp lệ vẫn **200**.

**F03 — Lộ /metrics — *Đỗ Đức Quốc Anh***
- **Lỗi:** `/metrics` (prom-client) mở, **không xác thực**; rủi ro **vận hành**, không phải lỗi code.
- **Impact:** **rò rỉ dữ liệu vận hành** (số người dùng, số đơn, số dư ví) cho bất kỳ ai tới host → **trinh sát/do thám** hệ thống, suy ra quy mô kinh doanh. Chuẩn: **GDPR Đ.25(2), 32**.
- **Phát hiện (quét kiểu gì):** rà bề mặt phơi nhiễm khi dựng giám sát — **thử `/metrics` từ host** → 200 không cần auth (động, kiểu DAST).
- **Xử lý (sửa kiểu gì):** backend vào **mạng internal**, proxy trả **404** cho `/metrics` (không xóa — giám sát nội bộ vẫn dùng); chống tái diễn tự động bằng **hai lớp**: **Policy as Code** `compose.rego` (NET-02) chặn backend mở cổng host ngay khi commit; còn lớp proxy (`nginx.conf`) không có luật Rego nào đọc được nên do **Operate** gọi thật `GET /metrics` → phải **404**. Thêm cảnh báo `HighClientErrorRate` fire thật.
- Pha **Deploy → Operate**.
- **Demo (vừa chạy vừa nói):** `python report/demos/tv3_f03_metrics.py`. Trước vá `3100/metrics` → **200**, cuộn cho thấy số người dùng/ví bị lộ. Sau vá `3102/metrics` → **404**; cổng backend cũ **refused**; nhưng `docker exec` proxy đọc metrics nội bộ → **vẫn được** ("giám sát trong mạng vẫn dùng"). Bảng cuối: **Conftest `compose.rego`** — compose trước vá **exit 1** (`F03 NET-02`), `docker-compose.yml` **exit 0**. Mở **Grafana**: số liệu thật + cảnh báo **FIRING** khi mô phỏng dò đăng nhập.

**F04 — Policy as Code container — *Hồ Anh Vũ***
- **Lỗi:** image gốc **không sai**; **fixture cố ý** `report/fixtures/Dockerfile.vulnerable` phạm **4 nhóm**: root (không USER), EXPOSE 22/3306, secret trong ENV, thiếu nhãn OCI.
- **Impact (nếu để nguyên):** chạy **root** → nếu có RCE thì **leo thang/thoát container**; **secret trong image** lộ qua `docker history`; cổng quản trị mở rộng **bề mặt tấn công**.
- **Chuẩn quốc tế quy định gì (4 nhóm luật):**
  - **LEAST-PRIVILEGE** — *CIS Docker 4.1*: container chạy **user riêng, KHÔNG root**; *PCI-DSS 2.2*: đặc quyền tối thiểu; *NIST SP 800-190*.
  - **ATTACK-SURFACE** — *CIS Docker 5.8*: **chỉ mở cổng cần thiết**, không mở cổng quản trị/CSDL (22/3306); *NIST SP 800-190*.
  - **SUPPLY-CHAIN** — *OCI image-spec*: **nhãn nguồn gốc**; *CIS §4*: không `:latest`, dùng `COPY` thay `ADD`, ghim digest; *NIST SSDF*; *SLSA* chỉ **tham chiếu** (chưa đạt).
  - **SECRET-IN-IMAGE** — *CIS Docker 4.10*: **không lưu bí mật trong Dockerfile**; *PCI-DSS 8.2.1*: không lưu credential dạng đọc được; *GDPR Đ.32*.
  - Bao trùm: *GDPR Đ.25*: bảo vệ dữ liệu **từ thiết kế & theo mặc định**.
- **Phát hiện (quét kiểu gì):** **Policy as Code** — Conftest quét **văn bản Dockerfile** theo bộ luật Rego (nhóm viết trước). `verify` kiểm luật (19/19); `test` soi file → fixture **exit 1** (chặn 4 nhóm).
- **Xử lý (sửa kiểu gì):** Dockerfile vá (thêm `USER` non-root, bỏ cổng 22/3306, thêm nhãn OCI, không secret ENV) + **luật Rego** chống tái diễn. Bản vá + Dockerfile gốc + hotfix **đều đạt** (không báo nhầm).
- Pha **Build → Release**.
- **Demo (vừa chạy vừa nói):** `python report/demos/tv4_f04_policy.py`. Chỉ dòng đầu `verify` **19/19** ("luật đúng"). Chỉ bảng: `Dockerfile.vulnerable` **exit 1**, đọc tên **4 nhóm** bị chặn; còn **bản vá / Dockerfile gốc / hotfix** đều **exit 0 "đạt"** ("luật không báo nhầm file hợp lệ").

---

## C. GIÁ TRỊ CÁC BỔ SUNG CỦA NHÓM (nói kĩ — mỗi cái lấp một lỗ hổng mà lớp khác không thấy)
- **SCA — Trivy:** phủ mảng **CVE của thư viện (dependency)** mà SAST (quét code tự viết) và Conftest (quét cấu hình) **không thấy** → biết rủi ro thư viện cũ (vd `crypto-js` CRITICAL) để nâng cấp khi lên thật.
- **Dockle (CIS image):** bắt lỗi **chỉ lộ ở image thành phẩm** — vd secret nằm trong **tệp bị COPY vào layer** — mà Conftest đọc *văn bản Dockerfile* không thấy. Conftest kiểm *công thức trước build*, Dockle kiểm *thành phẩm sau build* → **bổ trợ, không trùng**.
- **Luật `SECRET-IN-IMAGE` (nhóm tự viết):** chặn secret bị **bake vào layer** (lộ qua `docker history` kể cả khi xóa ở layer sau) — rủi ro dữ liệu thật, ngoài bộ luật nền.
- **Reverse proxy + rate-limit:** **điểm chặn tập trung** cho `/metrics` + **chống dò mật khẩu**; backend không lộ trực tiếp ra host.
- **`compose.rego`:** **đóng băng bài học F03 thành luật** → lần sau cấu hình sai bị **chặn tự động**, không phụ thuộc trí nhớ người triển khai.
- **Giám sát + cảnh báo (Prometheus/Grafana):** phát hiện **bất thường lúc chạy** (dò đăng nhập → 4XX tăng → FIRING) mà **mã nguồn không tự biết** — lớp phòng thủ cuối ở Operate.

## D. KẾT LUẬN
- Trọn vòng **phát hiện – sửa – kiểm chứng** cho 4 tình huống, viết thành mã, chạy được; trải Code/Test → Build/Deploy → Operate.
- Các kiểm soát **chạy tự động theo Git**: hook pre-commit/pre-push trên máy + GitHub Actions đủ 7 pha (mục A6) — mỗi lần sửa lỗi/đổi mã đều qua cùng một bộ cổng.
- Ranh giới: repo Juice Shop gốc **đã có** CI/CD, CodeQL, SBOM; đóng góp nhóm là **kiểm soát bổ sung, hướng dữ liệu cá nhân** trong phạm vi 4 tình huống, gắn vào quy trình Git. **Chưa có CD** lên môi trường thật (pre-push triển khai lên 3102 trên máy thành viên, Actions lên máy ảo tạm).

## Lưu ý thuật ngữ
- **lỗ hổng** (không "điểm yếu"); **Poison Null Byte** (không IDOR); **truy vấn tham số**; **Policy as Code**.
- Semgrep/Trivy/Gitleaks = **luật có sẵn**; chỉ **Conftest + kiểm thử** là nhóm tự viết.
- PaC = văn bản *trước build*; CaC = thực thể *đang chạy*. `verify` kiểm **luật**; `test` kiểm **file**.
- **Cổng** (gate) = một bước kiểm có PASS/FAIL; **pipeline** = các cổng xếp theo pha; **hook** = script Git tự chạy trước commit/push; **image ứng viên** (`ci-<sha>`) ≠ **image phát hành** (`hotfix-f01-f02`).

---

## Phụ lục — Lệnh chạy các công cụ

Đã tách sang **`report/scanSAC.md`** — lệnh chạy từng công cụ (slide A7) theo pha, kèm ghi chú Trivy/Dockle qua Docker và mục Prometheus.

Pipeline tích hợp Git (mục A6): cách hoạt động + bảng cổng ở **`devsecops/README.md`**; kịch bản test 4 lỗi qua `git commit` / `git push` (PowerShell) ở **`report/scanSAC.md`** mục *Integration*; script dọn `devsecops/demo-cleanup.sh`.
